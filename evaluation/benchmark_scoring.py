"""
benchmark_scoring.py
Chấm điểm kết quả Tầng 1 (SAST) so với ground truth của OWASP Benchmark.

Đầu ra:
  - data/results/tier1_baseline_scores.json : các chỉ số baseline (trước Reviewer)
  - data/results/tier1_findings_labeled.json: nhãn đáp án cho từng Finding
    (dùng để chấm Reviewer Agent ở Tầng 2)

Chạy từ thư mục gốc project:
  python3 -m evaluation.benchmark_scoring            # dùng cache nếu có
  python3 -m evaluation.benchmark_scoring --refresh  # quét lại Semgrep
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

from src.scanner.aggregator import SASTAggregator
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.pipeline import ScannerPipeline
from src.scanner.semgrep_tool import SemgrepTool
from src.schemas import Finding

BENCHMARK_ROOT = Path("data/raw/BenchmarkJava")
TESTCODE_DIR = BENCHMARK_ROOT / "src/main/java/org/owasp/benchmark/testcode"
EXPECTED_CSV = BENCHMARK_ROOT / "expectedresults-1.2.csv"
RESULTS_DIR = Path("data/results")
FINDINGS_CACHE = RESULTS_DIR / "tier1_findings.json"

TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d+)")


# ---------- 1. Nạp dữ liệu ----------

def load_expected_results(csv_path: Path) -> dict:
    """Đọc đáp án: {test_name: {"category", "real", "cwe"}}"""
    expected = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            test_name, category, real_vuln, cwe = (c.strip() for c in row[:4])
            expected[test_name] = {
                "category": category,
                "real": real_vuln.lower() == "true",
                "cwe": cwe,
            }
    return expected


def get_findings(refresh: bool) -> list[Finding]:
    """Lấy Finding từ cache; chỉ chạy lại pipeline (Semgrep) khi cần."""
    if FINDINGS_CACHE.exists() and not refresh:
        data = json.loads(FINDINGS_CACHE.read_text(encoding="utf-8"))
        print(f"[INFO] Nạp {len(data)} Finding từ cache: {FINDINGS_CACHE}")
        return [Finding(**item) for item in data]

    pipeline = ScannerPipeline(
        aggregator=SASTAggregator(tools=[SemgrepTool(ruleset="p/java")]),
        context_extractor=JavaContextExtractor(),
    )
    findings = pipeline.run(str(TESTCODE_DIR))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_CACHE.write_text(
        json.dumps([f.model_dump() for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[INFO] Đã lưu cache: {FINDINGS_CACHE}")
    return findings


def group_by_test(findings: list[Finding]) -> dict[str, list[Finding]]:
    by_test = defaultdict(list)
    for f in findings:
        m = TEST_NAME_PATTERN.search(f.file_path)
        if m:
            by_test[m.group(1)].append(f)
    return by_test


# ---------- 2. Tính điểm ở mức test case ----------

def compute_metrics(c: dict) -> dict:
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0          # còn gọi là TPR
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        **c,
        "precision": round(precision, 4),
        "recall_tpr": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "benchmark_score": round(recall - fpr, 4),  # chỉ số chuẩn của OWASP Benchmark
    }


def score_test_level(expected: dict, by_test: dict, strict: bool):
    """
    Mỗi test case được tính 1 lần (không đếm số finding).
    lenient: flagged nếu file có ÍT NHẤT 1 finding bất kỳ.
    strict : flagged chỉ khi có finding đúng CWE mà test case đó nhắm tới.
    """
    total = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    per_cat = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    for test_name, info in expected.items():
        findings = by_test.get(test_name, [])
        if strict:
            target_cwe = f"CWE-{info['cwe']}"
            flagged = any(f.cwe_id == target_cwe for f in findings)
        else:
            flagged = len(findings) > 0

        if info["real"] and flagged:
            label = "TP"
        elif not info["real"] and flagged:
            label = "FP"
        elif info["real"] and not flagged:
            label = "FN"
        else:
            label = "TN"

        total[label] += 1
        per_cat[info["category"]][label] += 1

    return compute_metrics(total), {c: compute_metrics(v) for c, v in sorted(per_cat.items())}


# ---------- 3. Gán nhãn đáp án cho từng Finding ----------

def label_findings(findings: list[Finding], expected: dict):
    """
    Với mỗi Finding, xác định "đáp án đúng" mà Reviewer cần đưa ra:
      is_true_positive = test case có lỗ hổng thật VÀ finding đúng CWE của test đó.
    """
    labeled, unmatched = [], 0
    for f in findings:
        m = TEST_NAME_PATTERN.search(f.file_path)
        info = expected.get(m.group(1)) if m else None
        if info is None:
            unmatched += 1
            continue
        labeled.append({
            "finding_id": f.finding_id,
            "test_name": m.group(1),
            "category": info["category"],
            "expected_cwe": f"CWE-{info['cwe']}",
            "finding_cwe": f.cwe_id,
            "test_is_real_vulnerability": info["real"],
            "is_true_positive": info["real"] and f.cwe_id == f"CWE-{info['cwe']}",
        })
    return labeled, unmatched


# ---------- 4. Báo cáo ----------

def print_summary(title: str, m: dict):
    print(f"\n=== {title} ===")
    print(f"TP={m['TP']}  FP={m['FP']}  TN={m['TN']}  FN={m['FN']}")
    print(f"Precision={m['precision']}  Recall(TPR)={m['recall_tpr']}  "
          f"FPR={m['fpr']}  F1={m['f1']}  Benchmark score={m['benchmark_score']}")


def print_per_category(per_cat: dict):
    print(f"\n{'category':<14}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}{'TPR':>8}{'FPR':>8}")
    for cat, m in per_cat.items():
        print(f"{cat:<14}{m['TP']:>5}{m['FP']:>5}{m['TN']:>5}{m['FN']:>5}"
              f"{m['recall_tpr']:>8}{m['fpr']:>8}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="Quét lại bằng Semgrep")
    args = parser.parse_args()

    expected = load_expected_results(EXPECTED_CSV)
    findings = get_findings(args.refresh)
    by_test = group_by_test(findings)

    lenient, lenient_cat = score_test_level(expected, by_test, strict=False)
    strict, strict_cat = score_test_level(expected, by_test, strict=True)
    labeled, unmatched = label_findings(findings, expected)

    true_pos = sum(1 for x in labeled if x["is_true_positive"])
    finding_precision = round(true_pos / len(labeled), 4) if labeled else 0.0

    print(f"Test case trong CSV: {len(expected)} | Finding: {len(findings)} "
          f"| File bị flag: {len(by_test)} | Finding không map được: {unmatched}")
    print_summary("Mức test case - LENIENT (file có finding bất kỳ)", lenient)
    print_summary("Mức test case - STRICT (finding đúng CWE)", strict)
    print_per_category(strict_cat)
    print(f"\n=== Mức finding (đầu vào của Reviewer) ===")
    print(f"{true_pos}/{len(labeled)} finding là TP thật -> precision đầu vào = {finding_precision}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "tier1_baseline_scores.json").write_text(json.dumps({
        "test_level_lenient": lenient, "test_level_strict": strict,
        "per_category_strict": strict_cat,
        "finding_level": {"total": len(labeled), "true_positives": true_pos,
                          "precision": finding_precision},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (RESULTS_DIR / "tier1_findings_labeled.json").write_text(
        json.dumps(labeled, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[INFO] Đã lưu kết quả vào {RESULTS_DIR}/")


if __name__ == "__main__":
    main()