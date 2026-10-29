"""
benchmark_scoring.py
Đánh giá toàn diện 3 chế độ trên toàn bộ OWASP Benchmark (~2,740 test cases):
  1. Semgrep Only
  2. SpotBugs Only
  3. Combined Pipeline (Semgrep + SpotBugs với Fuzzy Deduplication)

Đặc điểm:
  - Tái sử dụng workspace cố định (data/workspace/run_benchmark) để bỏ qua re-compile.
  - Lưu kết quả vào folder riêng biệt: data/results/benchmark_<timestamp>/
  - Chỉ quét 2 lần (Semgrep 1 lần + SpotBugs 1 lần), sau đó gộp findings để đánh giá chế độ Combined.
  - In bảng so sánh đối đầu (Side-by-side Scorecard) trực tiếp ra màn hình.

Chạy từ thư mục gốc project:
  python3 -m evaluation.benchmark_scoring
  python3 -m evaluation.benchmark_scoring --clean   # Xóa workspace và compile lại từ đầu
"""

import argparse
import csv
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from src.preprocessor import BenchmarkPreprocessor
from src.scanner.aggregator import SASTAggregator
from src.scanner.base import RawFinding
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.schemas import Finding

BENCHMARK_RAW_ROOT = Path("data/raw/BenchmarkJava")
EXPECTED_CSV = BENCHMARK_RAW_ROOT / "expectedresults-1.2.csv"
GLOBAL_RESULTS_DIR = Path("data/results")

TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d+)")
CWE_EQUIVALENT = {"CWE-327": {"CWE-326"}}

SEVERITY_BLOCKLIST = {"INFO"}
CONFIDENCE_BLOCKLIST = {"LOW"}


def cwe_matches(expected_cwe: str, finding_cwe: str, use_equivalence: bool) -> bool:
    if finding_cwe == expected_cwe:
        return True
    return use_equivalence and finding_cwe in CWE_EQUIVALENT.get(expected_cwe, set())


def load_expected_results(csv_path: Path) -> dict:
    """Đọc ground truth CSV: {test_name: {"category", "real", "cwe"}}"""
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


def filter_noise(findings: List[RawFinding]) -> List[RawFinding]:
    """Loại bỏ các finding mức LOW / INFO coi là nhiễu."""
    return [
        f for f in findings
        if f.severity not in SEVERITY_BLOCKLIST and f.confidence not in CONFIDENCE_BLOCKLIST
    ]


def group_by_test(findings: list) -> Dict[str, list]:
    by_test = defaultdict(list)
    for f in findings:
        m = TEST_NAME_PATTERN.search(f.file_path)
        if m:
            by_test[m.group(1)].append(f)
    return by_test


def compute_metrics(c: dict) -> dict:
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0          # TPR
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        **c,
        "precision": round(precision, 4),
        "recall_tpr": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "benchmark_score": round(recall - fpr, 4),        # OWASP Score = TPR - FPR
    }


def score_test_level(expected: dict, by_test: dict, mode: str) -> Tuple[dict, dict]:
    total = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    per_cat = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    for test_name, info in expected.items():
        findings = by_test.get(test_name, [])
        if mode == "lenient":
            flagged = len(findings) > 0
        else:
            target = f"CWE-{info['cwe']}"
            flagged = any(cwe_matches(target, f.cwe_id, mode == "strict_equiv") for f in findings)

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


def label_findings(findings: list, expected: dict) -> Tuple[List[dict], int]:
    labeled, unmatched = [], 0
    for f in findings:
        m = TEST_NAME_PATTERN.search(f.file_path)
        info = expected.get(m.group(1)) if m else None
        if info is None:
            unmatched += 1
            continue
        target = f"CWE-{info['cwe']}"
        f_id = getattr(f, "finding_id", str(uuid.uuid4()))
        labeled.append({
            "finding_id": f_id,
            "test_name": m.group(1),
            "category": info["category"],
            "expected_cwe": target,
            "finding_cwe": f.cwe_id,
            "test_is_real_vulnerability": info["real"],
            "is_true_positive": info["real"] and cwe_matches(target, f.cwe_id, True),
            "is_true_positive_exact": info["real"] and f.cwe_id == target,
        })
    return labeled, unmatched


def build_complete_findings(raw_findings: List[RawFinding], extractor: JavaContextExtractor) -> List[Finding]:
    """Trích xuất AST context cho các finding sau gộp."""
    complete = []
    print(f"[INFO] Đang trích xuất AST context cho {len(raw_findings)} finding ...")
    for raw in raw_findings:
        ctx_info = None
        try:
            ctx_info = extractor.extract_method(raw.file_path, raw.line_start)
        except Exception:
            pass

        complete.append(
            Finding(
                finding_id=str(uuid.uuid4()),
                tool_name=raw.tool_name,
                rule_id=raw.rule_id,
                cwe_id=raw.cwe_id,
                file_path=raw.file_path,
                line_start=raw.line_start,
                line_end=raw.line_end,
                message=raw.message,
                severity=raw.severity,
                confidence=raw.confidence,
                remediation_advice=raw.remediation_advice,
                suggested_fix_snippet=raw.suggested_fix_snippet,
                references=raw.references,
                method_name=ctx_info["method_name"] if ctx_info else None,
                function_context=ctx_info["source"] if ctx_info else None,
                context_start_line=ctx_info["start_line"] if ctx_info else None,
                context_end_line=ctx_info["end_line"] if ctx_info else None,
            )
        )
    return complete


def print_comparison_table(eval_results: Dict[str, dict]):
    """In bảng so sánh đối đầu trực quan ra màn hình."""
    print("\n" + "=" * 90)
    print("                    OWASP BENCHMARK - TIER 1 EVALUATION SCORECARD")
    print("=" * 90)
    print(f"{'Configuration':<24} | {'TPR (Recall)':<12} | {'FPR':<10} | {'OWASP Score':<12} | {'Precision':<10} | {'F1-Score':<8}")
    print("-" * 90)

    for name, res in eval_results.items():
        m = res["strict_equiv"]
        score_str = f"{m['benchmark_score']:+.2%}"
        tpr_str = f"{m['recall_tpr']:.2%}"
        fpr_str = f"{m['fpr']:.2%}"
        prec_str = f"{m['precision']:.2%}"
        f1_str = f"{m['f1']:.4f}"
        print(f"{name:<24} | {tpr_str:<12} | {fpr_str:<10} | {score_str:<12} | {prec_str:<10} | {f1_str:<8}")

    print("=" * 90)
    print("* Chú thích: Metrics hiển thị ở mức Strict Equivalence (chuẩn OWASP Benchmark).")
    print("  OWASP Benchmark Score = TPR - FPR (+100% là điểm tuyệt đối, 0% là đoán ngẫu nhiên).")


def print_category_comparison(eval_results: Dict[str, dict]):
    """In bảng so sánh chi tiết theo từng danh mục lỗ hổng."""
    categories = sorted(eval_results["Combined (Tier 1)"]["per_cat_strict_equiv"].keys())
    print("\n" + "=" * 90)
    print("                     PER-CATEGORY OWASP SCORES (TPR - FPR)")
    print("=" * 90)
    print(f"{'Category':<14} | {'Semgrep Only':<18} | {'SpotBugs Only':<18} | {'Combined Pipeline':<18}")
    print("-" * 90)

    for cat in categories:
        s_score = eval_results["Semgrep Only"]["per_cat_strict_equiv"][cat]["benchmark_score"]
        b_score = eval_results["SpotBugs Only"]["per_cat_strict_equiv"][cat]["benchmark_score"]
        c_score = eval_results["Combined (Tier 1)"]["per_cat_strict_equiv"][cat]["benchmark_score"]

        print(f"{cat:<14} | {s_score:>+8.2%}           | {b_score:>+8.2%}           | {c_score:>+8.2%}")
    print("=" * 90)


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Tier 1 Three-Mode Evaluation")
    parser.add_argument("--clean", action="store_true", help="Xóa workspace run_benchmark và chuẩn bị lại từ đầu")
    args = parser.parse_args()

    # 1. Khởi tạo workspace cố định run_benchmark qua Module 0
    preprocessor = BenchmarkPreprocessor()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_id = f"benchmark_{timestamp}"

    print(f"[INFO] Thiết lập môi trường đánh giá...")
    ctx = preprocessor.setup_run(
        test_list=["all"],
        run_id="run_benchmark",
        results_id=results_id,
        resume=not args.clean,
        clean=args.clean,
    )

    expected = load_expected_results(EXPECTED_CSV)
    print(f"[INFO] Nạp {len(expected)} test case từ ground truth CSV: {EXPECTED_CSV}")

    # 2. PASS 1: Semgrep Only
    print("\n" + "-" * 50)
    print("[RUN] Pass 1: Quét Semgrep trên toàn bộ test code...")
    semgrep = SemgrepTool(ruleset="p/java")
    semgrep_raw = semgrep.run(ctx.target_path)
    semgrep_filtered = filter_noise(semgrep_raw)
    print(f"[INFO] Semgrep tìm thấy: {len(semgrep_raw)} raw -> {len(semgrep_filtered)} sau lọc nhiễu")

    # 3. PASS 2: SpotBugs Only
    print("\n" + "-" * 50)
    print("[RUN] Pass 2: Quét SpotBugs trên toàn bộ test code...")
    spotbugs = SpotBugsTool()
    spotbugs_raw = spotbugs.run(ctx.target_path)
    spotbugs_filtered = filter_noise(spotbugs_raw)
    print(f"[INFO] SpotBugs tìm thấy: {len(spotbugs_raw)} raw -> {len(spotbugs_filtered)} sau lọc nhiễu")

    # 4. PASS 3: Combined (Deduplication qua Aggregator)
    print("\n" + "-" * 50)
    print("[RUN] Pass 3: Gộp kết quả Semgrep + SpotBugs qua SASTAggregator...")
    aggregator = SASTAggregator(tools=[], line_window=4)
    # Tận dụng findings từ 2 lần quét trước, gộp theo fuzzy window
    combined_filtered = aggregator._dedup(semgrep_filtered + spotbugs_filtered)
    print(f"[INFO] Combined findings sau fuzzy dedup: {len(combined_filtered)}")

    # 5. Chấm điểm cả 3 cấu hình
    modes = {
        "Semgrep Only": semgrep_filtered,
        "SpotBugs Only": spotbugs_filtered,
        "Combined (Tier 1)": combined_filtered,
    }

    eval_results = {}
    for name, findings_list in modes.items():
        by_test = group_by_test(findings_list)
        lenient, lenient_cat = score_test_level(expected, by_test, "lenient")
        strict, strict_cat = score_test_level(expected, by_test, "strict")
        equiv, equiv_cat = score_test_level(expected, by_test, "strict_equiv")
        labeled, unmatched = label_findings(findings_list, expected)

        tp_count = sum(1 for x in labeled if x["is_true_positive"])
        prec = round(tp_count / len(labeled), 4) if labeled else 0.0

        eval_results[name] = {
            "lenient": lenient,
            "strict": strict,
            "strict_equiv": equiv,
            "per_cat_strict": strict_cat,
            "per_cat_strict_equiv": equiv_cat,
            "finding_level": {"total": len(labeled), "true_positives": tp_count, "precision": prec},
        }

    # 6. In kết quả tổng hợp ra màn hình
    print_comparison_table(eval_results)
    print_category_comparison(eval_results)

    # 7. Trích xuất AST Context cho Combined Findings (chuẩn bị input cho Tier 2 Reviewer Agent)
    complete_combined = build_complete_findings(combined_filtered, JavaContextExtractor())
    labeled_combined, _ = label_findings(complete_combined, expected)

    # 8. Lưu toàn bộ kết quả vào data/results/benchmark_<timestamp>/
    res_path = ctx.results_path
    (res_path / "benchmark_summary.json").write_text(json.dumps(eval_results, indent=2, ensure_ascii=False))
    (res_path / "findings_semgrep.json").write_text(json.dumps([f.model_dump() for f in semgrep_filtered], indent=2))
    (res_path / "findings_spotbugs.json").write_text(json.dumps([f.model_dump() for f in spotbugs_filtered], indent=2))
    (res_path / "findings_combined.json").write_text(json.dumps([f.model_dump() for f in complete_combined], indent=2))
    (res_path / "tier1_findings_labeled.json").write_text(json.dumps(labeled_combined, indent=2))

    # Cập nhật bản baseline mới nhất tại data/results/ để tương thích với các script cũ
    (GLOBAL_RESULTS_DIR / "tier1_baseline_scores.json").write_text(
        json.dumps(eval_results["Combined (Tier 1)"], indent=2, ensure_ascii=False)
    )
    (GLOBAL_RESULTS_DIR / "tier1_findings_labeled.json").write_text(
        json.dumps(labeled_combined, indent=2, ensure_ascii=False)
    )

    print(f"\n[INFO] Đã lưu đầy đủ artifacts vào thư mục kết quả: {res_path}")
    print(f"[INFO] Đã cập nhật {GLOBAL_RESULTS_DIR / 'tier1_baseline_scores.json'}")


if __name__ == "__main__":
    main()
