"""
benchmark_scoring.py
Đánh giá toàn diện hệ sinh thái trên OWASP Benchmark (~2,740 test cases):
  1. Semgrep Only (Source-level SAST)
  2. SpotBugs Only (Bytecode-level SAST)
  3. Combined Pipeline (Tier 1 SAST Aggregator với Fuzzy Deduplication)
  4. Reviewer Agent (Tier 2 LLM Agentic Triage)

Đặc điểm:
  - Tái sử dụng workspace cố định (data/workspace/run_benchmark) để bỏ qua re-compile.
  - Hỗ trợ đánh giá trọn vẹn cả Tier 1 và Tier 2 trên cùng một bảng Scorecard đối đầu.
  - Hỗ trợ resume khi chạy LLM và chế độ --score-only xem lại điểm trong 0.1 giây.

Các cách chạy từ thư mục gốc:
  # 1. Đánh giá Tier 1 SAST như cũ (~10-15 phút):
  python3 -m evaluation.benchmark_scoring

  # 2. Đánh giá cả Tier 1 và Tier 2 Reviewer (tập test):
  python3 -m evaluation.benchmark_scoring --reviewer --split test

  # 3. Bỏ qua quét SAST (dùng kết quả Tier 1 có sẵn), chỉ chạy và chấm Tier 2:
  python3 -m evaluation.benchmark_scoring --reviewer --skip-sast --split test

  # 4. Chỉ in lại bảng điểm đối đầu 4 cột từ kết quả đã lưu (0.1 giây):
  python3 -m evaluation.benchmark_scoring --reviewer --score-only --split test
"""

import argparse
import csv
import json
import re
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scipy.stats import fisher_exact

from src.preprocessor import BenchmarkPreprocessor
from src.scanner.aggregator import SASTAggregator
from src.scanner.base import RawFinding
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.agents.llm_client import OllamaClient
from src.agents.reviewer import ReviewerAgent
from src.schemas import Finding

BENCHMARK_RAW_ROOT = Path("data/raw/BenchmarkJava")
EXPECTED_CSV = BENCHMARK_RAW_ROOT / "expectedresults-1.2.csv"
GLOBAL_RESULTS_DIR = Path("data/results")
REVIEWER_RESULTS_DIR = GLOBAL_RESULTS_DIR / "reviewer"
SPLIT_FILE = Path("data/splits/dev_test_split.json")

TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d+)")
CWE_EQUIVALENT = {"CWE-327": {"CWE-326"}}

SEVERITY_BLOCKLIST = {"INFO"}
CONFIDENCE_BLOCKLIST = {"LOW"}


def safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


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
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        **c,
        "precision": round(precision, 4),
        "recall_tpr": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "benchmark_score": round(recall - fpr, 4),
    }


def score_test_level(expected: dict, by_test: dict, mode: str, target_names: Optional[set] = None) -> Tuple[dict, dict]:
    total = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    per_cat = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    for test_name, info in expected.items():
        if target_names is not None and test_name not in target_names:
            continue

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
    complete = []
    print(f"[INFO] Đang trích xuất AST + Callee context cho {len(raw_findings)} finding ...")
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
                callee_context=ctx_info.get("callee_context") if ctx_info else None,
            )
        )
    return complete


def print_comparison_table(eval_results: Dict[str, dict], scope_name: str = "FULL BENCHMARK"):
    """In bảng so sánh đối đầu trực quan đa cấu hình (3 hoặc 4 cột)."""
    print("\n" + "=" * 105)
    print(f"               OWASP BENCHMARK - SYSTEM EVALUATION SCORECARD ({scope_name})")
    print("=" * 105)
    print(f"{'Configuration':<26} | {'TPR (Recall)':<12} | {'FPR':<10} | {'OWASP Score':<12} | {'Precision':<10} | {'F1-Score':<8}")
    print("-" * 105)

    for name, res in eval_results.items():
        m = res["strict_equiv"]
        score_str = f"{m['benchmark_score']:+.2%}"
        tpr_str = f"{m['recall_tpr']:.2%}"
        fpr_str = f"{m['fpr']:.2%}"
        prec_str = f"{m['precision']:.2%}"
        f1_str = f"{m['f1']:.4f}"
        print(f"{name:<26} | {tpr_str:<12} | {fpr_str:<10} | {score_str:<12} | {prec_str:<10} | {f1_str:<8}")

    print("=" * 105)
    print("* Chú thích: Metrics hiển thị ở mức Strict Equivalence (chuẩn OWASP Benchmark).")
    print("  OWASP Benchmark Score = TPR - FPR (+100% là điểm tuyệt đối, 0% là đoán ngẫu nhiên).")


def print_category_comparison(eval_results: Dict[str, dict]):
    """In bảng so sánh chi tiết theo từng danh mục lỗ hổng."""
    first_mode = next(iter(eval_results.values()))
    categories = sorted(first_mode["per_cat_strict_equiv"].keys())
    modes = list(eval_results.keys())

    header_parts = [f"{'Category':<13}"] + [f"{m:<18}" for m in modes]
    header = " | ".join(header_parts)

    print("\n" + "=" * len(header))
    print("                     PER-CATEGORY OWASP SCORES (TPR - FPR)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for cat in categories:
        row = [f"{cat:<13}"]
        for m in modes:
            val = eval_results[m]["per_cat_strict_equiv"].get(cat, {}).get("benchmark_score", 0.0)
            row.append(f"{val:>+8.2%}          ")
        print(" | ".join(row))
    print("=" * len(header))


# ==============================================================================
# HÀM CHẠY VÀ ĐÁNH GIÁ TIER 2 REVIEWER AGENT (PASS 4)
# ==============================================================================

def run_and_score_tier2(
    findings_list: List[Finding],
    expected: dict,
    split_name: str,
    prompt_version: str = "reviewer_v4",
    model_name: str = "qwen2.5-coder:3b",
    use_rule_triage: bool = True,
    score_only: bool = False,
) -> Tuple[List[Finding], dict]:
    """Chạy Reviewer trên các finding và trả về (danh sách finding được duyệt là TP, metrics)."""
    REVIEWER_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"{split_name}_{safe(model_name)}_{prompt_version}"
    out_path = REVIEWER_RESULTS_DIR / f"{stem}.jsonl"

    target_names = set(json.loads(SPLIT_FILE.read_text(encoding="utf-8"))[split_name]) if split_name in ("dev", "test") else None
    todo_findings = [
        f for f in findings_list
        if target_names is None or ((m := TEST_NAME_PATTERN.search(f.file_path)) and m.group(1) in target_names)
    ]

    print(f"\n" + "-" * 50)
    print(f"[RUN] Pass 4: Đánh giá Reviewer Agent (Tier 2) trên tập '{split_name}' ({len(todo_findings)} finding)...")

    if not score_only:
        client = OllamaClient(model=model_name)
        agent = ReviewerAgent(
            client=client,
            prompt_version=prompt_version,
            output_mode="text",
            use_rule_triage=use_rule_triage,
        )

        done_ids = set()
        if out_path.exists():
            for line in out_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    done_ids.add(json.loads(line)["finding_id"])

        remaining = [f for f in todo_findings if f.finding_id not in done_ids]
        print(f"[INFO] Đã có {len(done_ids)} verdicts, cần chạy tiếp {len(remaining)}...")

        t0 = time.perf_counter()
        with open(out_path, "a", encoding="utf-8") as fh:
            for i, f in enumerate(remaining, 1):
                verdict = agent.review(f)
                fh.write(verdict.model_dump_json() + "\n")
                fh.flush()
                if i % 25 == 0 or i == len(remaining):
                    el = time.perf_counter() - t0
                    eta = el / i * (len(remaining) - i)
                    print(f"  [{i}/{len(remaining)}] đã chạy {el/60:.1f}m, còn ~{eta/60:.1f}m")

    # Đọc verdicts đã lưu để lọc finding
    if not out_path.exists():
        print(f"[ERROR] Không tìm thấy file kết quả Reviewer tại: {out_path}")
        return [], {}

    verdicts = [json.loads(x) for x in out_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    verdict_of = {v["finding_id"]: v["verdict"] for v in verdicts}

    # Finding được Tier 2 Reviewer giữ lại (Verdict == TP)
    tp_findings = [f for f in todo_findings if verdict_of.get(f.finding_id) == "TP"]
    dropped_noise_count = sum(1 for f in todo_findings if verdict_of.get(f.finding_id) == "FP")

    print(f"[INFO] Tier 2 Reviewer hoàn tất: giữ lại {len(tp_findings)} finding TP, loại bỏ {dropped_noise_count} finding FP")

    # Kiểm định thống kê Fisher Exact Test
    labeled_file = GLOBAL_RESULTS_DIR / "tier1_findings_labeled.json"
    if labeled_file.exists():
        labeled_data = json.loads(labeled_file.read_text(encoding="utf-8"))
        labels = {x["finding_id"]: x for x in labeled_data}
        a = b = c = d = 0
        for v in verdicts:
            if v["finding_id"] in labels:
                real = labels[v["finding_id"]]["is_true_positive"]
                drop = v["verdict"] == "FP"
                if drop and not real: a += 1
                elif drop and real: b += 1
                elif not drop and not real: c += 1
                else: d += 1
        if min(a + c, b + d) > 0:
            odds, p = fisher_exact([[a, b], [c, d]])
            print(f"[STATS] Fisher Exact Test: OR={odds:.2f}, p-value={p:.4f} (Loại được {a}/{a+c} nhiễu vs mất {b}/{b+d} thật)")

    return tp_findings, {"stem": stem, "total_reviewed": len(verdicts)}


# ==============================================================================
# HÀM CHÍNH (MAIN DISPATCHER)
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Full System Evaluation (Tier 1 & Tier 2)")
    parser.add_argument("--clean", action="store_true", help="Xóa workspace run_benchmark và chuẩn bị lại từ đầu")
    parser.add_argument("--reviewer", action="store_true", help="Chạy và chấm điểm kèm theo cả Reviewer Agent (Tier 2)")
    parser.add_argument("--skip-sast", action="store_true", help="Bỏ qua quét SAST Pass 1-3, nạp findings Tier 1 có sẵn")
    parser.add_argument("--score-only", action="store_true", help="Không quét SAST hay chạy LLM, chỉ nạp kết quả in Scorecard")
    parser.add_argument("--split", choices=["dev", "test", "all"], default="test", help="Tập dữ liệu để đánh giá Reviewer")
    parser.add_argument("--prompt", default="reviewer_v4", help="Phiên bản prompt Reviewer")
    parser.add_argument("--model", default="qwen2.5-coder:3b", help="Tên model Ollama")
    parser.add_argument("--no-rule-triage", action="store_true", help="Tắt quy tắc lọc cứng rule-triage")
    args = parser.parse_args()

    expected = load_expected_results(EXPECTED_CSV)
    print(f"[INFO] Nạp {len(expected)} test case từ ground truth CSV: {EXPECTED_CSV}")

    eval_results = {}
    complete_combined: List[Finding] = []

    # Xác định có cần quét SAST fresh hay không
    should_run_sast = not args.skip_sast and not args.score_only

    # =========================================================================
    # BƯỚC 1: XỬ LÝ TIER 1 SAST (PASS 1, 2, 3)
    # =========================================================================
    if should_run_sast:
        preprocessor = BenchmarkPreprocessor()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_id = f"benchmark_{timestamp}"

        print(f"[INFO] Thiết lập môi trường đánh giá Tier 1...")
        ctx = preprocessor.setup_run(
            test_list=["all"],
            run_id="run_benchmark",
            results_id=results_id,
            resume=not args.clean,
            clean=args.clean,
        )

        # PASS 1: Semgrep Only
        print("\n" + "-" * 50)
        print("[RUN] Pass 1: Quét Semgrep trên toàn bộ test code...")
        semgrep = SemgrepTool(ruleset="p/java")
        semgrep_raw = semgrep.run(ctx.target_path)
        semgrep_filtered = filter_noise(semgrep_raw)
        print(f"[INFO] Semgrep tìm thấy: {len(semgrep_raw)} raw -> {len(semgrep_filtered)} sau lọc nhiễu")

        # PASS 2: SpotBugs Only
        print("\n" + "-" * 50)
        print("[RUN] Pass 2: Quét SpotBugs trên toàn bộ test code...")
        spotbugs = SpotBugsTool()
        spotbugs_raw = spotbugs.run(ctx.target_path)
        spotbugs_filtered = filter_noise(spotbugs_raw)
        print(f"[INFO] SpotBugs tìm thấy: {len(spotbugs_raw)} raw -> {len(spotbugs_filtered)} sau lọc nhiễu")

        # PASS 3: Combined (Aggregator Fuzzy Dedup)
        print("\n" + "-" * 50)
        print("[RUN] Pass 3: Gộp kết quả Semgrep + SpotBugs qua SASTAggregator...")
        aggregator = SASTAggregator(tools=[], line_window=4)
        combined_filtered = aggregator._dedup(semgrep_filtered + spotbugs_filtered)
        print(f"[INFO] Combined findings sau fuzzy dedup: {len(combined_filtered)}")

        # Trích xuất AST Context
        complete_combined = build_complete_findings(combined_filtered, JavaContextExtractor())
        labeled_combined, _ = label_findings(complete_combined, expected)

        # Lưu artifacts Tier 1
        res_path = ctx.results_path
        (res_path / "findings_semgrep.json").write_text(json.dumps([f.model_dump() for f in semgrep_filtered], indent=2))
        (res_path / "findings_spotbugs.json").write_text(json.dumps([f.model_dump() for f in spotbugs_filtered], indent=2))
        (res_path / "findings_combined.json").write_text(json.dumps([f.model_dump() for f in complete_combined], indent=2))
        (res_path / "tier1_findings_labeled.json").write_text(json.dumps(labeled_combined, indent=2))

        (GLOBAL_RESULTS_DIR / "tier1_findings_labeled.json").write_text(json.dumps(labeled_combined, indent=2))
        (GLOBAL_RESULTS_DIR / "tier1_findings.json").write_text(
            json.dumps([f.model_dump() for f in complete_combined], indent=2, ensure_ascii=False), encoding="utf-8"
        )
    else:
        # Nạp lại findings Tier 1 đã có sẵn trong data/results/
        tier1_file = GLOBAL_RESULTS_DIR / "tier1_findings.json"
        if not tier1_file.exists():
            print(f"[ERROR] Không tìm thấy {tier1_file}. Vui lòng chạy không có cờ --skip-sast/--score-only trước!")
            sys.exit(1)
        print(f"[INFO] Nạp sẵn findings Tier 1 từ: {tier1_file}")
        complete_combined = [Finding(**x) for x in json.loads(tier1_file.read_text(encoding="utf-8"))]

    # Phân tách danh sách findings theo công cụ từ tập combined
    semgrep_findings = [f for f in complete_combined if "semgrep" in f.tool_name]
    spotbugs_findings = [f for f in complete_combined if "spotbugs" in f.tool_name]
    combined_findings = complete_combined

    # Lấy phạm vi test case theo split
    target_names = set(json.loads(SPLIT_FILE.read_text(encoding="utf-8"))[args.split]) if args.split in ("dev", "test") else None
    scope_name = f"SPLIT: {args.split.upper()}" if target_names else "FULL SUITE"

    # =========================================================================
    # BƯỚC 2: CHẤM ĐIỂM CÁC CHẾ ĐỘ TIER 1
    # =========================================================================
    tier1_modes = {
        "Semgrep Only": semgrep_findings,
        "SpotBugs Only": spotbugs_findings,
        "Combined (Tier 1)": combined_findings,
    }

    for name, f_list in tier1_modes.items():
        by_test = group_by_test(f_list)
        lenient, lenient_cat = score_test_level(expected, by_test, "lenient", target_names)
        strict, strict_cat = score_test_level(expected, by_test, "strict", target_names)
        equiv, equiv_cat = score_test_level(expected, by_test, "strict_equiv", target_names)
        labeled, _ = label_findings(f_list, expected)

        # Lọc label theo split nếu cần
        if target_names is not None:
            labeled = [x for x in labeled if x["test_name"] in target_names]

        tp_count = sum(1 for x in labeled if x["is_true_positive"])
        prec = round(tp_count / len(labeled), 4) if labeled else 0.0

        eval_results[name] = {
            "lenient": lenient, "strict": strict, "strict_equiv": equiv,
            "per_cat_strict": strict_cat, "per_cat_strict_equiv": equiv_cat,
            "finding_level": {"total": len(labeled), "true_positives": tp_count, "precision": prec},
        }

    # =========================================================================
    # BƯỚC 3: PASS 4 - CHẠY VÀ CHẤM ĐIỂM REVIEWER AGENT (TIER 2)
    # =========================================================================
    if args.reviewer or args.score_only:
        tp_findings, meta = run_and_score_tier2(
            findings_list=complete_combined,
            expected=expected,
            split_name=args.split,
            prompt_version=args.prompt,
            model_name=args.model,
            use_rule_triage=not args.no_rule_triage,
            score_only=args.score_only,
        )

        by_test_t2 = group_by_test(tp_findings)
        lenient, lenient_cat = score_test_level(expected, by_test_t2, "lenient", target_names)
        strict, strict_cat = score_test_level(expected, by_test_t2, "strict", target_names)
        equiv, equiv_cat = score_test_level(expected, by_test_t2, "strict_equiv", target_names)
        labeled_t2, _ = label_findings(tp_findings, expected)

        if target_names is not None:
            labeled_t2 = [x for x in labeled_t2 if x["test_name"] in target_names]

        tp_count = sum(1 for x in labeled_t2 if x["is_true_positive"])
        prec = round(tp_count / len(labeled_t2), 4) if labeled_t2 else 0.0

        eval_results["Reviewer Agent (Tier 2)"] = {
            "lenient": lenient, "strict": strict, "strict_equiv": equiv,
            "per_cat_strict": strict_cat, "per_cat_strict_equiv": equiv_cat,
            "finding_level": {"total": len(labeled_t2), "true_positives": tp_count, "precision": prec},
        }

    # =========================================================================
    # BƯỚC 4: IN SCORECARD ĐỐI ĐẦU TỔNG KẾT
    # =========================================================================
    print_comparison_table(eval_results, scope_name=scope_name)
    print_category_comparison(eval_results)

    # Lưu kết quả tổng kết toàn hệ thống
    summary_path = GLOBAL_RESULTS_DIR / "benchmark_system_summary.json"
    summary_path.write_text(json.dumps(eval_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[INFO] Đã cập nhật tổng kết toàn hệ sinh thái tại: {summary_path}")


if __name__ == "__main__":
    main()