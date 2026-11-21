"""
metrics.py
Tính toán bộ chỉ số đánh giá cho Tầng 3 + Tầng 4 + Tầng 5:
- Single-shot (vòng 1) vs Multi-loop (vòng <= N)
- Phân bố 4 trạng thái đầu ra chuẩn hóa của Loop Controller
- Thống kê hiệu quả lọc FP của Module 2 ở vòng lặp >= 2
"""

from collections import Counter, defaultdict
from typing import List

from src.module5.schemas import FixSummary


def compute_fixer_metrics(summaries: List[FixSummary]) -> dict:
    """Tính toán chỉ số Single-shot (iter 1) vs Multi-loop (iter <= N) và mức tiêu tốn token."""
    n = len(summaries)
    if n == 0:
        return {
            "total_findings": 0,
            "single_shot": {},
            "multi_loop": {},
            "failure_stages": {},
            "final_statuses": {},
            "re_review_stats": {},
            "per_category": {},
        }

    def _rate(count: int) -> float:
        return round(count / n, 4)

    # --- Single-shot (chỉ xét iteration == 1) ---
    ss_parsed = ss_applied = ss_syntax = ss_sig = ss_compiled = ss_passed = 0
    ss_prompt_tok = ss_comp_tok = 0
    ss_lat = 0.0

    # --- Multi-loop (tổng hợp qua các iteration 1..N) ---
    ml_parsed = ml_applied = ml_syntax = ml_sig = ml_compiled = ml_passed = 0
    ml_prompt_tok = ml_comp_tok = 0
    ml_lat = 0.0

    resolved_sast_clean = 0
    resolved_fp_filtered = 0
    total_re_reviewed = 0
    total_sast_fp_filtered = 0

    failure_counter: Counter = Counter()
    status_counter: Counter = Counter()
    per_cat_raw = defaultdict(lambda: {"total": 0, "single_shot_passed": 0, "multi_loop_passed": 0})

    for s in summaries:
        iters = s.iterations
        if iters:
            it1 = iters[0]
            if not it1.patch.parse_error and not it1.patch.llm_error:
                ss_parsed += 1
            if it1.apply_result and it1.apply_result.applied:
                ss_applied += 1
            if it1.validation.syntax_valid:
                ss_syntax += 1
            if it1.validation.signature_preserved:
                ss_sig += 1
            if it1.validation.compiled:
                ss_compiled += 1
            if it1.passed:
                ss_passed += 1
            ss_prompt_tok += it1.patch.prompt_tokens or 0
            ss_comp_tok += it1.patch.completion_tokens or 0
            ss_lat += it1.patch.latency_sec or 0.0

        if any(not it.patch.parse_error and not it.patch.llm_error for it in iters):
            ml_parsed += 1
        if any(it.apply_result and it.apply_result.applied for it in iters):
            ml_applied += 1
        if any(it.validation.syntax_valid for it in iters):
            ml_syntax += 1
        if any(it.validation.signature_preserved for it in iters):
            ml_sig += 1
        if any(it.validation.compiled for it in iters):
            ml_compiled += 1

        status_counter[s.final_status] += 1
        if s.multi_loop_passed:
            ml_passed += 1
            if s.resolved_via_sast_fp_filter:
                resolved_fp_filtered += 1
            else:
                resolved_sast_clean += 1
        elif s.final_failure_stage:
            failure_counter[s.final_failure_stage] += 1

        total_re_reviewed += s.total_re_reviewed
        total_sast_fp_filtered += s.total_sast_fp_filtered

        ml_prompt_tok += s.total_prompt_tokens
        ml_comp_tok += s.total_completion_tokens
        ml_lat += s.total_latency_sec

        if s.category:
            per_cat_raw[s.category]["total"] += 1
            if s.single_shot_passed:
                per_cat_raw[s.category]["single_shot_passed"] += 1
            if s.multi_loop_passed:
                per_cat_raw[s.category]["multi_loop_passed"] += 1

    ss_total_tok = ss_prompt_tok + ss_comp_tok
    ml_total_tok = ml_prompt_tok + ml_comp_tok

    per_category = {}
    for cat, counts in sorted(per_cat_raw.items()):
        tot = counts["total"]
        per_category[cat] = {
            **counts,
            "single_shot_rate": round(counts["single_shot_passed"] / tot, 4) if tot else 0.0,
            "multi_loop_rate": round(counts["multi_loop_passed"] / tot, 4) if tot else 0.0,
        }

    return {
        "total_findings": n,
        "single_shot": {
            "parsed_rate": _rate(ss_parsed),
            "applied_rate": _rate(ss_applied),
            "syntax_rate": _rate(ss_syntax),
            "signature_rate": _rate(ss_sig),
            "compiled_rate": _rate(ss_compiled),
            "fix_success_count": ss_passed,
            "fix_success_rate": _rate(ss_passed),
            "avg_prompt_tokens": round(ss_prompt_tok / n, 1),
            "avg_completion_tokens": round(ss_comp_tok / n, 1),
            "avg_total_tokens": round(ss_total_tok / n, 1),
            "avg_tokens_per_success": round(ss_total_tok / ss_passed, 1) if ss_passed else None,
            "avg_latency_sec": round(ss_lat / n, 2),
        },
        "multi_loop": {
            "parsed_rate": _rate(ml_parsed),
            "applied_rate": _rate(ml_applied),
            "syntax_rate": _rate(ml_syntax),
            "signature_rate": _rate(ml_sig),
            "compiled_rate": _rate(ml_compiled),
            "fix_success_count": ml_passed,
            "fix_success_rate": _rate(ml_passed),
            "avg_prompt_tokens": round(ml_prompt_tok / n, 1),
            "avg_completion_tokens": round(ml_comp_tok / n, 1),
            "avg_total_tokens": round(ml_total_tok / n, 1),
            "avg_tokens_per_success": round(ml_total_tok / ml_passed, 1) if ml_passed else None,
            "avg_latency_sec": round(ml_lat / n, 2),
        },
        "failure_stages": dict(failure_counter),
        "final_statuses": dict(status_counter),
        "re_review_stats": {
            "resolved_sast_clean": resolved_sast_clean,
            "resolved_via_sast_fp_filter": resolved_fp_filtered,
            "total_re_reviewed": total_re_reviewed,
            "total_sast_fp_filtered": total_sast_fp_filtered,
        },
        "per_category": per_category,
    }
