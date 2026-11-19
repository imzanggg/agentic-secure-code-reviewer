"""
runner.py
Điều phối vòng lặp Fix-Validate cho Module 3 (hỗ trợ Single-shot và Multi-loop),
đảm bảo backup/rollback file nguồn sạch giữa các vòng lặp và giữa các finding,
đồng thời tính toán bộ chỉ số so sánh Single-shot vs. Multi-loop.
"""

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from src.schemas import Finding, Verdict
from src.module3.fixer import FixerAgent
from src.module3.schemas import FixIterationResult, FixSummary
from src.module3.validator import PatchValidator

TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d+)")


class FixLoopRunner:
    def __init__(
        self,
        fixer: FixerAgent,
        validator: PatchValidator,
        max_iterations: int = 3,
        keep_passing_patch: bool = False,
    ):
        if max_iterations < 1:
            raise ValueError("max_iterations phải >= 1")
        self.fixer = fixer
        self.validator = validator
        self.max_iterations = max_iterations
        self.keep_passing_patch = keep_passing_patch

    def run_finding(
        self,
        finding: Finding,
        verdict: Optional[Verdict] = None,
        category: Optional[str] = None,
    ) -> FixSummary:
        target = Path(finding.file_path)
        original_bytes = target.read_bytes() if target.exists() else None

        m = TEST_NAME_PATTERN.search(finding.file_path)
        test_name = m.group(1) if m else None

        iterations: List[FixIterationResult] = []
        feedback: Optional[str] = None
        previous_fixed: Optional[str] = None

        single_shot_passed = False
        multi_loop_passed = False
        passed_at_iteration: Optional[int] = None
        final_failure_stage: Optional[str] = None

        total_prompt_tokens = 0
        total_completion_tokens = 0
        total_latency_sec = 0.0

        try:
            for it in range(1, self.max_iterations + 1):
                # Luôn khôi phục file gốc sạch trước khi thử vòng mới
                if it > 1 and original_bytes is not None:
                    target.write_bytes(original_bytes)

                patch = self.fixer.fix(
                    finding=finding,
                    verdict=verdict,
                    feedback=feedback,
                    iteration=it,
                    previous_fixed=previous_fixed,
                )

                total_prompt_tokens += patch.prompt_tokens or 0
                total_completion_tokens += patch.completion_tokens or 0
                total_latency_sec += patch.latency_sec or 0.0

                apply_res, val_res = self.validator.validate(finding, patch)
                passed = bool(val_res.sast_passed)

                iterations.append(
                    FixIterationResult(
                        iteration=it,
                        patch=patch,
                        apply_result=apply_res,
                        validation=val_res,
                        passed=passed,
                    )
                )

                if passed:
                    multi_loop_passed = True
                    passed_at_iteration = it
                    if it == 1:
                        single_shot_passed = True
                    final_failure_stage = None
                    break

                final_failure_stage = val_res.failure_stage
                # Không đưa lỗi hạ tầng (timeout/HTTP) vào prompt thử lại
                feedback = None if val_res.failure_stage == "llm_error" else val_res.feedback
                previous_fixed = patch.fixed_snippet or None
        finally:
            if original_bytes is not None and not (self.keep_passing_patch and multi_loop_passed):
                target.write_bytes(original_bytes)

        return FixSummary(
            finding_id=finding.finding_id,
            test_name=test_name,
            category=category,
            cwe_id=finding.cwe_id,
            file_path=finding.file_path,
            max_iterations=self.max_iterations,
            single_shot_passed=single_shot_passed,
            multi_loop_passed=multi_loop_passed,
            passed_at_iteration=passed_at_iteration,
            final_failure_stage=final_failure_stage,
            total_prompt_tokens=total_prompt_tokens,
            total_completion_tokens=total_completion_tokens,
            total_tokens=total_prompt_tokens + total_completion_tokens,
            total_latency_sec=round(total_latency_sec, 2),
            iterations=iterations,
        )

    def run_batch(
        self,
        findings: Iterable[Finding],
        verdicts_by_id: Optional[Dict[str, Verdict]] = None,
        categories_by_test: Optional[Dict[str, str]] = None,
    ) -> List[FixSummary]:
        verdicts_by_id = verdicts_by_id or {}
        categories_by_test = categories_by_test or {}
        summaries: List[FixSummary] = []

        for f in findings:
            m = TEST_NAME_PATTERN.search(f.file_path)
            cat = categories_by_test.get(m.group(1)) if m else None
            summaries.append(
                self.run_finding(
                    finding=f,
                    verdict=verdicts_by_id.get(f.finding_id),
                    category=cat,
                )
            )
        return summaries


def compute_fixer_metrics(summaries: List[FixSummary]) -> dict:
    """Tính toán chỉ số Single-shot (iter 1) vs Multi-loop (iter <= N) và mức tiêu tốn token."""
    n = len(summaries)
    if n == 0:
        return {"total_findings": 0, "single_shot": {}, "multi_loop": {}, "failure_stages": {}, "per_category": {}}

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

    failure_counter: Counter = Counter()
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
        if s.multi_loop_passed:
            ml_passed += 1
        elif s.final_failure_stage:
            failure_counter[s.final_failure_stage] += 1

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
        "per_category": per_category,
    }
