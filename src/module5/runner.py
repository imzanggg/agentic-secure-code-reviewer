"""
runner.py
Điều phối thực thi LangGraph Fix-Validate-ReReview Loop cho Module 5 (Tầng 5),
đảm bảo backup/rollback file nguồn sạch giữa các finding
và tổng hợp FixSummary đầy đủ cho từng finding.
"""

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from src.agents.reviewer import ReviewerAgent
from src.module3.fixer import FixerAgent
from src.module4.validator import PatchValidator
from src.module5.schemas import FixIterationResult, FixSummary
from src.schemas import Finding, LoopStatus, Verdict

TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d+)")


class FixLoopRunner:
    def __init__(
        self,
        fixer: FixerAgent,
        validator: PatchValidator,
        reviewer: Optional[ReviewerAgent] = None,
        max_iterations: int = 3,
        keep_passing_patch: bool = False,
    ):
        if max_iterations < 1:
            raise ValueError("max_iterations phải >= 1")
        self.fixer = fixer
        self.validator = validator
        self.reviewer = reviewer
        self.max_iterations = max_iterations
        self.keep_passing_patch = keep_passing_patch

        from src.graph.workflow import build_fix_finding_graph

        self.fix_graph = build_fix_finding_graph(
            fixer_agent=self.fixer,
            validator=self.validator,
            reviewer_agent=self.reviewer,
        )

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

        initial_state = {
            "finding": finding,
            "initial_verdict": verdict,
            "file_path": finding.file_path,
            "original_bytes": original_bytes,
            "iteration": 1,
            "max_iterations": self.max_iterations,
            "feedback": None,
            "previous_fixed": None,
            "iterations": [],
            "should_continue": True,
            "final_status": "unresolved - max iterations exceeded",
            "resolved_via_sast_fp_filter": False,
            "final_failure_stage": None,
        }

        final_state: dict = {}
        try:
            recursion_limit = max(25, self.max_iterations * 6 + 10)
            final_state = self.fix_graph.invoke(
                initial_state,
                config={"recursion_limit": recursion_limit},
            )
        finally:
            resolved = final_state.get("final_status") == "resolved"
            if original_bytes is not None and not (self.keep_passing_patch and resolved):
                target.write_bytes(original_bytes)

        iterations: List[FixIterationResult] = final_state.get("iterations", [])
        final_status: LoopStatus = final_state.get(
            "final_status", "unresolved - max iterations exceeded"
        )
        resolved_via_fp = bool(final_state.get("resolved_via_sast_fp_filter", False))
        final_failure_stage = final_state.get("final_failure_stage")

        single_shot_passed = bool(iterations and iterations[0].passed)
        multi_loop_passed = final_status == "resolved"
        passed_at_iteration = next((it.iteration for it in iterations if it.passed), None)

        total_prompt_tokens = sum((it.patch.prompt_tokens or 0) for it in iterations)
        total_completion_tokens = sum((it.patch.completion_tokens or 0) for it in iterations)
        total_latency_sec = sum((it.patch.latency_sec or 0.0) for it in iterations)
        total_re_reviewed = sum(len(it.re_reviews) for it in iterations)
        total_sast_fp_filtered = sum(it.sast_fp_filtered_count for it in iterations)

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
            final_status=final_status,
            resolved_via_sast_fp_filter=resolved_via_fp,
            final_failure_stage=final_failure_stage,
            total_re_reviewed=total_re_reviewed,
            total_sast_fp_filtered=total_sast_fp_filtered,
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
