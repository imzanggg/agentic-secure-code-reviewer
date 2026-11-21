"""
workflow.py
Điều phối pipeline qua LangGraph:
- build_review_graph:      Tier 1 (Scanner) -> Tier 2 (Reviewer Agent)
- build_fix_finding_graph: Vòng lặp cho 1 finding:
                           Tier 3 (Fixer) -> Tier 4 (Validator) -> [Tier 2 Re-reviewer] -> Tier 5 (Controller)
- build_full_graph:        Tier 1 (Scanner) -> Tier 2 (Reviewer) -> Tier 5 Runner (chạy fix_finding_graph)
"""

from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, TypedDict
from langgraph.graph import END, START, StateGraph

from src.agents.reviewer import ReviewerAgent
from src.module3.fixer import FixerAgent
from src.module3.schemas import Module3Patch
from src.module4.schemas import PatchApplyResult, ValidationResult
from src.module4.validator import PatchValidator
from src.module5.controller import evaluate_iteration
from src.module5.metrics import compute_fixer_metrics
from src.module5.schemas import FixIterationResult, FixSummary, ReReviewRecord
from src.scanner.pipeline import ScannerPipeline
from src.schemas import Finding, LoopStatus, Verdict

if TYPE_CHECKING:
    from src.module5.runner import FixLoopRunner


class ReviewGraphState(TypedDict, total=False):
    target_path: Optional[str]
    findings: List[Finding]
    verdicts: List[Verdict]
    tp_findings: List[Finding]


class FindingFixState(TypedDict, total=False):
    finding: Finding
    initial_verdict: Optional[Verdict]
    file_path: str
    original_bytes: Optional[bytes]
    iteration: int
    max_iterations: int
    feedback: Optional[str]
    previous_fixed: Optional[str]
    current_patch: Optional[Module3Patch]
    current_apply_result: Optional[PatchApplyResult]
    current_validation: Optional[ValidationResult]
    current_re_reviews: List[ReReviewRecord]
    iterations: List[FixIterationResult]
    should_continue: bool
    final_status: LoopStatus
    resolved_via_sast_fp_filter: bool
    final_failure_stage: Optional[str]


class FullPipelineGraphState(TypedDict, total=False):
    target_path: Optional[str]
    findings: List[Finding]
    verdicts: List[Verdict]
    tp_findings: List[Finding]
    fix_summaries: List[FixSummary]
    fixer_metrics: dict


def build_fix_finding_graph(
    fixer_agent: FixerAgent,
    validator: PatchValidator,
    reviewer_agent: Optional[ReviewerAgent] = None,
):
    """
    Đồ thị LangGraph cho 1 finding:
      START -> fixer -> validator
        - nếu compile lỗi hoặc SAST thô đã sạch -> controller
        - nếu đã compile và còn raw SAST findings -> re_reviewer (Tầng 2 lọc FP) -> controller
      controller -> fixer (nếu should_continue=True) hoặc END
    """

    def fixer_node(state: FindingFixState) -> FindingFixState:
        patch = fixer_agent.fix(
            finding=state["finding"],
            verdict=state.get("initial_verdict"),
            feedback=state.get("feedback"),
            iteration=state["iteration"],
            previous_fixed=state.get("previous_fixed"),
        )
        return {"current_patch": patch, "current_re_reviews": []}

    def validator_node(state: FindingFixState) -> FindingFixState:
        original_bytes = state.get("original_bytes")
        file_path = state.get("file_path")
        if original_bytes is not None and file_path:
            Path(file_path).write_bytes(original_bytes)

        apply_res, val_res = validator.validate(state["finding"], state["current_patch"])
        return {
            "current_apply_result": apply_res,
            "current_validation": val_res,
        }

    def route_after_validator(state: FindingFixState) -> str:
        val = state["current_validation"]
        if val.compiled and not val.sast_raw_clean:
            return "re_reviewer"
        return "controller"

    def re_reviewer_node(state: FindingFixState) -> FindingFixState:
        val = state["current_validation"]
        records: List[ReReviewRecord] = []

        tagged_findings = [
            ("persisting", f) for f in val.persisting_findings
        ] + [
            ("introduced", f) for f in val.introduced_findings
        ]

        for kind, raw_ctx_finding in tagged_findings:
            if reviewer_agent is not None:
                verdict = reviewer_agent.review(raw_ctx_finding)
            else:
                verdict = Verdict(
                    finding_id=raw_ctx_finding.finding_id,
                    verdict="TP",
                    confidence="low",
                    confidence_score=0.0,
                    reasoning="NO_REVIEWER: fail-safe TP",
                    source="fail_open",
                )
            records.append(
                ReReviewRecord(
                    kind=kind,  # type: ignore[arg-type]
                    finding=raw_ctx_finding,
                    verdict=verdict,
                )
            )
        return {"current_re_reviews": records}

    def controller_node(state: FindingFixState) -> FindingFixState:
        prev_iters = list(state.get("iterations", []))
        patch = state["current_patch"]
        decision = evaluate_iteration(
            iteration=state["iteration"],
            max_iterations=state["max_iterations"],
            patch=patch,
            apply_result=state.get("current_apply_result"),
            validation=state["current_validation"],
            re_reviews=state.get("current_re_reviews", []),
            previous_iterations=prev_iters,
        )

        updated_iters = prev_iters + [decision.iteration_result]

        if decision.should_continue:
            original_bytes = state.get("original_bytes")
            file_path = state.get("file_path")
            if original_bytes is not None and file_path:
                Path(file_path).write_bytes(original_bytes)

            return {
                "iterations": updated_iters,
                "should_continue": True,
                "iteration": state["iteration"] + 1,
                "feedback": decision.next_feedback,
                "previous_fixed": patch.fixed_snippet or None,
                "final_failure_stage": decision.final_failure_stage,
            }

        return {
            "iterations": updated_iters,
            "should_continue": False,
            "final_status": decision.final_status or "unresolved - max iterations exceeded",
            "resolved_via_sast_fp_filter": decision.resolved_via_sast_fp_filter,
            "final_failure_stage": decision.final_failure_stage,
        }

    def route_after_controller(state: FindingFixState) -> str:
        return "fixer" if state.get("should_continue") else END

    graph = StateGraph(FindingFixState)
    graph.add_node("fixer", fixer_node)
    graph.add_node("validator", validator_node)
    graph.add_node("re_reviewer", re_reviewer_node)
    graph.add_node("controller", controller_node)

    graph.add_edge(START, "fixer")
    graph.add_edge("fixer", "validator")
    graph.add_conditional_edges(
        "validator",
        route_after_validator,
        {"re_reviewer": "re_reviewer", "controller": "controller"},
    )
    graph.add_edge("re_reviewer", "controller")
    graph.add_conditional_edges(
        "controller",
        route_after_controller,
        {"fixer": "fixer", END: END},
    )

    return graph.compile()


def build_review_graph(
    scanner_pipeline: Optional[ScannerPipeline],
    reviewer_agent: ReviewerAgent,
):
    def scanner_node(state: ReviewGraphState) -> ReviewGraphState:
        if state.get("findings"):
            return {}
        target = state.get("target_path")
        if not target or scanner_pipeline is None:
            raise ValueError("Cần truyền findings hoặc (target_path + scanner_pipeline).")
        return {"findings": scanner_pipeline.run(target)}

    def reviewer_node(state: ReviewGraphState) -> ReviewGraphState:
        findings = state.get("findings", [])
        verdicts = reviewer_agent.review_batch(findings)
        tp_ids = {v.finding_id for v in verdicts if v.verdict == "TP"}
        tp_findings = [f for f in findings if f.finding_id in tp_ids]
        return {"verdicts": verdicts, "tp_findings": tp_findings}

    graph = StateGraph(ReviewGraphState)
    graph.add_node("scanner", scanner_node)
    graph.add_node("reviewer", reviewer_node)

    graph.add_edge(START, "scanner")
    graph.add_edge("scanner", "reviewer")
    graph.add_edge("reviewer", END)

    return graph.compile()


def build_full_graph(
    scanner_pipeline: Optional[ScannerPipeline],
    reviewer_agent: Optional[ReviewerAgent],
    fix_loop_runner: "FixLoopRunner",
):
    def scanner_node(state: FullPipelineGraphState) -> FullPipelineGraphState:
        if state.get("findings"):
            return {}
        target = state.get("target_path")
        if not target or scanner_pipeline is None:
            raise ValueError("Cần truyền findings hoặc (target_path + scanner_pipeline).")
        return {"findings": scanner_pipeline.run(target)}

    def reviewer_node(state: FullPipelineGraphState) -> FullPipelineGraphState:
        if state.get("verdicts") and "tp_findings" in state:
            return {}
        findings = state.get("findings", [])
        if reviewer_agent is None:
            return {"verdicts": [], "tp_findings": findings}
        verdicts = reviewer_agent.review_batch(findings)
        tp_ids = {v.finding_id for v in verdicts if v.verdict == "TP"}
        tp_findings = [f for f in findings if f.finding_id in tp_ids]
        return {"verdicts": verdicts, "tp_findings": tp_findings}

    def fix_controller_node(state: FullPipelineGraphState) -> FullPipelineGraphState:
        verdicts = state.get("verdicts", [])
        verdicts_by_id: Dict[str, Verdict] = {v.finding_id: v for v in verdicts}
        targets = state.get("tp_findings")
        if targets is None:
            targets = state.get("findings", [])

        fix_summaries = fix_loop_runner.run_batch(
            targets,
            verdicts_by_id=verdicts_by_id,
        )
        fixer_metrics = compute_fixer_metrics(fix_summaries)
        return {"fix_summaries": fix_summaries, "fixer_metrics": fixer_metrics}

    graph = StateGraph(FullPipelineGraphState)
    graph.add_node("scanner", scanner_node)
    graph.add_node("reviewer", reviewer_node)
    graph.add_node("fix_controller", fix_controller_node)

    graph.add_edge(START, "scanner")
    graph.add_edge("scanner", "reviewer")
    graph.add_edge("reviewer", "fix_controller")
    graph.add_edge("fix_controller", END)

    return graph.compile()
