"""
workflow.py
Điều phối pipeline qua LangGraph:
- build_review_graph: Tier 1 (Scanner) -> Tier 2 (Reviewer Agent)
- build_full_graph:   Tier 1 (Scanner) -> Tier 2 (Reviewer Agent) -> Tier 3 (Fixer + Validation Loop)
"""

from typing import List, Optional, TypedDict
from langgraph.graph import END, START, StateGraph

from src.agents.reviewer import ReviewerAgent
from src.module3.runner import FixLoopRunner, compute_fixer_metrics
from src.module3.schemas import FixSummary
from src.scanner.pipeline import ScannerPipeline
from src.schemas import Finding, Verdict


class ReviewGraphState(TypedDict, total=False):
    target_path: Optional[str]
    findings: List[Finding]
    verdicts: List[Verdict]
    tp_findings: List[Finding]


class FullPipelineGraphState(TypedDict, total=False):
    target_path: Optional[str]
    findings: List[Finding]
    verdicts: List[Verdict]
    tp_findings: List[Finding]
    fix_summaries: List[FixSummary]
    fixer_metrics: dict


def build_review_graph(
    scanner_pipeline: Optional[ScannerPipeline],
    reviewer_agent: ReviewerAgent,
):
    def scanner_node(state: ReviewGraphState) -> ReviewGraphState:
        # Nếu đã truyền sẵn findings (vd từ benchmark_scoring), bỏ qua bước quét lại
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
    fix_loop_runner: FixLoopRunner,
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
            # Nếu bỏ qua Reviewer (test Module 3 trực tiếp), đưa toàn bộ findings sang Fixer
            return {"verdicts": [], "tp_findings": findings}
        verdicts = reviewer_agent.review_batch(findings)
        tp_ids = {v.finding_id for v in verdicts if v.verdict == "TP"}
        tp_findings = [f for f in findings if f.finding_id in tp_ids]
        return {"verdicts": verdicts, "tp_findings": tp_findings}

    def fixer_node(state: FullPipelineGraphState) -> FullPipelineGraphState:
        verdicts = state.get("verdicts", [])
        verdicts_by_id = {v.finding_id: v for v in verdicts}
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
    graph.add_node("fixer", fixer_node)

    graph.add_edge(START, "scanner")
    graph.add_edge("scanner", "reviewer")
    graph.add_edge("reviewer", "fixer")
    graph.add_edge("fixer", END)

    return graph.compile()
