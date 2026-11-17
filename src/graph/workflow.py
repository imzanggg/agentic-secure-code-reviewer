"""
workflow.py
Điều phối pipeline qua LangGraph: Tier 1 (Scanner) -> Tier 2 (Reviewer Agent).
"""

from typing import List, Optional, TypedDict
from langgraph.graph import END, START, StateGraph

from src.agents.reviewer import ReviewerAgent
from src.scanner.pipeline import ScannerPipeline
from src.schemas import Finding, Verdict


class ReviewGraphState(TypedDict, total=False):
    target_path: Optional[str]
    findings: List[Finding]
    verdicts: List[Verdict]
    tp_findings: List[Finding]


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