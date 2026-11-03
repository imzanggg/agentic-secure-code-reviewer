"""
schemas.py
Định nghĩa các cấu trúc dữ liệu dùng chung xuyên suốt toàn bộ hệ thống,
không thuộc riêng tầng nào. Đây là "hợp đồng" giữa các tầng.
"""

from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """
    Object hoàn chỉnh: kết hợp thông tin từ SAST tool (RawFinding)
    + ngữ cảnh code đã trích xuất (từ context_extractor).
    Đây là input chuẩn cho Reviewer Agent ở Tầng 2.
    """
    finding_id: str

    # Từ RawFinding (Tầng 1 - SAST)
    tool_name: str
    rule_id: str
    cwe_id: Optional[str] = None
    file_path: str
    line_start: int
    line_end: int
    message: str
    severity: str
    confidence: Optional[str] = None
    remediation_advice: Optional[str] = None
    suggested_fix_snippet: Optional[str] = None
    references: List[str] = []

    # Từ context_extractor (Tầng 1 - AST)
    method_name: Optional[str] = None
    function_context: Optional[str] = None
    context_start_line: Optional[int] = None
    context_end_line: Optional[int] = None
    callee_context: Optional[str] = None

class ReviewerLLMOutput(BaseModel):
    reasoning: str
    verdict: Literal["TP", "FP"]
    confidence: Literal["low", "medium", "high"]


class Verdict(BaseModel):
    finding_id: str
    verdict: Literal["TP", "FP"]
    confidence: Literal["low", "medium", "high"]
    reasoning: str
    source: Literal["local_llm", "api_fallback", "fail_open", "rule_based"] = "local_llm"
    model: Optional[str] = None
    latency_sec: Optional[float] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    raw_output: Optional[str] = None