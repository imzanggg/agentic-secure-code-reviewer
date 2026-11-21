"""
schemas.py
Định nghĩa các cấu trúc dữ liệu dùng chung xuyên suốt toàn bộ hệ thống,
không thuộc riêng tầng nào. Đây là "hợp đồng" giữa các tầng.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

CONFIDENCE_SCORE_MAP = {"low": 0.3, "medium": 0.65, "high": 0.95}

LoopStatus = Literal[
    "resolved",
    "unresolved - suspected SAST FP",
    "unresolved - drift detection",
    "unresolved - max iterations exceeded",
]


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
    references: List[str] = Field(default_factory=list)

    # Từ context_extractor (Tầng 1 - AST)
    method_name: Optional[str] = None
    function_context: Optional[str] = None
    context_start_line: Optional[int] = None
    context_end_line: Optional[int] = None
    callee_context: Optional[str] = None


class DataFlowTrace(BaseModel):
    source: Optional[str] = None
    sink: Optional[str] = None
    flow: Optional[str] = None
    protection: Optional[str] = None


class ReviewerLLMOutput(BaseModel):
    reasoning: str
    verdict: Literal["TP", "FP"]
    confidence: Literal["low", "medium", "high"]
    confidence_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    data_flow_trace: Optional[DataFlowTrace] = None

    @model_validator(mode="after")
    def _fill_confidence_score(self):
        if self.confidence_score is None:
            self.confidence_score = CONFIDENCE_SCORE_MAP[self.confidence]
        return self


class Verdict(BaseModel):
    finding_id: str
    verdict: Literal["TP", "FP"]
    confidence: Literal["low", "medium", "high"]
    confidence_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    reasoning: str
    data_flow_trace: Optional[DataFlowTrace] = None
    source: Literal["local_llm", "api_fallback", "fail_open", "rule_based"] = "local_llm"
    model: Optional[str] = None
    latency_sec: Optional[float] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    raw_output: Optional[str] = None

    @model_validator(mode="after")
    def _fill_confidence_score(self):
        if self.confidence_score is None:
            if self.source == "fail_open":
                self.confidence_score = 0.0
            elif self.source == "rule_based":
                self.confidence_score = 1.0
            else:
                self.confidence_score = CONFIDENCE_SCORE_MAP[self.confidence]
        return self


class Patch(BaseModel):
    finding_id: str
    # Khối thay thế rõ ràng, dễ áp vào file gốc bằng script
    original_snippet: str          # đoạn code gốc bị thay (để kiểm tra khớp trước khi áp)
    fixed_snippet: str             # đoạn code đã sửa
    line_start: Optional[int] = None   # vị trí khối bị thay, điền sau khi apply_patch tìm thấy
    line_end: Optional[int] = None
    explanation: Optional[str] = None
    iteration: int = 1             # vòng lặp thứ mấy (cho single-shot vs multi-loop)
    source: Literal["local_llm", "api_fallback", "fail_open"] = "local_llm"
    model: Optional[str] = None
    latency_sec: Optional[float] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    raw_output: Optional[str] = None
