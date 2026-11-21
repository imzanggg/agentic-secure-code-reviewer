"""
schemas.py
Định nghĩa các cấu trúc dữ liệu riêng cho Module 5 (Tầng 5: Loop Controller).
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

from src.module3.schemas import Module3Patch
from src.module4.schemas import PatchApplyResult, ValidationResult
from src.schemas import Finding, LoopStatus, Verdict


class ReReviewRecord(BaseModel):
    """Lưu vết 1 cảnh báo thô từ Tầng 4 sau khi được Module 2 (Reviewer) đánh giá lại."""

    kind: Literal["persisting", "introduced"]
    finding: Finding
    verdict: Verdict


class FixIterationResult(BaseModel):
    iteration: int
    patch: Module3Patch
    apply_result: Optional[PatchApplyResult] = None
    validation: ValidationResult
    re_reviews: List[ReReviewRecord] = Field(default_factory=list)
    sast_fp_filtered_count: int = 0
    confirmed_tp_count: int = 0
    sast_passed: bool = False
    passed: bool = False
    effective_failure_stage: Optional[
        Literal[
            "llm_error",
            "parse",
            "apply",
            "syntax",
            "signature",
            "compile",
            "sast_tp",
            "stalled",
            "drift",
        ]
    ] = None
    clean_feedback: Optional[str] = None


class FixSummary(BaseModel):
    finding_id: str
    test_name: Optional[str] = None
    category: Optional[str] = None
    cwe_id: Optional[str] = None
    file_path: str
    max_iterations: int
    single_shot_passed: bool = False
    multi_loop_passed: bool = False
    passed_at_iteration: Optional[int] = None
    final_status: LoopStatus
    resolved_via_sast_fp_filter: bool = False
    final_failure_stage: Optional[str] = None
    total_re_reviewed: int = 0
    total_sast_fp_filtered: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_latency_sec: float = 0.0
    iterations: List[FixIterationResult] = Field(default_factory=list)
