"""
schemas.py
Định nghĩa các cấu trúc dữ liệu riêng cho Module 3 (Fixer Agent & Validation Loop),
kế thừa và tương thích hoàn toàn với Patch trong src/schemas.py.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

from src.schemas import Patch


class Module3Patch(Patch):
    """Mở rộng Patch với danh sách import cần bổ sung, lỗi LLM và lỗi parse (nếu có)."""
    required_imports: List[str] = Field(default_factory=list)
    parse_error: Optional[str] = None
    llm_error: Optional[str] = None


class PatchApplyResult(BaseModel):
    applied: bool
    strategy: Literal["exact", "normalized", "failed"] = "failed"
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    added_imports: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class ValidationResult(BaseModel):
    syntax_valid: bool = False
    signature_preserved: bool = False
    compiled: bool = False
    sast_passed: bool = False
    failure_stage: Optional[
        Literal["llm_error", "parse", "apply", "syntax", "signature", "compile", "sast"]
    ] = None
    feedback: Optional[str] = None
    remaining_findings_count: int = 0
    new_cwe_ids: List[str] = Field(default_factory=list)


class FixIterationResult(BaseModel):
    iteration: int
    patch: Module3Patch
    apply_result: Optional[PatchApplyResult] = None
    validation: ValidationResult
    passed: bool = False


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
    final_failure_stage: Optional[str] = None
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_latency_sec: float = 0.0
    iterations: List[FixIterationResult] = Field(default_factory=list)
