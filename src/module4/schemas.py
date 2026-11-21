"""
schemas.py
Định nghĩa các cấu trúc dữ liệu riêng cho Module 4 (Tầng 4: Validator).
Validator chỉ thực hiện các phép kiểm định tất định và xuất dữ liệu thô có cấu trúc,
không tự kết luận FP thay cho Reviewer Agent (Tầng 2).
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field

from src.schemas import Finding


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
    sast_raw_clean: bool = False
    failure_stage: Optional[
        Literal["llm_error", "parse", "apply", "syntax", "signature", "compile", "sast_raw"]
    ] = None
    feedback: Optional[str] = None

    # Danh sách Finding đầy đủ ngữ cảnh trên file sau khi vá để chuyển qua Module 2 (Re-review)
    persisting_findings: List[Finding] = Field(default_factory=list)
    introduced_findings: List[Finding] = Field(default_factory=list)
    remaining_findings_count: int = 0
    new_cwe_ids: List[str] = Field(default_factory=list)

    # Hook mở rộng cho Regression / Exploit PoC / Coverage theo kiến trúc Tầng 4
    regression_pass_rate: Optional[float] = None
    exploit_blocked: Optional[bool] = None
    coverage_hit: Optional[bool] = None
