"""base.py: Interface chung cho mọi SAST tool + schema finding thống nhất."""

from abc import ABC, abstractmethod
from typing import Optional, List
from pydantic import BaseModel


class RawFinding(BaseModel):
    tool_name: str
    rule_id: str
    cwe_id: Optional[str] = None
    file_path: str
    line_start: int
    line_end: int
    message: str
    severity: str
    confidence: Optional[str] = None

    # gợi ý sửa lỗi lấy từ chính SAST tool
    remediation_advice: Optional[str] = None      # mô tả dạng text (vd: Semgrep message)
    suggested_fix_snippet: Optional[str] = None    # đoạn code thay thế cụ thể, nếu tool hỗ trợ autofix
    references: List[str] = []                     # link tài liệu tham khảo (OWASP, CWE...)


class SASTTool(ABC):
    name: str

    @abstractmethod
    def run(self, target_path: str) -> List[RawFinding]:
        """Chạy tool, trả về danh sách RawFinding đã chuẩn hóa."""
        ...