"""
schemas.py
Định nghĩa cấu trúc dữ liệu riêng cho Module 3 (Tầng 3: Fixer Agent),
kế thừa từ Patch trong src/schemas.py.
"""

from typing import List, Optional
from pydantic import Field

from src.schemas import Patch


class Module3Patch(Patch):
    """Mở rộng Patch với danh sách import cần bổ sung, lỗi LLM và lỗi parse (nếu có)."""

    required_imports: List[str] = Field(default_factory=list)
    parse_error: Optional[str] = None
    llm_error: Optional[str] = None
