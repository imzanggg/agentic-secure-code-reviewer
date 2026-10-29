"""
models.py
Định nghĩa cấu trúc dữ liệu cho Module 0 (Preprocessor).
"""

from typing import List, Optional
from pydantic import BaseModel
from pathlib import Path


class RunContext(BaseModel):
    run_id: str
    workspace_dir: str     # Đường dẫn tới root của workspace (chứa pom.xml)
    target_path: str       # Đường dẫn tới thư mục testcode trong workspace
    results_dir: str       # Đường dẫn lưu kết quả (findings, score)
    target_tests: List[str] # Danh sách các file .java được copy

    @property
    def workspace_path(self) -> Path:
        return Path(self.workspace_dir)

    @property
    def results_path(self) -> Path:
        return Path(self.results_dir)


class RunMetadata(BaseModel):
    run_id: str
    timestamp: str
    target_tests_count: int
    categories: List[str]
    status: str
