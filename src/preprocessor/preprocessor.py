"""
preprocessor.py
Quản lý việc tạo Workspace (data/workspace/run_<id>) và copy dataset theo yêu cầu (on-demand).
Giúp tăng tốc độ quét và bảo vệ dataset gốc.
"""

import csv
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import RunContext, RunMetadata


class BenchmarkPreprocessor:
    RAW_ROOT = Path("data/raw/BenchmarkJava")
    WORKSPACE_ROOT = Path("data/workspace")
    RESULTS_ROOT = Path("data/results")

    def __init__(self):
        self.csv_path = self.RAW_ROOT / "expectedresults-1.2.csv"
        self._categories_cache: Optional[Dict[str, List[str]]] = None

    def get_categories(self) -> Dict[str, List[str]]:
        """Đọc file CSV ground truth và gom nhóm test case theo category."""
        if self._categories_cache is not None:
            return self._categories_cache

        categories = {}
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Không tìm thấy {self.csv_path}. Bạn đã clone dataset chưa?")

        with open(self.csv_path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].startswith("#"):
                    continue
                test_name, category = row[0].strip(), row[1].strip()
                categories.setdefault(category, []).append(f"{test_name}.java")
        
        self._categories_cache = categories
        return categories

    def setup_run(
        self,
        test_list: Optional[List[str]] = None,
        category: Optional[str] = None,
        limit: Optional[int] = None,
        run_id: Optional[str] = None,
        resume: bool = False,
        clean: bool = False
    ) -> RunContext:
        """Chuẩn bị workspace cho một chu trình quét/sửa lỗi."""
        
        # 1. Xác định target files
        target_files: Set[str] = set()
        categories_used = []

        if test_list and len(test_list) > 0 and test_list[0] != "all":
            # Chuẩn hóa tên file (thêm .java nếu thiếu)
            target_files = {t if t.endswith(".java") else f"{t}.java" for t in test_list}
        elif category:
            cats = self.get_categories()
            if category not in cats:
                raise ValueError(f"Category '{category}' không tồn tại. Có sẵn: {list(cats.keys())}")
            categories_used.append(category)
            files = cats[category]
            target_files = set(files[:limit] if limit else files)
        else:
            # Full benchmark
            cats = self.get_categories()
            categories_used = list(cats.keys())
            for files in cats.values():
                target_files.update(files)
            if limit:
                target_files = set(list(target_files)[:limit])

        # 2. Xử lý Run ID & Thư mục
        if not run_id:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_id = f"run_{timestamp}"

        workspace_dir = self.WORKSPACE_ROOT / run_id
        results_dir = self.RESULTS_ROOT / run_id

        # Kiểm tra trạng thái tồn tại
        if workspace_dir.exists():
            if clean:
                print(f"[INFO] Đang xóa workspace cũ: {workspace_dir}")
                shutil.rmtree(workspace_dir)
            elif not resume:
                raise FileExistsError(
                    f"Run ID '{run_id}' đã tồn tại! Dùng --resume để chạy tiếp hoặc --clean để ghi đè."
                )

        # 3. Copy scaffolding và target files
        if not workspace_dir.exists():
            self._copy_workspace(workspace_dir, target_files)

        results_dir.mkdir(parents=True, exist_ok=True)

        # 4. Lưu metadata
        meta = RunMetadata(
            run_id=run_id,
            timestamp=datetime.now().isoformat(),
            target_tests_count=len(target_files),
            categories=categories_used,
            status="INITIALIZED"
        )
        with open(results_dir / "run_meta.json", "w", encoding="utf-8") as f:
            f.write(meta.model_dump_json(indent=2))

        return RunContext(
            run_id=run_id,
            workspace_dir=str(workspace_dir),
            target_path=str(workspace_dir / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"),
            results_dir=str(results_dir),
            target_tests=list(target_files)
        )

    def _copy_workspace(self, workspace_dir: Path, target_files: Set[str]):
        """Copy thư mục scaffolding (cần thiết cho compile) và CHỈ copy test files được chọn."""
        print(f"[INFO] Đang tạo workspace mới tại {workspace_dir} ...")
        
        # Hàm filter thông minh: bỏ qua các file testcode không nằm trong danh sách
        def ignore_unselected_tests(dir_path: str, contents: List[str]) -> List[str]:
            ignored = []
            path_parts = Path(dir_path).parts
            if "testcode" in path_parts:
                for item in contents:
                    if item.endswith(".java") and item not in target_files:
                        ignored.append(item)
            return ignored

        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Các thành phần cốt lõi bắt buộc phải copy để Maven chạy được
        core_items = [".mvn", "src", "pom.xml"]
        
        for item_name in core_items:
            src_path = self.RAW_ROOT / item_name
            dst_path = workspace_dir / item_name
            
            if not src_path.exists():
                continue
                
            if src_path.is_dir():
                shutil.copytree(src_path, dst_path, ignore=ignore_unselected_tests)
            else:
                shutil.copy2(src_path, dst_path)

    def restore_file(self, run_id: str, test_name: str):
        """Khôi phục 1 file về trạng thái gốc từ RAW nếu Agent làm hỏng code."""
        filename = f"{test_name}.java" if not test_name.endswith(".java") else test_name
        rel_path = Path("src/main/java/org/owasp/benchmark/testcode") / filename
        
        src_path = self.RAW_ROOT / rel_path
        dst_path = self.WORKSPACE_ROOT / run_id / rel_path

        if src_path.exists():
            shutil.copy2(src_path, dst_path)
            print(f"[INFO] Đã khôi phục file: {filename} trong {run_id}")
        else:
            raise FileNotFoundError(f"Không tìm thấy file gốc: {src_path}")
