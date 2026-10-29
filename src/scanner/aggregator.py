"""
aggregator.py: chạy nhiều SAST tool, dedup fuzzy finding trùng dòng, gộp remediation advice.
"""

from collections import defaultdict
from pathlib import Path
from typing import List
from .base import SASTTool, RawFinding


class SASTAggregator:
    def __init__(self, tools: List[SASTTool], line_window: int = 4):
        self.tools = tools
        self.line_window = line_window

    def run_all(self, target_path: str) -> List[RawFinding]:
        all_findings = []
        for tool in self.tools:
            try:
                all_findings.extend(tool.run(target_path))
            except Exception as e:
                print(f"[WARN] Tool '{tool.name}' lỗi khi chạy: {e}")

        return self._dedup(all_findings)

    def _normalize_path(self, path_str: str) -> str:
        """Đảm bảo đồng nhất đường dẫn để so khớp."""
        return str(Path(path_str).resolve())

    def _dedup(self, findings: List[RawFinding]) -> List[RawFinding]:
        """
        Deduplication theo logic:
        1. Gom nhóm theo (file_path chuẩn hóa, exact cwe_id).
        2. Nếu cùng file và cùng CWE, cho phép fuzzy window (+- 4 dòng).
        3. Ưu tiên Semgrep làm gốc (giữ line_start/end và fix snippet).
        4. Gộp remediation advice và cập nhật tool_name = 'semgrep+spotbugs'.
        """
        # Nhóm theo (normalized_path, cwe_id)
        groups = defaultdict(list)
        for f in findings:
            key = (self._normalize_path(f.file_path), f.cwe_id)
            groups[key].append(f)

        merged_results: List[RawFinding] = []

        for (norm_path, cwe_id), items in groups.items():
            # Tách findings theo công cụ
            semgrep_items = [f for f in items if "semgrep" in f.tool_name]
            spotbugs_items = [f for f in items if "spotbugs" in f.tool_name]

            # Những tool khác hoặc trường hợp chỉ có 1 trong 2 công cụ
            if not semgrep_items or not spotbugs_items:
                merged_results.extend(items)
                continue

            used_spotbugs = set()

            for semgrep_f in semgrep_items:
                matched_spotbugs = None

                # Tìm SpotBugs finding gần nhất trong khoảng +- line_window
                for sb_f in spotbugs_items:
                    if id(sb_f) in used_spotbugs:
                        continue
                    if abs(semgrep_f.line_start - sb_f.line_start) <= self.line_window:
                        matched_spotbugs = sb_f
                        used_spotbugs.add(id(sb_f))
                        break

                if matched_spotbugs:
                    # Gộp: Lấy Semgrep làm primary
                    primary = semgrep_f.model_copy()
                    primary.tool_name = "semgrep+spotbugs"

                    # Gộp lời khuyên sửa lỗi
                    advices = [
                        adv for adv in [semgrep_f.remediation_advice, matched_spotbugs.remediation_advice]
                        if adv
                    ]
                    primary.remediation_advice = " | ".join(dict.fromkeys(advices))
                    merged_results.append(primary)
                else:
                    merged_results.append(semgrep_f)

            # Thêm các finding của SpotBugs không tìm được cặp ghép với Semgrep
            for sb_f in spotbugs_items:
                if id(sb_f) not in used_spotbugs:
                    merged_results.append(sb_f)

        return merged_results
