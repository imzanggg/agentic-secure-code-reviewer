"""aggregator.py: chạy nhiều SAST tool, dedup finding trùng, gộp remediation advice."""

from collections import defaultdict
from .base import SASTTool, RawFinding


class SASTAggregator:
    def __init__(self, tools: list[SASTTool]):
        self.tools = tools

    def run_all(self, target_path: str) -> list[RawFinding]:
        all_findings = []
        for tool in self.tools:
            try:
                all_findings.extend(tool.run(target_path))
            except Exception as e:
                print(f"[WARN] Tool '{tool.name}' lỗi khi chạy: {e}")
                # Không để 1 tool lỗi làm hỏng toàn bộ pipeline — ghi log, bỏ qua, chạy tiếp

        return self._dedup(all_findings)

    def _dedup(self, findings: list[RawFinding]) -> list[RawFinding]:
        """Gộp các finding cùng vị trí/CWE do nhiều tool cùng phát hiện."""
        groups = defaultdict(list)
        for f in findings:
            key = (f.file_path, f.line_start, f.cwe_id)
            groups[key].append(f)

        merged = []
        for group in groups.values():
            if len(group) == 1:
                merged.append(group[0])
                continue

            primary = group[0].model_copy()
            primary.tool_name = "+".join(sorted({g.tool_name for g in group}))

            # Gộp remediation advice từ nhiều tool, loại trùng, giữ tất cả góc nhìn
            advices = [g.remediation_advice for g in group if g.remediation_advice]
            primary.remediation_advice = " | ".join(dict.fromkeys(advices))

            merged.append(primary)

        return merged