# src/scanner/spotbugs_tool.py — khung sườn, cần build file .class trước khi chạy
class SpotBugsTool(SASTTool):
    name = "spotbugs"

    def run(self, target_path: str) -> list[RawFinding]:
        # Cần: mvn compile trước (SpotBugs phân tích bytecode, không phải source trực tiếp)
        # Chạy: spotbugs -textui -include findsecbugs-include.xml -xml:withMessages ...
        # Parse XML output -> RawFinding
        ...