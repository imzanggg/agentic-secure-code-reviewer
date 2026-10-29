"""
test_aggregator_manual.py — kiểm thử gộp và deduplication giữa Semgrep và SpotBugs.
"""

from src.scanner.aggregator import SASTAggregator
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool


def main():
    semgrep = SemgrepTool(ruleset="p/java")
    spotbugs = SpotBugsTool()
    aggregator = SASTAggregator(tools=[semgrep, spotbugs], line_window=4)

    # Chạy trên 1 file đơn giản
    target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"

    print(f"--- Đang chạy Aggregator trên {target} ---")
    findings = aggregator.run_all(target)
    print(f"\nTổng số finding sau gộp: {len(findings)}")

    for idx, f in enumerate(findings):
        print(f"\n[{idx+1}] Tool: {f.tool_name} | CWE: {f.cwe_id} | Line: {f.line_start}")
        print(f"Message: {f.message[:80]}...")
        if f.remediation_advice:
            print(f"Advice: {f.remediation_advice[:100]}...")


if __name__ == "__main__":
    main()
