"""test_aggregator_manual.py — kiểm thử nhanh SASTAggregator."""

from src.scanner.aggregator import SASTAggregator
from src.scanner.semgrep_tool import SemgrepTool

def main():
    aggregator = SASTAggregator(tools=[SemgrepTool(ruleset="p/java")])
    target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"

    findings = aggregator.run_all(target)
    print(f"Tổng số finding sau dedup: {len(findings)}")
    print("\n--- Finding đầu tiên ---")
    print(findings[0].model_dump_json(indent=2))

if __name__ == "__main__":
    main()