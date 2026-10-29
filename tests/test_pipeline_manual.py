"""test_pipeline_manual.py — chạy thử toàn bộ Tầng 1 end-to-end (Semgrep + SpotBugs)."""

from src.scanner.pipeline import ScannerPipeline
from src.scanner.aggregator import SASTAggregator
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.scanner.context_extractor import JavaContextExtractor


def main():
    pipeline = ScannerPipeline(
        aggregator=SASTAggregator(
            tools=[SemgrepTool(ruleset="p/java"), SpotBugsTool()],
            line_window=4,
        ),
        context_extractor=JavaContextExtractor(),
    )

    # Thử nghiệm trên 1 file
    target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
    findings = pipeline.run(target)

    print(f"\nTổng số Finding hoàn chỉnh: {len(findings)}")
    if findings:
        print("\n--- Finding đầu tiên hoàn chỉnh ---")
        print(findings[0].model_dump_json(indent=2))


if __name__ == "__main__":
    main()
