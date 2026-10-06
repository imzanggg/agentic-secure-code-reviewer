"""test_pipeline_manual.py — chạy thử toàn bộ Tầng 1 end-to-end."""

from src.scanner.pipeline import ScannerPipeline
from src.scanner.aggregator import SASTAggregator
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.context_extractor import JavaContextExtractor


def main():
    pipeline = ScannerPipeline(
        aggregator=SASTAggregator(tools=[SemgrepTool(ruleset="p/java")]),
        context_extractor=JavaContextExtractor(),
    )

    target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"
    findings = pipeline.run(target)

    print(f"\nTong so Finding hoan chinh: {len(findings)}")
    print("\n--- Finding dau tien (day du) ---")
    print(findings[0].model_dump_json(indent=2))


if __name__ == "__main__":
    main()