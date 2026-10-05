"""test_scanner.py — chạy thử nhanh SemgrepTool, chưa phải unit test chính thức."""

from src.scanner.semgrep_tool import SemgrepTool

def main():
    tool = SemgrepTool(ruleset="p/java")
    target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"

    print(f"Đang chạy {tool.name} trên {target} ...")
    findings = tool.run(target)

    print(f"\nTổng số finding: {len(findings)}")
    print("\n--- Finding đầu tiên ---")
    print(findings[0].model_dump_json(indent=2))

if __name__ == "__main__":
    main()