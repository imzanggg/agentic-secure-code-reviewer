"""
test_spotbugs_manual.py — kiểm tra chạy SpotBugs độc lập.
"""

from src.scanner.spotbugs_tool import SpotBugsTool

def main():
    tool = SpotBugsTool()
    
    # Test quét 1 file đơn lẻ trước để kiểm tra tốc độ
    single_target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
    print(f"=== 1. Quét thử 1 file: {single_target} ===")
    findings = tool.run(single_target)
    print(f"Số finding tìm thấy: {len(findings)}")
    if findings:
        print(findings[0].model_dump_json(indent=2))

    # Nếu muốn test quét toàn bộ thư mục (sẽ mất ~30-60s):
    # all_target = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"
    # print(f"\n=== 2. Quét toàn bộ: {all_target} ===")
    # all_findings = tool.run(all_target)
    # print(f"Tổng số finding SpotBugs: {len(all_findings)}")

if __name__ == "__main__":
    main()
