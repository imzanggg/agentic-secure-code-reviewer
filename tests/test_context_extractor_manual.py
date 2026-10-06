"""test_context_extractor_manual.py"""

from src.scanner.context_extractor import JavaContextExtractor

def main():
    extractor = JavaContextExtractor()
    file_path = "data/raw/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"

    result = extractor.extract_method(file_path, target_line=72)

    if result is None:
        print("Không tìm thấy method bao trùm dòng 72")
        return

    print(f"Method: {result['method_name']}")
    print(f"Dòng: {result['start_line']}–{result['end_line']}")
    print("\n--- Source ---")
    print(result["source"])

if __name__ == "__main__":
    main()