"""
test_interactive.py
Test Runner hợp nhất: Hỗ trợ chế độ tương tác (Interactive Wizard) hoặc Headless (qua args).
Thay thế toàn bộ các file test_*_manual.py cũ.
"""

import argparse
import sys
import json
from pathlib import Path

from src.preprocessor import BenchmarkPreprocessor
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.scanner.aggregator import SASTAggregator
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.pipeline import ScannerPipeline


def run_headless(args):
    """Chế độ CLI tự động."""
    preprocessor = BenchmarkPreprocessor()
    
    context = preprocessor.setup_run(
        test_list=[args.test] if args.test else None,
        category=args.category,
        limit=args.limit,
        run_id=args.run_id,
        resume=args.resume,
        clean=args.clean
    )
    execute_module(args.module, context)


def run_interactive():
    """Chế độ giao diện dòng lệnh."""
    print("=" * 60)
    print("      AGENTIC CODE REVIEWER - TEST RUNNER")
    print("=" * 60)

    # STEP 1: Chọn Module
    print("\n[?] What module do you want to test?")
    print("  [1] Semgrep Tool only        (Source code SAST)")
    print("  [2] SpotBugs Tool only       (Bytecode compilation + FindSecBugs)")
    print("  [3] SAST Aggregator          (Both tools + Fuzzy Deduplication)")
    print("  [4] AST Context Extractor    (Tree-sitter Java method extraction)")
    print("  [5] Entire Tier 1 Pipeline   (Full scan -> Dedup -> Context)")
    mod_choice = input("\nSelect option [1-5] (Default: 5): ").strip()
    module_mapping = {"1": "semgrep", "2": "spotbugs", "3": "aggregator", "4": "ast", "5": "pipeline"}
    module = module_mapping.get(mod_choice, "pipeline")

    # STEP 2: Chọn Scope
    print("\n[?] Select dataset scope for this test:")
    print("  [1] Single test file         (Fastest, copies 1 file + scaffolding)")
    print("  [2] Specific Category        (e.g., sqli, xss, pathtraver, cmdi)")
    print("  [3] Full Benchmark Suite     (Copies all ~2,740 test cases)")
    scope_choice = input("\nSelect option [1-3] (Default: 1): ").strip() or "1"

    test_list = None
    category = None
    limit = None

    preprocessor = BenchmarkPreprocessor()

    if scope_choice == "1":
        test_file = input("Enter test name (Default: BenchmarkTest00001): ").strip()
        test_list = [test_file if test_file else "BenchmarkTest00001"]
    elif scope_choice == "2":
        print("\n-- Available categories --")
        cats = preprocessor.get_categories()
        cat_names = list(cats.keys())
        for i, c in enumerate(cat_names):
            print(f"  [{i}] {c} ({len(cats[c])} tests)")
        cat_input = input("Enter category name or index: ").strip()
        if cat_input.isdigit() and int(cat_input) < len(cat_names):
            category = cat_names[int(cat_input)]
        else:
            category = cat_input

        lim_input = input("How many tests to copy and scan? (Enter number or 'all', Default: 5): ").strip()
        if lim_input.isdigit():
            limit = int(lim_input)
        elif lim_input != "all":
            limit = 5
    elif scope_choice == "3":
        test_list = ["all"]

    # STEP 3: Cấu hình Session
    print("\n[?] Session configuration:")
    print("  [1] Fresh Run            (Auto-generates ID)")
    print("  [2] Custom Run ID        (Enter your own identifier)")
    print("  [3] Resume Existing Run  (Run on an already modified workspace)")
    sess_choice = input("\nSelect option [1-3] (Default: 1): ").strip() or "1"

    run_id = None
    resume = False
    clean = False

    if sess_choice == "2":
        run_id = input("Enter custom Run ID: ").strip()
        # Mặc định ghi đè nếu dùng interactive và chọn tên tùy chỉnh
        clean = True
    elif sess_choice == "3":
        run_id = input("Enter existing Run ID to resume: ").strip()
        resume = True

    # Khởi tạo Preprocessor
    try:
        context = preprocessor.setup_run(
            test_list=test_list, category=category, limit=limit, 
            run_id=run_id, resume=resume, clean=clean
        )
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    print(f"\n[INFO] Workspace ready at: {context.workspace_dir}")
    print(f"[INFO] Target tests count: {len(context.target_tests)}")
    
    execute_module(module, context)


def execute_module(module: str, ctx):
    """Dispatcher để chạy công cụ tương ứng với lựa chọn của user."""
    print(f"\n{'='*40}\nExecuting Module: {module.upper()}\n{'='*40}")

    semgrep = SemgrepTool(ruleset="p/java")
    spotbugs = SpotBugsTool()
    
    results = []

    if module == "semgrep":
        results = semgrep.run(ctx.target_path)
    elif module == "spotbugs":
        results = spotbugs.run(ctx.target_path)
    elif module == "aggregator":
        aggregator = SASTAggregator(tools=[semgrep, spotbugs], line_window=4)
        results = aggregator.run_all(ctx.target_path)
    elif module == "ast":
        extractor = JavaContextExtractor()
        # Test nhanh trên file đầu tiên
        target_file = Path(ctx.target_path) / ctx.target_tests[0]
        results = [extractor.extract_method(str(target_file), target_line=1)] # mock line
        print(f"\nAST Method extracted:\n{results[0] if results[0] else 'None'}")
        return
    elif module == "pipeline":
        pipeline = ScannerPipeline(
            aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
            context_extractor=JavaContextExtractor(),
        )
        results = pipeline.run(ctx.target_path)

    # Lưu kết quả và in báo cáo
    if module != "ast":
        out_file = Path(ctx.results_dir) / f"{module}_findings.json"
        
        # Phân loại results (Pydantic objects)
        dict_results = [r.model_dump() for r in results]
        out_file.write_text(json.dumps(dict_results, indent=2, ensure_ascii=False))
        
        print("\n=== SUMMARY OF FINDINGS ===")
        print(f"Total Findings Found: {len(results)}")
        if len(results) > 0:
            print(f"First finding preview:\n{json.dumps(dict_results[0], indent=2)}")
        print(f"\n[INFO] Full results saved to {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic Code Reviewer Test Runner")
    parser.add_argument("--module", choices=["semgrep", "spotbugs", "aggregator", "ast", "pipeline"], help="Module to test")
    parser.add_argument("--test", "-t", help="Specific test name (e.g. BenchmarkTest00001)")
    parser.add_argument("--category", "-c", help="Benchmark category (e.g. sqli)")
    parser.add_argument("--limit", "-n", type=int, help="Limit number of test cases")
    parser.add_argument("--run-id", "-r", help="Custom Run ID")
    parser.add_argument("--resume", action="store_true", help="Resume existing workspace")
    parser.add_argument("--clean", action="store_true", help="Overwrite existing workspace")

    args = parser.parse_args()

    # Nếu có bất kỳ đối số nào được truyền, chạy Headless mode
    if any(vars(args).values()):
        if not args.module:
            args.module = "pipeline"  # Default headless module
        run_headless(args)
    else:
        # Nếu không có tham số nào, chạy Interactive Wizard
        try:
            run_interactive()
        except KeyboardInterrupt:
            print("\n[INFO] Canceled by user. Exiting...")
            sys.exit(0)
