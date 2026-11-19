"""
test_interactive.py
Test Runner hợp nhất: Hỗ trợ chế độ tương tác (Interactive Wizard) hoặc Headless (qua args).
Giữ nguyên cơ chế tách riêng từng run trong data/workspace/<run_id>/ và data/results/<run_id>/.
Hỗ trợ kiểm thử từng module (Tier 1, Tier 2, Tier 3 Fixer) hoặc toàn bộ pipeline (full_graph).
"""

import argparse
import json
import sys
from pathlib import Path

from src.agents.llm_client import OllamaClient
from src.agents.reviewer import ReviewerAgent
from src.graph.workflow import build_full_graph, build_review_graph
from src.module3 import FixerAgent, FixLoopRunner, PatchValidator, compute_fixer_metrics
from src.preprocessor import BenchmarkPreprocessor
from src.scanner.aggregator import SASTAggregator
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.pipeline import ScannerPipeline
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.schemas import Finding, Verdict

DEFAULT_REVIEWER_MODEL = "qwen2.5-coder:3b"
DEFAULT_FIXER_MODEL = "hf.co/ibm-granite/granite-4.2-3b-GGUF:Q4_K_M"
DEFAULT_MAX_ITERATIONS = 3
DEFAULT_LLM_TIMEOUT = 300.0
DEFAULT_NUM_CTX = 4096
DEFAULT_FIXER_NUM_PREDICT = 1024


def _load_categories_by_test() -> dict[str, str]:
    mapping: dict[str, str] = {}
    try:
        cats = BenchmarkPreprocessor().get_categories()
        for cat, files in cats.items():
            for fname in files:
                mapping[Path(fname).stem] = cat
    except Exception:
        pass
    return mapping


def run_headless(args):
    """Chế độ CLI tự động."""
    preprocessor = BenchmarkPreprocessor()

    context = preprocessor.setup_run(
        test_list=[args.test] if args.test else None,
        category=args.category,
        limit=args.limit,
        run_id=args.run_id,
        resume=args.resume,
        clean=args.clean,
    )
    execute_module(
        module=args.module,
        ctx=context,
        reviewer_model=args.reviewer_model or DEFAULT_REVIEWER_MODEL,
        fixer_model=args.fixer_model or DEFAULT_FIXER_MODEL,
        max_iterations=args.max_iterations or DEFAULT_MAX_ITERATIONS,
        keep_passing_patch=args.keep_passing_patch,
    )


def run_interactive():
    """Chế độ giao diện dòng lệnh."""
    print("=" * 64)
    print("      AGENTIC CODE REVIEWER - TEST RUNNER")
    print("=" * 64)

    # STEP 1: Chọn Module
    print("\n[?] What module do you want to test?")
    print("  [1] Semgrep Tool only        (Source code SAST)")
    print("  [2] SpotBugs Tool only       (Bytecode compilation + FindSecBugs)")
    print("  [3] SAST Aggregator          (Both tools + Fuzzy Deduplication)")
    print("  [4] AST Context Extractor    (Tree-sitter Java method extraction)")
    print("  [5] Entire Tier 1 Pipeline   (Full scan -> Dedup -> Context)")
    print("  [6] LangGraph (Tier 1 -> 2)  (Scanner -> Reviewer Agent)")
    print("  [7] Module 3 Fixer only      (Fixer + Patch Applier + Validator Loop)")
    print("  [8] Full LangGraph (1->2->3) (Scanner -> Reviewer -> Fixer Loop)")

    mod_choice = input("\nSelect option [1-8] (Default: 5): ").strip()
    module_mapping = {
        "1": "semgrep",
        "2": "spotbugs",
        "3": "aggregator",
        "4": "ast",
        "5": "pipeline",
        "6": "graph",
        "7": "fixer",
        "8": "full_graph",
    }
    module = module_mapping.get(mod_choice, "pipeline")

    reviewer_model = DEFAULT_REVIEWER_MODEL
    fixer_model = DEFAULT_FIXER_MODEL
    max_iterations = DEFAULT_MAX_ITERATIONS
    keep_passing_patch = False

    if module in ("graph", "full_graph"):
        rm = input(f"Reviewer Ollama model (Default: {DEFAULT_REVIEWER_MODEL}): ").strip()
        if rm:
            reviewer_model = rm

    if module in ("fixer", "full_graph"):
        fm = input(f"Fixer model (Default: {DEFAULT_FIXER_MODEL}): ").strip()
        if fm:
            fixer_model = fm
        mi = input(f"Max Fix-Validate loop iterations (1=single-shot, Default: {DEFAULT_MAX_ITERATIONS}): ").strip()
        if mi.isdigit() and int(mi) >= 1:
            max_iterations = int(mi)
        kp = input("Keep passing patches on disk in workspace? [y/N]: ").strip().lower()
        keep_passing_patch = kp == "y"

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
        clean = True
    elif sess_choice == "3":
        run_id = input("Enter existing Run ID to resume: ").strip()
        resume = True

    try:
        context = preprocessor.setup_run(
            test_list=test_list,
            category=category,
            limit=limit,
            run_id=run_id,
            resume=resume,
            clean=clean,
        )
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    print(f"\n[INFO] Workspace ready at: {context.workspace_dir}")
    print(f"[INFO] Results dir at:   {context.results_dir}")
    print(f"[INFO] Target tests count: {len(context.target_tests)}")

    execute_module(
        module=module,
        ctx=context,
        reviewer_model=reviewer_model,
        fixer_model=fixer_model,
        max_iterations=max_iterations,
        keep_passing_patch=keep_passing_patch,
    )


def _print_fixer_summary(summaries, metrics: dict, out_dir: Path):
    (out_dir / "fixer_results.json").write_text(
        json.dumps([s.model_dump() for s in summaries], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "fixer_metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    ss = metrics.get("single_shot", {})
    ml = metrics.get("multi_loop", {})
    print(f"\n=== FIXER SUMMARY ({metrics.get('total_findings', 0)} findings) ===")
    if metrics.get("total_findings", 0) > 0:
        print(
            f"Single-shot (iter=1) : "
            f"Pass={ss['fix_success_count']}/{metrics['total_findings']} ({ss['fix_success_rate']:.2%}) | "
            f"Applied={ss['applied_rate']:.2%} | Compiled={ss['compiled_rate']:.2%} | "
            f"AvgTokens={ss['avg_total_tokens']}"
        )
        print(
            f"Multi-loop (iter<={summaries[0].max_iterations}): "
            f"Pass={ml['fix_success_count']}/{metrics['total_findings']} ({ml['fix_success_rate']:.2%}) | "
            f"Applied={ml['applied_rate']:.2%} | Compiled={ml['compiled_rate']:.2%} | "
            f"AvgTokens={ml['avg_total_tokens']}"
        )
        if metrics.get("failure_stages"):
            print(f"Failure stages       : {metrics['failure_stages']}")
    print(f"[INFO] Fixer results saved to {out_dir / 'fixer_results.json'}")


def execute_module(
    module: str,
    ctx,
    reviewer_model: str = DEFAULT_REVIEWER_MODEL,
    fixer_model: str = DEFAULT_FIXER_MODEL,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    keep_passing_patch: bool = False,
):
    """Dispatcher để chạy công cụ tương ứng với lựa chọn của user."""
    print(f"\n{'='*40}\nExecuting Module: {module.upper()}\n{'='*40}")

    semgrep = SemgrepTool(ruleset="p/java")
    spotbugs = SpotBugsTool()
    out_dir = Path(ctx.results_dir)
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
        target_file = Path(ctx.target_path) / ctx.target_tests[0]
        results = [extractor.extract_method(str(target_file), target_line=1)]
        print(f"\nAST Method extracted:\n{results[0] if results[0] else 'None'}")
        return
    elif module == "pipeline":
        pipeline = ScannerPipeline(
            aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
            context_extractor=JavaContextExtractor(),
        )
        results = pipeline.run(ctx.target_path)

    elif module == "graph":
        pipeline = ScannerPipeline(
            aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
            context_extractor=JavaContextExtractor(),
        )
        reviewer = ReviewerAgent(
            client=OllamaClient(model=reviewer_model, timeout_sec=DEFAULT_LLM_TIMEOUT, num_ctx=DEFAULT_NUM_CTX),
            prompt_version="reviewer_v4",
            output_mode="text",
            use_rule_triage=True,
        )
        app = build_review_graph(pipeline, reviewer)
        final_state = app.invoke({"target_path": ctx.target_path})

        findings = final_state["findings"]
        verdicts = final_state["verdicts"]
        tp_findings = final_state["tp_findings"]

        (out_dir / "pipeline_findings.json").write_text(
            json.dumps([f.model_dump() for f in findings], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (out_dir / "reviewer_verdicts.json").write_text(
            json.dumps([v.model_dump() for v in verdicts], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\n=== GRAPH SUMMARY: {len(findings)} findings -> {len(tp_findings)} TP kept ===")
        if verdicts:
            print("\nFirst verdict preview:")
            print(verdicts[0].model_dump_json(indent=2))
        return

    elif module == "fixer":
        findings_file = out_dir / "pipeline_findings.json"
        verdicts_file = out_dir / "reviewer_verdicts.json"

        if findings_file.exists():
            findings = [Finding(**x) for x in json.loads(findings_file.read_text(encoding="utf-8"))]
            print(f"[INFO] Loaded {len(findings)} existing findings from {findings_file}")
        else:
            pipeline = ScannerPipeline(
                aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
                context_extractor=JavaContextExtractor(),
            )
            findings = pipeline.run(ctx.target_path)
            findings_file.write_text(
                json.dumps([f.model_dump() for f in findings], indent=2, ensure_ascii=False), encoding="utf-8"
            )

        verdicts_by_id = {}
        targets = findings
        if verdicts_file.exists():
            verdicts = [Verdict(**x) for x in json.loads(verdicts_file.read_text(encoding="utf-8"))]
            verdicts_by_id = {v.finding_id: v for v in verdicts}
            tp_ids = {v.finding_id for v in verdicts if v.verdict == "TP"}
            targets = [f for f in findings if f.finding_id in tp_ids]
            print(f"[INFO] Loaded Reviewer verdicts: {len(targets)} TP findings to fix.")
        else:
            print(f"[INFO] No reviewer_verdicts.json found; running Fixer directly on {len(targets)} Tier 1 findings.")

        categories_by_test = _load_categories_by_test()
        fixer_agent = FixerAgent(
            client=OllamaClient(
                model=fixer_model,
                timeout_sec=DEFAULT_LLM_TIMEOUT,
                num_ctx=DEFAULT_NUM_CTX,
                keep_alive="5m",
                num_predict=DEFAULT_FIXER_NUM_PREDICT,
                think=False,
            ),
            prompt_version="fixer_v1",
        )
        validator = PatchValidator(semgrep_tool=semgrep, spotbugs_tool=spotbugs)
        runner = FixLoopRunner(
            fixer=fixer_agent,
            validator=validator,
            max_iterations=max_iterations,
            keep_passing_patch=keep_passing_patch,
        )
        summaries = runner.run_batch(
            targets,
            verdicts_by_id=verdicts_by_id,
            categories_by_test=categories_by_test,
        )
        metrics = compute_fixer_metrics(summaries)
        _print_fixer_summary(summaries, metrics, out_dir)
        return

    elif module == "full_graph":
        pipeline = ScannerPipeline(
            aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
            context_extractor=JavaContextExtractor(),
        )
        reviewer = ReviewerAgent(
            client=OllamaClient(
                model=reviewer_model,
                timeout_sec=DEFAULT_LLM_TIMEOUT,
                num_ctx=DEFAULT_NUM_CTX,
                keep_alive="0",
            ),
            prompt_version="reviewer_v4",
            output_mode="text",
            use_rule_triage=True,
        )
        fixer_agent = FixerAgent(
            client=OllamaClient(
                model=fixer_model,
                timeout_sec=DEFAULT_LLM_TIMEOUT,
                num_ctx=DEFAULT_NUM_CTX,
                keep_alive="5m",
                num_predict=DEFAULT_FIXER_NUM_PREDICT,
                think=False,
            ),
            prompt_version="fixer_v1",
        )
        validator = PatchValidator(semgrep_tool=semgrep, spotbugs_tool=spotbugs)
        runner = FixLoopRunner(
            fixer=fixer_agent,
            validator=validator,
            max_iterations=max_iterations,
            keep_passing_patch=keep_passing_patch,
        )
        app = build_full_graph(pipeline, reviewer, runner)
        final_state = app.invoke({"target_path": ctx.target_path})

        findings = final_state["findings"]
        verdicts = final_state["verdicts"]
        tp_findings = final_state["tp_findings"]
        summaries = final_state["fix_summaries"]

        categories_by_test = _load_categories_by_test()
        for s in summaries:
            if not s.category and s.test_name:
                s.category = categories_by_test.get(s.test_name)
        metrics = compute_fixer_metrics(summaries)

        (out_dir / "pipeline_findings.json").write_text(
            json.dumps([f.model_dump() for f in findings], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (out_dir / "reviewer_verdicts.json").write_text(
            json.dumps([v.model_dump() for v in verdicts], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\n=== REVIEWER SUMMARY: {len(findings)} findings -> {len(tp_findings)} TP kept ===")
        _print_fixer_summary(summaries, metrics, out_dir)
        return

    # Lưu kết quả và in báo cáo (cho các module Tier 1)
    if module != "ast":
        out_file = out_dir / f"{module}_findings.json"
        dict_results = [r.model_dump() for r in results]
        out_file.write_text(json.dumps(dict_results, indent=2, ensure_ascii=False), encoding="utf-8")

        print("\n=== SUMMARY OF FINDINGS ===")
        print(f"Total Findings Found: {len(results)}")
        if len(results) > 0:
            print(f"First finding preview:\n{json.dumps(dict_results[0], indent=2)}")
        print(f"\n[INFO] Full results saved to {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic Code Reviewer Test Runner")
    parser.add_argument(
        "--module",
        choices=["semgrep", "spotbugs", "aggregator", "ast", "pipeline", "graph", "fixer", "full_graph"],
        help="Module to test",
    )
    parser.add_argument("--test", "-t", help="Specific test name (e.g. BenchmarkTest00001)")
    parser.add_argument("--category", "-c", help="Benchmark category (e.g. sqli)")
    parser.add_argument("--limit", "-n", type=int, help="Limit number of test cases")
    parser.add_argument("--run-id", "-r", help="Custom Run ID")
    parser.add_argument("--resume", action="store_true", help="Resume existing workspace")
    parser.add_argument("--clean", action="store_true", help="Overwrite existing workspace")
    parser.add_argument("--reviewer-model", help=f"Reviewer Ollama model (default: {DEFAULT_REVIEWER_MODEL})")
    parser.add_argument("--fixer-model", help=f"Fixer model (default: {DEFAULT_FIXER_MODEL})")
    parser.add_argument("--max-iterations", type=int, help=f"Max Fix-Validate iterations (default: {DEFAULT_MAX_ITERATIONS})")
    parser.add_argument("--keep-passing-patch", action="store_true", help="Keep passing patches on disk in workspace")

    args = parser.parse_args()

    # Nếu có bất kỳ đối số nào được truyền, chạy Headless mode
    if any(vars(args).values()):
        if not args.module:
            args.module = "pipeline"
        run_headless(args)
    else:
        try:
            run_interactive()
        except KeyboardInterrupt:
            print("\n[INFO] Canceled by user. Exiting...")
            sys.exit(0)
