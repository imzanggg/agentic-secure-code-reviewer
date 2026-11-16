"""
test_interactive.py - Test Runner hợp nhất cho Module 1 (scanner) và Module 2 (reviewer).
(Đã gộp tests/module2_runner.py vào đây; đây là cổng vào duy nhất.)

LUỒNG MODULE 2
  Luồng A: chạy thử nhanh, dữ liệu sinh ra tại chỗ, không có nhãn nên không chấm điểm
    Benchmark -> [Tier 1: SpotBugs+Semgrep -> dedup -> context] -> pipeline_findings.json
              -> [Reviewer: rule_triage (mặc định bật) -> LLM] -> reviewer_verdicts.jsonl
    Module: pipeline+reviewer (scan + review) | reviewer (review lại findings của run cũ)
            reviewer-rules (chỉ xem rule bắt được gì, không LLM)
            reviewer-file (review một file findings bất kỳ, không cần workspace)
  Luồng B: đo chất lượng trên tập dev/test đã gán nhãn
    tier1_findings.json -> evaluation.run_reviewer -> score_reviewer -> discrimination_test
    Module: reviewer-eval

VÍ DỤ
  # Scan + Reviewer cho 1 test
  python3 -m tests.test_interactive --module pipeline+reviewer -t BenchmarkTest00318 --run-id r1 --clean
  # Xem rule_triage bắt được gì (không LLM) trên run đã scan
  python3 -m tests.test_interactive --module reviewer-rules --run-id r1 --resume
  # Review lại findings của run cũ với model khác
  python3 -m tests.test_interactive --module reviewer --run-id r1 --resume --model qwen2.5-coder:7b
  # Review một file findings bất kỳ
  python3 -m tests.test_interactive --module reviewer-file --findings path/pipeline_findings.json
  # Đo trên tập dev: chạy + chấm điểm + kiểm định
  python3 -m tests.test_interactive --module reviewer-eval --split dev --tag c10
"""

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from evaluation.build_callee_context import CALL, DEF, methods_named, thing_impls
from src.agents.llm_client import OllamaClient
from src.agents.reviewer import ReviewerAgent, rule_triage as rule_triage_fn
from src.preprocessor import BenchmarkPreprocessor
from src.scanner.aggregator import SASTAggregator
from src.scanner.context_extractor import JavaContextExtractor
from src.scanner.pipeline import ScannerPipeline
from src.scanner.semgrep_tool import SemgrepTool
from src.scanner.spotbugs_tool import SpotBugsTool
from src.schemas import Finding

MODULE1 = ("semgrep", "spotbugs", "aggregator", "ast", "pipeline")
MODULE2 = ("reviewer-rules", "reviewer", "pipeline+reviewer", "reviewer-file", "reviewer-eval")
ALL_MODULES = MODULE1 + MODULE2
NO_WORKSPACE = ("reviewer-file", "reviewer-eval")   # không cần setup_run


@dataclass
class ReviewerConfig:
    """Toàn bộ tham số của Module 2, truyền qua một đối tượng thay cho biến toàn cục."""
    model: str = "qwen2.5-coder:3b"
    prompt: str = "reviewer_v3callee_text"
    mode: str = "text"                # text | json (prompt *_text cần mode text)
    limit: int | None = None          # số finding tối đa cho Reviewer
    rule_triage: bool = True          # cổng luật trước LLM (cấu hình D1)
    repeat_penalty: float | None = None
    repeat_last_n: int | None = None
    findings: str | None = None       # ghi đè đường dẫn findings đầu vào
    out: str | None = None            # ghi đè đường dẫn verdict đầu ra
    split: str = "dev"                # chỉ dùng cho reviewer-eval
    tag: str = ""                     # hậu tố tên file kết quả (reviewer-eval)


# ================================================================ Module 2: lõi
def attach_callee(d: dict) -> dict:
    """callee = thân doSomething (đã bỏ comment), logic chép từ build_callee_context.main().
    Chỉ có nghĩa với mẫu doSomething của Benchmark; ngoài đó callee_context = None."""
    if d.get("callee_context"):
        return d
    d["callee_context"] = None
    ctx = d.get("function_context") or ""
    if not CALL.search(ctx) or DEF.search(ctx):
        return d
    path = Path(d["file_path"])
    if not path.exists():
        return d
    defs = methods_named(path, "doSomething") or thing_impls(path)
    if defs:
        d["callee_context"] = "\n\n".join(defs)
    return d


def run_reviewer_stage(findings_path: Path, out_path: Path, cfg: ReviewerConfig,
                       no_llm: bool = False) -> list[dict]:
    """Đọc findings, (tuỳ chọn) chạy rule_triage, rồi gọi LLM cho phần còn lại."""
    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    if cfg.limit:
        raw = raw[:cfg.limit]
    findings = [Finding(**attach_callee(dict(x))) for x in raw]
    print(f"{len(findings)} finding | callee: {sum(1 for f in findings if f.callee_context)} | "
          f"model={cfg.model} prompt={cfg.prompt} mode={cfg.mode} "
          f"rule_triage={cfg.rule_triage or no_llm} no_llm={no_llm}")

    if no_llm:
        hit = 0
        for f in findings:
            algo = rule_triage_fn(f)
            hit += bool(algo)
            print(f"{f.finding_id[:8]} {f.rule_id[-40:]:<40} rule_triage={algo}")
        print(f"Rule bắt được {hit}/{len(findings)} finding; còn lại sẽ chuyển cho LLM")
        return []

    client = OllamaClient(model=cfg.model, repeat_penalty=cfg.repeat_penalty,
                          repeat_last_n=cfg.repeat_last_n)
    agent = ReviewerAgent(client, prompt_version=cfg.prompt, output_mode=cfg.mode,
                          use_rule_triage=cfg.rule_triage)
    rows, t0 = [], time.perf_counter()
    with open(out_path, "w", encoding="utf-8") as fh:
        for i, f in enumerate(findings, 1):
            r = agent.review(f).model_dump()
            rows.append(r)
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            fh.flush()
            print(f"[{i}/{len(findings)}] {f.finding_id[:8]} verdict={r.get('verdict')} "
                  f"conf={r.get('confidence')} source={r.get('source')}")
    fo = sum(1 for r in rows if r.get("source") == "fail_open")
    print(f"Xong {len(rows)} verdict | fail-open: {fo} | {time.perf_counter() - t0:.1f}s | {out_path}")
    return rows


def run_pipeline_to_file(ctx, semgrep, spotbugs, findings_file: Path):
    pipeline = ScannerPipeline(
        aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
        context_extractor=JavaContextExtractor(),
    )
    res = pipeline.run(ctx.target_path)
    findings_file.write_text(
        json.dumps([r.model_dump() for r in res], indent=2, ensure_ascii=False),
        encoding="utf-8")
    print(f"[INFO] Tier 1: {len(res)} finding -> {findings_file}")


def run_module2(module: str, ctx, cfg: ReviewerConfig, semgrep, spotbugs):
    """Luồng A: reviewer-rules | reviewer | pipeline+reviewer | reviewer-file."""
    if module == "reviewer-file":
        if not cfg.findings:
            sys.exit("[ERROR] reviewer-file cần --findings <file>.")
        findings_file = Path(cfg.findings)
        out = Path(cfg.out) if cfg.out else findings_file.with_name("reviewer_verdicts.jsonl")
    else:
        findings_file = (Path(cfg.findings) if cfg.findings
                         else Path(ctx.results_dir) / "pipeline_findings.json")
        out = Path(cfg.out) if cfg.out else Path(ctx.results_dir) / "reviewer_verdicts.jsonl"

        if module == "pipeline+reviewer":
            run_pipeline_to_file(ctx, semgrep, spotbugs, findings_file)   # luôn scan lại
        elif not findings_file.exists():
            sys.exit(f"[ERROR] Không thấy {findings_file}. Chạy '--module pipeline+reviewer' "
                     f"trước, hoặc truyền --findings <file>.")
        else:
            print(f"[INFO] Dùng lại findings có sẵn: {findings_file}")

    if not findings_file.exists():
        sys.exit(f"[ERROR] Không thấy {findings_file}.")
    run_reviewer_stage(findings_file, out, cfg, no_llm=(module == "reviewer-rules"))


# ================================================================ Module 2: luồng B
def _sh(cmd: list[str]) -> int:
    print("\n$ " + " ".join(cmd))
    return subprocess.run(cmd).returncode


def run_reviewer_eval(cfg: ReviewerConfig):
    """Chạy Reviewer trên tập dev/test rồi chấm điểm (không cần workspace)."""
    base = ["--model", cfg.model, "--split", cfg.split, "--prompt", cfg.prompt]
    tag = ["--tag", cfg.tag] if cfg.tag else []

    run = [sys.executable, "-m", "evaluation.run_reviewer", *base, *tag, "--mode", cfg.mode]
    if cfg.limit:
        run += ["--limit", str(cfg.limit)]
    if cfg.rule_triage:
        run += ["--rule-triage"]
    if cfg.repeat_penalty is not None:
        run += ["--repeat-penalty", str(cfg.repeat_penalty)]
    if cfg.repeat_last_n is not None:
        run += ["--repeat-last-n", str(cfg.repeat_last_n)]
    if cfg.findings:
        run += ["--findings", cfg.findings]

    if _sh(run) != 0:
        sys.exit("[ERROR] run_reviewer thất bại, dừng.")
    if _sh([sys.executable, "-m", "evaluation.score_reviewer", *base, *tag]) != 0:
        sys.exit("[ERROR] score_reviewer thất bại.")
    if cfg.tag:
        print("\n[INFO] Bỏ qua discrimination_test: script này chưa nhận --tag "
              "(thêm đối số --tag vào script nếu muốn dùng).")
    else:
        _sh([sys.executable, "-m", "evaluation.discrimination_test", *base, *tag])


# ================================================================ Dispatcher
def execute_module(module: str, ctx, cfg: ReviewerConfig):
    print(f"\n{'=' * 40}\nExecuting Module: {module.upper()}\n{'=' * 40}")

    if module == "reviewer-eval":
        return run_reviewer_eval(cfg)

    semgrep = SemgrepTool(ruleset="p/java")
    spotbugs = SpotBugsTool()

    if module in MODULE2:
        return run_module2(module, ctx, cfg, semgrep, spotbugs)

    results = []
    if module == "semgrep":
        results = semgrep.run(ctx.target_path)
    elif module == "spotbugs":
        results = spotbugs.run(ctx.target_path)
    elif module == "aggregator":
        results = SASTAggregator(tools=[semgrep, spotbugs], line_window=4).run_all(ctx.target_path)
    elif module == "ast":
        target_file = Path(ctx.target_path) / ctx.target_tests[0]
        res = JavaContextExtractor().extract_method(str(target_file), target_line=1)  # mock line
        print(f"\nAST Method extracted:\n{res if res else 'None'}")
        return
    elif module == "pipeline":
        pipeline = ScannerPipeline(
            aggregator=SASTAggregator(tools=[semgrep, spotbugs], line_window=4),
            context_extractor=JavaContextExtractor(),
        )
        results = pipeline.run(ctx.target_path)

    out_file = Path(ctx.results_dir) / f"{module}_findings.json"
    dict_results = [r.model_dump() for r in results]
    out_file.write_text(json.dumps(dict_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n=== SUMMARY OF FINDINGS ===")
    print(f"Total Findings Found: {len(results)}")
    if dict_results:
        print(f"First finding preview:\n{json.dumps(dict_results[0], indent=2)}")
    print(f"\n[INFO] Full results saved to {out_file}")


# ================================================================ Headless
def run_headless(args):
    cfg = ReviewerConfig(
        model=args.model, prompt=args.prompt, mode=args.output_mode,
        limit=args.reviewer_limit, rule_triage=args.rule_triage,
        repeat_penalty=args.repeat_penalty, repeat_last_n=args.repeat_last_n,
        findings=args.findings, out=args.out, split=args.split, tag=args.tag)

    if args.module in NO_WORKSPACE:
        return execute_module(args.module, None, cfg)

    context = BenchmarkPreprocessor().setup_run(
        test_list=[args.test] if args.test else None,
        category=args.category, limit=args.limit,
        run_id=args.run_id, resume=args.resume, clean=args.clean)
    execute_module(args.module, context, cfg)


# ================================================================ Interactive
def ask(prompt: str, default: str = "") -> str:
    return input(f"{prompt} (Default: {default or 'none'}): ").strip() or default


def ask_reviewer_config(module: str) -> ReviewerConfig:
    print("\n[?] Module 2 configuration (Enter = giữ mặc định):")
    cfg = ReviewerConfig()
    if module == "reviewer-file":
        cfg.findings = ask("  Đường dẫn file findings", "")
    if module == "reviewer-rules":
        return cfg                               # không dùng LLM nên không hỏi thêm
    cfg.model = ask("  Ollama model", cfg.model)
    cfg.prompt = ask("  Prompt version", cfg.prompt)
    cfg.mode = ask("  Output mode [text/json]", cfg.mode)
    cfg.rule_triage = ask("  Bật rule_triage trước LLM? [y/n]", "y").lower() == "y"
    lim = ask("  Giới hạn số finding", "all")
    cfg.limit = int(lim) if lim.isdigit() else None
    if module == "reviewer-eval":
        cfg.split = ask("  Split [dev/test]", cfg.split)
        cfg.tag = ask("  Tag kết quả", "")
    return cfg


def run_interactive():
    print("=" * 60)
    print("      AGENTIC CODE REVIEWER - TEST RUNNER")
    print("=" * 60)
    print("\n[?] What module do you want to test?")
    print("  -- Module 1: Scanner --")
    print("  [1] Semgrep only   [2] SpotBugs only   [3] SAST Aggregator")
    print("  [4] AST Context Extractor   [5] Entire Tier 1 Pipeline")
    print("  -- Module 2: Reviewer --")
    print("  [6] Reviewer rules only   (rule_triage, không LLM; cần run đã scan)")
    print("  [7] Reviewer (LLM)        (review lại findings của một run có sẵn)")
    print("  [8] Tier 1 + Reviewer     (scan rồi review, luồng đầy đủ)")
    print("  [9] Reviewer on file      (review một file findings bất kỳ, không cần workspace)")
    print("  [10] Reviewer evaluation  (tập dev/test: chạy + chấm điểm + kiểm định)")
    names = {"1": "semgrep", "2": "spotbugs", "3": "aggregator", "4": "ast", "5": "pipeline",
             "6": "reviewer-rules", "7": "reviewer", "8": "pipeline+reviewer",
             "9": "reviewer-file", "10": "reviewer-eval"}
    module = names.get(input("\nSelect option [1-10] (Default: 5): ").strip(), "pipeline")

    cfg = ask_reviewer_config(module) if module in MODULE2 else ReviewerConfig()

    if module in NO_WORKSPACE:
        return execute_module(module, None, cfg)

    preprocessor = BenchmarkPreprocessor()
    test_list = category = limit = None
    run_id, resume, clean = None, False, False

    if module in ("reviewer-rules", "reviewer"):
        run_id, resume = input("\nExisting Run ID to review: ").strip(), True
    else:
        print("\n[?] Select dataset scope:")
        print("  [1] Single test file   [2] Specific Category   [3] Full Benchmark Suite")
        scope = input("Select option [1-3] (Default: 1): ").strip() or "1"
        if scope == "1":
            test_list = [ask("Enter test name", "BenchmarkTest00001")]
        elif scope == "2":
            cats = preprocessor.get_categories()
            cat_names = list(cats)
            for i, c in enumerate(cat_names):
                print(f"  [{i}] {c} ({len(cats[c])} tests)")
            ci = input("Enter category name or index: ").strip()
            category = cat_names[int(ci)] if ci.isdigit() and int(ci) < len(cat_names) else ci
            li = ask("How many tests?", "5")
            limit = int(li) if li.isdigit() else None
        else:
            test_list = ["all"]

        print("\n[?] Session: [1] Fresh   [2] Custom Run ID   [3] Resume")
        sess = input("Select option [1-3] (Default: 1): ").strip() or "1"
        if sess == "2":
            run_id, clean = input("Enter custom Run ID: ").strip(), True
        elif sess == "3":
            run_id, resume = input("Enter existing Run ID: ").strip(), True

    try:
        context = preprocessor.setup_run(test_list=test_list, category=category, limit=limit,
                                         run_id=run_id, resume=resume, clean=clean)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    print(f"\n[INFO] Workspace ready at: {context.workspace_dir}")
    print(f"[INFO] Target tests count: {len(context.target_tests)}")
    execute_module(module, context, cfg)


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Agentic Code Reviewer Test Runner",
        epilog="Chạy không tham số để vào chế độ hỏi đáp. Xem docstring đầu file để biết luồng Module 2.")
    p.add_argument("--module", choices=ALL_MODULES, help="Module to test")
    # Chọn dữ liệu / phiên chạy
    p.add_argument("--test", "-t", help="Specific test name (e.g. BenchmarkTest00001)")
    p.add_argument("--category", "-c", help="Benchmark category (e.g. sqli)")
    p.add_argument("--limit", "-n", type=int, help="Limit number of test cases")
    p.add_argument("--run-id", "-r", help="Custom Run ID")
    p.add_argument("--resume", action="store_true", help="Resume existing workspace")
    p.add_argument("--clean", action="store_true", help="Overwrite existing workspace")
    # Module 2
    p.add_argument("--model", default="qwen2.5-coder:3b", help="Module 2: Ollama model")
    p.add_argument("--prompt", default="reviewer_v3callee_text", help="Module 2: prompt version")
    p.add_argument("--output-mode", choices=["text", "json"], default="text",
                   help="Module 2: giao thức đầu ra của LLM")
    p.add_argument("--no-rule-triage", dest="rule_triage", action="store_false",
                   help="Module 2: tắt rule_triage (mặc định bật, cấu hình D1)")
    p.add_argument("--reviewer-limit", type=int, default=None, help="Module 2: max findings to review")
    p.add_argument("--repeat-penalty", type=float, default=None)
    p.add_argument("--repeat-last-n", type=int, default=None)
    p.add_argument("--findings", default=None, help="Module 2: file findings đầu vào thay cho mặc định")
    p.add_argument("--out", default=None, help="Module 2: file verdict đầu ra thay cho mặc định")
    p.add_argument("--split", choices=["dev", "test"], default="dev", help="reviewer-eval: tập dữ liệu")
    p.add_argument("--tag", default="", help="reviewer-eval: hậu tố tên file kết quả")

    args = p.parse_args()
    if len(sys.argv) > 1:                     # có đối số -> headless
        args.module = args.module or "pipeline"
        run_headless(args)
    else:
        try:
            run_interactive()
        except KeyboardInterrupt:
            print("\n[INFO] Canceled by user. Exiting...")
            sys.exit(0)