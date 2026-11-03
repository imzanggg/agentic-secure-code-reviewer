"""run_reviewer.py — chạy Reviewer trên tập dev/test, lưu từng verdict, có resume."""

import argparse
import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests

from src.agents.llm_client import OllamaClient
from src.agents.reviewer import ReviewerAgent
from src.schemas import Finding

FINDINGS = Path("data/results/tier1_findings.json")
SPLIT = Path("data/splits/dev_test_split.json")
TEST_NAME = re.compile(r"(BenchmarkTest\d+)")


def safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def model_digest(client):
    """Lấy mã định danh của model trong Ollama, để ghi lại cho việc tái lập."""
    try:
        r = requests.get(f"{client.base_url}/api/tags", timeout=5)
        r.raise_for_status()
        for m in r.json().get("models", []):
            if m.get("name") == client.model:
                return m.get("digest")
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:3b")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--prompt", default="reviewer_v1")
    ap.add_argument("--mode", choices=["json", "text"], default="json")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--tag", default="", help="hậu tố tên file kết quả, ví dụ c5")
    ap.add_argument("--repeat-penalty", type=float, default=None)
    ap.add_argument("--repeat-last-n", type=int, default=None)
    ap.add_argument("--rule-triage", action="store_true")
    ap.add_argument("--findings", default=str(FINDINGS), help="file finding đầu vào")
    args = ap.parse_args()

    names = set(json.loads(SPLIT.read_text(encoding="utf-8"))[args.split])
    findings = [Finding(**x) for x in json.loads(Path(args.findings).read_text(encoding="utf-8"))]
    todo = [f for f in findings
            if (m := TEST_NAME.search(f.file_path)) and m.group(1) in names]
    todo.sort(key=lambda f: (f.file_path, f.line_start))
    if args.limit:
        todo = todo[:args.limit]

    client = OllamaClient(model=args.model, repeat_penalty=args.repeat_penalty,
                          repeat_last_n=args.repeat_last_n)
    agent = ReviewerAgent(client, prompt_version=args.prompt, output_mode=args.mode,
                          use_rule_triage=args.rule_triage)

    out_dir = Path("data/results/reviewer")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{args.split}_{safe(args.model)}_{args.prompt}"
    if args.tag:
        stem += f"_{safe(args.tag)}"
    out_path = out_dir / f"{stem}.jsonl"

    (out_dir / f"{stem}.meta.json").write_text(json.dumps({
        "model": args.model, "model_digest": model_digest(client),
        "prompt_version": args.prompt, "split": args.split,
        "temperature": client.temperature, "seed": client.seed,
        "num_ctx": client.num_ctx, "n_findings": len(todo),
        "last_started": datetime.now().isoformat(timespec="seconds"),
        "output_mode": args.mode, "num_predict": getattr(client, "num_predict", None),
        "tag": args.tag, "parser": "v2_relaxed_regex",
        "repeat_penalty": args.repeat_penalty, "repeat_last_n": args.repeat_last_n,
        "findings_file": args.findings,
    }, indent=2), encoding="utf-8")

    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line)["finding_id"])
    remaining = [f for f in todo if f.finding_id not in done]
    print(f"{len(todo)} finding trong '{args.split}', đã có {len(done)}, "
          f"cần chạy {len(remaining)} | model={args.model} prompt={args.prompt}")

    t0 = time.perf_counter()
    with open(out_path, "a", encoding="utf-8") as fh:
        for i, f in enumerate(remaining, 1):
            fh.write(agent.review(f).model_dump_json() + "\n")
            fh.flush()
            if i % 10 == 0 or i == len(remaining):
                el = time.perf_counter() - t0
                eta = el / i * (len(remaining) - i)
                print(f"[{i}/{len(remaining)}] đã chạy {el/60:.1f} phút, còn ~{eta/60:.1f} phút")

    rows = [json.loads(x) for x in out_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    fo = sum(1 for r in rows if r["source"] == "fail_open")
    lat = [r["latency_sec"] for r in rows if r.get("latency_sec")]
    print(f"\nTổng {len(rows)} verdict | fail-open: {fo} | "
          f"độ trễ trung bình: {sum(lat)/len(lat):.2f}s" if lat else f"\nTổng {len(rows)} verdict")
    print(f"Kết quả: {out_path}")


if __name__ == "__main__":
    main()