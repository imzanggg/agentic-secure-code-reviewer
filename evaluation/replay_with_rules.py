"""replay_with_rules.py: phát lại một lần chạy Reviewer với bước phân loại bằng luật (không gọi LLM)."""

import argparse
import json
import re
from pathlib import Path

from evaluation.discrimination_test import report
from evaluation.run_reviewer import safe
from src.agents.reviewer import rule_triage
from src.schemas import Finding

LABELED = Path("data/results/tier1_findings_labeled.json")
FINDINGS = Path("data/results/tier1_findings.json")
RUN_DIR = Path("data/results/reviewer")


def summary(title, rows, labels):
    kept = [r for r in rows if r["verdict"] == "TP"]
    kr = sum(labels[r["finding_id"]]["is_true_positive"] for r in kept)
    n_real = sum(labels[r["finding_id"]]["is_true_positive"] for r in rows)
    print(f"  {title}: giữ {len(kept)}/{len(rows)} | precision {kr/len(kept):.3f} "
          f"(trước {n_real/len(rows):.3f}) | giữ lại {kr}/{n_real} lỗi thật ({kr/n_real:.1%})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--split", default="dev")
    ap.add_argument("--prompt", required=True)
    a = ap.parse_args()

    path = RUN_DIR / f"{a.split}_{safe(a.model)}_{a.prompt}.jsonl"
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    labels = {x["finding_id"]: x for x in json.loads(LABELED.read_text(encoding="utf-8"))}
    fnd = {x["finding_id"]: Finding(**x)
           for x in json.loads(FINDINGS.read_text(encoding="utf-8"))}

    replay, n_ruled = [], 0
    for r in rows:
        r = dict(r)
        if rule_triage(fnd[r["finding_id"]]):
            if r["verdict"] != "TP":
                n_ruled += 1          # ca bị LLM loại nhưng luật giữ lại
            r["verdict"] = "TP"
        replay.append(r)

    print(f"=== {path.stem} + rule_triage ===")
    print(f"Số verdict bị luật đổi từ FP sang TP: {n_ruled}")
    summary("chỉ LLM    ", rows, labels)
    summary("LLM + luật ", replay, labels)
    report("Tất cả verdict (chỉ LLM)", rows, labels)
    report("Tất cả verdict (LLM + luật)", replay, labels)


if __name__ == "__main__":
    main()