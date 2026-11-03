"""discrimination_test.py: Reviewer có phân biệt được nhiễu với lỗi thật không? (không gọi LLM)"""

import argparse
import json
import math
from pathlib import Path

from scipy.stats import fisher_exact

from evaluation.run_reviewer import safe

LABELED = Path("data/results/tier1_findings_labeled.json")
RUN_DIR = Path("data/results/reviewer")


def odds_ci(a, b, c, d, z=1.96):
    a, b, c, d = (x + 0.5 for x in (a, b, c, d))   # hiệu chỉnh 0,5 để tránh chia cho 0
    lor = math.log(a * d / (b * c))
    se = math.sqrt(1 / a + 1 / b + 1 / c + 1 / d)
    return math.exp(lor - z * se), math.exp(lor + z * se)


def report(title, rows, labels):
    a = b = c = d = 0   # a: loại nhiễu, b: loại thật, c: giữ nhiễu, d: giữ thật
    for r in rows:
        real = labels[r["finding_id"]]["is_true_positive"]
        drop = r["verdict"] == "FP"
        if drop and not real: a += 1
        elif drop and real: b += 1
        elif not drop and not real: c += 1
        else: d += 1
    odds, p = fisher_exact([[a, b], [c, d]])
    lo, hi = odds_ci(a, b, c, d)
    print(f"{title}: n={a + b + c + d}")
    print(f"  bị loại | nhiễu {a}/{a + c} ({a / (a + c):.1%}) vs thật {b}/{b + d} ({b / (b + d):.1%})")
    print(f"  OR={odds:.2f} (95%CI {lo:.2f}-{hi:.2f}) p={p:.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:3b")
    ap.add_argument("--split", default="dev")
    ap.add_argument("--prompt", required=True)
    a = ap.parse_args()

    path = RUN_DIR / f"{a.split}_{safe(a.model)}_{a.prompt}.jsonl"
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    labels = {x["finding_id"]: x for x in json.loads(LABELED.read_text(encoding="utf-8"))}

    print(f"=== {path.stem} ===")
    report("Tất cả verdict", rows, labels)
    report("Chỉ verdict do model sinh (bỏ fail-open)",
           [r for r in rows if r["source"] != "fail_open"], labels)


if __name__ == "__main__":
    main()