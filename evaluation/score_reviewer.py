"""
score_reviewer.py
Chấm điểm Reviewer cho một lần chạy (model + prompt + split).

Mức finding : Reviewer có giữ đúng finding thật và loại đúng finding nhiễu không?
Mức test case: gộp ngược lên test case, so với baseline "giữ hết" TRÊN CÙNG tập con.

Chạy: python3 -m evaluation.score_reviewer --model qwen2.5-coder:3b --split dev
"""

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

from evaluation.benchmark_scoring import (
    EXPECTED_CSV, compute_metrics, cwe_matches, load_expected_results)
from evaluation.run_reviewer import safe

SPLIT = Path("data/splits/dev_test_split.json")
LABELED = Path("data/results/tier1_findings_labeled.json")
RUN_DIR = Path("data/results/reviewer")


def wilson(k, n, z=1.96):
    """Khoảng tin cậy 95% (Wilson) cho một tỷ lệ."""
    if n == 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round((c - m) / d, 3), round((c + m) / d, 3)


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "value": round(k / n, 4) if n else None, "ci95": [lo, hi]}


def finding_level(verdicts, labels):
    cm = {"kept_real": 0, "kept_noise": 0, "dropped_real": 0, "dropped_noise": 0}
    by_cat = defaultdict(lambda: dict.fromkeys(cm, 0))
    by_conf = defaultdict(lambda: {"n": 0, "correct": 0})
    errors = []

    for v in verdicts:
        lab = labels[v["finding_id"]]
        real = lab["is_true_positive"]            # đáp án (có áp dụng CWE tương đương)
        keep = v["verdict"] == "TP"
        key = ("kept" if keep else "dropped") + ("_real" if real else "_noise")
        cm[key] += 1
        by_cat[lab["category"]][key] += 1
        if v["source"] != "fail_open":
            by_conf[v["confidence"]]["n"] += 1
            by_conf[v["confidence"]]["correct"] += int(keep == real)
        if keep != real:
            errors.append({
                "finding_id": v["finding_id"], "test_name": lab["test_name"],
                "category": lab["category"],
                "error": "dropped_real" if real else "kept_noise",
                "confidence": v["confidence"], "source": v["source"],
                "reasoning": v["reasoning"][:600],
            })

    n = len(verdicts)
    n_real = cm["kept_real"] + cm["dropped_real"]
    n_noise = cm["kept_noise"] + cm["dropped_noise"]
    kept = cm["kept_real"] + cm["kept_noise"]
    summary = {
        "n": n, "n_real": n_real, "n_noise": n_noise, "confusion": cm,
        "precision_before": rate(n_real, n),          # = baseline "luôn giữ" trên tập này
        "precision_after": rate(cm["kept_real"], kept),
        "real_kept_rate": rate(cm["kept_real"], n_real),
        "noise_removed_rate": rate(cm["dropped_noise"], n_noise),
        "fail_open": sum(1 for v in verdicts if v["source"] == "fail_open"),
    }
    return summary, by_cat, by_conf, errors


def test_level(expected, names, labeled_by_test, verdict_of, use_reviewer):
    total = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    missing = 0
    for name in names:
        info = expected[name]
        target = f"CWE-{info['cwe']}"
        flagged = False
        for lab in labeled_by_test.get(name, []):
            if use_reviewer:
                v = verdict_of.get(lab["finding_id"])
                if v is None:
                    missing += 1      # chưa có verdict -> giữ lại (tinh thần fail-open)
                elif v != "TP":
                    continue
            if cwe_matches(target, lab["finding_cwe"], True):
                flagged = True
                break
        if info["real"] and flagged:
            total["TP"] += 1
        elif not info["real"] and flagged:
            total["FP"] += 1
        elif info["real"]:
            total["FN"] += 1
        else:
            total["TN"] += 1
    return compute_metrics(total), missing


def fmt(r):
    if r["value"] is None:
        return "n/a"
    return f"{r['value']:.3f} ({r['k']}/{r['n']}, 95%CI {r['ci95'][0]}-{r['ci95'][1]})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:3b")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--prompt", default="reviewer_v1")
    ap.add_argument("--tag", default="", help="hậu tố tên file kết quả, ví dụ c9")
    args = ap.parse_args()

    stem = f"{args.split}_{safe(args.model)}_{args.prompt}"
    if args.tag:
        stem += f"_{safe(args.tag)}"
    run_path = RUN_DIR / f"{stem}.jsonl"
    verdicts = [json.loads(x) for x in run_path.read_text(encoding="utf-8").splitlines() if x.strip()]

    labeled = json.loads(LABELED.read_text(encoding="utf-8"))
    labels = {x["finding_id"]: x for x in labeled}
    labeled_by_test = defaultdict(list)
    for x in labeled:
        labeled_by_test[x["test_name"]].append(x)
    names = json.loads(SPLIT.read_text(encoding="utf-8"))[args.split]
    expected = load_expected_results(EXPECTED_CSV)
    verdict_of = {v["finding_id"]: v["verdict"] for v in verdicts}

    summary, by_cat, by_conf, errors = finding_level(verdicts, labels)
    base, _ = test_level(expected, names, labeled_by_test, verdict_of, use_reviewer=False)
    after, missing = test_level(expected, names, labeled_by_test, verdict_of, use_reviewer=True)

    print(f"=== {stem} ===")
    print(f"Finding: {summary['n']} ({summary['n_real']} thật, {summary['n_noise']} nhiễu) "
          f"| fail-open: {summary['fail_open']}")
    print("\n[MỨC FINDING]")
    print(f"Precision trước (giữ hết): {fmt(summary['precision_before'])}")
    print(f"Precision sau Reviewer   : {fmt(summary['precision_after'])}")
    print(f"Giữ lại finding thật     : {fmt(summary['real_kept_rate'])}   <- loại nhầm = mất Recall")
    print(f"Loại được finding nhiễu  : {fmt(summary['noise_removed_rate'])}")

    print("\n[THEO CATEGORY]  (giữ thật / tổng thật | loại nhiễu / tổng nhiễu)")
    for cat in sorted(by_cat):
        c = by_cat[cat]
        r = c["kept_real"] + c["dropped_real"]
        z = c["kept_noise"] + c["dropped_noise"]
        print(f"{cat:<13} {c['kept_real']:>3}/{r:<3} | {c['dropped_noise']:>3}/{z:<3}")

    print("\n[ĐỘ TIN CẬY: tỷ lệ verdict đúng theo mức confidence]")
    for lvl in ("high", "medium", "low"):
        if lvl in by_conf:
            b = by_conf[lvl]
            print(f"{lvl:<7} {b['correct']}/{b['n']} = {b['correct']/b['n']:.3f}")

    print(f"\n[MỨC TEST CASE, {len(names)} test case của tập '{args.split}' (strict + tương đương CWE)]")
    print(f"{'':<16}{'Precision':>10}{'TPR':>8}{'FPR':>8}{'Bench':>8}   TP/FP/TN/FN")
    for label, m in (("Giữ hết", base), ("Sau Reviewer", after)):
        print(f"{label:<16}{m['precision']:>10}{m['recall_tpr']:>8}{m['fpr']:>8}"
              f"{m['benchmark_score']:>8}   {m['TP']}/{m['FP']}/{m['TN']}/{m['FN']}")
    if missing:
        print(f"CẢNH BÁO: {missing} finding chưa có verdict (đã giữ lại).")

    n_dropped_real = sum(1 for e in errors if e["error"] == "dropped_real")
    print(f"\nLỗi: {n_dropped_real} finding thật bị loại nhầm, "
          f"{len(errors) - n_dropped_real} finding nhiễu bị giữ")

    (RUN_DIR / f"{stem}.scores.json").write_text(json.dumps({
        "finding_level": summary, "by_category": by_cat,
        "by_confidence": by_conf, "test_level_baseline": base,
        "test_level_after_reviewer": after}, indent=2, ensure_ascii=False), encoding="utf-8")
    (RUN_DIR / f"{stem}.errors.json").write_text(
        json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Đã lưu: {RUN_DIR / (stem + '.scores.json')} và .errors.json")


if __name__ == "__main__":
    main()