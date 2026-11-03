"""split_dev_test.py — chia 2740 test case thành dev/test (cố định, tái lập được)."""

import json
import math
import random
from collections import defaultdict
from pathlib import Path

from evaluation.benchmark_scoring import EXPECTED_CSV, load_expected_results

SEED = 42
DEV_FRACTION = 0.10
FORCE_DEV = ["BenchmarkTest00001", "BenchmarkTest00063"]  # đã xem tay khi viết prompt
OUT = Path("data/splits/dev_test_split.json")
LABELED = Path("data/results/tier1_findings_labeled.json")


def main():
    expected = load_expected_results(EXPECTED_CSV)

    groups = defaultdict(list)
    for name, info in expected.items():
        groups[(info["category"], info["real"])].append(name)

    rng = random.Random(SEED)
    dev = set()
    for key in sorted(groups):
        names = sorted(groups[key])
        rng.shuffle(names)
        dev.update(names[:max(1, math.ceil(len(names) * DEV_FRACTION))])
    dev.update(FORCE_DEV)
    test = sorted(set(expected) - dev)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "seed": SEED, "dev_fraction": DEV_FRACTION, "forced_dev": FORCE_DEV,
        "dev": sorted(dev), "test": test,
    }, indent=2), encoding="utf-8")

    labeled = json.loads(LABELED.read_text(encoding="utf-8"))
    for name, subset in (("dev", dev), ("test", set(test))):
        rows = [x for x in labeled if x["test_name"] in subset]
        tp = sum(1 for x in rows if x["is_true_positive"])
        print(f"{name}: {len(subset)} test case, {len(rows)} finding "
              f"({tp} TP, {len(rows) - tp} nhiễu)")
    print(f"Đã lưu: {OUT}")


if __name__ == "__main__":
    main()