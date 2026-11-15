"""Build the live-monitor demo traffic file from real dataset rows (no synthetic traffic).

    python build_live_demo.py                 # writes backend/data/live_demo_flows.csv (gitignored)

Rows come from the S58 replay stream, with all 43 scaled features read from the source CSVs (cached outside the
repository by ablate_policy_xai.matrix), the dataset label and family, in a fixed shuffled order.

Within each family, flagged and unflagged rows are chosen so that the family's flagged share equals its flag rate
on the full original snapshot (from the stream metadata's population counts): the live monitor's per-family
detection rates and false-alarm rate then reflect the real detector, not the stream's sampling quotas. The mix
*between* families is not real-network proportions (DDoS would be 74% of rows). Re-scoring each row must reproduce
the stream's stored decision. The demo is for showing the pipeline; it is not an evaluation set.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ablate_policy_xai as abl  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services.live_service import DEMO_FILE  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEED = 20261115
STREAM = "S58 (exploratory)"


def rate_matched_counts(flagged_available: int, unflagged_available: int, rate: float) -> tuple[int, int]:
    """Largest (n_flagged, n_unflagged) within the available rows whose flagged share is closest to `rate`."""
    best = (0, 0)
    for n in range(flagged_available + unflagged_available, 0, -1):
        nf = round(rate * n)
        if nf <= flagged_available and n - nf <= unflagged_available:
            best = (nf, n - nf)
            break
    return best


def select(alerts, population, seed=SEED):
    rng = random.Random(seed)
    groups = defaultdict(list)
    for i, a in enumerate(alerts):
        groups[(a["_family"], bool(a["detected"]))].append(i)
    chosen, plan = [], {}
    for fam in sorted({a["_family"] for a in alerts}):
        f, u = population.get(f"{fam}|flagged", 0), population.get(f"{fam}|unflagged", 0)
        rate = f / (f + u) if f + u else 0.0
        nf, nu = rate_matched_counts(len(groups[(fam, True)]), len(groups[(fam, False)]), rate)
        chosen += rng.sample(groups[(fam, True)], nf) + rng.sample(groups[(fam, False)], nu)
        plan[fam] = {"population_flag_rate": rate, "flagged": nf, "unflagged": nu,
                     "demo_flag_rate": nf / (nf + nu) if nf + nu else 0.0}
    rng.shuffle(chosen)
    return chosen, plan


def build(out: Path = DEMO_FILE, stream: str = STREAM, seed: int = SEED):
    from services.model_service import Detector
    det = Detector(ROOT)
    path = abl.stream_path(stream)
    alerts = replay.load_stream(path)
    population = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))["population"]
    order, plan = select(alerts, population, seed)
    alerts = [alerts[i] for i in order]
    X = abl.matrix(alerts, det.features)
    scores = det.score_batch(X)
    agree = float(((scores >= det.threshold) == np.array([bool(a["detected"]) for a in alerts])).mean())
    if agree < 1.0:
        raise RuntimeError(f"Re-scored flag decisions differ from the stream ({agree:.4%} agree); not writing.")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(det.features) + ["label", "family"])
        for x, a in zip(X, alerts):
            w.writerow([repr(float(v)) for v in x] + [a["_attack_label"], a["_family"]])
    for fam, p in plan.items():
        print(f"  {fam:12s} full-data flag rate {p['population_flag_rate']:.3f} -> demo {p['flagged']} flagged + "
              f"{p['unflagged']} unflagged ({p['demo_flag_rate']:.3f})")
    print(f"wrote {out} ({len(alerts)} rows; flag agreement {agree:.2%})")
    return out, plan


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=DEMO_FILE)
    build(p.parse_args(argv).out)


if __name__ == "__main__":
    main()
