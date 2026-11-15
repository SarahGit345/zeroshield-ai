"""Build the live-monitor demo traffic file from real dataset rows (no synthetic traffic).

    python build_live_demo.py                 # writes backend/data/live_demo_flows.csv (gitignored)

Rows: every row of the S58 replay stream (flagged and unflagged; benign and every family), with all 43 scaled
features read from the source CSVs (cached outside the repository by ablate_policy_xai.matrix), the dataset label
and family, in a fixed shuffled order. Re-scoring each row must reproduce the stream's stored score.
The demo is for showing the pipeline; it is not an evaluation set and the mix is not real-network proportions.
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ablate_policy_xai as abl  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services.live_service import DEMO_FILE  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SEED = 20261115


def build(out: Path = DEMO_FILE, stream: str = "S58 (exploratory)", seed: int = SEED):
    from services.model_service import Detector
    det = Detector(ROOT)
    alerts = replay.load_stream(abl.stream_path(stream))
    X = abl.matrix(alerts, det.features)
    scores = det.score_batch(X)
    stored = np.array([a["anomaly_score"] for a in alerts])
    flags = scores >= det.threshold
    agree = float((flags == np.array([bool(a["detected"]) for a in alerts])).mean())
    rel = float(np.max(np.abs(scores - stored) / np.maximum(stored, 1e-12)))
    if agree < 1.0:
        raise RuntimeError(f"Re-scored flag decisions differ from the stream ({agree:.4%} agree); not writing.")
    order = list(range(len(alerts)))
    random.Random(seed).shuffle(order)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(det.features) + ["label", "family"])
        for i in order:
            w.writerow([repr(float(v)) for v in X[i]] + [alerts[i]["_attack_label"], alerts[i]["_family"]])
    print(f"wrote {out} ({len(order)} rows; flag agreement {agree:.2%}; max relative score difference {rel:.2e})")
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=DEMO_FILE)
    build(p.parse_args(argv).out)


if __name__ == "__main__":
    main()
