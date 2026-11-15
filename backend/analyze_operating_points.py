"""Plan amendment 13: detector operating points per family (descriptive).

    python analyze_operating_points.py            # two full passes over the original snapshot, about 20-30 min

Thresholds are benign-score percentiles of train_benign_only.csv plus the deployed threshold; every row of the
validation and zero-day files is scored once and counted per (source, family) at each threshold. No threshold is
selected and the deployed threshold is not changed.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_replay_stream as builder  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "experiments" / "operating_points"
PERCENTILES = (90, 93, 95, 97, 99)
CHUNK = 500_000


def wilson(k, n, z=1.96):
    if not n:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [(c - h) / d, (c + h) / d]


def threshold_set(benign_scores, deployed, percentiles=PERCENTILES):
    """Named thresholds: train-benign percentiles plus the deployed one, sorted ascending."""
    named = {f"p{p}": float(np.percentile(benign_scores, p)) for p in percentiles}
    named["deployed"] = float(deployed)
    return dict(sorted(named.items(), key=lambda kv: kv[1]))


def count_at_or_above(scores, thresholds):
    """Rows with score >= each threshold (vector in the order of `thresholds`)."""
    s = np.sort(np.asarray(scores, dtype=np.float64))
    return np.array([len(s) - np.searchsorted(s, t, side="left") for t in thresholds], dtype=np.int64)


def summarise(counts, totals, names, values):
    """counts[(source, family)] = array per threshold; totals[(source, family)] = rows."""
    out = {"thresholds": dict(zip(names, values)), "per_group": {}, "per_threshold": {}}
    for key in sorted(totals):
        n = int(totals[key])
        out["per_group"]["/".join(key)] = {"rows": n, "flagged": {nm: int(c) for nm, c in zip(names, counts[key])}}
    for i, nm in enumerate(names):
        row = {"threshold": values[i], "families": {}}
        attack_rows = attack_flagged = 0
        for key in sorted(totals):
            source, family = key
            n, k = int(totals[key]), int(counts[key][i])
            rate = k / n if n else None
            row["families"]["/".join(key)] = {"rate": rate, "wilson_95": wilson(k, n), "flagged": k, "rows": n}
            if family == "Benign":
                if source == "validation":
                    row["validation_benign_fpr"] = rate
            else:
                attack_rows += n
                attack_flagged += k
        row["overall_attack_recall_row_weighted"] = attack_flagged / attack_rows if attack_rows else None
        out["per_threshold"][nm] = row
    return out


def score_file(detector, path, label_col=True, chunk=CHUNK, log=print):
    """Yield (family array, score array) per chunk for finite rows."""
    import pandas as pd
    features = list(detector.features)
    cols = features + (["label"] if label_col else [])
    done, started = 0, time.time()
    for frame in pd.read_csv(path, usecols=cols, chunksize=chunk,
                             dtype={**{f: np.float32 for f in features}, **({"label": str} if label_col else {})}):
        X = frame[features].to_numpy(dtype=np.float32)
        ok = np.isfinite(X).all(axis=1)
        scores = detector.score_batch(X[ok]) if ok.any() else np.empty(0)
        fams = (frame["label"].astype(str).map(builder.label_family).to_numpy()[ok] if label_col
                else np.full(int(ok.sum()), "Benign", dtype=object))
        done += len(frame)
        log(f"  {Path(path).name}: {done:,} rows ({done / max(time.time() - started, 1e-9):,.0f}/s)")
        yield fams, np.asarray(scores, dtype=np.float64), len(frame)


def markdown(res):
    names = list(res["thresholds"])
    groups = list(res["per_group"])
    L = ["# Detector operating points per family (amendment 13, descriptive)", "",
         f"Thresholds from {res['train_benign_rows']:,} train benign scores; evaluated on "
         f"{res['rows_scored']:,} rows ({res['non_finite_skipped']} non-finite skipped). No threshold is selected; "
         "the deployed threshold stays 0.0614.", "",
         "| threshold | value | validation benign FPR | overall attack recall (row-weighted) |", "|---|---|---|---|"]
    for nm in names:
        r = res["per_threshold"][nm]
        L.append(f"| {nm} | {r['threshold']:.4f} | {100 * r['validation_benign_fpr']:.2f}% | "
                 f"{100 * r['overall_attack_recall_row_weighted']:.2f}% |")
    L += ["", "Recall per family (flagged / rows); 95% Wilson interval for the deployed threshold.", "",
          "| source/family | rows | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    for g in groups:
        cells = []
        for nm in names:
            f = res["per_threshold"][nm]["families"][g]
            cell = f"{100 * f['rate']:.1f}%"
            if nm == "deployed":
                cell += f" [{100 * f['wilson_95'][0]:.1f}, {100 * f['wilson_95'][1]:.1f}]"
            cells.append(cell)
        L.append(f"| {g} | {res['per_group'][g]['rows']:,} | " + " | ".join(cells) + " |")
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--max-rows", type=int, default=None, help="testing only")
    a = p.parse_args(argv)
    sys.stdout.reconfigure(errors="replace")
    from services.model_service import Detector
    det = Detector(ROOT)
    validation, zero_day = builder.default_data_paths()
    train = validation.parent / "train_benign_only.csv"
    print("pass 1: train benign", train)
    benign = np.concatenate([s for _, s, _ in score_file(det, train, label_col=False)])
    th = threshold_set(benign, det.threshold)
    names, values = list(th), list(th.values())
    print("thresholds:", th)
    counts, totals = defaultdict(lambda: np.zeros(len(values), dtype=np.int64)), defaultdict(int)
    rows = skipped = 0
    for source, path in (("validation", validation), ("zero_day", zero_day)):
        print("pass 2:", source, path)
        for fams, scores, raw in score_file(det, path):
            for fam in np.unique(fams):
                m = fams == fam
                counts[(source, fam)] += count_at_or_above(scores[m], values)
                totals[(source, fam)] += int(m.sum())
            rows += raw
    total_rows = sum(totals.values())
    res = summarise(counts, totals, names, values)
    res.update({"train_benign_rows": int(len(benign)), "rows_scored": int(total_rows),
                "non_finite_skipped": int(rows - total_rows),
                "deployed_threshold": float(det.threshold),
                "deployed_threshold_train_benign_percentile": float((benign < det.threshold).mean() * 100)})
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (OUT / "summary.md").write_text(markdown(res), encoding="utf-8")
    print(markdown(res))


if __name__ == "__main__":
    main()
