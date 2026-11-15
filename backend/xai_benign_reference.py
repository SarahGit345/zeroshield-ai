"""Plan amendment 14: occlusion with a benign-median reference (descriptive).

    python xai_benign_reference.py          # deletion test on S10/S30/S58 + SHAP comparison on S30, about 15-30 min

Reference = per-feature median of train_benign_only.csv. The live explanation (reference 0) is not changed.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ablate_policy_xai as abl  # noqa: E402
import build_replay_stream as builder  # noqa: E402
import run_response_experiment as replay  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "experiments" / "xai_benign_reference"
KS = (1, 3, 5)


def benign_medians(features, path=None, max_rows=None):
    import pandas as pd
    path = path or builder.default_data_paths()[0].parent / "train_benign_only.csv"
    frame = pd.read_csv(path, usecols=list(features), nrows=max_rows, dtype=np.float32)
    X = frame[list(features)].to_numpy(dtype=np.float32)
    X = X[np.isfinite(X).all(axis=1)]
    return np.median(X, axis=0).astype(np.float64), int(len(X))


def contributions(score_batch, X, ref):
    """Score drop when each feature is set to its reference value (one column at a time)."""
    s0 = score_batch(X)
    out = np.zeros_like(X, dtype=np.float64)
    for j in range(X.shape[1]):
        Xj = X.copy()
        Xj[:, j] = ref[j]
        out[:, j] = s0 - score_batch(Xj)
    return s0, out


def removal(score_batch, X, s0, idx_sets, ref):
    """Share of the score removed when each row's index set is set to the reference together."""
    Xk = X.copy()
    for i, idx in enumerate(idx_sets):
        idx = list(idx)
        Xk[i, idx] = ref[idx]
    after = score_batch(Xk)
    return (s0 - after) / s0, after


def deletion(score_batch, threshold, X, ref, fams, seed=abl.RNG_SEED, draws=20):
    rng, nrng = random.Random(seed), np.random.default_rng(seed)
    s0, contrib = contributions(score_batch, X, ref)
    ranked = np.argsort(-contrib, axis=1)
    bottom = np.argsort(contrib, axis=1)
    res = {"alerts": int(len(X)), "k": {}}
    for k in KS:
        top_r, top_s = removal(score_batch, X, s0, [r[:k] for r in ranked], ref)
        bot_r, _ = removal(score_batch, X, s0, [b[:k] for b in bottom], ref)
        rand = np.mean([removal(score_batch, X, s0, [rng.sample(range(X.shape[1]), k) for _ in range(len(X))], ref)[0]
                        for _ in range(draws)], axis=0)
        diff = top_r - rand
        res["k"][str(k)] = {
            "top_removed": float(top_r.mean()), "top_ci95": abl.bootstrap_mean(top_r, nrng),
            "random_removed": float(rand.mean()), "random_ci95": abl.bootstrap_mean(rand, nrng),
            "bottom_removed": float(bot_r.mean()),
            "top_minus_random": float(diff.mean()), "top_minus_random_ci95": abl.bootstrap_mean(diff, nrng),
            "falls_below_threshold_after_top": float((top_s < threshold).mean()),
            "per_family_top_removed": {f: float(top_r[[i for i, x in enumerate(fams) if x == f]].mean())
                                       for f in sorted(set(fams))}}
    return res, ranked


def faithful_beyond_top(streams):
    """Pre-stated reading (amendment 14): positive top-3 and top-5 removal and top-random CI above 0 at every k."""
    for s in streams.values():
        for k in KS:
            v = s["k"][str(k)]
            if v["top_minus_random_ci95"][0] <= 0:
                return False
        if s["k"]["3"]["top_removed"] <= 0 or s["k"]["5"]["top_removed"] <= 0:
            return False
    return True


def run_shap(det, ref, feats):
    """Same sample and background as amendment 9 part D; compares SHAP with both occlusion rankings."""
    import shap
    import torch

    class Score(torch.nn.Module):
        def __init__(self, d):
            super().__init__()
            self.net, self.c = d.model, d.center

        def forward(self, x):
            return ((self.net(x) - self.c) ** 2).sum(dim=1, keepdim=True)

    col = {f: i for i, f in enumerate(feats)}
    rng = random.Random(abl.RNG_SEED)
    torch.manual_seed(abl.RNG_SEED)
    pool = abl.flagged("S30")
    fam = defaultdict(list)
    for a in pool:
        fam[a["_family"]].append(a)
    per = max(1, 300 // len(fam))
    sample = [a for f in sorted(fam) for a in rng.sample(fam[f], min(per, len(fam[f])))]
    benign = [a for a in replay.load_stream(abl.stream_path("S58 (exploratory)"))
              if not a["detected"] and a["_family"] == "Benign"]
    background = rng.sample(benign, min(200, len(benign)))
    explainer = shap.GradientExplainer(Score(det), torch.tensor(abl.matrix(background, feats), dtype=torch.float32))
    Xs = abl.matrix(sample, feats)
    sv = explainer.shap_values(torch.tensor(Xs, dtype=torch.float32))
    sv = np.asarray(sv[0] if isinstance(sv, list) else sv).reshape(len(sample), -1)
    _, contrib = contributions(det.score_batch, Xs, ref)
    rows = []
    for a, v, c in zip(sample, sv, contrib):
        zero_ref = [col[x["feature"]] for x in sorted(a["xai_evidence"], key=lambda x: x["rank"])][:5]
        med_ref = list(np.argsort(-c)[:5])
        shp = list(np.argsort(-v)[:5])
        rows.append((a["_family"], zero_ref[0] == shp[0], len(set(zero_ref) & set(shp)) / 5,
                     med_ref[0] == shp[0], len(set(med_ref) & set(shp)) / 5))

    def agg(rs):
        return {"alerts": len(rs), "zero_ref_top1": float(np.mean([r[1] for r in rs])),
                "zero_ref_top5": float(np.mean([r[2] for r in rs])),
                "median_ref_top1": float(np.mean([r[3] for r in rs])),
                "median_ref_top5": float(np.mean([r[4] for r in rs]))}
    return {"overall": agg(rows), "per_family": {f: agg([r for r in rows if r[0] == f]) for f in sorted(fam)}}


def markdown(res):
    L = ["# Benign-reference occlusion (amendment 14, descriptive)", "",
         f"Reference: per-feature median of {res['benign_rows']:,} train benign rows. Reset value = that median.", "",
         f"**Pre-stated reading — faithful beyond the top feature: {'YES' if res['faithful_beyond_top'] else 'NO'}.**", ""]
    for name, s in res["streams"].items():
        L += [f"## {name} ({s['alerts']} flagged alerts)", "",
              "| k | top-k removed [95% CI] | random k removed | bottom k removed | top minus random [95% CI] | below threshold after top-k |",
              "|---|---|---|---|---|---|"]
        for k, v in s["k"].items():
            L.append(f"| {k} | {v['top_removed']:.1%} [{v['top_ci95'][0]:.1%}, {v['top_ci95'][1]:.1%}] | {v['random_removed']:.1%} | "
                     f"{v['bottom_removed']:.1%} | {v['top_minus_random']:+.1%} [{v['top_minus_random_ci95'][0]:+.1%}, "
                     f"{v['top_minus_random_ci95'][1]:+.1%}] | {v['falls_below_threshold_after_top']:.1%} |")
        L.append("")
    if "shap" in res:
        L += ["## Agreement with SHAP (same 296 S30 alerts as amendment 9)", "",
              "| subset | alerts | top-1 zero ref | top-1 median ref | top-5 zero ref | top-5 median ref |", "|---|---|---|---|---|---|"]
        for k, v in [("Overall", res["shap"]["overall"])] + list(res["shap"]["per_family"].items()):
            L.append(f"| {k} | {v['alerts']} | {v['zero_ref_top1']:.1%} | {v['median_ref_top1']:.1%} | "
                     f"{v['zero_ref_top5']:.1%} | {v['median_ref_top5']:.1%} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--no-shap", action="store_true")
    a = p.parse_args(argv)
    sys.stdout.reconfigure(errors="replace")
    from services.model_service import Detector
    det = Detector(ROOT)
    feats = det.features
    ref, n = benign_medians(feats)
    print(f"benign medians from {n:,} rows")
    res = {"benign_rows": n, "reference": dict(zip(feats, ref.tolist())), "streams": {}}
    for name in abl.STREAMS:
        alerts = abl.flagged(name)
        X = abl.matrix(alerts, feats)
        res["streams"][name], _ = deletion(det.score_batch, det.threshold, X, ref, [x["_family"] for x in alerts])
        print(name, "done")
    res["faithful_beyond_top"] = faithful_beyond_top(res["streams"])
    if not a.no_shap:
        res["shap"] = run_shap(det, ref, feats)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (OUT / "summary.md").write_text(markdown(res), encoding="utf-8")
    print(markdown(res))


if __name__ == "__main__":
    main()
