"""Plan amendment 9: policy-context ablation, exploration setting, XAI deletion test, occlusion vs SHAP.

    python ablate_policy_xai.py policy [--jobs 4]   # parts A and B (bandit retrained per condition)
    python ablate_policy_xai.py xai                 # part C (deletion test)
    python ablate_policy_xai.py shap                # part D (occlusion vs SHAP)

Descriptive ablations on S58, S10, S30 (never S10b). No LLM call; BanditService and the detector are unchanged.
A context group is removed by holding it constant, which the bandit's intercept absorbs.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_response_experiment as replay  # noqa: E402
from services.bandit_service import BanditService, simulate_outcome  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "experiments" / "ablation_amendment9"
STREAMS = {"S10": "replay_stream_share10_seed2.jsonl", "S30": "replay_stream_share30_seed3.jsonl",
           "S58 (exploratory)": "replay_stream_seed1.jsonl"}
PUBLISHED = {"S10": ("replay_study_share10_seed2", 0.591), "S30": ("replay_study_share30_seed3", -0.260),
             "S58 (exploratory)": ("replay_study_seed1_all_policies", 0.755)}
CONDITIONS = ["full", "no_score", "no_xai", "no_attack", "no_verification", "score_only"]
ALPHAS = [0.0, 0.25, 1.0]
SEEDS, FOLDS, BOOT, RNG_SEED = [1, 2, 3, 4, 5], 5, 2000, 20261115


def stream_path(name):
    return HERE / "experiments" / "replay_streams" / STREAMS[name]


# ------------------------------------------------------------------ A/B: policy
def mask(alert: dict, condition: str) -> dict:
    """Hold one context group constant (no label is touched; the label is not in a cleaned alert)."""
    a = dict(alert)
    if condition == "no_score":
        a["anomaly_score"] = a["threshold"]                 # normalized_score constant at 1.0
    if condition in ("no_xai", "score_only"):
        a["xai_evidence"] = []                              # xai_feature_fraction and leading magnitude constant 0
    if condition in ("no_attack", "score_only"):
        a["retrieved_techniques"] = []                      # mitre_context_present constant 0
    if condition in ("no_verification", "score_only"):
        a["verification_confidence"] = 1.0                  # already constant in every stream
    return a


def replay_condition(path: str, condition: str, alpha: float, seed: int, folds: int = FOLDS):
    """Same folds, seeds and training loop as run_response_experiment.run_replay, bandit only."""
    routed, _ = replay.route(replay.load_stream(Path(path)))
    fold_sets = replay.make_folds(routed, folds, seed)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for fi, test in enumerate(fold_sets):
            train = [a for i, f in enumerate(fold_sets) if i != fi for a in f]
            bandit = BanditService(Path(tmp) / f"f{fi}.sqlite3", seed=seed + fi, alpha=alpha)
            for alert in train:
                rec = bandit.record(mask(replay.clean(alert), condition))
                bandit.feedback(alert["alert_id"], bool(alert["_simulator_attack"]),
                                "APPROVED" if rec["selected_action"] == "CONFIRM_TO_ACT" else None)
            for alert in test:
                action = bandit.select(mask(replay.clean(alert), condition), explore=False)["selected_action"]
                attack = bool(alert["_simulator_attack"])     # read only after the choice
                rows.append((alert["alert_id"], attack, alert["_family"], action, simulate_outcome(action, attack)["reward"]))
    return rows


def _job(args):
    name, condition, alpha, seed = args
    return (name, condition, alpha, seed, replay_condition(str(stream_path(name)), condition, alpha, seed))


def bootstrap_mean(values, rng):
    n = len(values); arr = np.asarray(values)
    means = np.sort([arr[rng.integers(0, n, n)].mean() for _ in range(BOOT)])
    return [float(means[int(0.025 * BOOT)]), float(means[int(0.975 * BOOT) - 1])]


def summarise_policy(results):
    out = {}
    by = defaultdict(dict)
    for name, cond, alpha, seed, rows in results:
        by[(name, cond, alpha)][seed] = rows
    rng = np.random.default_rng(RNG_SEED)
    for name in STREAMS:
        s = {}
        full = by[(name, "full", 0.25)]
        full_alert = defaultdict(list)
        for rows in full.values():
            for aid, *_rest, r in rows: full_alert[aid].append(r)
        for (n2, cond, alpha), seeds in sorted(by.items(), key=lambda kv: (CONDITIONS.index(kv[0][1]), kv[0][2])):
            if n2 != name: continue
            label = cond if alpha == 0.25 else f"alpha={alpha}"
            per_seed = [statistics.mean(r[4] for r in rows) for rows in seeds.values()]
            allrows = [r for rows in seeds.values() for r in rows]
            att = [r for r in allrows if r[1]]; ben = [r for r in allrows if not r[1]]
            alert_mean = defaultdict(list)
            for aid, *_rest, r in allrows: alert_mean[aid].append(r)
            diffs = [statistics.mean(alert_mean[a]) - statistics.mean(full_alert[a]) for a in full_alert]
            s[label] = {"mean_reward": statistics.mean(per_seed), "std": statistics.stdev(per_seed),
                        "attacks_missed": sum(r[3] == "MONITOR_ONLY" for r in att) / len(att),
                        "benign_auto_remediated": sum(r[3] == "AUTO_REMEDIATE" for r in ben) / len(ben),
                        "analyst_workload": sum(r[3] in ("HUMAN_REVIEW", "CONFIRM_TO_ACT") for r in allrows) / len(allrows),
                        "minus_full": statistics.mean(diffs), "minus_full_ci95": bootstrap_mean(diffs, rng)}
        study, published = PUBLISHED[name]
        exact = json.loads((HERE / "experiments" / study / "study_summary.json").read_text(encoding="utf-8"))
        exact = exact["versions"]["designed-simulation-v2"]["policies"]["Contextual bandit (greedy held-out)"]["mean_reward_per_alert"]["mean"]
        s["_harness_check"] = {"full_mean": s["full"]["mean_reward"], "published_mean": exact,
                               "reproduced": abs(s["full"]["mean_reward"] - exact) < 1e-9}
        out[name] = s
    return out


def policy_markdown(res):
    L = ["# Policy-context ablation and exploration setting (amendment 9, parts A and B)", "",
         "Descriptive. Bandit retrained per condition on the same folds and seeds (1-5, 5 folds, reward v2). "
         "A removed context group is held constant. Difference to full: mean over alerts of (condition - full), "
         "each alert averaged over seeds, 95% paired bootstrap.", "",
         "**Known before running:** `verification_confidence` is 1.0 for every alert in every stream (template "
         "reasoning), so removing it cannot change anything.", ""]
    for name, s in res.items():
        h = s["_harness_check"]
        L += [f"## {name}", "", f"Harness check: full context reproduces the published bandit mean "
              f"({h['full_mean']:.6f} vs {h['published_mean']:.6f}): **{'yes' if h['reproduced'] else 'NO'}**.", "",
              "| condition | mean reward ± std | minus full [95% CI] | attacks missed | benign auto-remediated | analyst workload |",
              "|---|---|---|---|---|---|"]
        for label, v in s.items():
            if label.startswith("_"): continue
            ci = v["minus_full_ci95"]
            L.append(f"| {label} | {v['mean_reward']:.3f} ± {v['std']:.3f} | {v['minus_full']:+.3f} [{ci[0]:+.3f}, {ci[1]:+.3f}] | "
                     f"{v['attacks_missed']:.1%} | {v['benign_auto_remediated']:.1%} | {v['analyst_workload']:.1%} |")
        L.append("")
    return "\n".join(L) + "\n"


def run_policy(jobs):
    tasks = [(n, c, 0.25, s) for n in STREAMS for c in CONDITIONS for s in SEEDS] + \
            [(n, "full", a, s) for n in STREAMS for a in ALPHAS if a != 0.25 for s in SEEDS]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        results = []
        for i, r in enumerate(pool.map(_job, tasks), 1):
            results.append(r); print(f"{i}/{len(tasks)} {r[0]} {r[1]} alpha={r[2]} seed={r[3]}", flush=True)
    res = summarise_policy(results)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "policy.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (OUT / "policy.md").write_text(policy_markdown(res), encoding="utf-8")
    print("written", OUT / "policy.md")


# ------------------------------------------------------------------ C: deletion test
def flagged(name):
    return [a for a in replay.load_stream(stream_path(name)) if a["detected"]]


def matrix(alerts, features):
    return np.array([[float(a["feature_summary"][f]) for f in features] for a in alerts], dtype=np.float64)


def removal(detector, X, s0, idx_sets):
    """Share of the score removed when the features in each row's index set are reset to 0 together."""
    Xk = X.copy()
    for i, idx in enumerate(idx_sets): Xk[i, list(idx)] = 0.0
    return (s0 - detector.score_batch(Xk)) / s0, detector.score_batch(Xk)


def run_xai():
    from services.model_service import Detector
    det = Detector(ROOT); feats = det.features; col = {f: i for i, f in enumerate(feats)}
    rng = random.Random(RNG_SEED); nrng = np.random.default_rng(RNG_SEED)
    res = {"note": "Amendment 9 part C. Top-k = features named by the stored occlusion explanation, reset together.", "streams": {}}
    for name in STREAMS:
        alerts = flagged(name); X = matrix(alerts, feats); s0 = det.score_batch(X)
        stored = np.array([a["anomaly_score"] for a in alerts])
        ranked = [[col[x["feature"]] for x in sorted(a["xai_evidence"], key=lambda x: x["rank"])] for a in alerts]
        # full occlusion for the bottom-k baseline
        contrib = np.zeros_like(X)
        for j in range(X.shape[1]):
            Xj = X.copy(); Xj[:, j] = 0.0; contrib[:, j] = s0 - det.score_batch(Xj)
        bottom = [list(np.argsort(c)[:5]) for c in contrib]
        fams = [a["_family"] for a in alerts]
        s = {"alerts": len(alerts), "max_abs_score_mismatch_vs_stream": float(np.abs(s0 - stored).max()), "k": {}}
        for k in (1, 3, 5):
            top_r, top_s = removal(det, X, s0, [r[:k] for r in ranked])
            bot_r, _ = removal(det, X, s0, [b[:k] for b in bottom])
            rand = np.mean([removal(det, X, s0, [rng.sample(range(X.shape[1]), k) for _ in alerts])[0] for _ in range(20)], axis=0)
            diff = top_r - rand
            s["k"][str(k)] = {"top_removed": float(top_r.mean()), "top_ci95": bootstrap_mean(top_r, nrng),
                              "random_removed": float(rand.mean()), "random_ci95": bootstrap_mean(rand, nrng),
                              "bottom_removed": float(bot_r.mean()),
                              "top_minus_random": float(diff.mean()), "top_minus_random_ci95": bootstrap_mean(diff, nrng),
                              "falls_below_threshold_after_top": float((top_s < det.threshold).mean()),
                              "per_family_top_removed": {f: float(np.mean([top_r[i] for i in range(len(alerts)) if fams[i] == f]))
                                                         for f in sorted(set(fams))}}
        res["streams"][name] = s
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "xai_deletion.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    L = ["# XAI deletion test (amendment 9, part C)", "", res["note"],
         "Score removed = (original - after reset) / original, mean over flagged alerts; random = mean of 20 seeded draws per alert; "
         "bottom = the k features with the lowest occlusion contribution.", ""]
    for name, s in res["streams"].items():
        L += [f"## {name} ({s['alerts']} flagged alerts; recomputed vs stored score max difference {s['max_abs_score_mismatch_vs_stream']:.2e})", "",
              "| k | top-k removed [95% CI] | random k removed [95% CI] | bottom k removed | top minus random [95% CI] | alerts below threshold after top-k |",
              "|---|---|---|---|---|---|"]
        for k, v in s["k"].items():
            L.append(f"| {k} | {v['top_removed']:.1%} [{v['top_ci95'][0]:.1%}, {v['top_ci95'][1]:.1%}] | {v['random_removed']:.1%} "
                     f"[{v['random_ci95'][0]:.1%}, {v['random_ci95'][1]:.1%}] | {v['bottom_removed']:.1%} | {v['top_minus_random']:+.1%} "
                     f"[{v['top_minus_random_ci95'][0]:+.1%}, {v['top_minus_random_ci95'][1]:+.1%}] | {v['falls_below_threshold_after_top']:.1%} |")
        L += ["", "Top-3 removed per family: " + "; ".join(f"{f} {v:.1%}" for f, v in s["k"]["3"]["per_family_top_removed"].items()), ""]
    (OUT / "xai_deletion.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("written", OUT / "xai_deletion.md")


# ------------------------------------------------------------------ D: occlusion vs SHAP
def run_shap():
    import shap
    import torch
    from services.model_service import Detector
    det = Detector(ROOT); feats = det.features; col = {f: i for i, f in enumerate(feats)}

    class Score(torch.nn.Module):
        def __init__(self, d): super().__init__(); self.net, self.c = d.model, d.center
        def forward(self, x): return ((self.net(x) - self.c) ** 2).sum(dim=1, keepdim=True)

    rng = random.Random(RNG_SEED); torch.manual_seed(RNG_SEED)
    pool = flagged("S30"); fam = defaultdict(list)
    for a in pool: fam[a["_family"]].append(a)
    per = max(1, 300 // len(fam))
    sample = [a for f in sorted(fam) for a in rng.sample(fam[f], min(per, len(fam[f])))]
    benign = [a for a in replay.load_stream(stream_path("S58 (exploratory)")) if not a["detected"] and a["_family"] == "Benign"]
    background = rng.sample(benign, min(200, len(benign)))
    explainer = shap.GradientExplainer(Score(det), torch.tensor(matrix(background, feats), dtype=torch.float32))
    sv = explainer.shap_values(torch.tensor(matrix(sample, feats), dtype=torch.float32))
    sv = np.asarray(sv[0] if isinstance(sv, list) else sv).reshape(len(sample), -1)
    rows = []
    for a, v in zip(sample, sv):
        occ = [col[x["feature"]] for x in sorted(a["xai_evidence"], key=lambda x: x["rank"])][:5]
        shp = list(np.argsort(-v)[:5]); shp_abs = list(np.argsort(-np.abs(v))[:5])
        rows.append((a["_family"], occ[0] == shp[0], len(set(occ) & set(shp)) / 5, len(set(occ) & set(shp_abs)) / 5))
    agg = lambda rs: {"alerts": len(rs), "top1_agreement": float(np.mean([r[1] for r in rs])),
                      "top5_overlap": float(np.mean([r[2] for r in rs])), "top5_overlap_abs": float(np.mean([r[3] for r in rs]))}
    res = {"note": "Amendment 9 part D. shap.GradientExplainer on the detector score; background 200 unflagged benign alerts from S58. "
                   "SHAP top-5 by value (pushes the score up) and by absolute value.",
           "overall": agg(rows), "per_family": {f: agg([r for r in rows if r[0] == f]) for f in sorted(fam)}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "shap_vs_occlusion.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    L = ["# Occlusion vs SHAP (amendment 9, part D)", "", res["note"], "",
         "| subset | alerts | top-1 agreement | top-5 overlap (SHAP by value) | top-5 overlap (SHAP by abs value) |", "|---|---|---|---|---|"]
    for k, v in [("Overall", res["overall"])] + list(res["per_family"].items()):
        L.append(f"| {k} | {v['alerts']} | {v['top1_agreement']:.1%} | {v['top5_overlap']:.1%} | {v['top5_overlap_abs']:.1%} |")
    (OUT / "shap_vs_occlusion.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("written", OUT / "shap_vs_occlusion.md")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("part", choices=["policy", "xai", "shap"])
    p.add_argument("--jobs", type=int, default=4)
    a = p.parse_args(argv)
    {"policy": lambda: run_policy(a.jobs), "xai": run_xai, "shap": run_shap}[a.part]()


if __name__ == "__main__":
    main()
