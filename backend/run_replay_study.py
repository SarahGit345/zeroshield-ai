"""Multi-seed replay study: the comparison fixed in docs/stage10-evaluation-plan.md.

    python run_replay_study.py --stream experiments/replay_streams/replay_stream_seed1.jsonl --seeds 1 2 3 4 5 --folds 5 --jobs 10

For every reward version (designed v1 and v2, and the named v2 perturbations) and every seed it calls
run_response_experiment.run_replay, which trains a fresh bandit and fits every fold baseline on the
training folds only, and evaluates every routed alert once. Then:

  * Paired bootstrap (plan section 4): each alert's reward is averaged over the seeds for every policy;
    d_i = bandit - baseline; alerts are resampled with replacement within each family (the stream was
    sampled per family), 10,000 times, RNG seed 20261108. "Better"/"worse" only if the 95% interval
    excludes 0; otherwise "no difference shown". A Bonferroni (6 comparisons) interval is shown for
    information and does not change the verdict.
  * The bandit's mistakes: share of benign false positives it auto-remediates, and its mean reward on
    benign alerts against always-review (paired bootstrap on benign alerts).
  * Oracle references that use labels (never baselines): best single action chosen with labels, and the
    per-alert best action.

The seed changes the fold split, the bandit's exploration and the random baseline. The routed alerts are
the same for every seed, so the spread across seeds is split sensitivity, not new traffic.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_response_experiment as replay  # noqa: E402
from services.bandit_service import (  # noqa: E402
    ACTIONS, REWARD_TABLES, REWARD_VERSION, SENSITIVITY_REWARD_TABLES, reward_table,
)

ALL_VERSIONS = list(REWARD_TABLES) + list(SENSITIVITY_REWARD_TABLES)
BANDIT = replay.BANDIT_POLICY
BASELINES = [p for p in replay.POLICIES if p != BANDIT]
ALWAYS_REVIEW = "Always HUMAN_REVIEW"
BOOTSTRAP_RESAMPLES, BOOTSTRAP_SEED = 10_000, 20261108
TIE_TOLERANCE = 1e-9


def mean_std(values):
    values = list(values)
    return {"mean": statistics.fmean(values), "std": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values), "max": max(values), "n": len(values)}


# ---------------------------------------------------------------- bootstrap
def stratified_bootstrap_means(diffs: np.ndarray, groups: np.ndarray, resamples=BOOTSTRAP_RESAMPLES, seed=BOOTSTRAP_SEED, chunk=250):
    """diffs: (n_alerts, k) paired differences. Resample alerts with replacement within each group.
    Returns (resamples, k) bootstrap means of the column means. Same draws for every column."""
    rng = np.random.default_rng(seed)
    n, k = diffs.shape
    out = np.zeros((resamples, k))
    for g in np.unique(groups):
        rows = diffs[groups == g]
        done = 0
        while done < resamples:
            b = min(chunk, resamples - done)
            idx = rng.integers(0, len(rows), size=(b, len(rows)))
            out[done:done + b] += rows[idx].sum(axis=1)
            done += b
    return out / n


def interval(samples, level):
    lo, hi = np.percentile(samples, [50 * (1 - level), 100 - 50 * (1 - level)])
    return [float(lo), float(hi)]


def verdict_from_interval(ci):
    if ci[0] > 0: return "bandit better"
    if ci[1] < 0: return "bandit worse"
    return "no difference shown"


# ---------------------------------------------------------------- running
_WORKER_STREAM = None


def _init_worker(stream_path):
    global _WORKER_STREAM
    os.environ.pop("OPENAI_API_KEY", None)
    _WORKER_STREAM = replay.load_stream(Path(stream_path))


def _run_job(args):
    run_dir, seed, folds, source, version = args
    replay.run_replay(_WORKER_STREAM, Path(run_dir), seed=seed, folds=folds, stream_source=source,
                      reward_version=version, write_ledger=False)
    return version, seed


def run_all(stream, out_dir, seeds, folds, versions, source, jobs=1, stream_path=None):
    jobs_list = [(str(out_dir / v / f"seed{s}"), s, folds, source, v) for v in versions for s in seeds]
    if jobs > 1:
        if stream_path is None: raise ValueError("jobs > 1 needs stream_path")
        with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker, initargs=(str(stream_path),)) as pool:
            for version, seed in pool.map(_run_job, jobs_list):
                print(f"  done {version} seed {seed}", flush=True)
    else:
        for run_dir, s, f, src, v in jobs_list:
            replay.run_replay(stream, Path(run_dir), seed=s, folds=f, stream_source=src, reward_version=v, write_ledger=False)


def read_decisions(run_dir: Path):
    with (run_dir / "evaluation_decisions.csv").open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------- aggregation
def summarise_version(stream, out_dir, version, seeds):
    table = reward_table(version)
    routed, _ = replay.route(stream)
    order = [a["alert_id"] for a in routed]
    position = {aid: i for i, aid in enumerate(order)}
    attack = np.array([bool(a["_simulator_attack"]) for a in routed])
    family = np.array([a.get("_family", "Attack" if a["_simulator_attack"] else "Benign") for a in routed])
    n = len(order)

    reward_sum = {p: np.zeros(n) for p in replay.POLICIES}
    action_counts = {p: defaultdict(Counter) for p in replay.POLICIES}
    per_seed, rates = {p: [] for p in replay.POLICIES}, {p: defaultdict(list) for p in replay.POLICIES}
    for seed in seeds:
        run_dir = out_dir / version / f"seed{seed}"
        seen = {p: 0 for p in replay.POLICIES}
        for row in read_decisions(run_dir):
            i = position[row["alert_id"]]
            reward_sum[row["policy"]][i] += float(row["reward"])
            action_counts[row["policy"]][family[i]][row["selected_action"]] += 1
            seen[row["policy"]] += 1
        assert all(v == n for v in seen.values()), f"{run_dir}: not every routed alert evaluated once per policy"
        metrics = json.loads((run_dir / "policy_comparison_metrics.json").read_text(encoding="utf-8"))
        for m in metrics["metrics"]:
            per_seed[m["policy"]].append(m["mean_reward_per_alert"])
            for key in ("benign_remediation_rate", "attack_remediation_rate", "attack_monitor_only_rate",
                        "benign_human_review_rate", "approval_queue_size"):
                rates[m["policy"]][key].append(m[key])
    avg = {p: reward_sum[p] / len(seeds) for p in replay.POLICIES}

    diffs = np.column_stack([avg[BANDIT] - avg[b] for b in BASELINES])
    boot = stratified_bootstrap_means(diffs, family)
    level_bonf = 1 - 0.05 / len(BASELINES)
    comparisons = {}
    for k, base in enumerate(BASELINES):
        ci95, cib = interval(boot[:, k], 0.95), interval(boot[:, k], level_bonf)
        seed_diffs = [b - x for b, x in zip(per_seed[BANDIT], per_seed[base])]
        comparisons[base] = {"mean_difference": float(diffs[:, k].mean()), "ci95": ci95, "verdict": verdict_from_interval(ci95),
                             f"ci_bonferroni_{level_bonf:.4f}": cib, "verdict_bonferroni": verdict_from_interval(cib),
                             "per_seed_difference": seed_diffs,
                             "seeds_bandit_higher": sum(d > TIE_TOLERANCE for d in seed_diffs),
                             "seeds_tied": sum(abs(d) <= TIE_TOLERANCE for d in seed_diffs),
                             "seeds_bandit_lower": sum(d < -TIE_TOLERANCE for d in seed_diffs)}

    benign = ~attack
    benign_diff = (avg[BANDIT] - avg[ALWAYS_REVIEW])[benign][:, None]
    benign_boot = stratified_bootstrap_means(benign_diff, np.zeros(benign.sum(), dtype=int))[:, 0]
    bandit_benign_auto = action_counts[BANDIT]["Benign"]["AUTO_REMEDIATE"]
    bandit_benign_total = sum(action_counts[BANDIT]["Benign"].values())
    mistakes = {"false_positives_auto_remediated_share": bandit_benign_auto / max(bandit_benign_total, 1),
                "false_positives_auto_remediated_per_seed": rates[BANDIT]["benign_remediation_rate"],
                "false_positives_auto_remediated_mean_count_per_seed": bandit_benign_auto / len(seeds),
                "attacks_left_monitor_only_share": statistics.fmean(rates[BANDIT]["attack_monitor_only_rate"]),
                "benign_mean_reward_bandit": float(avg[BANDIT][benign].mean()),
                "benign_mean_reward_always_review": float(avg[ALWAYS_REVIEW][benign].mean()),
                "benign_difference_bandit_minus_review": float(benign_diff.mean()),
                "benign_difference_ci95": interval(benign_boot, 0.95),
                "benign_verdict": verdict_from_interval(interval(benign_boot, 0.95))}

    R = np.array([[table["attack" if y else "benign"][a] for a in ACTIONS] for y in attack], dtype=float)
    constant = dict(zip(ACTIONS, R.mean(axis=0)))
    best_const = max(ACTIONS, key=lambda a: (constant[a], -ACTIONS.index(a)))
    oracles = {"best single action chosen with labels": {"action": best_const, "mean_reward": float(constant[best_const])},
               "per-alert best action (labels)": {"mean_reward": float(R.max(axis=1).mean())},
               "constant action means (labels)": {a: float(v) for a, v in constant.items()}}

    per_family = {}
    for p in replay.POLICIES:
        per_family[p] = {}
        for fam in sorted(set(family.tolist())):
            mask = family == fam
            counts = action_counts[p][fam]; total = max(sum(counts.values()), 1)
            per_family[p][fam] = {"n": int(mask.sum()), "mean_reward": float(avg[p][mask].mean()),
                                  "action_share": {a: counts[a] / total for a in ACTIONS}}

    return {"reward_table": table,
            "policies": {p: {"mean_reward_per_alert": mean_std(per_seed[p]), "per_seed": per_seed[p],
                             "rates_mean_over_seeds": {k: statistics.fmean(v) for k, v in rates[p].items()}} for p in replay.POLICIES},
            "comparisons": comparisons, "bandit_mistakes": mistakes, "oracle_references": oracles, "per_family": per_family}


def run_study(stream, out_dir: Path, seeds, folds=5, versions=None, stream_source="stream", jobs=1, stream_path=None):
    versions = versions or ALL_VERSIONS
    routed, not_routed = replay.route(stream)
    fam = Counter(a.get("_family", "?") for a in routed)
    run_all(stream, out_dir, seeds, folds, versions, stream_source, jobs, stream_path)
    study = {"stream_source": stream_source, "seeds": list(seeds), "folds": folds, "primary_reward_version": REWARD_VERSION,
             "routed_alerts": len(routed), "routed_attacks": sum(a["_simulator_attack"] for a in routed),
             "routed_benign": sum(not a["_simulator_attack"] for a in routed),
             "routed_attack_share": sum(a["_simulator_attack"] for a in routed) / max(len(routed), 1),
             "routed_by_family": dict(sorted(fam.items())), "not_routed": not_routed,
             "bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": BOOTSTRAP_SEED, "stratified_by": "family",
                           "unit": "routed alert, reward averaged over seeds"},
             "versions": {v: summarise_version(stream, out_dir, v, seeds) for v in versions}}
    (out_dir / "study_summary.json").write_text(json.dumps(study, indent=2), encoding="utf-8")
    (out_dir / "study_summary.md").write_text(render_markdown(study), encoding="utf-8")
    return study


# ---------------------------------------------------------------- report
def fmt_ci(ci): return f"[{ci[0]:+.3f}, {ci[1]:+.3f}]"


def render_markdown(study) -> str:
    primary = study["primary_reward_version"]
    out = ["# Replay study\n",
           f"Stream `{study['stream_source']}`; seeds {study['seeds']}; {study['folds']} folds. "
           f"Routed alerts: {study['routed_alerts']} ({study['routed_attacks']} attacks, {study['routed_benign']} benign false positives; "
           f"attack share {study['routed_attack_share']:.3f}). By family: {study['routed_by_family']}.\n"]
    v = study["versions"].get(primary)
    if v:
        out += [f"## Primary comparison ({primary})\n",
                "| policy | mean reward per alert (mean ± std over seeds) |", "|---|---|"]
        for p, row in v["policies"].items():
            m = row["mean_reward_per_alert"]; out.append(f"| {p} | {m['mean']:.3f} ± {m['std']:.3f} |")
        out += ["", "| bandit minus | mean difference | 95% paired-bootstrap interval | verdict | Bonferroni verdict (info) | seeds higher / tied / lower |",
                "|---|---|---|---|---|---|"]
        for base, c in v["comparisons"].items():
            out.append(f"| {base} | {c['mean_difference']:+.3f} | {fmt_ci(c['ci95'])} | **{c['verdict']}** | {c['verdict_bonferroni']} | "
                       f"{c['seeds_bandit_higher']} / {c['seeds_tied']} / {c['seeds_bandit_lower']} |")
        mk = v["bandit_mistakes"]
        out += ["", "### The bandit's mistakes\n",
                f"- False positives auto-remediated: {mk['false_positives_auto_remediated_share']:.1%} "
                f"(about {mk['false_positives_auto_remediated_mean_count_per_seed']:.1f} per seed).",
                f"- Attacks left at MONITOR_ONLY: {mk['attacks_left_monitor_only_share']:.1%}.",
                f"- Mean reward on benign alerts: bandit {mk['benign_mean_reward_bandit']:.3f} vs always-review "
                f"{mk['benign_mean_reward_always_review']:.3f}; difference {mk['benign_difference_bandit_minus_review']:+.3f}, "
                f"95% interval {fmt_ci(mk['benign_difference_ci95'])}: {mk['benign_verdict']}.", ""]
        out += ["### Oracle references (labels used; not baselines)\n"]
        o = v["oracle_references"]
        out += [f"- Best single action chosen with labels: {o['best single action chosen with labels']['action']} "
                f"({o['best single action chosen with labels']['mean_reward']:.3f}).",
                f"- Per-alert best action: {o['per-alert best action (labels)']['mean_reward']:.3f}.", ""]
        out += [f"### Per family ({primary}), mean reward per alert averaged over seeds\n",
                "| family | n | " + " | ".join(study["versions"][primary]["policies"]) + " |",
                "|---|---|" + "---|" * len(v["policies"])]
        fams = next(iter(v["per_family"].values())).keys()
        for fam in fams:
            out.append(f"| {fam} | {v['per_family'][BANDIT][fam]['n']} | " +
                       " | ".join(f"{v['per_family'][p][fam]['mean_reward']:.2f}" for p in v["policies"]) + " |")
        out += ["", "Bandit action shares per family:\n", "| family | " + " | ".join(ACTIONS) + " |", "|---|" + "---|" * len(ACTIONS)]
        for fam in fams:
            out.append(f"| {fam} | " + " | ".join(f"{v['per_family'][BANDIT][fam]['action_share'][a]:.2f}" for a in ACTIONS) + " |")
    out += ["", "## Sensitivity: other reward tables (not evidence for the primary question)\n",
            "| reward table | " + " | ".join(BASELINES) + " |", "|---|" + "---|" * len(BASELINES)]
    for version, vv in study["versions"].items():
        if version == primary: continue
        out.append(f"| {version} | " + " | ".join(f"{vv['comparisons'][b]['mean_difference']:+.2f} {fmt_ci(vv['comparisons'][b]['ci95'])} {vv['comparisons'][b]['verdict']}"
                                                  for b in BASELINES) + " |")
    out += ["", "Cells: bandit minus baseline, mean difference, 95% paired-bootstrap interval, verdict.",
            "Rewards are designed simulation values, not measured costs. The same routed alerts are reused across seeds."]
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stream", type=Path, required=True)
    p.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--versions", nargs="+", choices=ALL_VERSIONS, help="default: all")
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    os.environ.pop("OPENAI_API_KEY", None)
    stream = replay.load_stream(args.stream)
    out = args.out or replay.ROOT / "backend" / "experiments" / f"replay_study_{args.stream.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out.mkdir(parents=True, exist_ok=False)
    study = run_study(stream, out, args.seeds, args.folds, args.versions, str(args.stream), args.jobs, args.stream)
    print(render_markdown(study))
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
