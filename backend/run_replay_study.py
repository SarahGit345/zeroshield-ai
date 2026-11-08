"""Multi-seed replay study with per-family results and a reward-sensitivity check.

    python run_replay_study.py --stream experiments/replay_streams/replay_stream_seed1.jsonl --seeds 1 2 3 4 5 --folds 5

For every reward version (designed v1, designed v2, and the named v2 perturbations in
SENSITIVITY_REWARD_TABLES) and every seed it calls run_response_experiment.run_replay, which
trains a fresh bandit per fold UNDER THAT REWARD TABLE and evaluates every routed alert once.
It then joins each held-out decision to the alert's family (read from the stream's `_family`
key, after the decision) and aggregates across seeds.

What the seed changes: the fold assignment and the bandit's tie-breaking/exploration; the
random baseline's draws. The set of routed alerts is the same for every seed, so the spread
across seeds measures sensitivity to the split, not sampling of new traffic.

Reference rows computed in hindsight from labels (not policies, never deployable):
  * Oracle: AUTO_REMEDIATE every attack, MONITOR_ONLY every benign flow.
  * Always <action>: the same action for every routed alert.
No parameter is tuned here; LinUCB alpha stays at the code default (0.25).
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_response_experiment as replay  # noqa: E402
from services.bandit_service import (  # noqa: E402
    ACTIONS, REWARD_TABLES, REWARD_VERSION, SENSITIVITY_REWARD_TABLES, reward_table,
)

ALL_VERSIONS = list(REWARD_TABLES) + list(SENSITIVITY_REWARD_TABLES)
BANDIT, FIXED = replay.POLICIES[0], replay.POLICIES[1]
TIE_TOLERANCE = 1e-9


def mean_std(values):
    values = list(values)
    return {"mean": statistics.fmean(values), "std": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values), "max": max(values), "n": len(values)}


def evaluation_traces(run_dir: Path):
    for line in (run_dir / "action_ledger.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("phase") == "evaluation": yield row


def hindsight_references(routed, version):
    table = reward_table(version)
    rows = {"Oracle (hindsight, labels)": [table["attack"]["AUTO_REMEDIATE"] if a["_simulator_attack"] else table["benign"]["MONITOR_ONLY"] for a in routed]}
    for action in ACTIONS:
        rows[f"Always {action} (hindsight reference)"] = [table["attack" if a["_simulator_attack"] else "benign"][action] for a in routed]
    return {name: statistics.fmean(v) for name, v in rows.items()}


def run_study(stream, out_dir: Path, seeds, folds=5, versions=None, stream_source="stream"):
    versions = versions or ALL_VERSIONS
    family_of = {a["alert_id"]: a.get("_family", "Attack" if a["_simulator_attack"] else "Benign") for a in stream}
    routed, not_routed = replay.route(stream)
    routed_families = Counter(family_of[a["alert_id"]] for a in routed)
    study = {"stream_source": stream_source, "seeds": list(seeds), "folds": folds, "default_reward_version": REWARD_VERSION,
             "routed_alerts": len(routed), "routed_by_family": dict(sorted(routed_families.items())),
             "routed_attacks": sum(a["_simulator_attack"] for a in routed), "routed_benign": sum(not a["_simulator_attack"] for a in routed),
             "not_routed": not_routed, "versions": {}}
    for version in versions:
        per_seed = {p: [] for p in replay.POLICIES}
        fold_std = {p: [] for p in replay.POLICIES}
        rates = {p: defaultdict(list) for p in replay.POLICIES}
        fam_rewards = {p: defaultdict(list) for p in replay.POLICIES}       # (policy, family) -> per-seed mean
        fam_actions = {p: defaultdict(Counter) for p in replay.POLICIES}
        for seed in seeds:
            run_dir = out_dir / version / f"seed{seed}"
            result = replay.run_replay(stream, run_dir, seed=seed, folds=folds, stream_source=stream_source, reward_version=version)
            for m in result["metrics"]:
                per_seed[m["policy"]].append(m["mean_reward_per_alert"])
                fold_std[m["policy"]].append(m["fold_std_of_means"] or 0.0)
                for key in ("benign_remediation_rate", "attack_remediation_rate", "attack_human_review_rate",
                            "attack_monitor_only_rate", "benign_human_review_rate"):
                    rates[m["policy"]][key].append(m[key])
                for a in ACTIONS: rates[m["policy"]][f"share_{a}"].append(m["action_selection_rate"][a])
            seed_fam = defaultdict(list)
            for row in evaluation_traces(run_dir):
                family = family_of[row["alert"]["alert_id"]]
                seed_fam[(row["policy"], family)].append(row["reward"])
                fam_actions[row["policy"]][family][row["selected_action"]] += 1
            for (policy, family), rewards in seed_fam.items():
                fam_rewards[policy][family].append(statistics.fmean(rewards))
        diffs = [b - f for b, f in zip(per_seed[BANDIT], per_seed[FIXED])]
        wins = sum(d > TIE_TOLERANCE for d in diffs); losses = sum(d < -TIE_TOLERANCE for d in diffs)
        study["versions"][version] = {
            "reward_table": reward_table(version),
            "policies": {p: {"mean_reward_per_alert": mean_std(per_seed[p]), "per_seed": per_seed[p],
                             "mean_within_seed_fold_std": statistics.fmean(fold_std[p]),
                             "rates_mean_over_seeds": {k: statistics.fmean(v) for k, v in rates[p].items()}}
                         for p in replay.POLICIES},
            "hindsight_references": hindsight_references(routed, version),
            "bandit_minus_fixed": {"per_seed": diffs, **mean_std(diffs), "seeds_bandit_higher": wins,
                                   "seeds_tied": len(diffs) - wins - losses, "seeds_bandit_lower": losses},
            "per_family": {p: {fam: {"mean_reward": mean_std(fam_rewards[p][fam]),
                                     "action_share": {a: fam_actions[p][fam][a] / max(sum(fam_actions[p][fam].values()), 1) for a in ACTIONS}}
                               for fam in sorted(fam_rewards[p])} for p in replay.POLICIES},
        }
    (out_dir / "study_summary.json").write_text(json.dumps(study, indent=2), encoding="utf-8")
    (out_dir / "study_summary.md").write_text(render_markdown(study), encoding="utf-8")
    return study


def verdict(cmp):
    if cmp["seeds_bandit_higher"] == cmp["n"]: return "bandit higher on every seed"
    if cmp["seeds_bandit_lower"] == cmp["n"]: return "bandit lower on every seed"
    if cmp["seeds_tied"] == cmp["n"]: return "tied on every seed"
    return f"mixed ({cmp['seeds_bandit_higher']} higher / {cmp['seeds_tied']} tied / {cmp['seeds_bandit_lower']} lower)"


def render_markdown(study) -> str:
    out = [f"# Replay study\n", f"Stream: `{study['stream_source']}`. Seeds {study['seeds']}, {study['folds']} folds.",
           f"Routed (detector-flagged) alerts: {study['routed_alerts']} = {study['routed_attacks']} attacks + {study['routed_benign']} benign false positives. "
           f"By family: {study['routed_by_family']}. Not routed: {study['not_routed']['unflagged_attack_flows']} attack, "
           f"{study['not_routed']['unflagged_benign_flows']} benign flows (never alerts, not scored).\n"]
    out.append("## Bandit vs fixed rule, per reward version\n")
    out.append("| reward version | bandit mean ± std | fixed rule mean ± std | always HUMAN_REVIEW | random | bandit − fixed (mean ± std) | seeds |")
    out.append("|---|---|---|---|---|---|---|")
    for version, v in study["versions"].items():
        p = v["policies"]; c = v["bandit_minus_fixed"]
        fmt = lambda name: f"{p[name]['mean_reward_per_alert']['mean']:.3f} ± {p[name]['mean_reward_per_alert']['std']:.3f}"
        out.append(f"| {version} | {fmt(BANDIT)} | {fmt(FIXED)} | {fmt(replay.POLICIES[2])} | {fmt(replay.POLICIES[3])} | "
                   f"{c['mean']:+.3f} ± {c['std']:.3f} | {verdict(c)} |")
    out.append("\nStd is the sample standard deviation across seeds (same alerts, different fold splits).\n")
    out.append("## Hindsight references (labels used; not policies)\n")
    out.append("| reward version | " + " | ".join(next(iter(study["versions"].values()))["hindsight_references"]) + " |")
    out.append("|---|" + "---|" * len(next(iter(study["versions"].values()))["hindsight_references"]))
    for version, v in study["versions"].items():
        out.append(f"| {version} | " + " | ".join(f"{x:.3f}" for x in v["hindsight_references"].values()) + " |")
    for version, v in study["versions"].items():
        if version != study["default_reward_version"]: continue
        out.append(f"\n## Per family ({version})\n")
        out.append("Mean reward per alert (mean ± std over seeds) and the share of each action, routed alerts only.\n")
        for policy, fams in v["per_family"].items():
            out.append(f"### {policy}\n")
            out.append("| family | mean reward | " + " | ".join(ACTIONS) + " |")
            out.append("|---|---|" + "---|" * len(ACTIONS))
            for fam, row in fams.items():
                out.append(f"| {fam} | {row['mean_reward']['mean']:.3f} ± {row['mean_reward']['std']:.3f} | "
                           + " | ".join(f"{row['action_share'][a]:.2f}" for a in ACTIONS) + " |")
            out.append("")
    out.append("Rewards are designed simulation values, not measured costs. The stream is quota-sampled (false positives over-sampled), "
               "so mean rewards depend on that mix and are not deployment estimates.")
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stream", type=Path, required=True)
    p.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--versions", nargs="+", choices=ALL_VERSIONS, help="default: all")
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)
    import os
    os.environ.pop("OPENAI_API_KEY", None)
    stream = replay.load_stream(args.stream)
    out = args.out or replay.ROOT / "backend" / "experiments" / f"replay_study_{args.stream.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out.mkdir(parents=True, exist_ok=False)
    study = run_study(stream, out, args.seeds, args.folds, args.versions, str(args.stream))
    print(render_markdown(study))
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
