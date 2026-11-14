"""Trade-off table and break-even analysis from saved replay decisions (plan amendment 4; post hoc, descriptive).

    python analyze_tradeoffs.py [--out experiments/tradeoff_analysis]

No policy is rerun and no reward table is changed. Reads the reward-v2 `evaluation_decisions.csv` of each seed,
recovers each alert's label from its (action, reward) pair under that seed's `reward_table.json`, then reports:
  1. per stream and policy, how actions split across attacks and benign alerts (no reward involved);
  2. with decisions held fixed, the value of one reward entry at which the bandit ties each baseline.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXP = HERE / "experiments"
VERSION = "designed-simulation-v2"
STREAMS = {"S10": "replay_study_share10_seed2", "S30": "replay_study_share30_seed3",
           "S58 (exploratory)": "replay_study_seed1_all_policies"}
BANDIT = "Contextual bandit (greedy held-out)"
ACTIONS = ("MONITOR_ONLY", "HUMAN_REVIEW", "CONFIRM_TO_ACT", "AUTO_REMEDIATE")
# break-even parameters: name -> list of (label, action) entries that move together, and the scan description
PARAMS = {
    "wrongful block (benign AUTO_REMEDIATE value)": [("benign", "AUTO_REMEDIATE")],
    "missed attack (attack MONITOR_ONLY value)": [("attack", "MONITOR_ONLY")],
    "analyst cost (shift added to both HUMAN_REVIEW values)": [("attack", "HUMAN_REVIEW"), ("benign", "HUMAN_REVIEW")],
}


def label_lookup(table):
    """(action, reward) -> label; refuses a table where a pair is ambiguous."""
    seen = {}
    for label, row in table.items():
        for action, value in row.items():
            key = (action, float(value))
            if key in seen and seen[key] != label:
                raise SystemExit(f"reward table is ambiguous for {key}: cannot recover labels")
            seen[key] = label
    return seen


def load_seed(seed_dir):
    """policy -> Counter[(label, action)] for one seed."""
    table = json.loads((seed_dir / "reward_table.json").read_text(encoding="utf-8"))
    table = table.get("table", table)
    table = {k: v for k, v in table.items() if k in ("attack", "benign")}
    lookup = label_lookup(table)
    counts = defaultdict(Counter)
    with (seed_dir / "evaluation_decisions.csv").open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = lookup[(row["selected_action"], float(row["reward"]))]
            counts[row["policy"]][(label, row["selected_action"])] += 1
    return table, counts


def rates(c):
    attacks = sum(v for (l, _), v in c.items() if l == "attack")
    benign = sum(v for (l, _), v in c.items() if l == "benign")
    share = lambda num, den: num / den if den else float("nan")
    return {
        "attacks missed (MONITOR_ONLY)": share(c[("attack", "MONITOR_ONLY")], attacks),
        "attacks to HUMAN_REVIEW": share(c[("attack", "HUMAN_REVIEW")], attacks),
        "attacks actioned (CONFIRM or AUTO)": share(c[("attack", "CONFIRM_TO_ACT")] + c[("attack", "AUTO_REMEDIATE")], attacks),
        "benign wrongly AUTO_REMEDIATED": share(c[("benign", "AUTO_REMEDIATE")], benign),
        "benign to CONFIRM_TO_ACT": share(c[("benign", "CONFIRM_TO_ACT")], benign),
        "analyst workload (REVIEW or CONFIRM, all alerts)": share(
            sum(v for (_, a), v in c.items() if a in ("HUMAN_REVIEW", "CONFIRM_TO_ACT")), attacks + benign),
    }


def mean_reward(c, table):
    n = sum(c.values())
    return sum(v * float(table[l][a]) for (l, a), v in c.items()) / n


def break_even(bandit_seeds, base_seeds, table, entries):
    """Mean over seeds of (bandit - baseline) reward is a + b*x when the listed entries move by x from v2.
    Returns (a, b, x_star) where x_star is the shift at which they tie (None if b == 0)."""
    a_vals, b_vals = [], []
    for cb, cs in zip(bandit_seeds, base_seeds):
        nb, ns = sum(cb.values()), sum(cs.values())
        a_vals.append(mean_reward(cb, table) - mean_reward(cs, table))
        b_vals.append(sum(cb[e] for e in entries) / nb - sum(cs[e] for e in entries) / ns)
    a, b = statistics.mean(a_vals), statistics.mean(b_vals)
    return a, b, (None if abs(b) < 1e-12 else -a / b)


def analyse(exp_dir=EXP, streams=STREAMS):
    out = {"note": "POST HOC, descriptive (plan amendment 4). Decisions are the saved reward-v2 replay decisions; "
                   "break-even holds them fixed, so a policy retrained under another table could choose differently.",
           "streams": {}}
    for name, folder in streams.items():
        seed_dirs = sorted((exp_dir / folder / VERSION).glob("seed*"))
        seed_dirs = [d for d in seed_dirs if (d / "evaluation_decisions.csv").exists()]
        if not seed_dirs:
            out["streams"][name] = {"missing": str(exp_dir / folder / VERSION)}; continue
        loaded = [load_seed(d) for d in seed_dirs]
        table = loaded[0][0]
        policies = sorted({p for _, c in loaded for p in c}, key=lambda p: (p != BANDIT, p))
        trade = {}
        for p in policies:
            per_seed = [rates(c[p]) for _, c in loaded]
            trade[p] = {k: {"mean": statistics.mean(s[k] for s in per_seed),
                            "std": statistics.stdev(s[k] for s in per_seed) if len(per_seed) > 1 else 0.0}
                        for k in per_seed[0]}
        bandit = [c[BANDIT] for _, c in loaded]
        be = {}
        for pname, entries in PARAMS.items():
            v2 = float(table[entries[0][0]][entries[0][1]])
            be[pname] = {}
            for p in policies:
                if p == BANDIT: continue
                a, b, x = break_even(bandit, [c[p] for _, c in loaded], table, entries)
                if x is None:
                    verdict = "same decisions on this entry: difference does not depend on it"
                    tie = None
                else:
                    tie = v2 + x if len(entries) == 1 else x
                    wins_above = b > 0
                    verdict = f"bandit better when value {'>' if wins_above else '<'} {tie:+.2f}" if len(entries) == 1 else \
                              f"bandit better when shift {'>' if wins_above else '<'} {x:+.2f}"
                be[pname][p] = {"difference_at_v2": a, "slope": b, "tie_at": tie, "v2_value": v2 if len(entries) == 1 else 0.0,
                                "verdict": verdict}
        out["streams"][name] = {"seeds": len(seed_dirs), "reward_table": table, "tradeoff": trade, "break_even": be}
    return out


def to_markdown(res):
    lines = ["# Trade-off and break-even analysis (post hoc, descriptive)", "", res["note"], ""]
    for name, s in res["streams"].items():
        lines += [f"## {name}", ""]
        if "missing" in s:
            lines += [f"Decision files not found under `{s['missing']}`; rerun that replay study.", ""]; continue
        keys = list(next(iter(s["tradeoff"].values())))
        lines += [f"Mean ± std over {s['seeds']} seeds (shares).", "", "| policy | " + " | ".join(keys) + " |",
                  "|---|" + "---|" * len(keys)]
        for p, r in s["tradeoff"].items():
            lines.append(f"| {p} | " + " | ".join(f"{r[k]['mean']:.1%} ± {r[k]['std']:.1%}" for k in keys) + " |")
        lines += ["", "Break-even (decisions fixed; one entry varied, others at v2):", ""]
        for pname, rows in s["break_even"].items():
            lines += [f"**{pname}**", "", "| baseline | bandit − baseline at v2 | verdict |", "|---|---|---|"]
            for p, r in rows.items():
                lines.append(f"| {p} | {r['difference_at_v2']:+.3f} | {r['verdict']} |")
            lines.append("")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=EXP / "tradeoff_analysis")
    args = p.parse_args(argv)
    res = analyse()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "tradeoff.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (args.out / "tradeoff.md").write_text(to_markdown(res), encoding="utf-8")
    print(to_markdown(res))
    print(f"\nWritten to {args.out}")


if __name__ == "__main__":
    main()
