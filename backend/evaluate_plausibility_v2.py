"""Plausibility rules v2 (plan amendment 6): tune on S58, test once on S10. No LLM call.

    python evaluate_plausibility_v2.py --tune        # S58 only: compare v1 and the candidate v2 variants
    python evaluate_plausibility_v2.py --test        # S10 once, frozen v2 (run only after v2 is committed)

Unit: (flagged alert, retrieved candidate). Attack candidates are relevant if their root ID is in relevant_set;
every candidate on a benign alert is irrelevant. Primary metric: balanced accuracy of keep/drop
= mean(relevant kept, irrelevant removed); no rules = 0.5.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_llm_verification as measure  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services import technique_plausibility as tp  # noqa: E402

HERE = Path(__file__).resolve().parent
STREAMS = HERE / "experiments" / "replay_streams"
TUNE = STREAMS / "replay_stream_seed1.jsonl"          # S58
TEST = STREAMS / "replay_stream_share10_seed2.jsonl"  # S10
SEED, RESAMPLES = 20261114, 2000


def wilson(k, n, z=1.96):
    if not n: return (float("nan"), float("nan"))
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def load(path):
    """Flagged alerts as (family, [(relevant, top_features, technique_id), ...])."""
    out = []
    for a in replay.load_stream(Path(path)):
        if not a["detected"]: continue
        fam = a["_family"]
        rel = measure.relevant_set({"attack_label": a["_attack_label"], "family": fam}) if fam != "Benign" else set()
        out.append((fam, [(t["technique_id"].split(".")[0] in rel, a["xai_evidence"], t["technique_id"])
                          for t in a.get("retrieved_techniques", [])]))
    return out


def judge(rules):
    """keep(candidate) under a rule set; None means keep everything (no rules)."""
    if rules is None: return lambda tid, top: True
    return lambda tid, top: tp.plausible(tid, top, rules) is not False


def counts(alerts, keep):
    """Per alert: (rel_kept, rel_total, irr_removed, irr_total, attack_has_rel_after, benign_empty_after)."""
    rows = []
    for fam, cands in alerts:
        rk = rt = ir = it = 0; kept_rel = kept_any = False
        for rel, top, tid in cands:
            k = keep(tid, top)
            if rel: rt += 1; rk += k; kept_rel |= k
            else: it += 1; ir += not k
            kept_any |= k
        rows.append((fam, rk, rt, ir, it, kept_rel, kept_any))
    return rows


def summarise(rows):
    rk = sum(r[1] for r in rows); rt = sum(r[2] for r in rows); ir = sum(r[3] for r in rows); it = sum(r[4] for r in rows)
    att = [r for r in rows if r[0] != "Benign"]; ben = [r for r in rows if r[0] == "Benign"]
    rel_rate, irr_rate = (rk / rt if rt else float("nan")), (ir / it if it else float("nan"))
    return {"relevant_kept": [rk, rt, rel_rate, *wilson(rk, rt)], "irrelevant_removed": [ir, it, irr_rate, *wilson(ir, it)],
            "balanced_accuracy": (rel_rate + irr_rate) / 2 if rt and it else float("nan"),
            "attacks_with_relevant_after": [sum(r[5] for r in att), sum(1 for r in att if r[2]), len(att)],
            "benign_with_no_candidate_after": [sum(not r[6] for r in ben), len(ben)]}


def bal(rows):
    rk = sum(r[1] for r in rows); rt = sum(r[2] for r in rows); ir = sum(r[3] for r in rows); it = sum(r[4] for r in rows)
    return (rk / rt + ir / it) / 2 if rt and it else float("nan")


def paired_bootstrap(rows_a, rows_b):
    """95% interval of bal(b) - bal(a), resampling alerts (same indices for both)."""
    rng, n, diffs = random.Random(SEED), len(rows_a), []
    for _ in range(RESAMPLES):
        idx = [rng.randrange(n) for _ in range(n)]
        d = bal([rows_b[i] for i in idx]) - bal([rows_a[i] for i in idx])
        if d == d: diffs.append(d)
    diffs.sort()
    return [diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs)) - 1]]


def evaluate(alerts, rule_sets):
    rows = {name: counts(alerts, judge(r)) for name, r in rule_sets.items()}
    fams = sorted({f for f, _ in alerts})
    res = {"overall": {n: summarise(r) for n, r in rows.items()},
           "per_family": {f: {n: summarise([x for x in r if x[0] == f]) for n, r in rows.items()} for f in fams}}
    return res, rows


def fmt(s):
    rk, ir = s["relevant_kept"], s["irrelevant_removed"]
    f = lambda v: f"{v[0]}/{v[1]} ({v[2]:.1%})" if v[1] else "n/a"
    return f"relevant kept {f(rk)} | irrelevant removed {f(ir)} | balanced {s['balanced_accuracy']:.3f}"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--tune", action="store_true"); g.add_argument("--test", action="store_true")
    p.add_argument("--out", type=Path, default=HERE / "experiments" / "plausibility_v2")
    args = p.parse_args(argv)
    if args.tune:
        res, _ = evaluate(load(TUNE), {"no rules": None, "v1": tp.SIGNATURES, **tp.V2_CANDIDATES})
        for name, s in res["overall"].items(): print(f"{name:>14}: {fmt(s)}")
        for f, by in res["per_family"].items():
            print(f"\n{f}"); [print(f"  {n:>12}: {fmt(s)}") for n, s in by.items()]
        return
    alerts = load(TEST)
    res, rows = evaluate(alerts, {"no rules": None, "v1": tp.SIGNATURES, "v2": tp.SIGNATURES_V2})
    res["bootstrap_v2_minus_v1"] = paired_bootstrap(rows["v1"], rows["v2"])
    res["bootstrap_v2_minus_none"] = paired_bootstrap(rows["no rules"], rows["v2"])
    d = res["overall"]["v2"]["balanced_accuracy"] - res["overall"]["v1"]["balanced_accuracy"]
    lo, hi = res["bootstrap_v2_minus_v1"]
    res["verdict"] = "improvement over v1" if d > 0 and lo > 0 else "no improvement over v1"
    res["note"] = ("Plan amendment 6. Test set S10 evaluated once with v2 frozen (rules " + tp.RULES_VERSION_V2 + "). "
                   "Unit: flagged alert x retrieved candidate; benign candidates are all irrelevant.")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "test_s10.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    L = ["# Plausibility rules v2: test on S10 (run once)", "", res["note"], "",
         f"**Verdict: {res['verdict']}.** Balanced accuracy v2 minus v1 = {d:+.3f}, 95% paired-bootstrap interval "
         f"[{lo:+.3f}, {hi:+.3f}]; v2 minus no rules interval [{res['bootstrap_v2_minus_none'][0]:+.3f}, {res['bootstrap_v2_minus_none'][1]:+.3f}].", "",
         "| rules | relevant kept [95% CI] | irrelevant removed [95% CI] | balanced accuracy | attacks keeping a relevant candidate | benign left with no candidate |",
         "|---|---|---|---|---|---|"]
    def row(n, s):
        rk, ir, ar, be = s["relevant_kept"], s["irrelevant_removed"], s["attacks_with_relevant_after"], s["benign_with_no_candidate_after"]
        c = lambda v: f"{v[0]}/{v[1]} = {v[2]:.1%} [{v[3]:.1%}, {v[4]:.1%}]" if v[1] else "n/a"
        return f"| {n} | {c(rk)} | {c(ir)} | {s['balanced_accuracy']:.3f} | {ar[0]} of {ar[1]} with one before (of {ar[2]} attacks) | {be[0]} of {be[1]} |"
    L += [row(n, s) for n, s in res["overall"].items()] + ["", "## Per family", ""]
    for f, by in res["per_family"].items():
        L += [f"**{f}**", "", "| rules | relevant kept | irrelevant removed | balanced |", "|---|---|---|---|"]
        for n, s in by.items():
            rk, ir = s["relevant_kept"], s["irrelevant_removed"]
            c = lambda v: f"{v[0]}/{v[1]} ({v[2]:.1%})" if v[1] else "n/a"
            ba = s["balanced_accuracy"]
            L.append(f"| {n} | {c(rk)} | {c(ir)} | {'n/a' if ba != ba else f'{ba:.3f}'} |")
        L.append("")
    (args.out / "test_s10.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"{res['verdict']}; written to {args.out}")


if __name__ == "__main__":
    main()
