"""Damage test on saved LLM reports (no LLM calls). Analysis done after the main run; descriptive.

    python damage_llm_reports.py [--run experiments/llm_verification/main_qwen3_8b]

For every saved report that the verifier VERIFIED, apply each kind of damage once (the damage sentence is
added to the report's own text, or the limitations are emptied), re-run verify_record, and count a catch when
the damaged report is no longer VERIFIED; also count whether the expected check is among the failed ones.
The damage kinds mirror DamagedReportsAreCaught (detected alerts only), adapted to each alert's evidence.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_llm_verification as measure  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services.verification_service import verify_record  # noqa: E402


def wilson(k, n, z=1.96):
    if n == 0: return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def add(field, text):
    def edit(report, analysis, mitre):
        value = report[field]
        if isinstance(value, list): value.append(text(analysis, mitre))
        else: report[field] = (value + " " + text(analysis, mitre)).strip()
    return edit


def setf(field, value):
    def edit(report, analysis, mitre): report[field] = value
    return edit


def unretrieved_id(mitre):
    ids = {t["technique_id"].split(".")[0] for t in mitre["techniques"]}
    return next(t for t in ("T1059", "T1110", "T1046", "T1003") if t not in ids)


def wrong_direction(analysis, mitre):
    top = analysis["top_features"][0]
    return f"Replacing {top['feature']} with zero {'increased' if top['contribution'] > 0 else 'decreased'} the anomaly score."


def outside_feature(analysis, mitre):
    top = {f["feature"] for f in analysis["top_features"]}
    name = next(n for n in analysis["all_feature_names"] if n not in top)
    return f"{name} was extremely high."


DAMAGE = [  # (kind, expected check, edit)
    ("status contradicts detector", "threshold_and_status", add("interpretation", lambda a, m: "The flow is not anomalous.")),
    ("below-threshold claim", "threshold_and_status", add("evidence", lambda a, m: "The score is below the threshold.")),
    ("technique not retrieved", "technique_ids_retrieved", add("attack_context", lambda a, m: f"Consistent with {unretrieved_id(m)}.")),
    ("fabricated number", "numeric_claims_grounded", add("evidence", lambda a, m: "The score was 0.987654 for this flow.")),
    ("fake rounding of threshold", "numeric_claims_grounded", add("evidence", lambda a, m: "The threshold was about 0.1.")),
    ("wrong feature direction", "feature_directions_consistent", add("evidence", wrong_direction)),
    ("feature outside XAI evidence", "feature_claims_supported", add("evidence", outside_feature)),
    ("certainty overclaim", "certainty_claims_hedged", add("interpretation", lambda a, m: "This confirms a botnet attack.")),
    ("completed-action claim", "no_completed_action_claims", add("recommended_action", lambda a, m: "The host was isolated and the flow blocked.")),
    ("invented IP", "no_invented_specifics", add("interpretation", lambda a, m: "Traffic came from 192.168.1.45.")),
    ("invented MAC", "no_invented_specifics", add("interpretation", lambda a, m: "Source device aa:bb:cc:dd:ee:ff sent the flow.")),
    ("invented date", "no_invented_specifics", add("interpretation", lambda a, m: "The flow was captured on 2026-03-14.")),
    ("invented URL", "no_invented_specifics", add("attack_context", lambda a, m: "See https://evil.example.com/report.")),
    ("limitations removed", "uncertainty_present", setf("limitations", "")),
]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", type=Path, default=measure.DEFAULT_OUT / "main_qwen3_8b")
    p.add_argument("--stream", type=Path, default=measure.DEFAULT_STREAM)
    args = p.parse_args(argv)
    alerts = {a["alert_id"]: a for a in replay.load_stream(args.stream)}
    names = measure.feature_names()
    records = [json.loads(f.read_text(encoding="utf-8")) for f in sorted((args.run / "raw").glob("*.json"))]
    base = [r for r in records if r.get("verdict") == "VERIFIED"]
    rows, missed = [], []
    for kind, check, edit in DAMAGE:
        caught = by_check = 0
        for r in base:
            alert = alerts[r["alert_id"]]
            analysis, mitre = measure.analysis_of(alert, names), measure.mitre_of(alert)
            reasoning = copy.deepcopy(r["reasoning"])
            edit(reasoning["report"], analysis, mitre)
            result = verify_record(analysis, mitre, reasoning)
            if result["verdict"] != "VERIFIED": caught += 1
            else: missed.append({"kind": kind, "alert_id": r["alert_id"], "family": r["family"]})
            if check in result["failed_checks"]: by_check += 1
        n = len(base)
        rows.append({"kind": kind, "expected_check": check, "n": n, "caught": caught, "catch_rate": caught / n if n else None,
                     "ci95": wilson(caught, n), "caught_by_expected_check": by_check})
    total_n, total_k = sum(r["n"] for r in rows), sum(r["caught"] for r in rows)
    out = {"run": str(args.run), "base_reports": len(base), "kinds": rows, "missed": missed,
           "overall": {"n": total_n, "caught": total_k, "ci95": wilson(total_k, total_n)},
           "note": "Post-run analysis on saved reports; no LLM calls. Catch = damaged report not VERIFIED."}
    (args.run / "damage_test.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    lines = [f"Damage test on {len(base)} VERIFIED main-run reports (one damage per report per kind).", "",
             "| damage | expected check | caught | rate [95% CI] | by expected check |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['kind']} | {r['expected_check']} | {r['caught']}/{r['n']} | {r['catch_rate']:.1%} "
                     f"[{r['ci95'][0]:.1%}, {r['ci95'][1]:.1%}] | {r['caught_by_expected_check']}/{r['n']} |")
    lines += ["", f"Overall: {total_k}/{total_n}. Missed: {len(missed)}."] + [f"- {m['kind']}: {m['alert_id']} ({m['family']})" for m in missed[:50]]
    (args.run / "damage_test.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
