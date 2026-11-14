"""Technique plausibility rules: retrieval abstention and verifier check (plan amendment 5; post hoc). Run once.

    python evaluate_plausibility.py [--run experiments/llm_verification/main_qwen3_8b] [--stream S30.jsonl]

No LLM call. (a) 200-sample retrieval evidence, with and without abstention. (b) The 100 saved main-run reports:
retrieval candidates and verifier verdicts with and without the plausibility check. (c) The damage test with the
check on, on the reports still VERIFIED with it on.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import damage_llm_reports as damage  # noqa: E402
import evaluate_retrieval as er  # noqa: E402
import measure_llm_verification as measure  # noqa: E402
import posthoc_llm_analysis as posthoc  # noqa: E402
import run_response_experiment as replay  # noqa: E402
from services.mitre_service import MitreService  # noqa: E402
from services.technique_plausibility import RULES_VERSION, plausible  # noqa: E402
from services.verification_service import verify_record  # noqa: E402

FBW = ("irrelevant", "benign_cites_technique")


def retrieval_part(service):
    rows = []
    for s in er.load_samples():
        for mode in (False, True):
            ids = [t["technique_id"] for t in service.retrieve_behavior(s["analysis"], abstain_implausible=mode).get("techniques", [])]
            rows.append({"label": s["label"], "half": s["half"], "detected": s["detected"], "abstain": mode,
                         "answered": bool(ids), "hit": any(i.split(".")[0] in er.EXPECTED[s["label"]] for i in ids)})
    out = {}
    for half in ("tuning", "test"):
        for mode in (False, True):
            sub = [r for r in rows if r["half"] == half and r["detected"] and r["abstain"] == mode]
            ans = [r for r in sub if r["answered"]]
            out[f"{half} half, flagged, abstention {'on' if mode else 'off'}"] = {
                "samples": len(sub), "answered": len(ans), "relevant": sum(r["hit"] for r in sub),
                "wrong_answers": len(ans) - sum(r["hit"] for r in ans),
                "precision_when_answering": round(sum(r["hit"] for r in ans) / len(ans), 3) if ans else None}
    fam = defaultdict(dict)
    for mode in (False, True):
        for r in rows:
            if r["half"] == "test" and r["detected"] and r["abstain"] == mode:
                c = fam[r["label"]].setdefault("on" if mode else "off", Counter())
                c["flagged"] += 1; c["answered"] += r["answered"]; c["relevant"] += r["hit"]
    return out, {k: {m: dict(c) for m, c in v.items()} for k, v in sorted(fam.items())}


def llm_part(run, stream):
    alerts = {a["alert_id"]: a for a in replay.load_stream(stream)}
    names = measure.feature_names()
    records = [json.loads(f.read_text(encoding="utf-8")) for f in sorted((run / "raw").glob("*.json"))]
    records = [r for r in records if r.get("status") == "ok"]
    rows, mismatch = [], []
    for r in records:
        alert = alerts[r["alert_id"]]
        analysis, mitre = measure.analysis_of(alert, names), measure.mitre_of(alert)
        top, cands = analysis["top_features"], mitre["techniques"]
        kept = [t for t in cands if plausible(t["technique_id"], top) is not False]
        rel = measure.relevant_set(r) if r["is_attack"] else set()
        is_rel = lambda ts: any(t["technique_id"].split(".")[0] in rel for t in ts)
        v1 = verify_record(analysis, mitre, r["reasoning"])
        v2 = verify_record(analysis, mitre, r["reasoning"], plausibility=True)
        if v1["verdict"] != r["verdict"]: mismatch.append(r["alert_id"])
        cls, _ = posthoc.classify(r)
        rows.append({"family": r["family"], "is_attack": r["is_attack"], "cands": len(cands), "kept": len(kept),
                     "not_judged": sum(plausible(t["technique_id"], top) is None for t in cands),
                     "rel_before": is_rel(cands), "rel_after": is_rel(kept), "class": cls,
                     "v1": v1["verdict"], "v2": v2["verdict"]})
    fam = defaultdict(Counter)
    for x in rows:
        c = fam[x["family"]]
        c["alerts"] += 1; c["with_candidates_before"] += x["cands"] > 0; c["with_candidates_after"] += x["kept"] > 0
        c["relevant_before"] += x["rel_before"]; c["relevant_after"] += x["rel_after"]
        c["verified_v1"] += x["v1"] == "VERIFIED"; c["verified_v2"] += x["v2"] == "VERIFIED"
        c["fbw_v1"] += x["v1"] == "VERIFIED" and x["class"] in FBW
        c["fbw_v2"] += x["v2"] == "VERIFIED" and x["class"] in FBW
        c["relevant_citing_downgraded"] += x["class"] == "relevant" and x["v1"] == "VERIFIED" and x["v2"] != "VERIFIED"
    tot = Counter()
    for c in fam.values(): tot.update(c)
    cand = {"candidates": sum(x["cands"] for x in rows), "removed": sum(x["cands"] - x["kept"] for x in rows),
            "not_judged": sum(x["not_judged"] for x in rows)}
    return {"by_family": {k: dict(v) for k, v in sorted(fam.items())}, "total": dict(tot), "candidates": cand,
            "v1_recomputed_mismatches": mismatch}, records, alerts, names


def damage_part(records, alerts, names):
    base = []
    for r in records:
        a = alerts[r["alert_id"]]
        if verify_record(measure.analysis_of(a, names), measure.mitre_of(a), r["reasoning"], plausibility=True)["verdict"] == "VERIFIED":
            base.append(r)
    out = []
    for kind, check, edit in damage.DAMAGE:
        caught = 0
        for r in base:
            a = alerts[r["alert_id"]]
            analysis, mitre = measure.analysis_of(a, names), measure.mitre_of(a)
            reasoning = copy.deepcopy(r["reasoning"])
            edit(reasoning["report"], analysis, mitre)
            caught += verify_record(analysis, mitre, reasoning, plausibility=True)["verdict"] != "VERIFIED"
        lo, hi = damage.wilson(caught, len(base))
        out.append({"damage": kind, "caught": caught, "n": len(base), "ci95": [round(lo, 3), round(hi, 3)]})
    return out


def to_markdown(res):
    L = ["# Technique plausibility: retrieval abstention and verifier check (post hoc, amendment 5)", "",
         f"Rules `{res['rules']}`. Run once. No LLM call; nothing tuned (the rules have no threshold).", "",
         "## (a) Retrieval, 200-sample labelled evidence, detector-flagged", "",
         "| subset | samples | answered | relevant | wrong answers | precision when answering |", "|---|---|---|---|---|---|"]
    for k, v in res["retrieval"].items():
        L.append(f"| {k} | {v['samples']} | {v['answered']} | {v['relevant']} | {v['wrong_answers']} | {v['precision_when_answering']} |")
    L += ["", "Test half per family (off -> on): flagged / answered / relevant", ""]
    for fam, m in res["retrieval_per_family"].items():
        o, n = m.get("off", {}), m.get("on", {})
        L.append(f"- {fam}: {o.get('flagged', 0)} / {o.get('answered', 0)} -> {n.get('answered', 0)} / {o.get('relevant', 0)} -> {n.get('relevant', 0)}")
    t, c = res["llm"]["total"], res["llm"]["candidates"]
    L += ["", "## (b) The 100 saved main-run reports", "",
          f"Candidates {c['candidates']}; removed as implausible {c['removed']}; not judged (no rule) {c['not_judged']}. "
          f"Recomputed 11-check verdicts that differ from the saved ones: {len(res['llm']['v1_recomputed_mismatches'])}.", "",
          "| family | alerts | with candidates before -> after | relevant candidate before -> after | VERIFIED 11 checks -> 12 | faithful-but-wrong before -> after | relevant-citing reports downgraded |",
          "|---|---|---|---|---|---|---|"]
    for fam, v in list(res["llm"]["by_family"].items()) + [("Total", t)]:
        L.append(f"| {fam} | {v['alerts']} | {v['with_candidates_before']} -> {v['with_candidates_after']} | {v['relevant_before']} -> {v['relevant_after']} | "
                 f"{v['verified_v1']} -> {v['verified_v2']} | {v['fbw_v1']} -> {v['fbw_v2']} | {v['relevant_citing_downgraded']} |")
    L += ["", "Benign rows: VERIFIED is a false positive reaching the automated policy; 'relevant candidate' does not apply.", "",
          "## (c) Damage test with the check on (reports still VERIFIED with it on)", "",
          "| damage | caught | 95% CI |", "|---|---|---|"]
    for d in res["damage"]:
        L.append(f"| {d['damage']} | {d['caught']}/{d['n']} | [{d['ci95'][0]:.1%}, {d['ci95'][1]:.1%}] |")
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", type=Path, default=measure.DEFAULT_OUT / "main_qwen3_8b")
    p.add_argument("--stream", type=Path, default=measure.DEFAULT_STREAM)
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "experiments" / "plausibility")
    args = p.parse_args(argv)
    retrieval, per_family = retrieval_part(MitreService(er.ROOT))
    llm, records, alerts, names = llm_part(args.run, args.stream)
    res = {"note": "POST HOC (plan amendment 5). Rules written after aggregate results were seen; run once.",
           "rules": RULES_VERSION, "retrieval": retrieval, "retrieval_per_family": per_family, "llm": llm,
           "damage": damage_part(records, alerts, names)}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (args.out / "summary.md").write_text(to_markdown(res), encoding="utf-8")
    print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
