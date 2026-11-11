"""Post-hoc analysis of the saved LLM main run (no LLM calls); decided AFTER seeing the results.

    python posthoc_llm_analysis.py [--run experiments/llm_verification/main_qwen3_8b]

1. Technique citations matched by technique NAME or ID (the pre-registered count matched IDs only, but the
   reports name techniques rather than citing IDs). Same relevant sets as the pre-registered count.
2. A blank human-check sheet: the 30 pre-registered sampled reports plus any UNCERTAIN ones, verdict and
   family hidden, in alert-ID order.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_llm_verification as measure  # noqa: E402


def classify(record):
    ev = json.loads(record["prompt_messages"][1]["content"])
    text = json.dumps(record["reasoning"]["report"]).lower()
    cands = ev["mitre_candidates"]
    named = [t for t in cands if t["technique_name"].lower() in text or t["technique_id"].lower() in text]
    if not cands: return "no_candidates", []
    if not named: return "candidates_not_cited", []
    ids = [t["technique_id"] for t in named]
    if not record["is_attack"]: return "benign_cites_technique", ids
    return ("relevant" if any(i.split(".")[0] in measure.relevant_set(record) for i in ids) else "irrelevant"), ids


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", type=Path, default=measure.DEFAULT_OUT / "main_qwen3_8b")
    args = p.parse_args(argv)
    records = [json.loads(f.read_text(encoding="utf-8")) for f in sorted((args.run / "raw").glob("*.json"))]
    by_family, total, rows = defaultdict(Counter), Counter(), []
    for r in records:
        if r["status"] != "ok": continue
        cls, ids = classify(r)
        fbw = r["verdict"] == "VERIFIED" and cls in ("irrelevant", "benign_cites_technique")
        for c in (by_family[r["family"]], total):
            c[cls] += 1; c["faithful_but_wrong"] += fbw
        rows.append({"alert_id": r["alert_id"], "family": r["family"], "label": r["attack_label"], "class": cls,
                     "cited": ids, "verdict": r["verdict"]})
    out = {"note": "POST HOC: name-or-ID matching chosen after seeing that reports name techniques; not pre-registered.",
           "total": dict(total), "by_family": {f: dict(c) for f, c in sorted(by_family.items())}, "per_alert": rows}
    (args.run / "posthoc_technique_names.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    summary = json.loads((args.run / "summary.json").read_text(encoding="utf-8"))
    ids = set(summary["human_check_sample"]) | {r["alert_id"] for r in records if r.get("verdict") == "UNCERTAIN"}
    with (args.run / "human_check_sheet.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["alert_id", "raw_file", "faithful_to_evidence (Y/N)", "unsupported_or_wrong_claims (quote)",
                    "technique_cited_fits_flow (Y/N/none)", "checker", "notes"])
        for aid in sorted(ids): w.writerow([aid, f"raw/{aid}.json", "", "", "", "", ""])
    print(json.dumps({"total": out["total"], "by_family": out["by_family"], "sheet_rows": len(ids)}, indent=1))


if __name__ == "__main__":
    main()
