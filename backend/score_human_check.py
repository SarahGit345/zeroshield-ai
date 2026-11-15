"""Score the blind human check (plan item 4) against the key kept outside the repository.

    python score_human_check.py --answers <report_check_answers.csv> --key <human_check_key.csv>

The answers file holds only row IDs and the checker's judgements (no labels) and is copied into the results folder.
The key (row -> alert, verdict, family, label) is read from outside the repository and never written into it;
only aggregate results and per-row verdict/family comparisons are written.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = HERE / "experiments" / "llm_verification" / "main_qwen3_8b"
OUR_CLASS = {"relevant": "Yes", "irrelevant": "No", "benign_cites_technique": "No", "no_candidates": "None cited"}


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return [{k.strip(): (v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def our_technique_judgement(record):
    """Relevance-list judgement from the post hoc name-or-ID analysis (amendment-era, committed)."""
    if not record["cited"]:
        return "None cited"
    return OUR_CLASS.get(record["class"], "No")


def score(answers, key, per_alert):
    k = {r["row_id"]: r for r in key}
    pa = {r["alert_id"]: r for r in per_alert}
    rows = []
    for a in answers:
        kr = k[a["row_id"]]
        rec = pa.get(kr["alert_id"], {"cited": [], "class": "no_candidates"})
        rows.append({"row_id": a["row_id"], "verdict": kr["verdict"], "family": kr["family"],
                     "human_supported": a["supported_by_evidence"], "human_technique": a["technique_plausible"],
                     "our_technique": our_technique_judgement(rec), "notes": a["notes"]})
    cross = defaultdict(Counter)
    for r in rows:
        cross[r["verdict"]][r["human_supported"]] += 1
    tech = Counter((r["human_technique"], r["our_technique"]) for r in rows)
    agree = sum(n for (h, o), n in tech.items() if h == o)
    fam = defaultdict(Counter)
    for r in rows:
        fam[r["family"]][r["human_supported"]] += 1
    return {"n": len(rows),
            "human_supported": dict(Counter(r["human_supported"] for r in rows)),
            "human_technique": dict(Counter(r["human_technique"] for r in rows)),
            "supported_by_verifier_verdict": {v: dict(c) for v, c in cross.items()},
            "verified_but_human_no": [{kk: r[kk] for kk in ("row_id", "family", "notes")}
                                      for r in rows if r["verdict"] == "VERIFIED" and r["human_supported"] == "No"],
            "technique_agreement_with_relevance_lists": {"agree": agree, "n": len(rows),
                                                         "table": {f"human {h} / lists {o}": n for (h, o), n in sorted(tech.items())}},
            "supported_by_family": {f: dict(c) for f, c in sorted(fam.items())},
            "rows": [{kk: r[kk] for kk in ("row_id", "verdict", "family", "human_supported", "human_technique", "our_technique")}
                     for r in rows]}


def markdown(res):
    hs, ht = res["human_supported"], res["human_technique"]
    L = ["# Blind human check: result (plan item 4)", "",
         f"{res['n']} reports (30 drawn with seed 20261108 before the run + the 2 UNCERTAIN), judged from the blind packet only.", "",
         "| Supported by evidence | Yes | Partly | No |", "|---|---|---|---|",
         f"| All reports | {hs.get('Yes', 0)} | {hs.get('Partly', 0)} | {hs.get('No', 0)} |"]
    for v, c in res["supported_by_verifier_verdict"].items():
        L.append(f"| verifier {v} | {c.get('Yes', 0)} | {c.get('Partly', 0)} | {c.get('No', 0)} |")
    L += ["", f"Technique plausible (human): Yes {ht.get('Yes', 0)} · No {ht.get('No', 0)} · None cited {ht.get('None cited', 0)}.",
          f"Agreement with the project's relevance lists: {res['technique_agreement_with_relevance_lists']['agree']} of {res['n']}.", ""]
    L += ["| human / relevance lists | reports |", "|---|---|"] + [f"| {k} | {n} |" for k, n in res["technique_agreement_with_relevance_lists"]["table"].items()]
    L += ["", "**VERIFIED by the verifier but judged not supported by the human:**", ""]
    L += [f"- {r['row_id']} ({r['family']}): {r['notes']}" for r in res["verified_but_human_no"]] or ["- none"]
    L += ["", "| family | Yes | Partly | No |", "|---|---|---|---|"]
    L += [f"| {f} | {c.get('Yes', 0)} | {c.get('Partly', 0)} | {c.get('No', 0)} |" for f, c in res["supported_by_family"].items()]
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--answers", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    a = p.parse_args(argv)
    if RUN in a.key.resolve().parents:
        raise SystemExit("The key must stay outside the repository.")
    answers, key = read_csv(a.answers), read_csv(a.key)
    per_alert = json.loads((RUN / "posthoc_technique_names.json").read_text(encoding="utf-8"))["per_alert"]
    res = score(answers, key, per_alert)
    shutil.copyfile(a.answers, RUN / "human_check_answers.csv")
    (RUN / "human_check_result.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    (RUN / "human_check_result.md").write_text(markdown(res), encoding="utf-8")
    print(markdown(res))


if __name__ == "__main__":
    main()
