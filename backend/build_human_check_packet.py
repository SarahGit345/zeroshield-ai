"""Blind human-check packet for the LLM main run (no LLM calls).

    python build_human_check_packet.py --key "D:\\path\\outside\\repo\\human_check_key.csv"

Writes ONE self-contained HTML file (main_qwen3_8b/human_check_packet.html): the 30 pre-registered sampled
reports plus the UNCERTAIN ones, in a seeded shuffled order with neutral row IDs (R01...). Each row shows only
the evidence the model was given (score, threshold, top-5 features with values and contributions, ATT&CK
candidates with IDs and names) and the report text, plus blank answer fields. No verdict, failed check,
family, dataset label, alert ID or file path. The key (row ID -> alert ID, verdict, family) is written to
--key, which must be outside the repository; the script refuses a path inside it.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_llm_verification as measure  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SEED = 20261108
FIELDS = ("incident_summary", "evidence", "attack_context", "interpretation", "recommended_action", "limitations")
LEAK_WORDS = ["Benign", "DDoS", "DoS", "Recon", "Brute Force", "Spoofing", "Mirai", "Web-Based", "SqlInjection", "XSS",
              "CommandInjection", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack", "DictionaryBruteForce",
              "ArpSpoofing", "DNS_Spoofing", "VERIFIED", "UNCERTAIN", "REJECTED", "failed_checks", "alert_id", "raw/", ".json"]


def esc(x): return html.escape(str(x))


def row_html(rid, ev, report):
    feats = "".join(f"<tr><td>{f['rank']}</td><td>{esc(f['feature'])}</td><td>{f['value']:+.4f}</td><td>{f['contribution']:+.5f}</td></tr>"
                    for f in ev["top_features"][:5])
    cands = "".join(f"<li>{esc(t['technique_id'])} {esc(t['technique_name'])}</li>" for t in ev["mitre_candidates"]) or "<li>none retrieved</li>"
    rep = "".join(f"<dt>{k.replace('_', ' ')}</dt><dd>{'<br>'.join(esc(s) for s in report[k]) if isinstance(report[k], list) else esc(report[k])}</dd>"
                  for k in FIELDS)
    return f"""<section><h2>{rid}</h2><div class="grid"><div><h3>Evidence given to the model</h3>
<p>anomaly_score <b>{ev['anomaly_score']}</b><br>threshold <b>{ev['threshold']}</b> (flagged: score at or above threshold)</p>
<table><tr><th>rank</th><th>feature</th><th>value (scaled)</th><th>contribution</th></tr>{feats}</table>
<p class="small">Top 5 of the 10 features given to the model. Contribution = score minus score with the feature set to 0.</p>
<h4>ATT&amp;CK candidates retrieved</h4><ul>{cands}</ul></div>
<div><h3>Report</h3><dl>{rep}</dl></div></div>
<fieldset data-row="{rid}"><legend>Your check</legend>
<label>Supported by evidence: <select name="supported"><option></option><option>Yes</option><option>Partly</option><option>No</option></select></label>
<label>Technique plausible for this flow: <select name="technique"><option></option><option>Yes</option><option>No</option><option>None cited</option></select></label>
<label>Notes <textarea name="notes" rows="2"></textarea></label></fieldset></section>"""


SCRIPT = """<script>
const KEY = "zeroshield-report-check-v1";
const sets = [...document.querySelectorAll("fieldset[data-row]")];
function collect() { return sets.map(f => ({row: f.dataset.row, supported: f.querySelector("[name=supported]").value,
  technique: f.querySelector("[name=technique]").value, notes: f.querySelector("[name=notes]").value})); }
function progress() { const done = collect().filter(a => a.supported && a.technique).length;
  document.getElementById("progress").textContent = done + " of " + sets.length + " rows answered"; }
try { const saved = JSON.parse(localStorage.getItem(KEY) || "[]");
  saved.forEach(a => { const f = sets.find(s => s.dataset.row === a.row); if (!f) return;
    f.querySelector("[name=supported]").value = a.supported; f.querySelector("[name=technique]").value = a.technique;
    f.querySelector("[name=notes]").value = a.notes; }); } catch (e) {}
document.addEventListener("input", () => { try { localStorage.setItem(KEY, JSON.stringify(collect())); } catch (e) {} progress(); });
document.getElementById("download").addEventListener("click", () => {
  const q = s => '"' + String(s).replace(/"/g, '""') + '"';
  const csv = "row_id,supported_by_evidence,technique_plausible,notes\\n" +
    collect().map(a => [a.row, a.supported, a.technique, a.notes].map(q).join(",")).join("\\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], {type: "text/csv"}));
  link.download = "report_check_answers.csv"; link.click(); });
progress();
</script>"""


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", type=Path, default=measure.DEFAULT_OUT / "main_qwen3_8b")
    p.add_argument("--key", type=Path, required=True)
    args = p.parse_args(argv)
    key_path = args.key.resolve()
    if REPO in key_path.parents: raise SystemExit("the key must be written outside the repository")
    summary = json.loads((args.run / "summary.json").read_text(encoding="utf-8"))
    records = {json.loads(f.read_text(encoding="utf-8"))["alert_id"]: json.loads(f.read_text(encoding="utf-8"))
               for f in (args.run / "raw").glob("*.json")}
    ids = sorted(set(summary["human_check_sample"]) | {a for a, r in records.items() if r.get("verdict") == "UNCERTAIN"})
    random.Random(SEED).shuffle(ids)
    sections, key = [], []
    for i, aid in enumerate(ids, 1):
        r, rid = records[aid], f"R{i:02d}"
        ev = json.loads(r["prompt_messages"][1]["content"])
        sections.append(row_html(rid, ev, r["reasoning"]["report"]))
        key.append({"row_id": rid, "alert_id": aid, "verdict": r["verdict"], "family": r["family"], "label": r["attack_label"]})
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Report check packet</title><style>
body{{font:15px/1.45 system-ui,sans-serif;max-width:1100px;margin:0 auto;padding:16px;background:#fff;color:#111}}
section{{border:1px solid #ccc;border-radius:6px;padding:12px;margin:16px 0}} .grid{{display:grid;grid-template-columns:1fr 1.4fr;gap:16px}}
@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}} table{{border-collapse:collapse}} td,th{{border:1px solid #ddd;padding:2px 6px;font-size:13px}}
dt{{font-weight:600;margin-top:6px}} dd{{margin:0 0 0 8px}} .small{{font-size:12px;color:#555}} fieldset{{margin-top:10px}}
label{{display:block;margin:4px 0}} textarea{{width:100%}}</style></head><body>
<h1>Report check packet ({len(ids)} reports)</h1>
<p>For each report, judge only whether its statements are supported by the evidence shown, and whether any cited ATT&amp;CK
technique is plausible for a flow with these features. Do not look anything up. Answers are kept in this browser as you go;
when you finish, press <b>Download answers</b> and send the CSV file back.</p>
<p style="position:sticky;top:0;background:#fff;padding:6px 0;border-bottom:1px solid #ccc"><button id="download">Download answers (CSV)</button>
<span id="progress"></span></p>
{''.join(sections)}{SCRIPT}</body></html>"""
    out = args.run / "human_check_packet.html"
    out.write_text(page, encoding="utf-8")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    with key_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(key[0])); w.writeheader(); w.writerows(key)
    print(f"packet: {out} ({len(ids)} rows); key: {key_path}")
    # leak scan: every occurrence with context; alert IDs too
    text = re.sub(r"<[^>]+>", " ", page)
    for word in LEAK_WORDS + [a[:8] for a in ids]:
        for m in re.finditer(re.escape(word), text):
            row = re.findall(r"R\d\d", text[:m.start()])
            print(f"LEAK? {word!r} in {row[-1] if row else 'header'}: ...{text[max(0, m.start() - 50):m.end() + 30].strip()}...")
    print("scan done")


if __name__ == "__main__":
    main()
