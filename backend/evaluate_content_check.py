"""Evaluate the frozen HTTP content rules on PCAP captures (plan amendment 3). Side by side, not fused.

    python evaluate_content_check.py --benign ..\\..\\Dataset\\BenignTraffic3.pcap ^
        --attack SqlInjection=path\\SqlInjection.pcap --attack XSS=path\\XSS.pcap ... --out experiments\\content_check

For every capture: extract plaintext HTTP requests, scan each with services.content_rules, and report
requests, requests with at least one hit, hits per category and per rule, and sample snippets.
Labels are per capture file. Attack captures may also contain benign background requests, so the
attack-file hit rate is a lower bound on recall over the attack requests themselves. The benign
false-positive rate is reported with a Wilson 95% interval. Next to it, the flow detector's flag rate
per family over the full dataset (from the committed stream meta) is shown; the two cannot be fused
because CSV rows cannot be linked to individual requests.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcap_http_extract import iter_requests  # noqa: E402
from services import content_rules  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STREAM_META = ROOT / "backend" / "experiments" / "replay_streams" / "replay_stream_seed1.meta.json"
MAX_EXAMPLES = 20


def wilson(k, n, z=1.96):
    if n == 0: return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def evaluate_capture(path: Path, label: str, kind: str, out_dir: Path | None = None) -> dict:
    stats, n, hit_requests = Counter(), 0, 0
    by_category, by_rule, examples = Counter(), Counter(), []
    sink = (out_dir / f"{kind}_{label}_hits.jsonl").open("w", encoding="utf-8") if out_dir else None
    try:
        for req in iter_requests(path, label, stats):
            n += 1
            hits = content_rules.scan_request(req["method"], req["uri"], req["body"], req["headers"])
            if not hits: continue
            hit_requests += 1
            by_category.update({h["category"] for h in hits}); by_rule.update(h["rule_id"] for h in hits)
            record = {"uri": req["uri"][:300], "method": req["method"], "hits": hits, "src": req["src"], "dst": req["dst"]}
            if len(examples) < MAX_EXAMPLES: examples.append(record)
            if sink: sink.write(json.dumps(record) + "\n")
    finally:
        if sink: sink.close()
    return {"label": label, "kind": kind, "file": str(path), "requests": n, "requests_with_hit": hit_requests,
            "hit_rate": hit_requests / n if n else None, "hit_rate_ci95": wilson(hit_requests, n),
            "requests_by_category": dict(by_category), "hits_by_rule": dict(by_rule.most_common()),
            "extraction": dict(stats), "examples": examples}


def flow_detector_rates():
    try:
        meta = json.loads(STREAM_META.read_text(encoding="utf-8"))
    except Exception:
        return {}
    pop = meta["population"]
    out = {}
    for key in pop:
        fam = key.split("|")[0]
        f, u = pop.get(f"{fam}|flagged", 0), pop.get(f"{fam}|unflagged", 0)
        out[fam] = {"flagged": f, "total": f + u, "flag_rate": f / (f + u) if f + u else None}
    return out


def render(summary) -> str:
    lines = [f"# HTTP content check ({summary['ruleset_version']}, sha256 {summary['ruleset_sha256'][:12]})\n",
             "Signature-based, plaintext HTTP only; complementary to the flow detector, not zero-day detection. "
             "Labels are per capture file.\n",
             "| capture | kind | requests | with a hit | hit rate [95% CI] | categories | TLS hellos |", "|---|---|---|---|---|---|---|"]
    for c in summary["captures"]:
        rate = "n/a" if c["hit_rate"] is None else f"{c['hit_rate']:.1%} [{c['hit_rate_ci95'][0]:.1%}, {c['hit_rate_ci95'][1]:.1%}]"
        lines.append(f"| {c['label']} | {c['kind']} | {c['requests']} | {c['requests_with_hit']} | {rate} | "
                     f"{c['requests_by_category']} | {c['extraction'].get('tls_client_hellos', 0)} |")
    b = summary["benign_false_positives"]
    lines += ["", f"Benign false positives: {b['requests_with_hit']} of {b['requests']} requests "
                  f"({(b['rate'] or 0):.2%}, 95% Wilson [{b['ci95'][0]:.2%}, {b['ci95'][1]:.2%}]).",
              "", "Flow detector flag rate over the full dataset (side by side; not linkable to requests):", ""]
    for fam, r in summary["flow_detector_flag_rate"].items():
        if r["flag_rate"] is not None: lines.append(f"- {fam}: {r['flag_rate']:.3f} ({r['flagged']:,} of {r['total']:,} flows)")
    lines += ["", "Attack-file hit rates are lower bounds on recall: attack captures may include benign background requests. "
                  "A capture with 0 requests means no plaintext HTTP was found (encrypted or not HTTP)."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--benign", type=Path, action="append", default=[], help="benign capture (repeatable)")
    p.add_argument("--attack", action="append", default=[], help="LABEL=capture (repeatable)")
    p.add_argument("--out", type=Path, default=ROOT / "backend" / "experiments" / "content_check")
    args = p.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    captures = [evaluate_capture(path, path.stem, "benign", args.out) for path in args.benign]
    for item in args.attack:
        label, _, path = item.partition("=")
        captures.append(evaluate_capture(Path(path), label, "attack", args.out))
    benign = [c for c in captures if c["kind"] == "benign"]
    bn, bk = sum(c["requests"] for c in benign), sum(c["requests_with_hit"] for c in benign)
    summary = {"ruleset_version": content_rules.RULESET_VERSION, "ruleset_sha256": content_rules.ruleset_sha256(),
               "run_at": datetime.now(timezone.utc).isoformat(), "captures": captures,
               "benign_false_positives": {"requests": bn, "requests_with_hit": bk, "rate": bk / bn if bn else None, "ci95": wilson(bk, bn)},
               "flow_detector_flag_rate": flow_detector_rates()}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (args.out / "summary.md").write_text(render(summary), encoding="utf-8")
    print(render(summary))


if __name__ == "__main__":
    main()
