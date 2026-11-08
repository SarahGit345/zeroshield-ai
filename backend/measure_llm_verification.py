"""Stage 10 step 3: verification measured on a real local LLM (Ollama). Runs without the backend.

    python measure_llm_verification.py --phase pilot            # 10 alerts
    python measure_llm_verification.py --phase main             # 100 alerts, stratified by family

Sample (fixed in code before any run): flagged alerts of the confirmatory S30 stream, seed 20261108.
  pilot: 3 benign + 1 per attack family (10).   main: 30 benign + 10 per attack family (100), disjoint from the pilot.
Benign alerts are over-weighted because false positives are what the verification gate could remove.

For each alert the stored detector score, XAI evidence and retrieved techniques are sent to the model
(no dataset label), the reply goes through llm_service.ollama_reason (JSON schema, temperature 0, fixed
seed, parse-and-repair, one retry), and verification_service.verify_record checks it. Every raw model
output, the exact prompt, the parsed report and every check are saved per alert under raw/. The run
resumes: alerts that already have a saved record are skipped.

False positives with and without the gate: without the gate every flagged benign alert reaches the
automated response policy; with the live API's gate only VERIFIED alerts do (the rest get HUMAN_REVIEW).
Verification checks faithfulness to the evidence, not whether the flow is an attack, so it is not
expected to separate benign from attack alerts much; the attacks it diverts are reported too.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_response_experiment as replay  # noqa: E402
from services import llm_service  # noqa: E402
from services.verification_service import verify_record  # noqa: E402

ROOT = replay.ROOT
DEFAULT_STREAM = ROOT / "backend" / "experiments" / "replay_streams" / "replay_stream_share30_seed3.jsonl"
DEFAULT_OUT = ROOT / "backend" / "experiments" / "llm_verification"
SAMPLE_SEED = 20261108
ATTACK_FAMILIES = ("DDoS", "DoS", "Recon", "Brute Force", "Spoofing", "Mirai", "Web-Based")
PLAN = {"pilot": {"Benign": 3, **{f: 1 for f in ATTACK_FAMILIES}},
        "main": {"Benign": 30, **{f: 10 for f in ATTACK_FAMILIES}}}
PHASE_SAMPLE = {"pilot": "pilot", "smoke": "pilot", "main": "main"}     # the smoke test reuses the 10 pilot alerts
# Alerts already sent to a model before the main run (pilot 0, 2026-11-08, before the post-pilot fixes).
# The main set must never contain them (plan amendment 2). Pilot alerts are excluded from main anyway.
SEEN_BEFORE_MAIN = frozenset({"7b4cbfff-746d-54af-ab94-f43232d90c78"})


def feature_names():
    return json.loads((ROOT / "model_training" / "outputs" / "zero_shield_feature_columns.json").read_text(encoding="utf-8"))


def select(stream, seed=SAMPLE_SEED):
    """Deterministic pilot and main samples of flagged alerts; main never reuses a pilot alert."""
    flagged = sorted((a for a in stream if a["detected"]), key=lambda a: a["alert_id"])
    by_family = defaultdict(list)
    for a in flagged: by_family[a["_family"]].append(a)
    rng = random.Random(seed)
    chosen = {}
    for phase in ("pilot", "main"):
        used = {a["alert_id"] for alerts in chosen.values() for a in alerts}
        if phase == "main": used |= SEEN_BEFORE_MAIN
        picked = []
        for family, n in PLAN[phase].items():
            pool = [a for a in by_family[family] if a["alert_id"] not in used]
            if len(pool) < n: raise ValueError(f"{phase}: only {len(pool)} flagged {family} alerts, need {n}")
            picked += rng.sample(pool, n)
        chosen[phase] = picked
    return chosen


def analysis_of(alert, all_names):
    top = alert["xai_evidence"]
    return {"anomaly_score": alert["anomaly_score"], "threshold": alert["threshold"], "detected": alert["detected"],
            "top_features": top, "feature_names": [x["feature"] for x in top], "all_feature_names": all_names}


def mitre_of(alert):
    return {"techniques": alert.get("retrieved_techniques", []), "query": alert.get("retrieval_query")}


def ollama_info(host, model):
    try:
        with urllib.request.urlopen(host.rstrip("/") + "/api/tags", timeout=10) as r:
            tags = json.loads(r.read())
        with urllib.request.urlopen(host.rstrip("/") + "/api/version", timeout=10) as r:
            version = json.loads(r.read()).get("version")
        entry = next((m for m in tags.get("models", []) if m.get("name") == model or m.get("model") == model), {})
        return {"ollama_version": version, "model": model, "digest": entry.get("digest"), "size": entry.get("size"),
                "details": entry.get("details")}
    except Exception as exc:
        return {"model": model, "error": str(exc)}


def run_alert(alert, all_names, host, model, seed, timeout, num_predict=None):
    analysis, mitre = analysis_of(alert, all_names), mitre_of(alert)
    messages = [{"role": "system", "content": llm_service.SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(llm_service.evidence_payload(analysis, None, mitre))}]
    record = {"alert_id": alert["alert_id"], "sample_id": alert["sample_id"], "family": alert["_family"],
              "attack_label": alert["_attack_label"], "is_attack": bool(alert["_simulator_attack"]),
              "template_verification": alert["verification_result"], "prompt_messages": messages}
    started = time.perf_counter()
    try:
        reasoning = llm_service.ollama_reason(analysis, None, mitre, host=host, model=model, seed=seed, timeout=timeout,
                                              num_predict=num_predict)
        verification = verify_record(analysis, mitre, reasoning)
        record.update(status="ok", reasoning=reasoning, raw_outputs=reasoning["raw_outputs"], verification=verification,
                      verdict=verification["verdict"], failed_checks=verification["failed_checks"])
    except llm_service.LLMTimeout as exc:
        record.update(status="timeout", verdict="TIMEOUT", error=str(exc.args[0]),
                      raw_outputs=exc.args[1] if len(exc.args) > 1 else [], parse_errors=exc.args[2] if len(exc.args) > 2 else [],
                      failed_checks=[])
    except llm_service.ReportError as exc:
        record.update(status="llm_failed", verdict="LLM_FAILED", error=str(exc.args[0]),
                      raw_outputs=exc.args[1] if len(exc.args) > 1 else [], parse_errors=exc.args[2] if len(exc.args) > 2 else [],
                      failed_checks=[])
    except Exception as exc:                       # connection error, timeout: not a model output, may be retried
        record.update(status="error", verdict="ERROR", error=f"{type(exc).__name__}: {exc}", raw_outputs=[], failed_checks=[])
    record["elapsed_seconds"] = time.perf_counter() - started
    return record


def wilson(k, n, z=1.96):
    if n == 0: return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def summarise(records, meta):
    done = [r for r in records if r["status"] in ("ok", "llm_failed", "timeout")]
    verdicts = Counter(r["verdict"] for r in done)
    by_family = defaultdict(Counter)
    for r in done: by_family[r["family"]][r["verdict"]] += 1
    failed = Counter(c for r in done for c in r["failed_checks"])
    ok = [r for r in done if r["status"] == "ok"]
    benign = [r for r in done if not r["is_attack"]]
    attacks = [r for r in done if r["is_attack"]]
    benign_pass = sum(r["verdict"] == "VERIFIED" for r in benign)
    attack_pass = sum(r["verdict"] == "VERIFIED" for r in attacks)
    return {**meta, "alerts_attempted": len(records), "alerts_completed": len(done),
            "errors_not_counted": [r["alert_id"] for r in records if r["status"] == "error"],
            "verdicts": dict(verdicts), "verdict_shares": {k: v / max(len(done), 1) for k, v in verdicts.items()},
            "verdicts_by_family": {f: dict(c) for f, c in sorted(by_family.items())},
            "failed_check_counts": dict(failed.most_common()),
            "failed_check_share_of_completed": {k: v / max(len(done), 1) for k, v in failed.most_common()},
            "parsing": {"first_attempt_valid": sum(r["reasoning"]["attempts"] == 1 for r in ok),
                        "first_attempt_invalid": sum(r["reasoning"]["attempts"] == 2 for r in ok)
                                                 + sum(r["status"] != "ok" and len(r.get("raw_outputs", [])) >= 1 for r in done),
                        "retry_succeeded": sum(r["reasoning"]["attempts"] == 2 for r in ok),
                        "failed_after_retry": verdicts.get("LLM_FAILED", 0),
                        "repaired": sum(r["reasoning"]["repaired"] for r in ok),
                        "length_capped_replies": sum(t.get("done_reason") == "length" for r in ok for t in r["reasoning"]["timings"]),
                        "timeouts": verdicts.get("TIMEOUT", 0)},
            "template_verdicts_same_alerts": dict(Counter(r["template_verification"] for r in done)),
            "gate": {"benign_alerts": len(benign), "attack_alerts": len(attacks),
                     "false_positives_reaching_automation_without_gate": len(benign),
                     "false_positives_reaching_automation_with_gate": benign_pass,
                     "false_positive_reduction_share": 1 - benign_pass / max(len(benign), 1),
                     "benign_verified_rate": benign_pass / max(len(benign), 1), "benign_verified_rate_ci95": wilson(benign_pass, len(benign)),
                     "attacks_reaching_automation_with_gate": attack_pass,
                     "attack_verified_rate": attack_pass / max(len(attacks), 1), "attack_verified_rate_ci95": wilson(attack_pass, len(attacks)),
                     "note": "Without the gate every flagged alert reaches the automated policy. With it, only VERIFIED alerts do; "
                             "the others go to HUMAN_REVIEW. LLM failures and timeouts count as not VERIFIED."},
            "mean_seconds_per_alert": sum(r["elapsed_seconds"] for r in done) / max(len(done), 1),
            "max_seconds_per_alert": max((r["elapsed_seconds"] for r in done), default=0.0),
            "mean_output_tokens_per_attempt": (sum(t.get("eval_count") or 0 for r in ok for t in r["reasoning"]["timings"])
                                               / max(sum(len(r["reasoning"]["timings"]) for r in ok), 1))}


def render(summary) -> str:
    g = summary["gate"]
    lines = [f"# LLM verification measurement ({summary['phase']})\n",
             f"Model `{summary['model_info'].get('model')}` (digest {summary['model_info'].get('digest')}, Ollama {summary['model_info'].get('ollama_version')}); "
             f"temperature 0, seed {summary['llm_seed']}. Stream `{summary['stream']}` (SHA-256 {summary['stream_sha256']}). "
             f"{summary['alerts_completed']} of {summary['alerts_attempted']} alerts completed; mean {summary['mean_seconds_per_alert']:.0f} s per alert.\n",
             "| verdict | count | share |", "|---|---|---|"]
    for k in ("VERIFIED", "UNCERTAIN", "REJECTED", "LLM_FAILED", "TIMEOUT"):
        lines.append(f"| {k} | {summary['verdicts'].get(k, 0)} | {summary['verdict_shares'].get(k, 0):.1%} |")
    lines += ["", "| family | " + " | ".join(("VERIFIED", "UNCERTAIN", "REJECTED", "LLM_FAILED", "TIMEOUT")) + " |", "|---|---|---|---|---|---|"]
    for f, c in summary["verdicts_by_family"].items():
        lines.append(f"| {f} | " + " | ".join(str(c.get(k, 0)) for k in ("VERIFIED", "UNCERTAIN", "REJECTED", "LLM_FAILED", "TIMEOUT")) + " |")
    lines += ["", "Failed checks (alerts failing each check):", ""] + \
             [f"- {k}: {v} ({summary['failed_check_share_of_completed'][k]:.1%})" for k, v in summary["failed_check_counts"].items()]
    p = summary["parsing"]
    lines += ["", f"Parsing: {p['first_attempt_valid']} valid on the first attempt; {p['first_attempt_invalid']} invalid on the first attempt "
                  f"({p['retry_succeeded']} fixed by the retry, {p['failed_after_retry']} still invalid after it); {p['repaired']} repaired without a retry; "
                  f"{p['length_capped_replies']} replies hit the output cap; {p['timeouts']} timed out.",
              f"Time: mean {summary['mean_seconds_per_alert']:.0f} s per alert, max {summary['max_seconds_per_alert']:.0f} s; "
              f"mean {summary['mean_output_tokens_per_attempt']:.0f} output tokens per attempt.",
              f"Template reasoning on the same alerts: {summary['template_verdicts_same_alerts']}.", "",
              "False positives and the verification gate:", "",
              f"- Without the gate: {g['false_positives_reaching_automation_without_gate']} of {g['benign_alerts']} flagged benign alerts reach the automated policy.",
              f"- With the gate: {g['false_positives_reaching_automation_with_gate']} of {g['benign_alerts']} (benign VERIFIED rate {g['benign_verified_rate']:.1%}, "
              f"95% Wilson [{g['benign_verified_rate_ci95'][0]:.1%}, {g['benign_verified_rate_ci95'][1]:.1%}]); reduction {g['false_positive_reduction_share']:.1%}.",
              f"- Cost: {g['attacks_reaching_automation_with_gate']} of {g['attack_alerts']} attacks still reach the automated policy "
              f"(attack VERIFIED rate {g['attack_verified_rate']:.1%}, 95% Wilson [{g['attack_verified_rate_ci95'][0]:.1%}, {g['attack_verified_rate_ci95'][1]:.1%}]); the rest go to human review.",
              "", "Verification checks faithfulness to the evidence, not whether the flow is an attack."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phase", choices=tuple(PHASE_SAMPLE), required=True)
    p.add_argument("--stream", type=Path, default=DEFAULT_STREAM)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--host", default="http://127.0.0.1:11434")
    p.add_argument("--model", default=llm_service.DEFAULT_OLLAMA_MODEL)
    p.add_argument("--llm-seed", type=int, default=llm_service.DEFAULT_SEED)
    p.add_argument("--timeout", type=float, default=llm_service.DEFAULT_TIMEOUT_SECONDS, help="seconds per alert, retry included")
    p.add_argument("--num-predict", type=int, default=llm_service.DEFAULT_NUM_PREDICT, help="output token cap per attempt")
    p.add_argument("--limit", type=int, help="process at most this many alerts of the phase (smoke test)")
    args = p.parse_args(argv)

    from build_replay_stream import sha256_file
    stream = replay.load_stream(args.stream)
    sample = select(stream)[PHASE_SAMPLE[args.phase]][:args.limit]
    out = args.out / f"{args.phase}_{args.model.replace(':', '_').replace('/', '_')}"
    (out / "raw").mkdir(parents=True, exist_ok=True)
    meta = {"phase": args.phase, "stream": str(args.stream), "stream_sha256": sha256_file(args.stream), "sample_seed": SAMPLE_SEED,
            "sample_plan": PLAN[PHASE_SAMPLE[args.phase]], "llm_seed": args.llm_seed, "temperature": 0,
            "timeout_seconds_per_alert": args.timeout, "num_predict": args.num_predict,
            "model_info": ollama_info(args.host, args.model), "started_at": datetime.now(timezone.utc).isoformat(),
            "sample_alert_ids": [a["alert_id"] for a in sample]}
    all_names = feature_names()
    records = []
    for i, alert in enumerate(sample, 1):
        path = out / "raw" / f"{alert['alert_id']}.json"
        if path.exists():
            saved = json.loads(path.read_text(encoding="utf-8"))
            if saved.get("status") in ("ok", "llm_failed", "timeout"):
                records.append(saved); print(f"[{i}/{len(sample)}] {alert['alert_id'][:8]} {saved['family']}: saved earlier ({saved['verdict']})", flush=True)
                continue
        record = run_alert(alert, all_names, args.host, args.model, args.llm_seed, args.timeout, args.num_predict)
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        records.append(record)
        print(f"[{i}/{len(sample)}] {alert['alert_id'][:8]} {record['family']}: {record['verdict']} "
              f"{record['failed_checks']} ({record['elapsed_seconds']:.0f} s)", flush=True)
    summary = summarise(records, {**meta, "finished_at": datetime.now(timezone.utc).isoformat()})
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(render(summary), encoding="utf-8")
    print(render(summary))
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
