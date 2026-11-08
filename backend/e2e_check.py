"""End-to-end check of everything built so far. Prints PASS / WARN / FAIL per check and exits 1 on any FAIL.

    python e2e_check.py --stream path/to/alerts.jsonl --tests            # backend must be running on :8000
    python e2e_check.py --stream alerts.jsonl --skip-api                  # stream + replay checks only
    python e2e_check.py --api http://127.0.0.1:8000 --skip-ledger         # read-only API checks

Sections: A environment, B unit tests (--tests), C MITRE retrieval, D live API + ledger flow, E replay stream,
F replay invariants and policy comparison, G policy comparison across attack prevalence (--prevalence 0.1 0.3 0.5 0.8). It never claims a policy wins; it prints what the numbers show.

Ledger side effects: the API section sends the ten cached demo samples (labelled "E2E:<category>") and records
feedback on some of them, so those alerts and a few policy updates stay in the local ledger. Use --skip-ledger to
avoid writes, or --reset-policy-after to reset the learned policy afterwards (alerts remain, as the endpoint says).
"""
import argparse
import json
import math
import statistics
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

RESULTS: list[tuple[str, str, str]] = []
EXPECTED_THRESHOLD = 0.06141921002417763
EXPECTED_FLAGGED_DEMO = {"Mirai-greeth_flood", "Mirai-greip_flood", "Mirai-udpplain", "XSS", "Backdoor_Malware"}
VERDICTS = {"VERIFIED", "UNCERTAIN", "REJECTED"}
REQUIRED_STREAM_KEYS = ["alert_id", "anomaly_score", "threshold", "detected", "xai_evidence", "retrieved_techniques",
                        "verification_result", "verification_confidence", "_simulator_attack"]
FLOOD_FAMILIES = ("Mirai-greeth_flood", "Mirai-greip_flood", "Mirai-udpplain")


def report(level, name, detail=""):
    RESULTS.append((level, name, detail))
    print(f"[{level}] {name}" + (f" - {detail}" if detail else ""))


def check(condition, name, ok="", bad="", bad_level="FAIL"):
    report("PASS" if condition else bad_level, name, ok if condition else bad)
    return bool(condition)


def section(title):
    print(f"\n=== {title} ===")


def call(base, method, path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw.decode(errors="replace")
    except Exception as exc:  # connection refused, timeout, ...
        return None, str(exc)


# ---------------------------------------------------------------- A. environment
def section_environment():
    section("A. Environment")
    check(sys.version_info >= (3, 10), "Python version", sys.version.split()[0], "needs Python 3.10 or newer")
    checkpoint = ROOT / "model_training" / "outputs" / "Deep_SVDD_Tuned.pt"
    check(checkpoint.exists(), "Active detector checkpoint present", str(checkpoint.name), f"missing {checkpoint}")
    from services.mitre_service import MitreService
    svc = MitreService(ROOT)
    check(svc.index is not None and not svc.index_error, "MITRE index loads and passes its hash check",
          bad=f"index_error={svc.index_error}")
    for name in ("validation_set.csv", "zero_day_test_scaled_v2.csv", "train_benign_only.csv"):
        found = next(iter(ROOT.glob(f"**/{name}")), None) if not (ROOT / name).exists() else ROOT / name
        report("PASS" if found else "WARN", f"Dataset file {name}", str(found) if found else "not found under the repo (needed to build a stream)")


# ---------------------------------------------------------------- B. unit tests
def section_tests():
    section("B. Backend unit tests")
    run = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests"],
                         cwd=HERE, capture_output=True, text=True)
    tail = (run.stderr or run.stdout).strip().splitlines()
    ran = next((line for line in tail if line.startswith("Ran ")), "")
    check(run.returncode == 0, "All unit tests pass", ran, "failures:\n" + "\n".join(tail[-12:]))


# ---------------------------------------------------------------- C. retrieval
def section_retrieval():
    section("C. MITRE retrieval (held-out labelled evidence)")
    from evaluate_retrieval import evaluate
    frame = evaluate()
    test = frame[(frame.half == "test") & frame.detected]
    relevant, n = int(test.hit.sum()), len(test)
    report("PASS" if (relevant, n) == (19, 53) else "WARN", "Retrieval reproduces the documented held-out result",
           f"{relevant} of {n} flagged samples relevant" + ("" if (relevant, n) == (19, 53) else " (documented: 19 of 53; the index, ontology or library version differs)"))
    floods = frame[frame.detected & frame.label.str.startswith("Mirai")]
    check(floods.hit.mean() >= 0.5, "Flood alerts get a relevant technique", f"{floods.hit.mean():.0%} of {len(floods)} flagged Mirai samples",
          f"only {floods.hit.mean():.0%}")


# ---------------------------------------------------------------- D. live API
def section_api(base, write_ledger, reset_after):
    section(f"D. Live API at {base}")
    from services.bandit_service import ACTIONS, CONTEXT_FEATURES
    status, health = call(base, "GET", "/api/health")
    if not check(status == 200 and isinstance(health, dict) and health.get("status") == "ok", "Health is ok",
                 f"threshold {health.get('threshold') if isinstance(health, dict) else ''}",
                 f"status={status} body={health}. Is the backend running?"):
        return
    check(abs(float(health["threshold"]) - EXPECTED_THRESHOLD) < 1e-9, "Threshold is the tuned checkpoint's", f"{health['threshold']}",
          f"{health['threshold']} differs from {EXPECTED_THRESHOLD}; a different checkpoint is loaded", "WARN")
    _, info = call(base, "GET", "/api/model-info")
    check(info.get("feature_count") == 43 and info.get("model_loaded"), "Model info: 43 features, model loaded")
    check(info.get("mitre_behavior_index_available"), "MITRE behaviour index available")
    report("INFO", "Reasoning mode in the app", info.get("llm_status", "?"))

    _, demo = call(base, "GET", "/api/demo-samples")
    samples = [s for s in demo["samples"] if s["available"]]
    check(len(samples) == 10, "Ten cached demo samples available", bad=f"{len(samples)} available", bad_level="WARN")

    recorded, flagged = {}, set()
    for sample in samples:
        category = sample["category"]
        status, r = call(base, "POST", "/api/analyze", {"features": sample["features"], "attack_family": f"E2E:{category}"})
        tag = f"analyze {category}"
        if not check(status == 200 and isinstance(r, dict), tag, bad=f"status {status}: {str(r)[:160]}"):
            continue
        problems = []
        if bool(r["detected"]) != (r["anomaly_score"] >= r["threshold"]): problems.append("detected flag disagrees with score vs threshold")
        top = r["top_features"]
        if len(top) != 10 or [x["contribution"] for x in top] != sorted((x["contribution"] for x in top), reverse=True): problems.append("top-10 XAI not sorted/complete")
        if r["verification"]["verdict"] not in VERDICTS: problems.append("bad verdict")
        if len(r["verification"]["checks"]) != 11: problems.append(f"{len(r['verification']['checks'])} verification checks, expected 11")
        action = r["bandit"]["selected_action"]
        if action not in ACTIONS: problems.append(f"unknown action {action}")
        if not r["detected"] and (action != "MONITOR_ONLY" or r["bandit"].get("policy_update_status") != "NOT_ELIGIBLE"):
            problems.append(f"an unflagged flow was proposed {action} / {r['bandit'].get('policy_update_status')}; it should be MONITOR_ONLY and not recorded")
        if r["detected"] and r["verification"]["verdict"] == "VERIFIED" and list(r["bandit"]["context_features"]) != CONTEXT_FEATURES: problems.append("policy context differs from the documented schema")
        leaked = [text for text in (str(r["mitre"].get("query", "")), json.dumps(r["reasoning"])) if category.split("-")[0] in text and category != "BenignTraffic"]
        if leaked: problems.append("the dataset label appears in the query or report")
        check(not problems, tag, f"detected={r['detected']} verdict={r['verification']['verdict']} action={action}", "; ".join(problems))
        if r["detected"]: flagged.add(category)
        recorded[category] = r
    report("PASS" if flagged == EXPECTED_FLAGGED_DEMO else "WARN", "Flagged demo samples match the earlier check",
           f"flagged: {sorted(flagged)}" + ("" if flagged == EXPECTED_FLAGGED_DEMO else f"; expected {sorted(EXPECTED_FLAGGED_DEMO)}"))

    features = samples[0]["features"]
    missing = dict(list(features.items())[:-1])
    check(call(base, "POST", "/api/analyze", {"features": missing})[0] == 422, "Rejects a request with a missing feature")
    check(call(base, "POST", "/api/analyze", {"features": {**features, "bogus": 1.0}})[0] == 422, "Rejects a request with an extra feature")
    check(call(base, "POST", "/api/analyze", {"features": {**features, next(iter(features)): "abc"}})[0] == 422, "Rejects a non-numeric value")

    if not write_ledger:
        report("INFO", "Ledger flow skipped (--skip-ledger)")
    else:
        ledger_flow(base, recorded)
        if reset_after:
            status, body = call(base, "POST", "/api/response/reset-policy")
            check(status == 200 and body.get("status") == "policy_reset", "Policy reset after the check")
    status, experiment = call(base, "GET", "/api/response/experiment")
    report("INFO", "Dashboard replay experiment", str(experiment.get("status") if isinstance(experiment, dict) else status))


def ledger_flow(base, recorded):
    alerts = [r for r in recorded.values() if r["bandit"].get("policy_update_status") == "WAITING_FOR_FEEDBACK"]
    confirm = next((r for r in alerts if r["bandit"]["selected_action"] == "CONFIRM_TO_ACT"), None)
    other = next((r for r in alerts if r["bandit"]["selected_action"] != "CONFIRM_TO_ACT"), None)
    check(bool(alerts), "At least one analysed alert was recorded in the ledger", bad="no alert reached the response policy")

    if other:
        aid = other["alert_id"]
        s, rec = call(base, "POST", f"/api/response/feedback/{aid}", {"ground_truth_attack": True})
        events = [e["event"] for e in rec.get("history", [])] if isinstance(rec, dict) else []
        check(s == 200 and rec.get("policy_update_status") == "UPDATED" and rec.get("reward_version") and events[-2:] == ["OUTCOME_OBSERVED", "POLICY_UPDATED"],
              f"Feedback on {other['bandit']['selected_action']} updates the policy once",
              f"reward {rec.get('reward')} ({rec.get('reward_version')}), history {events}", f"status {s}: {str(rec)[:200]}")
        s2, again = call(base, "POST", f"/api/response/feedback/{aid}", {"ground_truth_attack": False})
        check(s2 == 200 and again.get("reward") == rec.get("reward") and len(again.get("history", [])) == len(rec.get("history", [])),
              "Duplicate feedback changes nothing (idempotent)", bad=f"status {s2}, reward {again.get('reward') if isinstance(again, dict) else again}")
        check(call(base, "POST", f"/api/response/approval/{aid}", {"choice": "APPROVED"})[0] == 409, "Approval refused on an action that needs none")
    else:
        report("WARN", "No non-confirm alert available to test plain feedback")

    if confirm:
        aid = confirm["alert_id"]
        check(call(base, "POST", f"/api/response/feedback/{aid}", {"ground_truth_attack": True})[0] == 409, "Feedback refused before approval")
        check(any(a["alert_id"] == aid for a in call(base, "GET", "/api/response/approvals")[1]["pending"]), "Pending approval appears in the queue")
        s, rec = call(base, "POST", f"/api/response/approval/{aid}", {"choice": "APPROVED"})
        check(s == 200 and rec.get("approval_status") == "APPROVED", "Approval is recorded", bad=f"status {s}")
        check(call(base, "POST", f"/api/response/approval/{aid}", {"choice": "APPROVED"})[0] == 409, "A second approval is refused")
        s, rec = call(base, "POST", f"/api/response/feedback/{aid}", {"ground_truth_attack": True})
        check(s == 200 and rec.get("reward") == 3 and rec.get("policy_update_status") == "UPDATED", "Approved confirm on an attack earns +3 and updates the policy",
              bad=f"status {s}, reward {rec.get('reward') if isinstance(rec, dict) else rec}")
    else:
        report("INFO", "No CONFIRM_TO_ACT alert among the demo samples, so the approval flow was not exercised here",
               "the unit tests cover it; use the dashboard on a mid-confidence alert to see it")

    check(call(base, "POST", "/api/response/feedback/does-not-exist", {"ground_truth_attack": True})[0] == 404, "Unknown alert gives 404")
    victim = next(iter(recorded.values()))["alert_id"]
    check(call(base, "POST", f"/api/response/feedback/{victim}", {"ground_truth_attack": "maybe"})[0] == 422, "A non-boolean label is rejected")
    listed = {a["alert_id"] for a in call(base, "GET", "/api/response/alerts")[1]["alerts"]}
    check(all(r["alert_id"] in listed for r in alerts), "Flagged, verified alerts are listed by the API")
    check(not any(r["alert_id"] in listed for r in recorded.values() if not r["detected"]), "Unflagged flows are not recorded in the ledger")


# ---------------------------------------------------------------- E. stream
def load_stream(path):
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                report("FAIL", "Stream line parses", f"line {number}: {exc}")
                return None
    return rows


def section_stream(path):
    section(f"E. Replay stream {path}")
    rows = load_stream(path)
    if rows is None: return None
    if not check(len(rows) > 0, "Stream is not empty", f"{len(rows)} rows", "no rows"): return None
    missing = Counter(k for r in rows for k in REQUIRED_STREAM_KEYS if k not in r)
    check(not missing, "Every row has the required fields", bad=f"missing: {dict(missing)}")
    if missing: return None
    ids = [r["alert_id"] for r in rows]
    check(len(ids) == len(set(ids)), "alert_id values are unique", bad=f"{len(ids) - len(set(ids))} duplicates")
    finite = all(math.isfinite(float(r["anomaly_score"])) and math.isfinite(float(r["threshold"])) for r in rows)
    check(finite, "Scores and thresholds are finite numbers")
    check(len({r["threshold"] for r in rows}) == 1, "One threshold for the whole stream", bad=f"{len({r['threshold'] for r in rows})} different thresholds")
    thr = rows[0]["threshold"]
    check(abs(thr - EXPECTED_THRESHOLD) < 1e-9, "Stream threshold is the tuned checkpoint's", str(thr), f"{thr} differs from {EXPECTED_THRESHOLD}", "WARN")
    bad_flag = [r["alert_id"] for r in rows if bool(r["detected"]) != (float(r["anomaly_score"]) >= float(r["threshold"]))]
    check(not bad_flag, "detected always equals score >= threshold", bad=f"{len(bad_flag)} rows disagree (wrong threshold or scores?)")
    check(all(isinstance(r["_simulator_attack"], bool) for r in rows), "_simulator_attack is a boolean on every row")
    check(all(r["verification_result"] in VERDICTS for r in rows), "Verification verdicts are valid")

    labelled = [r for r in rows if r.get("_attack_label")]
    if not labelled:
        report("WARN", "Rows carry _attack_label", "absent; per-family checks skipped")
        return rows
    leaks = []
    for r in labelled:
        label = r["_attack_label"]
        if label == "BenignTraffic": continue
        visible = json.dumps({k: v for k, v in r.items() if not k.startswith("_")})
        if label in visible: leaks.append(r["alert_id"])
    check(not leaks, "Dataset labels never appear in anything the policy or report sees", bad=f"{len(leaks)} rows leak the label (sample_id, query or report text)")

    by = defaultdict(lambda: [0, 0])
    for r in labelled:
        by[r["_attack_label"]][0] += 1
        by[r["_attack_label"]][1] += bool(r["detected"])
    print(f"      {'family':24s} {'rows':>6s} {'flagged':>8s} {'rate':>6s}")
    for label, (n, f) in sorted(by.items()):
        print(f"      {label:24s} {n:6d} {f:8d} {f / n:6.0%}")
    fp = by["BenignTraffic"][1] if "BenignTraffic" in by else 0
    tp = sum(f for label, (n, f) in by.items() if label != "BenignTraffic")
    check(fp >= 50, "Enough benign flows flagged to test false-positive handling", f"{fp} flagged benign flows", f"only {fp}; the comparison needs false positives", "WARN")
    check(tp >= 50, "Enough flagged attacks", f"{tp}", f"only {tp}", "WARN")
    if "BenignTraffic" in by:
        rate = by["BenignTraffic"][1] / by["BenignTraffic"][0]
        check(0.02 <= rate <= 0.10, "Benign flag rate is near the detector's ~5% FPR", f"{rate:.1%}", f"{rate:.1%} is far from the expected ~5% (wrong threshold, scaling or sampling?)", "WARN")
    for fam in FLOOD_FAMILIES:
        if fam in by:
            check(by[fam][1] / by[fam][0] >= 0.9, f"{fam} is mostly flagged", f"{by[fam][1] / by[fam][0]:.0%}", f"only {by[fam][1] / by[fam][0]:.0%} flagged", "WARN")
    return rows


# ---------------------------------------------------------------- F. replay
def stable(result):
    drop = {"policy_training_update_seconds", "total_elapsed_seconds"}
    return json.dumps({**{k: v for k, v in result.items() if k not in drop},
                       "metrics": [{k: v for k, v in m.items() if k not in drop} for m in result["metrics"]]}, sort_keys=True)


def section_replay(rows, seeds, folds):
    section(f"F. Replay invariants and policy comparison (seeds {seeds}, {folds} folds)")
    import run_response_experiment as replay
    flagged = sum(bool(r["detected"]) for r in rows)
    family = {r["alert_id"]: r.get("_attack_label", "?") for r in rows}
    per_seed, ledgers = {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        for seed in seeds:
            out = Path(tmp) / f"seed{seed}"
            result = replay.run_replay(rows, out, seed=seed, folds=folds, stream_source="e2e_check")
            per_seed[seed] = result
            ledgers[seed] = [json.loads(line) for line in (out / "action_ledger.jsonl").read_text().splitlines()]
        first = per_seed[seeds[0]]
        check(first["routed_alerts"] == flagged, "Only flagged flows are routed", f"{first['routed_alerts']} routed of {len(rows)}",
              f"routed {first['routed_alerts']} but {flagged} are flagged")
        for m in first["metrics"]:
            check(m["alerts_processed"] == flagged and sum(m["action_distribution"].values()) == flagged,
                  f"{m['policy']}: every routed alert evaluated exactly once", bad="counts do not add up")
        unsafe = [t for t in ledgers[seeds[0]] if t.get("phase") == "evaluation" and t["policy"].startswith("Contextual")
                  and t["selected_action"] == "AUTO_REMEDIATE" and not (t["alert"]["detected"] and float(t["alert"]["verification_confidence"]) >= 0.85)]
        check(not unsafe, "The bandit never auto-remediates an ineligible alert", bad=f"{len(unsafe)} unsafe auto-remediations")
        again = replay.run_replay(rows, Path(tmp) / "again", seed=seeds[0], folds=folds, stream_source="e2e_check")
        check(stable(again) == stable(first), "Same seed gives identical results (reproducible)", bad="two runs with the same seed differ")
        check(first["reward_version"], "Reward version recorded", first["reward_version"])

        names = [m["policy"] for m in first["metrics"]]
        table = {name: [next(m for m in per_seed[s]["metrics"] if m["policy"] == name)["mean_reward_per_alert"] for s in seeds] for name in names}
        print(f"\n      mean reward per alert over seeds {seeds}")
        print(f"      {'policy':38s} {'mean':>7s} {'std':>6s}   per seed")
        for name, values in table.items():
            std = statistics.stdev(values) if len(values) > 1 else float("nan")
            print(f"      {name:38s} {statistics.fmean(values):7.2f} {std:6.2f}   {[round(v, 2) for v in values]}")
        bandit, fixed, human, rand = (table[n] for n in names)
        wins = sum(b > f for b, f in zip(bandit, fixed)); ties = sum(b == f for b, f in zip(bandit, fixed))
        report("INFO", "Bandit vs fixed rules", f"better in {wins}, tied in {ties}, worse in {len(seeds) - wins - ties} of {len(seeds)} seeds (no significance claimed)")
        check(statistics.fmean(bandit) >= statistics.fmean(rand), "Bandit does at least as well as random", bad="bandit is below random: check the reward table and stream", bad_level="WARN")

        fam = defaultdict(lambda: defaultdict(list))
        for t in ledgers[seeds[0]]:
            if t.get("phase") == "evaluation":
                fam[family.get(t["alert"]["alert_id"], "?")][t["policy"]].append(t["reward"])
        print(f"\n      mean reward by family (seed {seeds[0]}, routed alerts only)")
        print("      " + f"{'family':24s}" + "".join(f"{n[:14]:>16s}" for n in names))
        for label in sorted(fam):
            print("      " + f"{label:24s}" + "".join(f"{statistics.fmean(fam[label][n]):16.2f}" if fam[label][n] else f"{'-':>16s}" for n in names) + f"   n={len(fam[label][names[0]])}")


# ---------------------------------------------------------------- G. prevalence sweep
def section_prevalence(rows, levels, seeds, folds):
    section("G. Policy comparison across the share of real attacks among flagged alerts")
    import random
    import run_response_experiment as replay
    from services.bandit_service import decision_regions
    routed = [r for r in rows if r["detected"]]
    attacks = [r for r in routed if r["_simulator_attack"]]
    benign = [r for r in routed if not r["_simulator_attack"]]
    if len(attacks) < 20 or len(benign) < 20:
        report("WARN", "Prevalence sweep skipped", f"needs at least 20 flagged attacks and 20 flagged benign flows (have {len(attacks)} and {len(benign)})")
        return
    print("      With the reward table in use, the best constant action by attack share p is:")
    print("      " + "; ".join(f"{r['action']} for p {r['from']:.2f}-{r['to']:.2f}" for r in decision_regions()))
    names = list(replay.POLICIES)
    print(f"\n      {'attack share':>12s} {'alerts':>7s} " + "".join(f"{n[:16]:>18s}" for n in names))
    with tempfile.TemporaryDirectory() as tmp:
        for p in levels:
            means = {n: [] for n in names}
            size = 0
            for seed in seeds:
                rng = random.Random(seed)
                n_b = min(len(benign), int(len(attacks) * (1 - p) / p))
                n_a = round(n_b * p / (1 - p))
                subset = rng.sample(benign, n_b) + rng.sample(attacks, min(n_a, len(attacks)))
                size = len(subset)
                result = replay.run_replay(subset, Path(tmp) / f"p{int(p * 100)}_s{seed}", seed=seed, folds=folds, stream_source="prevalence sweep")
                for m in result["metrics"]: means[m["policy"]].append(m["mean_reward_per_alert"])
            print(f"      {p:12.0%} {size:7d} " + "".join(f"{statistics.fmean(means[n]):18.2f}" for n in names))
    print("\n      Read this as a map of when each policy is the right one, not as a single score: the winner changes with the share of attacks.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--stream", type=Path, help="JSONL replay stream to check and replay")
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--tests", action="store_true", help="also run the backend unit tests")
    parser.add_argument("--prevalence", type=float, nargs="+", help="attack shares among flagged alerts to sweep, e.g. 0.1 0.3 0.5 0.8")
    parser.add_argument("--skip-api", action="store_true")
    parser.add_argument("--skip-ledger", action="store_true", help="API checks without writing alerts or feedback")
    parser.add_argument("--reset-policy-after", action="store_true")
    args = parser.parse_args()

    section_environment()
    if args.tests: section_tests()
    section_retrieval()
    if args.skip_api: report("INFO", "API checks skipped (--skip-api)")
    else: section_api(args.api.rstrip("/"), not args.skip_ledger, args.reset_policy_after)
    if args.stream:
        rows = section_stream(args.stream)
        if rows: section_replay(rows, args.seeds, args.folds)
        if rows and args.prevalence: section_prevalence(rows, args.prevalence, args.seeds, args.folds)
    else:
        report("INFO", "No --stream given; stream and replay checks skipped")

    counts = Counter(level for level, _, _ in RESULTS)
    print(f"\n=== Summary: {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL ===")
    for level, name, detail in RESULTS:
        if level == "FAIL": print(f"  FAIL: {name} - {detail}")
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
