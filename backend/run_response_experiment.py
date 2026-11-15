"""Reproducible replay of the response policy on prepared alerts.

    python run_response_experiment.py                      # ten cached demo samples (too small for claims)
    python run_response_experiment.py --stream alerts.jsonl --folds 5 --seed 20261020

What the replay does, and what it deliberately does not do:
  * Only flows the detector FLAGGED are routed to the response policy. A flow below the
    threshold never becomes an alert in a real system, so no policy acts on it. Unflagged
    flows are counted separately (detector misses / true negatives), not scored as responses.
  * Routed alerts are split into k folds. For each fold a fresh policy trains (with
    exploration and feedback) on the other folds, then is evaluated greedily on the held-out
    fold. Every routed alert is evaluated exactly once. Baselines see the same held-out alerts.
  * The simulator label is read only AFTER an action is chosen, to compute reward. It is never
    part of the policy's context. A CONFIRM_TO_ACT is assumed approved so a reward can be observed.
  * Rewards come from a designed table (see reward_table.json), not measured operational cost.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from services.bandit_service import (  # noqa: E402
    ACTIONS, CONTEXT_FEATURES, REJECTED_APPROVAL_REWARDS, REWARD_VERSION, REWARDS, BanditService,
    always_human_action, build_context, decision_regions, fixed_rule_action, reward_table, simulate_outcome,
)
from services.replay_baselines import FOLD_BASELINES  # noqa: E402

SEED = 20261020
OUT_ROOT = ROOT / "backend" / "experiments" / "contextual_bandit_replay_v1"
BANDIT_POLICY = "Contextual bandit (greedy held-out)"
GATE_POLICY = "Verification-gate rule (strawman on this stream)"
POLICIES = (BANDIT_POLICY, "Always HUMAN_REVIEW", "Random (seeded)", *(b.name for b in FOLD_BASELINES), GATE_POLICY)
BASELINE_TEXT = {"verification_gate": "VERIFIED + detected + confidence>=0.9 -> AUTO_REMEDIATE; else detected -> HUMAN_REVIEW; else MONITOR_ONLY. "
                                      "With template reasoning every alert is VERIFIED at 1.0, so this auto-remediates everything (strawman).",
                 "always_human": "HUMAN_REVIEW for every alert",
                 "random": "Python random.Random(seed), one draw per held-out alert",
                 "best_constant": "Action with the best mean reward on the fold's training alerts (AUTO safety mask per alert)",
                 "supervised": "Logistic regression P(attack) on the 6 non-constant context features (training folds), "
                               "action with the best expected reward under the table, AUTO safety mask",
                 "score_tier": "Up to 3 normalized-score tiers, cut points from training quantiles 0.05..0.95, "
                               "each tier's best training action; pair with the best training mean (AUTO safety mask)"}


def pipeline_alert(detector, mitre, features, alert_id, sample_id, timestamp=None, reason_fn=None, verify_fn=None):
    """Run one prepared flow through detector -> XAI -> retrieval -> reasoning -> verification and
    return the alert record the policy receives. Shared by the demo cache and build_replay_stream.py,
    so both streams carry identical fields. Callers add the `_`-prefixed simulator keys."""
    if reason_fn is None:
        from services.llm_service import reason as reason_fn
    if verify_fn is None:
        from services.verification_service import verify_record as verify_fn
    result = detector.analyze(features)
    mapping = mitre.retrieve_behavior(result)
    reasoning = reason_fn(result, None, mapping)   # no dataset label is passed to the reasoning step
    verified = verify_fn({**result, "feature_names": [x["feature"] for x in result["top_features"]],
                          "all_feature_names": [x["feature"] for x in result["all_contributions"]]}, mapping, reasoning)
    return {
        "alert_id": alert_id, "sample_id": sample_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "feature_summary": {x["feature"]: x["value"] for x in result["top_features"]},
        "anomaly_score": result["anomaly_score"], "threshold": result["threshold"], "detected": result["detected"],
        "xai_evidence": result["top_features"], "retrieval_query": mapping.get("query"),
        "retrieved_techniques": mapping.get("techniques", []), "llm_explanation": reasoning,
        "verification_result": verified["verdict"], "verification_checks": verified["checks"],
        "verification_confidence": verified["verification_confidence"],
    }


def demo_alert_stream():
    """Build alerts from the ten cached prepared samples. Needs PyTorch (loads the detector)."""
    from services.mitre_service import MitreService
    from services.model_service import Detector
    samples = json.loads((ROOT / "backend" / "data" / "demo_samples.json").read_text(encoding="utf-8"))
    detector, mitre = Detector(ROOT), MitreService(ROOT)
    stream = []
    for category, features in samples.items():
        alert = pipeline_alert(detector, mitre, features,   # offline: no API key, labelled template reasoning
                               str(uuid.uuid5(uuid.NAMESPACE_URL, f"zeroshield-demo:{category}")), category)
        stream.append({**alert, "_simulator_attack": category != "BenignTraffic"})
    return stream


def load_stream(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def route(stream):
    """Split into alerts the response stage would actually receive, and flows it never sees."""
    routed = sorted((a for a in stream if a["detected"]), key=lambda a: a["alert_id"])
    unflagged = [a for a in stream if not a["detected"]]
    return routed, {"unflagged_attack_flows": sum(a["_simulator_attack"] for a in unflagged),
                    "unflagged_benign_flows": sum(not a["_simulator_attack"] for a in unflagged),
                    "note": "Flows below the detector threshold never become alerts. They are detector misses or "
                            "true negatives, not response decisions, and are excluded from policy scoring."}


def make_folds(alerts, k, seed):
    order = list(alerts)
    random.Random(seed).shuffle(order)
    k = max(2, min(k, len(order)))
    return [order[i::k] for i in range(k)]


def clean(alert):
    return {k: v for k, v in alert.items() if not k.startswith("_")}


def score_policy(name, decisions, evaluation, reward_version=REWARD_VERSION):
    rewards, counts = [], Counter()
    benign_remediations = attack_remediations = attack_human = attack_monitor = benign_human = 0
    n_attack = n_benign = queue = 0
    for alert, action in zip(evaluation, decisions):
        attack = alert["_simulator_attack"]
        rewards.append(simulate_outcome(action, attack, reward_version)["reward"]); counts[action] += 1
        n_attack += attack; n_benign += not attack
        queue += action == "CONFIRM_TO_ACT"
        if attack and action == "AUTO_REMEDIATE": attack_remediations += 1
        if attack and action == "HUMAN_REVIEW": attack_human += 1
        if attack and action == "MONITOR_ONLY": attack_monitor += 1
        if not attack and action == "AUTO_REMEDIATE": benign_remediations += 1
        if not attack and action == "HUMAN_REVIEW": benign_human += 1
    n = len(evaluation)
    return {"policy": name, "alerts_processed": n, "mean_reward_per_alert": sum(rewards) / max(n, 1),
            "cumulative_reward": sum(rewards), "action_distribution": {a: counts[a] for a in ACTIONS},
            "action_selection_rate": {a: counts[a] / max(n, 1) for a in ACTIONS},
            "benign_remediation_rate": benign_remediations / max(n_benign, 1),
            "attack_remediation_rate": attack_remediations / max(n_attack, 1),
            "attack_human_review_rate": attack_human / max(n_attack, 1),
            "attack_monitor_only_rate": attack_monitor / max(n_attack, 1),
            "benign_human_review_rate": benign_human / max(n_benign, 1),
            "unnecessary_remediation_count": benign_remediations, "missed_attack_count": attack_monitor,
            "approval_queue_size": queue}


def svg_chart(path: Path, title: str, labels, values):
    width, height, margin = 760, 300, 45
    high, low = max(list(values) + [1]), min(list(values) + [0])
    span = max(high - low, 1)
    points = []
    for i, value in enumerate(values):
        x = margin + i * (width - 2 * margin) / max(len(values) - 1, 1)
        y = height - margin - (value - low) / span * (height - 2 * margin)
        points.append(f"{x:.1f},{y:.1f}")
    labels_svg = "".join(f'<text x="{margin+i*(width-2*margin)/max(len(labels)-1,1):.1f}" y="{height-12}" fill="#9aa" font-size="10">{label}</text>' for i, label in enumerate(labels))
    path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="#101820"/><text x="20" y="25" fill="white" font-size="16">{title}</text><polyline points="{" ".join(points)}" fill="none" stroke="#40cbbb" stroke-width="3"/>{labels_svg}</svg>', encoding="utf-8")


def svg_bars(path: Path, title: str, labels, values):
    width, height, left, bottom = 760, 300, 50, 55
    maximum = max(list(values) + [1])
    slot = (width - left - 20) / max(len(values), 1)
    bars = []
    for index, (label, value) in enumerate(zip(labels, values)):
        bar_height = (height - bottom - 50) * value / maximum
        x = left + index * slot + slot * .2
        y = height - bottom - bar_height
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{slot*.6:.1f}" height="{bar_height:.1f}" fill="#40cbbb"/><text x="{x:.1f}" y="{height-30}" fill="#9aa" font-size="10">{label}</text><text x="{x:.1f}" y="{y-5:.1f}" fill="white" font-size="11">{value:g}</text>')
    path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="#101820"/><text x="20" y="25" fill="white" font-size="16">{title}</text>{"".join(bars)}</svg>', encoding="utf-8")


def run_replay(stream, out_dir: Path, seed: int = SEED, folds: int = 5, stream_source: str = "demo cache",
               reward_version: str = REWARD_VERSION, write_ledger: bool = True):
    """Run the k-fold replay on `stream` and write all artifacts to `out_dir`. Returns the metrics dict.
    `reward_version` sets the table used both to train the bandit and to score every policy.
    Fold baselines are fitted on the training folds only (cleaned alerts plus a separate label list).
    `write_ledger=False` skips the large full action ledger; evaluation_decisions.csv is always written."""
    table = reward_table(reward_version)
    started = time.perf_counter()
    routed, not_routed = route(stream)
    if len(routed) < 2:
        raise SystemExit(f"Only {len(routed)} detected alert(s); at least 2 are needed to train and evaluate.")
    fold_sets = make_folds(routed, folds, seed)
    out_dir.mkdir(parents=True, exist_ok=False)

    evaluation, decisions = [], {name: [] for name in POLICIES}
    ledger, traces, per_fold = [], [], {name: [] for name in POLICIES}
    learning_curve, final_versions = [], []
    randomizer = random.Random(seed)
    train_seconds = 0.0
    with tempfile.TemporaryDirectory() as tmp:
        for fold_index, test in enumerate(fold_sets):
            train = [a for i, f in enumerate(fold_sets) if i != fold_index for a in f]
            bandit = BanditService(Path(tmp) / f"fold{fold_index}.sqlite3", seed=seed + fold_index, reward_version=reward_version)
            t0, curve = time.perf_counter(), []
            for alert in train:
                record = bandit.record(clean(alert))
                choice = "APPROVED" if record["selected_action"] == "CONFIRM_TO_ACT" else None
                done = bandit.feedback(alert["alert_id"], bool(alert["_simulator_attack"]), choice)
                ledger.append({**done, "fold": fold_index, "phase": "training"})
                curve.append((curve[-1] if curve else 0) + done["reward"])
            train_seconds += time.perf_counter() - t0
            if fold_index == 0: learning_curve = curve
            final_versions.append(f"linucb-v1+{bandit.updates}")
            train_clean, train_labels = [clean(a) for a in train], [bool(a["_simulator_attack"]) for a in train]
            fitted = [cls().fit(train_clean, train_labels, table) for cls in FOLD_BASELINES]

            fold_actions = {name: [] for name in POLICIES}
            for alert in test:
                c = clean(alert)    # the label is not in this dict; it is read only after the choice, below
                choice = {BANDIT_POLICY: bandit.select(c, explore=False),
                          "Always HUMAN_REVIEW": {"selected_action": always_human_action(c)},
                          "Random (seeded)": {"selected_action": randomizer.choice(ACTIONS)},
                          **{policy.name: policy.act(c) for policy in fitted},
                          GATE_POLICY: {"selected_action": fixed_rule_action(c)}}
                evaluation.append(alert)
                for name, decision in choice.items():
                    action = decision["selected_action"]
                    decisions[name].append(action); fold_actions[name].append(action)
                    outcome = simulate_outcome(action, bool(alert["_simulator_attack"]), reward_version)
                    traces.append({"phase": "evaluation", "fold": fold_index, "alert": c, "policy": name,
                                   "context_features": decision.get("context_features", dict(zip(CONTEXT_FEATURES, build_context(c)))),
                                   "action_scores": decision.get("action_scores"), "selected_action": action,
                                   "policy_version": decision.get("policy_version", "baseline-v1"),
                                   "selection_mode": decision.get("selection_mode", name),
                                   "simulated_execution_status": outcome["execution_status"],
                                   "approval_status": "SIMULATOR_ASSUMES_APPROVED" if action == "CONFIRM_TO_ACT" else "NOT_REQUIRED",
                                   "observed_outcome": outcome["observed_outcome"],
                                   "outcome_source": "offline simulator label; read after selection",
                                   "reward": outcome["reward"], "reward_version": reward_version,
                                   "policy_update_status": "EVALUATION_NO_UPDATE"})
            for name in POLICIES:
                rewards = [simulate_outcome(act, bool(a["_simulator_attack"]), reward_version)["reward"] for a, act in zip(test, fold_actions[name])]
                per_fold[name].append(sum(rewards) / len(rewards))

    metrics = [score_policy(name, decisions[name], evaluation, reward_version) for name in POLICIES]
    for row in metrics:
        row["per_fold_mean_reward"] = per_fold[row["policy"]]
        row["fold_mean_of_means"] = statistics.fmean(per_fold[row["policy"]])
        row["fold_std_of_means"] = statistics.stdev(per_fold[row["policy"]]) if len(per_fold[row["policy"]]) > 1 else None
        row["policy_training_update_seconds"] = train_seconds if row["policy"].startswith("Contextual") else None
    result = {"metrics": metrics, "reward_version": reward_version, "seed": seed, "folds": len(fold_sets),
              "routed_alerts": len(routed), "evaluation_alerts": len(evaluation), "not_routed": not_routed,
              "final_policy_version_per_fold": final_versions, "stream_source": stream_source,
              "total_elapsed_seconds": time.perf_counter() - started}

    if write_ledger:
        with (out_dir / "action_ledger.jsonl").open("w", encoding="utf-8") as f:
            for item in ledger + traces: f.write(json.dumps(item) + "\n")
    with (out_dir / "evaluation_decisions.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alert_id", "fold", "policy", "selected_action", "reward"])
        for t in traces: writer.writerow([t["alert"]["alert_id"], t["fold"], t["policy"], t["selected_action"], t["reward"]])
    (out_dir / "policy_comparison_metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "reward_table.json").write_text(json.dumps({
        "version": reward_version, "table": table, "rejected_approval_outcome": REJECTED_APPROVAL_REWARDS,
        "best_action_by_attack_probability": decision_regions(table),
        "claim": "Designed trade-off only; not real operational cost or optimal policy."}, indent=2), encoding="utf-8")
    (out_dir / "context_schema.json").write_text(json.dumps({"version": "context-v1", "features": CONTEXT_FEATURES, "no_labels_or_future_outcomes": True}, indent=2), encoding="utf-8")
    (out_dir / "baseline_definitions.json").write_text(json.dumps({**BASELINE_TEXT, "seed": seed}, indent=2), encoding="utf-8")
    (out_dir / "approval_queue_statistics.json").write_text(json.dumps({m["policy"]: {"queued": m["approval_queue_size"], "live_approval_simulated": False} for m in metrics}, indent=2), encoding="utf-8")
    (out_dir / "experiment_config.json").write_text(json.dumps({
        "seed": seed, "algorithm": "LinUCB", "alpha": 0.25, "reward_version": reward_version, "reward_table": table,
        "context_schema": {"version": "context-v1", "features": CONTEXT_FEATURES}, "baseline_definitions": BASELINE_TEXT,
        "split": f"{len(fold_sets)}-fold over detected alerts only; each alert evaluated once on a policy that did not train on it",
        "stream": stream_source, "routed_alerts": len(routed), "not_routed": not_routed,
        "approval_simulator_assumption": "CONFIRM_TO_ACT is assumed approved offline so its reward can be observed; this is not live approval.",
        "labels_in_context": False}, indent=2), encoding="utf-8")
    svg_chart(out_dir / "learning_curve.svg", "Training replay cumulative reward (fold 0)", [str(i + 1) for i in range(len(learning_curve))], learning_curve)
    svg_bars(out_dir / "action_distribution.svg", "Held-out action distribution: bandit", list(ACTIONS), [metrics[0]["action_distribution"][a] for a in ACTIONS])
    bandit_row, fixed_row = metrics[0], next(m for m in metrics if m["policy"] == GATE_POLICY)
    (out_dir / "summary.md").write_text(
        f"# Stage 7 replay summary\n\n"
        f"Stream: {stream_source}. {len(stream)} flows, of which {len(routed)} were flagged by the detector and routed to the response policy; "
        f"{not_routed['unflagged_attack_flows']} unflagged attack flow(s) and {not_routed['unflagged_benign_flows']} unflagged benign flow(s) never became alerts and are not scored.\n\n"
        f"Evaluation: {len(fold_sets)}-fold, every routed alert evaluated once by a policy that did not train on it. Reward table: {reward_version}. Seed: {seed}.\n\n"
        f"Bandit mean reward {bandit_row['mean_reward_per_alert']:.2f} per alert (fold std {bandit_row['fold_std_of_means'] if bandit_row['fold_std_of_means'] is None else round(bandit_row['fold_std_of_means'], 2)}); "
        f"verification-gate rule (strawman on this stream) {fixed_row['mean_reward_per_alert']:.2f}. See policy_comparison_metrics.json.\n\n"
        "The reward values are designed simulation trade-offs, not real-world costs. This response policy does not change or improve detector accuracy. "
        "No statistical significance is claimed, and a stream this small supports no general performance claim. "
        "Asset criticality and analyst history are unavailable and were not fabricated. "
        "CONFIRM_TO_ACT is assumed approved in the simulator; live alerts stay pending until an analyst decides.\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Replay the response policy on prepared alerts.")
    parser.add_argument("--stream", type=Path, help="JSONL of prepared alerts (same fields as the demo stream, plus _simulator_attack)")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    os.environ.pop("OPENAI_API_KEY", None)   # keep the experiment independent of credentials and network
    os.environ["ZEROSHIELD_LLM_PROVIDER"] = "template"
    stream = load_stream(args.stream) if args.stream else demo_alert_stream()
    out = OUT_ROOT / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    result = run_replay(stream, out, args.seed, args.folds, str(args.stream) if args.stream else "ten cached demo samples")
    print(json.dumps({"output_directory": str(out), "routed_alerts": result["routed_alerts"], "metrics": result["metrics"]}, indent=2))


if __name__ == "__main__":
    main()
