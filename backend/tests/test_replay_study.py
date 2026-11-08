"""Reward-version plumbing and the multi-seed study: the bandit trains and is scored under the
requested table, every rewarded record stores that version, aggregation is arithmetically
right, ties are reported as ties, and per-family results cover every routed family."""
import json
import random
import statistics
import tempfile
import unittest
from pathlib import Path

import run_replay_study as study
import run_response_experiment as replay
from services.bandit_service import (
    REWARD_TABLES, REWARD_VERSION, SENSITIVITY_REWARD_TABLES, BanditService, reward_table, simulate_outcome,
)

FAMILIES = ["Benign", "DDoS", "Mirai", "Web-Based"]


def make_stream(n=50, seed=2):
    rng = random.Random(seed)
    stream = []
    for i in range(n):
        family = FAMILIES[i % len(FAMILIES)]
        attack = family != "Benign"
        stream.append({"alert_id": f"a{i:03d}", "sample_id": "x", "anomaly_score": rng.uniform(.07, .5), "threshold": .0614,
                       "detected": rng.random() < .85, "verification_result": "VERIFIED",
                       "verification_confidence": 1.0 if rng.random() < .7 else .8,
                       "xai_evidence": [{"feature": "Rate", "contribution": rng.uniform(.01, .3)}],
                       "retrieved_techniques": [], "_simulator_attack": attack, "_family": family, "_attack_label": family})
    return stream


class RewardVersionTests(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory()
    def tearDown(self): self.tmp.cleanup()

    def test_sensitivity_versions_are_named_and_distinct_from_live_tables(self):
        self.assertFalse(set(SENSITIVITY_REWARD_TABLES) & set(REWARD_TABLES))
        tables = [json.dumps(t, sort_keys=True) for t in list(REWARD_TABLES.values()) + list(SENSITIVITY_REWARD_TABLES.values())]
        self.assertEqual(len(tables), len(set(tables)))
        with self.assertRaises(ValueError): reward_table("made-up")
        with self.assertRaises(ValueError): BanditService(Path(self.tmp.name) / "x.sqlite3", reward_version="made-up")

    def test_bandit_feedback_uses_and_stores_its_reward_version(self):
        version = "sens-v2-false-remediation-24"
        service = BanditService(Path(self.tmp.name) / "l.sqlite3", seed=1, reward_version=version)
        alert = make_stream()[0]
        rec = service.record(replay.clean(alert))
        choice = "APPROVED" if rec["selected_action"] == "CONFIRM_TO_ACT" else None
        done = service.feedback(alert["alert_id"], False, choice)
        self.assertEqual(done["reward_version"], version)
        self.assertEqual(done["reward"], simulate_outcome(rec["selected_action"], False, version)["reward"])

    def test_default_service_still_uses_v2(self):
        self.assertEqual(BanditService(Path(self.tmp.name) / "d.sqlite3").reward_version, REWARD_VERSION)

    def test_replay_records_the_requested_version_everywhere(self):
        version = "designed-simulation-v1"
        result = replay.run_replay(make_stream(), Path(self.tmp.name) / "r", seed=3, reward_version=version)
        self.assertEqual(result["reward_version"], version)
        rows = [json.loads(l) for l in (Path(self.tmp.name) / "r" / "action_ledger.jsonl").read_text().splitlines()]
        self.assertTrue(rows)
        for r in rows: self.assertEqual(r["reward_version"], version)
        table = json.loads((Path(self.tmp.name) / "r" / "reward_table.json").read_text())
        self.assertEqual(table["table"], REWARD_TABLES[version])


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.out = Path(self.tmp.name)
        self.stream = make_stream()
        self.versions = ["designed-simulation-v2", "sens-v2-missed-attack-12"]
        self.result = study.run_study(self.stream, self.out, seeds=[1, 2, 3], folds=5, versions=self.versions)

    def tearDown(self): self.tmp.cleanup()

    def test_mean_and_std_match_the_individual_runs(self):
        for version in self.versions:
            for policy in replay.POLICIES:
                per_seed = [json.loads((self.out / version / f"seed{s}" / "policy_comparison_metrics.json").read_text())
                            for s in (1, 2, 3)]
                values = [next(m for m in r["metrics"] if m["policy"] == policy)["mean_reward_per_alert"] for r in per_seed]
                agg = self.result["versions"][version]["policies"][policy]["mean_reward_per_alert"]
                self.assertAlmostEqual(agg["mean"], statistics.fmean(values))
                self.assertAlmostEqual(agg["std"], statistics.stdev(values))

    def test_win_tie_loss_counts_add_up_and_ties_are_counted(self):
        for v in self.result["versions"].values():
            c = v["bandit_minus_fixed"]
            self.assertEqual(c["seeds_bandit_higher"] + c["seeds_tied"] + c["seeds_bandit_lower"], 3)
        self.assertEqual(study.verdict({"n": 3, "seeds_bandit_higher": 0, "seeds_tied": 3, "seeds_bandit_lower": 0}), "tied on every seed")
        self.assertIn("mixed", study.verdict({"n": 3, "seeds_bandit_higher": 1, "seeds_tied": 1, "seeds_bandit_lower": 1}))

    def test_per_family_covers_routed_families_and_rewards_are_consistent(self):
        routed, _ = replay.route(self.stream)
        families = {a["_family"] for a in routed}
        v = self.result["versions"]["designed-simulation-v2"]
        for policy in replay.POLICIES:
            self.assertEqual(set(v["per_family"][policy]), families)
            for row in v["per_family"][policy].values():
                self.assertAlmostEqual(sum(row["action_share"].values()), 1.0)
        # Benign per-family reward for always-HUMAN_REVIEW is exactly the table's benign HUMAN_REVIEW value.
        self.assertAlmostEqual(v["per_family"][replay.POLICIES[2]]["Benign"]["mean_reward"]["mean"],
                               REWARD_TABLES["designed-simulation-v2"]["benign"]["HUMAN_REVIEW"])

    def test_hindsight_oracle_bounds_every_policy(self):
        for v in self.result["versions"].values():
            oracle = v["hindsight_references"]["Oracle (hindsight, labels)"]
            for policy in replay.POLICIES:
                self.assertLessEqual(v["policies"][policy]["mean_reward_per_alert"]["max"], oracle + 1e-12)

    def test_summary_files_written(self):
        self.assertTrue((self.out / "study_summary.json").exists())
        text = (self.out / "study_summary.md").read_text(encoding="utf-8")
        self.assertIn("Per family", text)
        self.assertIn("sens-v2-missed-attack-12", text)


if __name__ == "__main__":
    unittest.main()
