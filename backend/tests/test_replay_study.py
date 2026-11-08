"""Reward-version plumbing and the multi-seed study: the bandit trains and is scored under the
requested table, every rewarded record stores that version, the paired bootstrap is arithmetically
right, ties are reported as ties, per-family results cover every routed family, and oracles stay
separate from baselines."""
import json
import random
import tempfile
import unittest
from pathlib import Path

import numpy as np

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
        stream.append({"alert_id": f"a{i:03d}", "sample_id": "x",
                       "anomaly_score": rng.uniform(.2, .5) if attack else rng.uniform(.07, .2), "threshold": .0614,
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

    def test_ledger_can_be_skipped_but_decisions_are_always_written(self):
        replay.run_replay(make_stream(), Path(self.tmp.name) / "r", seed=3, write_ledger=False)
        self.assertFalse((Path(self.tmp.name) / "r" / "action_ledger.jsonl").exists())
        self.assertTrue((Path(self.tmp.name) / "r" / "evaluation_decisions.csv").exists())


class BootstrapTests(unittest.TestCase):
    def test_identical_policies_are_a_tie(self):
        boot = study.stratified_bootstrap_means(np.zeros((40, 1)), np.array([0, 1] * 20))
        ci = study.interval(boot[:, 0], .95)
        self.assertEqual(study.verdict_from_interval(ci), "no difference shown")

    def test_clear_difference_is_detected_and_mean_is_right(self):
        rng = np.random.default_rng(0)
        diffs = (1.0 + rng.normal(0, .1, 200))[:, None]
        groups = np.array([0] * 150 + [1] * 50)
        boot = study.stratified_bootstrap_means(diffs, groups)
        self.assertAlmostEqual(boot.mean(), diffs.mean(), places=2)
        self.assertEqual(study.verdict_from_interval(study.interval(boot[:, 0], .95)), "bandit better")
        self.assertEqual(study.verdict_from_interval(study.interval(-boot[:, 0], .95)), "bandit worse")

    def test_stratification_keeps_group_sizes(self):
        # One group always +1, the other always -1: every stratified resample has exactly the original mix.
        diffs = np.array([1.0] * 30 + [-1.0] * 10)[:, None]
        boot = study.stratified_bootstrap_means(diffs, np.array([0] * 30 + [1] * 10), resamples=200)
        np.testing.assert_allclose(boot[:, 0], 0.5)

    def test_bootstrap_is_reproducible(self):
        diffs = np.random.default_rng(1).normal(0, 1, (30, 2))
        a = study.stratified_bootstrap_means(diffs, np.zeros(30, dtype=int), resamples=300)
        b = study.stratified_bootstrap_means(diffs, np.zeros(30, dtype=int), resamples=300)
        np.testing.assert_array_equal(a, b)


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.out = Path(self.tmp.name)
        self.stream = make_stream()
        self.versions = ["designed-simulation-v2", "sens-v2-missed-attack-12"]
        self.result = study.run_study(self.stream, self.out, seeds=[1, 2, 3], folds=5, versions=self.versions)

    def tearDown(self): self.tmp.cleanup()

    def test_per_seed_means_match_the_individual_runs(self):
        for version in self.versions:
            for policy in replay.POLICIES:
                values = [next(m for m in json.loads((self.out / version / f"seed{s}" / "policy_comparison_metrics.json").read_text())["metrics"]
                               if m["policy"] == policy)["mean_reward_per_alert"] for s in (1, 2, 3)]
                self.assertEqual(self.result["versions"][version]["policies"][policy]["per_seed"], values)

    def test_mean_difference_equals_difference_of_seed_averaged_means(self):
        for version in self.versions:
            v = self.result["versions"][version]
            bandit = np.mean(v["policies"][study.BANDIT]["per_seed"])
            for base, c in v["comparisons"].items():
                self.assertAlmostEqual(c["mean_difference"], bandit - np.mean(v["policies"][base]["per_seed"]))
                self.assertLessEqual(c["ci95"][0], c["ci95"][1])
                self.assertEqual(c["seeds_bandit_higher"] + c["seeds_tied"] + c["seeds_bandit_lower"], 3)

    def test_every_baseline_is_compared_and_oracles_are_not_baselines(self):
        v = self.result["versions"]["designed-simulation-v2"]
        self.assertEqual(set(v["comparisons"]), set(replay.POLICIES) - {study.BANDIT})
        self.assertFalse(any("oracle" in name.lower() or "labels" in name.lower() for name in v["comparisons"]))
        oracle = v["oracle_references"]["per-alert best action (labels)"]["mean_reward"]
        for policy in replay.POLICIES:
            self.assertLessEqual(v["policies"][policy]["mean_reward_per_alert"]["max"], oracle + 1e-12)

    def test_mistakes_section_is_consistent(self):
        mk = self.result["versions"]["designed-simulation-v2"]["bandit_mistakes"]
        self.assertAlmostEqual(mk["benign_mean_reward_always_review"], REWARD_TABLES["designed-simulation-v2"]["benign"]["HUMAN_REVIEW"])
        self.assertAlmostEqual(mk["benign_difference_bandit_minus_review"], mk["benign_mean_reward_bandit"] - mk["benign_mean_reward_always_review"])
        self.assertGreaterEqual(mk["false_positives_auto_remediated_share"], 0)
        self.assertLessEqual(mk["false_positives_auto_remediated_share"], 1)

    def test_per_family_covers_routed_families(self):
        routed, _ = replay.route(self.stream)
        v = self.result["versions"]["designed-simulation-v2"]
        for policy in replay.POLICIES:
            self.assertEqual(set(v["per_family"][policy]), {a["_family"] for a in routed})
            for row in v["per_family"][policy].values():
                self.assertAlmostEqual(sum(row["action_share"].values()), 1.0)

    def test_summary_files_written(self):
        text = (self.out / "study_summary.md").read_text(encoding="utf-8")
        for needle in ("Primary comparison", "paired-bootstrap", "mistakes", "Oracle references", "sens-v2-missed-attack-12"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
