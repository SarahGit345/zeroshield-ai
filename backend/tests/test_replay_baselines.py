"""Fold baselines (plan B3-B5): labels never enter a decision, fitting uses the training folds only,
the AUTO safety mask is respected, and each baseline does what its definition says."""
import csv
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_response_experiment as replay
from services import replay_baselines as rb
from services.bandit_service import ACTIONS, REWARD_TABLES, BanditService

V2 = REWARD_TABLES["designed-simulation-v2"]


def alert(i, score, attack, conf=1.0, detected=True, techniques=False):
    return {"alert_id": f"a{i:03d}", "sample_id": "x", "anomaly_score": score, "threshold": .1, "detected": detected,
            "verification_result": "VERIFIED", "verification_confidence": conf,
            "xai_evidence": [{"feature": "Rate", "contribution": score / 2}],
            "retrieved_techniques": [{"technique_id": "T1"}] if techniques else [], "_simulator_attack": attack, "_family": "F"}


def make_stream(n=80, seed=4):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        attack = rng.random() < .5
        out.append(alert(i, rng.uniform(.3, .5) if attack else rng.uniform(.1, .3), attack,
                         conf=1.0 if rng.random() < .8 else .8, techniques=rng.random() < .5))
    return out


def decisions(run_dir):
    with (run_dir / "evaluation_decisions.csv").open(encoding="utf-8") as f:
        return {(r["policy"], r["alert_id"]): r["selected_action"] for r in csv.DictReader(f)}


class LabelIsolationTests(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.out = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()

    def test_flipping_held_out_labels_changes_no_held_out_decision(self):
        stream = make_stream()
        replay.run_replay(stream, self.out / "a", seed=5, write_ledger=False)
        routed, _ = replay.route(stream)
        fold0 = {a["alert_id"] for a in replay.make_folds(routed, 5, 5)[0]}
        flipped = [{**a, "_simulator_attack": not a["_simulator_attack"]} if a["alert_id"] in fold0 else a for a in stream]
        replay.run_replay(flipped, self.out / "b", seed=5, write_ledger=False)
        a, b = decisions(self.out / "a"), decisions(self.out / "b")
        for policy in replay.POLICIES:
            for aid in fold0:
                self.assertEqual(a[(policy, aid)], b[(policy, aid)], f"{policy} changed its decision on held-out {aid}")

    def test_baselines_never_receive_hidden_keys_and_fit_on_training_folds_only(self):
        stream = make_stream()
        routed, _ = replay.route(stream)
        folds = replay.make_folds(routed, 5, 7)
        fitted_on, acted_on = [], []
        originals = {cls: (cls.fit, cls.act) for cls in rb.FOLD_BASELINES}

        def spy(cls):
            fit, act = originals[cls]
            def fit_spy(self, alerts, labels, table):
                self.assertion_ids = [x["alert_id"] for x in alerts]
                assert not any(k.startswith("_") for x in alerts for k in x), "hidden key reached fit()"
                assert len(labels) == len(alerts)
                fitted_on.append((cls, frozenset(self.assertion_ids)))
                return fit(self, alerts, labels, table)
            def act_spy(self, x):
                assert not any(k.startswith("_") for k in x), "hidden key reached act()"
                acted_on.append((cls, x["alert_id"], frozenset(self.assertion_ids)))
                return act(self, x)
            return fit_spy, act_spy

        patches = []
        for cls in rb.FOLD_BASELINES:
            f, a = spy(cls)
            patches += [patch.object(cls, "fit", f), patch.object(cls, "act", a)]
        for p in patches: p.start()
        try:
            replay.run_replay(stream, self.out / "r", seed=7, write_ledger=False)
        finally:
            for p in patches: p.stop()
        expected_train = [frozenset(a["alert_id"] for i, f in enumerate(folds) if i != k for a in f) for k in range(len(folds))]
        for cls in rb.FOLD_BASELINES:
            self.assertEqual([ids for c, ids in fitted_on if c is cls], expected_train)
        for cls, aid, train_ids in acted_on:
            self.assertNotIn(aid, train_ids)                 # never decides an alert it was fitted on
        self.assertEqual(len(acted_on), len(routed) * len(rb.FOLD_BASELINES))


class MaskTests(unittest.TestCase):
    def test_mask_matches_the_bandit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bandit = BanditService(Path(tmp) / "m.sqlite3", seed=1)
            for detected in (True, False):
                for conf in (1.0, .9, .85, .84, .5):
                    a = alert(0, .3, True, conf=conf, detected=detected)
                    self.assertEqual(rb.auto_eligible(a), bandit.select(a)["auto_remediation_eligible"])

    def test_no_baseline_auto_remediates_an_ineligible_alert(self):
        train = [alert(i, .4, True) for i in range(30)]          # all attacks: AUTO would be best everywhere
        labels = [True] * 30
        risky = alert(99, .45, True, conf=.8)                     # ineligible
        for cls in rb.FOLD_BASELINES:
            policy = cls().fit(train, labels, V2)
            self.assertEqual(policy.act(alert(98, .45, True))["selected_action"], "AUTO_REMEDIATE", cls.name)
            self.assertNotEqual(policy.act(risky)["selected_action"], "AUTO_REMEDIATE", cls.name)


class DefinitionTests(unittest.TestCase):
    def test_best_constant_action_is_the_training_argmax(self):
        train = [alert(i, .3, i < 6) for i in range(10)]          # attack share 0.6 -> confirm under v2
        policy = rb.BestConstantAction().fit(train, [i < 6 for i in range(10)], V2)
        self.assertEqual(policy.act(alert(50, .2, False))["selected_action"], "CONFIRM_TO_ACT")
        policy = rb.BestConstantAction().fit(train, [i < 1 for i in range(10)], V2)   # share 0.1 -> monitor
        self.assertEqual(policy.act(alert(50, .2, False))["selected_action"], "MONITOR_ONLY")

    def test_supervised_policy_separates_by_score_and_uses_expected_reward(self):
        train = [alert(i, .4 + i * 1e-3, True) for i in range(40)] + [alert(100 + i, .11 + i * 1e-3, False) for i in range(40)]
        labels = [True] * 40 + [False] * 40
        policy = rb.SupervisedExpectedReward().fit(train, labels, V2)
        high, low = policy.act(alert(200, .45, False)), policy.act(alert(201, .1, False))
        self.assertEqual(high["selected_action"], "AUTO_REMEDIATE")
        self.assertEqual(low["selected_action"], "MONITOR_ONLY")
        p = high["p_attack"]
        self.assertAlmostEqual(high["action_scores"]["CONFIRM_TO_ACT"], p * 3 + (1 - p) * -3)

    def test_supervised_policy_with_one_class_falls_back_to_its_rate(self):
        policy = rb.SupervisedExpectedReward().fit([alert(i, .3, False) for i in range(5)], [False] * 5, V2)
        self.assertEqual(policy.act(alert(9, .3, False))["p_attack"], 0.0)
        self.assertEqual(policy.act(alert(9, .3, False))["selected_action"], "MONITOR_ONLY")

    def test_score_tier_rule_learns_tiers_from_training(self):
        train = [alert(i, .1 + .004 * i, i >= 50) for i in range(100)]   # low half benign, high half attack
        policy = rb.ScoreTierRule().fit(train, [i >= 50 for i in range(100)], V2)
        self.assertLessEqual(policy.c1, policy.c2)
        self.assertEqual(policy.act(alert(500, .12, False))["selected_action"], "MONITOR_ONLY")
        self.assertEqual(policy.act(alert(501, .48, True))["selected_action"], "AUTO_REMEDIATE")
        self.assertAlmostEqual(policy.train_mean_reward, (50 * 1 + 50 * 5) / 100)     # perfect split found

    def test_score_tier_rule_is_deterministic(self):
        stream = make_stream()
        labels = [a["_simulator_attack"] for a in stream]
        clean = [replay.clean(a) for a in stream]
        a = rb.ScoreTierRule().fit(clean, labels, V2)
        b = rb.ScoreTierRule().fit(clean, labels, V2)
        self.assertEqual((a.c1, a.c2, a.tier_means), (b.c1, b.c2, b.tier_means))

    def test_policy_list_and_names(self):
        self.assertEqual(replay.POLICIES[0], replay.BANDIT_POLICY)
        self.assertIn("Verification-gate rule (strawman on this stream)", replay.POLICIES)
        self.assertEqual(len(replay.POLICIES), 7)
        for cls in rb.FOLD_BASELINES: self.assertIn(cls.name, replay.POLICIES)
        self.assertEqual(set(ACTIONS), {"AUTO_REMEDIATE", "CONFIRM_TO_ACT", "HUMAN_REVIEW", "MONITOR_ONLY"})


if __name__ == "__main__":
    unittest.main()
