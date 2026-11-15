"""Plan amendments 13 (operating points), 14 (benign-reference occlusion), 15 (score-gated ATT&CK)."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

import analyze_operating_points as op
import evaluate_mapping as em
import xai_benign_reference as xb
from services import technique_plausibility as tp


class OperatingPoints(unittest.TestCase):
    def test_thresholds_include_deployed_and_are_sorted(self):
        th = op.threshold_set(np.arange(1, 101, dtype=float), deployed=95.5, percentiles=(90, 99))
        self.assertIn("deployed", th)
        self.assertEqual(list(th.values()), sorted(th.values()))

    def test_count_at_or_above_counts_ties(self):
        self.assertEqual(op.count_at_or_above([1, 2, 2, 3], [2, 3, 4]).tolist(), [3, 1, 0])

    def test_summary_fpr_and_row_weighted_recall(self):
        counts = {("validation", "Benign"): np.array([5]), ("validation", "DDoS"): np.array([90]),
                  ("validation", "Recon"): np.array([1])}
        totals = {("validation", "Benign"): 100, ("validation", "DDoS"): 100, ("validation", "Recon"): 10}
        r = op.summarise(counts, totals, ["deployed"], [0.06])["per_threshold"]["deployed"]
        self.assertAlmostEqual(r["validation_benign_fpr"], 0.05)
        self.assertAlmostEqual(r["overall_attack_recall_row_weighted"], 91 / 110)


def toy_score(X):
    return (np.asarray(X, dtype=float) ** 2).sum(axis=1)


class BenignReference(unittest.TestCase):
    def test_contribution_is_drop_to_reference(self):
        X = np.array([[3.0, 1.0]])
        s0, c = xb.contributions(toy_score, X, np.array([1.0, 1.0]))
        self.assertEqual(s0.tolist(), [10.0])
        self.assertEqual(c.tolist(), [[8.0, 0.0]])

    def test_removal_resets_to_reference_not_zero(self):
        X = np.array([[3.0, 2.0]])
        share, after = xb.removal(toy_score, X, toy_score(X), [[0, 1]], np.array([1.0, 1.0]))
        self.assertEqual(after.tolist(), [2.0])
        self.assertAlmostEqual(share[0], 11 / 13)

    def test_deletion_runs_and_top_beats_random_on_toy(self):
        X = np.array([[5.0, 0.1, 0.1, 0.1, 0.1, 0.1]] * 4)
        res, _ = xb.deletion(toy_score, 1.0, X, np.zeros(6), ["A", "A", "B", "B"], draws=3)
        self.assertGreater(res["k"]["1"]["top_minus_random"], 0)

    def test_pre_stated_reading(self):
        good = {"k": {k: {"top_minus_random_ci95": [0.1, 0.2], "top_removed": 0.5} for k in ("1", "3", "5")}}
        bad = {"k": {**good["k"], "5": {"top_minus_random_ci95": [0.1, 0.2], "top_removed": -0.1}}}
        self.assertTrue(xb.faithful_beyond_top({"S": good}))
        self.assertFalse(xb.faithful_beyond_top({"S": good, "T": bad}))


class ScoreGate(unittest.TestCase):
    def rows(self):
        return [{"family": "Benign", "score": 0.07, "candidates": {em.METHOD_GUARDED: ["T1498"]}},
                {"family": "DDoS", "score": 0.50, "candidates": {em.METHOD_GUARDED: ["T1498"]}},
                {"family": "Recon", "score": 0.08, "candidates": {em.METHOD_GUARDED: ["T1046"]}}]

    def test_gate_removes_low_score_context_only(self):
        out = em.add_gate(self.rows(), 2.0, 0.0614)
        self.assertEqual([r["candidates"][em.METHOD_GATED] for r in out], [[], ["T1498"], []])
        self.assertEqual(em.lost_context(out), {"DDoS": 0.0, "Recon": 1.0})

    def test_gate_frozen_to_tuning_winner(self):
        self.assertEqual(tp.A15_FROZEN_GATE, "gate-3x")
        self.assertTrue(tp.passes_score_gate(0.1228, 0.0614, 2.0))
        self.assertFalse(tp.passes_score_gate(0.1, 0.0614, 2.0))

    def test_one_time_test_refuses_before_freeze_and_twice(self):
        with mock.patch.object(tp, "A15_FROZEN_GATE", None), self.assertRaises(RuntimeError):
            em.test15_once(None, 0.0614)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(tp, "A15_FROZEN_GATE", "gate-2x"):
            (Path(tmp) / "test_s10c.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                em.test15_once(None, 0.0614, out_dir=Path(tmp))


if __name__ == "__main__":
    unittest.main()
