"""Plan amendment 9: context masking, the bandit-only replay harness, and the deletion measure."""
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

import ablate_policy_xai as ab
from services.bandit_service import build_context

ALERT = {"alert_id": "a1", "anomaly_score": 0.3, "threshold": 0.06, "detected": True, "verification_confidence": 0.8,
         "xai_evidence": [{"feature": "Rate", "value": 2.0, "contribution": 0.2, "rank": 1}],
         "retrieved_techniques": [{"technique_id": "T1498"}]}


class Masking(unittest.TestCase):
    def ctx(self, cond):
        return build_context(ab.mask(ALERT, cond))

    def test_each_condition_changes_only_its_group(self):
        full = build_context(ALERT)                  # [1, score, detected, verif, xai_frac, xai_mag, mitre]
        self.assertEqual(self.ctx("full"), full)
        self.assertEqual(self.ctx("no_score")[1], 1.0); self.assertEqual(self.ctx("no_score")[2:], full[2:])
        self.assertEqual(self.ctx("no_xai")[4:6], [0.0, 0.0]); self.assertEqual(self.ctx("no_xai")[:4], full[:4])
        self.assertEqual(self.ctx("no_attack")[6], 0.0); self.assertEqual(self.ctx("no_attack")[:6], full[:6])
        self.assertEqual(self.ctx("no_verification")[3], 1.0)
        self.assertEqual(self.ctx("score_only")[1], full[1])
        self.assertEqual(self.ctx("score_only")[3:], [1.0, 0.0, 0.0, 0.0])

    def test_mask_never_adds_label_and_does_not_mutate_input(self):
        before = json.dumps(ALERT, sort_keys=True)
        for c in ab.CONDITIONS:
            self.assertFalse(any(k.startswith("_") for k in ab.mask(ALERT, c)))
        self.assertEqual(json.dumps(ALERT, sort_keys=True), before)


class Harness(unittest.TestCase):
    def test_bandit_only_replay_evaluates_every_flagged_alert_once(self):
        rows = []
        for i in range(30):
            attack = i % 3 == 0
            rows.append({"alert_id": f"x{i}", "sample_id": f"s{i}", "timestamp": "2026-11-15T00:00:00+00:00",
                         "anomaly_score": 0.2 if attack else 0.07, "threshold": 0.06, "detected": True,
                         "verification_confidence": 1.0, "xai_evidence": ALERT["xai_evidence"], "retrieved_techniques": [],
                         "feature_summary": {}, "_simulator_attack": attack, "_family": "DDoS" if attack else "Benign"})
        rows.append({**rows[0], "alert_id": "u", "detected": False})          # unflagged: must be routed out
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"; p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            out = ab.replay_condition(str(p), "full", 0.25, seed=1, folds=3)
        self.assertEqual(sorted(r[0] for r in out), sorted(f"x{i}" for i in range(30)))


class RowLoader(unittest.TestCase):
    def test_rows_are_fetched_by_source_and_position_in_feature_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            v, z = Path(tmp) / "v.csv", Path(tmp) / "z.csv"
            v.write_text("b,a,label\n1,10,x\n2,20,x\n3,30,x\n", encoding="utf-8")
            z.write_text("b,a,label\n7,70,y\n", encoding="utf-8")
            alerts = [{"_source": "validation", "_source_row": 2}, {"_source": "zero_day", "_source_row": 0}]
            X = ab.matrix(alerts, ["a", "b"], paths=(v, z), cache=Path(tmp) / "c.npz", chunk_rows=2)
            self.assertEqual(X.tolist(), [[30.0, 3.0], [70.0, 7.0]])
            v.unlink(); z.unlink()                       # second call must come from the cache
            self.assertEqual(ab.matrix(alerts, ["a", "b"], paths=(v, z), cache=Path(tmp) / "c.npz").tolist(), X.tolist())


class Deletion(unittest.TestCase):
    def test_removal_is_share_of_score_and_empty_set_removes_nothing(self):
        class Fake:
            def score_batch(self, X): return (X ** 2).sum(axis=1)
        X = np.array([[2.0, 1.0, 1.0]]); s0 = Fake().score_batch(X)
        share, after = ab.removal(Fake(), X, s0, [[0]])
        self.assertAlmostEqual(float(share[0]), 4 / 6); self.assertAlmostEqual(float(after[0]), 2.0)
        self.assertAlmostEqual(float(ab.removal(Fake(), X, s0, [[]])[0][0]), 0.0)


if __name__ == "__main__":
    unittest.main()
