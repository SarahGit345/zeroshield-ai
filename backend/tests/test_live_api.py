"""Live monitor: recorded-flow replay. The dataset label must never reach the pipeline; feedback only after the action."""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from services.bandit_service import BanditService
from services.live_service import LiveReplay


class _StubDetector:
    loaded = False
    def __init__(self, *_a, **_k): self.features = []


with patch.dict(sys.modules, {"services.model_service": types.SimpleNamespace(Detector=_StubDetector)}):
    import main  # noqa: E402

FEATS = ["f1", "f2"]


def write_demo(path, rows):
    path.write_text("f1,f2,label,family\n" + "".join(f"{a},{b},{l},{f}\n" for a, b, l, f in rows), encoding="utf-8")


class LiveReplayTests(unittest.TestCase):
    def test_missing_file_is_reported_not_raised(self):
        live = LiveReplay(Path("does_not_exist.csv"), FEATS)
        self.assertFalse(live.available)
        self.assertIn("build_live_demo.py", live.error)

    def test_cycles_and_separates_truth_from_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "demo.csv"
            write_demo(p, [(1, 2, "BenignTraffic", "Benign"), (3, 4, "DDoS-SYN_Flood", "DDoS")])
            live = LiveReplay(p, FEATS)
            i, feats, truth = live.next()
            self.assertEqual((i, feats, truth["family"]), (0, {"f1": 1.0, "f2": 2.0}, "Benign"))
            self.assertNotIn("label", feats)
            live.next()
            self.assertEqual(live.next()[0], 0)          # wraps around
            self.assertEqual(live.status()["composition"], {"Benign": 1, "DDoS": 1})


class LiveApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = Path(self.tmp.name) / "demo.csv"
        write_demo(p, [(1, 2, "DDoS-SYN_Flood", "DDoS"), (0, 0, "BenignTraffic", "Benign")])
        main.services["live"] = LiveReplay(p, FEATS)
        main.services["live_bandit"] = BanditService(Path(self.tmp.name) / "live.sqlite3", seed=3)
        self.calls = []

        def fake_analyze(features, label=None, *, bandit=None, reasoner=None, attack_mode="default"):
            self.calls.append({"features": features, "label": label, "attack_mode": attack_mode})
            alert = {"alert_id": f"a{len(self.calls)}", "anomaly_score": .2, "threshold": .1, "detected": True,
                     "verification_result": "VERIFIED", "verification_confidence": 1., "xai_evidence": [{"contribution": .04}],
                     "retrieved_techniques": []}
            return {**alert, "bandit": bandit.record(alert), "verification": {"verdict": "VERIFIED"}, "mitre": {}}
        self.patch = patch.object(main, "analyze", fake_analyze)
        self.patch.start()
        self.local = TestClient(main.app)
        self.remote = TestClient(main.app, client=("203.0.113.9", 5000))

    def tearDown(self):
        self.patch.stop(); main.services.clear(); self.tmp.cleanup()

    def test_label_never_passed_to_pipeline_and_revealed_after(self):
        r = self.local.post("/api/live/next", json={"count": 2, "attack_mode": "gated"}).json()
        self.assertEqual([c["label"] for c in self.calls], [None, None])
        self.assertTrue(all(set(c["features"]) == set(FEATS) for c in self.calls))
        self.assertEqual(self.calls[0]["attack_mode"], "gated")
        self.assertEqual([x["ground_truth"]["family"] for x in r["results"]], ["DDoS", "Benign"])
        self.assertIsNone(r["results"][0]["simulated_feedback"])   # learning off by default

    def test_learning_applies_label_after_the_action(self):
        r = self.local.post("/api/live/next", json={"count": 1, "learn": True}).json()["results"][0]
        self.assertIsNotNone(r["bandit"]["reward"])
        self.assertEqual(r["bandit"]["policy_update_status"], "UPDATED")
        self.assertIn("after the action", r["simulated_feedback"]["source"])

    def test_operator_only_and_bad_mode_rejected(self):
        self.assertEqual(self.remote.post("/api/live/next", json={}).status_code, 403)
        self.assertEqual(self.remote.post("/api/live/reset").status_code, 403)
        self.assertEqual(self.local.post("/api/live/next", json={"attack_mode": "magic"}).status_code, 422)

    def test_unavailable_demo_returns_503(self):
        main.services["live"] = LiveReplay(Path("missing.csv"), FEATS)
        self.assertEqual(self.local.post("/api/live/next", json={}).status_code, 503)


if __name__ == "__main__":
    unittest.main()
