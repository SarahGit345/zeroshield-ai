"""build_replay_stream.py on small synthetic CSVs: stratified seeded sampling, flagged AND unflagged
rows kept, demo-stream fields plus hidden simulator keys, no label leaking into the policy view,
reproducibility, and chunk-size independence. The fake detector needs no PyTorch."""
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

import build_replay_stream as brs
import run_response_experiment as replay

FEATURES = [f"f{i}" for i in range(43)]
VALIDATION_LABELS = ["BenignTraffic"] * 6 + ["DDoS-SYN_Flood", "DoS-UDP_Flood", "Recon-PortScan", "VulnerabilityScan",
                                             "DictionaryBruteForce", "DNS_Spoofing", "MITM-ArpSpoofing"]
ZERO_DAY_LABELS = ["Mirai-udpplain", "Mirai-greeth_flood", "SqlInjection", "XSS", "Backdoor_Malware"]
QUOTAS = {"benign_flagged": 5, "benign_unflagged": 4, "attack_flagged": 3, "attack_unflagged": 2}


class FakeDetector:
    """Score = squared norm of the first three features; same output shape as services.model_service.Detector."""
    features, threshold = FEATURES, 1.0

    def score_batch(self, matrix):
        return (np.asarray(matrix, dtype=np.float64)[:, :3] ** 2).sum(axis=1)

    def analyze(self, values):
        vector = np.asarray([values[f] for f in FEATURES], dtype=np.float64)
        score = float(self.score_batch(vector[None])[0])
        contributions = []
        for i, name in enumerate(FEATURES):
            masked = vector.copy(); masked[i] = 0.0
            contributions.append({"feature": name, "value": float(vector[i]),
                                  "contribution": score - float(self.score_batch(masked[None])[0]), "rank": 0})
        contributions.sort(key=lambda x: x["contribution"], reverse=True)
        for rank, item in enumerate(contributions, 1): item["rank"] = rank
        return {"anomaly_score": score, "threshold": self.threshold, "detected": score >= self.threshold,
                "detection": "ANOMALOUS" if score >= self.threshold else "NORMAL", "top_features": contributions[:10],
                "all_contributions": contributions, "xai_method": "Feature Perturbation XAI", "xai_baseline": "0"}


class FakeMitre:
    def retrieve_behavior(self, analysis):
        return {"status": "empty_retrieval", "query": "network traffic with test behaviour", "techniques": [],
                "message": "No ATT&CK technique matched the observed behaviour strongly enough."}


def write_csv(path, labels, n, rng):
    frame = pd.DataFrame(rng.normal(0, 0.8, size=(n, len(FEATURES))).astype(np.float32), columns=FEATURES)
    frame["label"] = [labels[i % len(labels)] for i in range(n)]
    frame["binary_label"] = (frame["label"] != "BenignTraffic").astype(int)
    frame.to_csv(path, index=False)
    return frame


class BuildReplayStreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
        rng = np.random.default_rng(0)
        self.validation, self.zero_day = d / "validation.csv", d / "zero_day.csv"
        self.val_frame = write_csv(self.validation, VALIDATION_LABELS, 1300, rng)
        self.zd_frame = write_csv(self.zero_day, ZERO_DAY_LABELS, 500, rng)
        self.sources = [("validation", self.validation), ("zero_day", self.zero_day)]

    def tearDown(self): self.tmp.cleanup()

    def build(self, seed=3, chunk_rows=97, **kw):
        return brs.build_stream(self.sources, FakeDetector(), FakeMitre(), quotas=QUOTAS, seed=seed, chunk_rows=chunk_rows,
                                timestamp="2026-11-08T00:00:00+00:00", log=lambda *_: None, **kw)

    def test_label_family_mapping(self):
        cases = {"BenignTraffic": "Benign", "DDoS-ICMP_Flood": "DDoS", "DoS-HTTP_Flood": "DoS", "Recon-OSScan": "Recon",
                 "VulnerabilityScan": "Recon", "DictionaryBruteForce": "Brute Force", "DNS_Spoofing": "Spoofing",
                 "MITM-ArpSpoofing": "Spoofing", "Mirai-greip_flood": "Mirai", "Backdoor_Malware": "Web-Based",
                 "Uploading_Attack": "Web-Based", "SomethingNew": "Other"}
        for label, family in cases.items():
            self.assertEqual(brs.label_family(label), family, label)

    def test_every_family_sampled_to_quota_in_both_flag_states(self):
        alerts, meta = self.build()
        for family in brs.FAMILIES:
            for flagged in (True, False):
                key = f"{family}|{'flagged' if flagged else 'unflagged'}"
                expected = min(brs.quota_for(family, flagged, QUOTAS), meta["population"].get(key, 0))
                self.assertGreater(meta["population"].get(key, 0), 0, key)       # synthetic data has every stratum
                self.assertEqual(meta["sampled"].get(key, 0), expected, key)
        self.assertEqual(meta["screen_vs_pipeline_detection_mismatches"], 0)
        self.assertEqual(meta["rows_read"], 1800)
        self.assertEqual(sum(meta["population"].values()), 1800)            # every row was scored

    def test_population_counts_match_a_direct_count(self):
        _, meta = self.build()
        frame = pd.concat([self.val_frame, self.zd_frame])
        flagged = (frame[FEATURES[:3]].to_numpy(np.float64) ** 2).sum(axis=1) >= 1.0
        families = frame["label"].map(brs.label_family)
        for family in brs.FAMILIES:
            self.assertEqual(meta["population"].get(f"{family}|flagged", 0), int((flagged & (families == family)).sum()))

    def test_fields_match_the_demo_pipeline_plus_hidden_simulator_keys(self):
        alerts, _ = self.build()
        reference = replay.pipeline_alert(FakeDetector(), FakeMitre(), {f: 0.0 for f in FEATURES}, "id", "s",
                                          reason_fn=brs.offline_reason)
        hidden = {"_simulator_attack", "_attack_label", "_family", "_source", "_source_row"}
        for alert in alerts:
            self.assertEqual(set(replay.clean(alert)), set(reference))
            self.assertEqual({k for k in alert if k.startswith("_")}, hidden)
            self.assertEqual(alert["_simulator_attack"], alert["_attack_label"] != "BenignTraffic")
            self.assertEqual(alert["llm_explanation"]["mode"], "Demo Fallback Reasoning")

    def test_no_label_or_family_reaches_the_policy_view(self):
        alerts, _ = self.build()
        for alert in alerts:
            visible = json.dumps(replay.clean(alert))
            self.assertNotIn(alert["_attack_label"], visible)
            self.assertNotIn("Benign", visible)
            self.assertNotIn("_simulator_attack", visible)

    def test_same_seed_identical_and_chunk_size_does_not_matter(self):
        a, _ = self.build(seed=5, chunk_rows=97)
        b, _ = self.build(seed=5, chunk_rows=1000)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_different_seed_changes_the_sample(self):
        a, _ = self.build(seed=5)
        b, _ = self.build(seed=6)
        self.assertNotEqual([x["sample_id"] for x in a], [x["sample_id"] for x in b])

    def test_stream_feeds_the_replay_router(self):
        alerts, meta = self.build()
        out = Path(self.tmp.name) / "stream.jsonl"
        brs.write_stream(alerts, meta, out)
        loaded = replay.load_stream(out)
        routed, not_routed = replay.route(loaded)
        self.assertEqual(len(routed), sum(a["detected"] for a in alerts))
        self.assertEqual(not_routed["unflagged_benign_flows"], meta["sampled"]["Benign|unflagged"])
        self.assertTrue(out.with_suffix(".meta.json").exists())
        print_table = brs.counts_table(meta)
        self.assertIn("Web-Based", print_table)

    def test_non_finite_rows_are_skipped_and_counted(self):
        frame = pd.read_csv(self.validation)
        frame.loc[[0, 1], "f5"] = np.inf
        frame.to_csv(self.validation, index=False)
        _, meta = self.build()
        self.assertEqual(meta["non_finite_rows_skipped"], 2)
        self.assertEqual(sum(meta["population"].values()), 1798)


class AttackShareAndExclusionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); d = Path(self.tmp.name)
        rng = np.random.default_rng(1)
        self.validation, self.zero_day = d / "validation.csv", d / "zero_day.csv"
        write_csv(self.validation, VALIDATION_LABELS, 2600, rng)
        write_csv(self.zero_day, ZERO_DAY_LABELS, 1000, rng)
        self.sources = [("validation", self.validation), ("zero_day", self.zero_day)]

    def tearDown(self): self.tmp.cleanup()

    def build(self, **kw):
        return brs.build_stream(self.sources, FakeDetector(), FakeMitre(), seed=kw.pop("seed", 3), chunk_rows=211,
                                timestamp="2026-11-08T00:00:00+00:00", log=lambda *_: None, **kw)

    def test_attack_share_quotas_arithmetic(self):
        q = brs.attack_share_quotas(0.1, 300)
        self.assertEqual(q["attack_flagged"], 43)                    # ceil(300 / 7)
        self.assertEqual(q["benign_flagged"], 2709)                  # 301 * 0.9 / 0.1
        self.assertAlmostEqual(301 / (301 + q["benign_flagged"]), 0.1, places=3)
        self.assertLessEqual(1 / 7, 0.25)                            # even split: no family above 25%
        q = brs.attack_share_quotas(0.3, 300)
        self.assertEqual(q["benign_flagged"], 702)
        with self.assertRaises(ValueError): brs.attack_share_quotas(1.0, 300)

    def test_stream_hits_the_requested_share_with_even_families(self):
        alerts, meta = self.build(attack_share=0.3, min_attacks=14, quotas={"benign_unflagged": 3, "attack_unflagged": 1})
        flagged = [a for a in alerts if a["detected"]]
        attacks = [a for a in flagged if a["_simulator_attack"]]
        self.assertEqual(len(attacks), 14)                           # 2 per family x 7
        self.assertAlmostEqual(meta["flagged_attack_share"], len(attacks) / len(flagged))
        self.assertAlmostEqual(meta["flagged_attack_share"], 0.3, delta=0.01)
        from collections import Counter
        self.assertLessEqual(max(Counter(a["_family"] for a in attacks).values()) / len(attacks), 0.25)

    def test_excluded_rows_are_never_resampled_and_population_is_unchanged(self):
        first, meta1 = self.build(seed=3)
        path = Path(self.tmp.name) / "first.jsonl"
        brs.write_stream(first, meta1, path)
        second, meta2 = self.build(seed=3, exclude_streams=[path])   # same seed: would pick the same rows
        self.assertFalse({a["sample_id"] for a in first} & {a["sample_id"] for a in second})
        self.assertEqual(meta1["population"], meta2["population"])
        self.assertGreater(meta2["excluded_rows_skipped"], 0)
        self.assertEqual(meta2["excluded_streams"][0]["sha256"], brs.sha256_file(path))

    def test_written_stream_records_its_sha256(self):
        alerts, meta = self.build()
        path = Path(self.tmp.name) / "s.jsonl"
        digest = brs.write_stream(alerts, meta, path)
        self.assertEqual(digest, brs.sha256_file(path))
        self.assertNotIn(b"\r\n", path.read_bytes())                 # LF only: hash is platform-independent
        self.assertEqual(json.loads(path.with_suffix(".meta.json").read_text())["stream_sha256"], digest)


class RealDetectorBatchTests(unittest.TestCase):
    def test_batch_score_matches_single_row_score(self):
        try:
            from services.model_service import Detector
        except Exception as exc:                                            # no PyTorch installed
            self.skipTest(f"detector unavailable: {exc}")
        detector = Detector(brs.ROOT)
        if not detector.loaded: self.skipTest("checkpoint not present")
        rows = np.random.default_rng(1).normal(0, 1, size=(25, len(detector.features))).astype(np.float32)
        batch = detector.score_batch(rows)
        single = np.array([detector.score(r) for r in rows])
        np.testing.assert_allclose(batch, single, rtol=1e-5, atol=1e-7)


if __name__ == "__main__":
    unittest.main()
