"""Plan amendment 12: guarded behaviour mapping (scan and spoofing only), opt-in."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import evaluate_mapping as em
from services import technique_plausibility as tp
from services.mitre_service import MitreService

ROOT = Path(__file__).resolve().parents[2]


def feat(name, value, contribution=0.5):
    return {"feature": name, "value": value, "contribution": contribution}


class GuardRules(unittest.TestCase):
    def test_default_cutoffs_unchanged(self):
        features = [feat("rst_count", 1.5), feat("flow_duration", -1.2), feat("SSH", 3.0, -0.1)]
        self.assertEqual(tp.observed_behaviours(features), {("rst_count", "high"), ("flow_duration", "low")})

    def test_default_rule_equals_amendment_7(self):
        features = [feat("rst_count", 1.5), feat("ARP", 1.2), feat("ack_flag_number", -2.4)]
        seen = tp.observed_behaviours(features)
        old = {tid for tid, behaviours in tp.DIRECT_MAP_V1.items() if behaviours & seen}
        self.assertEqual(tp.mapped_techniques(tp.DIRECT_MAP_V1, features), old)

    def test_g1_never_maps_flood_or_login(self):
        g1 = tp.A12_VARIANTS["g1-scan-only"]
        self.assertEqual(set(g1["map"]), {"T1046", "T1595", "T1557"})
        flood = [feat("ack_flag_number", -2.4), feat("Rate", 3.0), feat("SSH", 2.0)]
        self.assertEqual(tp.mapped_techniques(g1["map"], flood), set())
        self.assertEqual(tp.mapped_techniques(g1["map"], [feat("rst_count", 1.5)]), {"T1046", "T1595"})

    def test_g2_needs_strong_behaviour(self):
        g2 = tp.A12_VARIANTS["g2-scan-only-strong"]
        args = {k: g2[k] for k in ("high_z", "low_z", "min_behaviours")}
        self.assertEqual(tp.mapped_techniques(g2["map"], [feat("rst_count", 1.5)], **args), set())
        self.assertEqual(tp.mapped_techniques(g2["map"], [feat("rst_count", 2.5)], **args), {"T1046", "T1595"})

    def test_g3_needs_two_behaviours(self):
        g3 = tp.A12_VARIANTS["g3-scan-only-two"]
        args = {k: g3[k] for k in ("high_z", "low_z", "min_behaviours")}
        self.assertEqual(tp.mapped_techniques(g3["map"], [feat("rst_count", 1.5)], **args), set())
        two = [feat("rst_count", 1.5), feat("syn_count", 1.3)]
        self.assertEqual(tp.mapped_techniques(g3["map"], two, **args), {"T1046", "T1595"})

    def test_frozen_variant_is_the_tuning_winner(self):
        self.assertEqual(tp.A12_FROZEN_VARIANT, "g1-scan-only")


class ServicePath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = MitreService(ROOT)

    def ids(self, features, variant):
        result = self.service.retrieve_behavior({"top_features": features}, behaviour_mapping=True,
                                                mapping_variant=variant)
        return {item["technique_id"].split(".")[0] for item in result["techniques"]}

    def test_guarded_variant_adds_scan_technique(self):
        self.assertTrue({"T1046", "T1595"} & self.ids([feat("rst_count", 2.1, 0.7)], "g1-scan-only"))

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            self.ids([feat("rst_count", 2.1)], "g9-nope")

    def test_default_off_unchanged(self):
        analysis = {"top_features": [feat("rst_count", 2.1, 0.7)]}
        self.assertEqual(self.service.retrieve_behavior(analysis), self.service._retrieve(analysis))


class OneTimeTest(unittest.TestCase):
    def test_refuses_before_freeze(self):
        with mock.patch.object(tp, "A12_FROZEN_VARIANT", None), self.assertRaises(RuntimeError):
            em.test12_once(service=None)

    def test_refuses_second_run(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(tp, "A12_FROZEN_VARIANT", "g1-scan-only"):
            (Path(tmp) / "test_s10b.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                em.test12_once(service=None, out_dir=Path(tmp))


if __name__ == "__main__":
    unittest.main()
