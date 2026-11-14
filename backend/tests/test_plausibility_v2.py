"""Plan amendment 6: v2 rules and the keep/drop evaluation (synthetic alerts)."""
import unittest

import evaluate_plausibility_v2 as ev
from services import technique_plausibility as tp


def feat(name, value, contribution=0.05):
    return {"feature": name, "value": value, "contribution": contribution}


ONE_WAY = [feat("ack_flag_number", -2.4), feat("syn_count", -1.0)]      # how Mirai floods look in the XAI
SESSION = [feat("IAT", 1.5), feat("psh_flag_number", 1.2)]               # how brute-force sessions look


class RulesV2(unittest.TestCase):
    def test_one_way_flood_is_plausible_in_v2_not_v1(self):
        self.assertFalse(tp.plausible("T1499.001", ONE_WAY))
        self.assertTrue(tp.plausible("T1499.001", ONE_WAY, tp.SIGNATURES_V2))

    def test_session_brute_force_is_plausible_in_v2_not_v1(self):
        self.assertFalse(tp.plausible("T1110.001", SESSION))
        self.assertTrue(tp.plausible("T1110.001", SESSION, tp.SIGNATURES_V2))

    def test_v2_does_not_treat_long_flows_as_login(self):
        self.assertFalse(tp.plausible("T1110.001", [feat("flow_duration", 2.0)], tp.SIGNATURES_V2))

    def test_v1_unchanged_for_amendment_5_reproducibility(self):
        self.assertEqual(tp.SIGNATURES["T1498"], tp._FLOOD)


class KeepDropMetric(unittest.TestCase):
    def test_balanced_accuracy_and_alert_level_counts(self):
        alerts = [("Mirai", [(True, ONE_WAY, "T1499"), (False, ONE_WAY, "T1110")]),
                  ("Benign", [(False, ONE_WAY, "T1110")])]
        s = ev.summarise(ev.counts(alerts, ev.judge(tp.SIGNATURES_V2)))
        self.assertEqual(s["relevant_kept"][:2], [1, 1])
        self.assertEqual(s["irrelevant_removed"][:2], [2, 2])
        self.assertAlmostEqual(s["balanced_accuracy"], 1.0)
        self.assertEqual(s["benign_with_no_candidate_after"], [1, 1])
        self.assertAlmostEqual(ev.summarise(ev.counts(alerts, ev.judge(None)))["balanced_accuracy"], 0.5)

    def test_paired_bootstrap_interval_contains_the_observed_difference(self):
        alerts = [("Mirai", [(True, ONE_WAY, "T1499"), (False, ONE_WAY, "T1110")])] * 20 + \
                 [("Brute Force", [(True, SESSION, "T1110"), (False, SESSION, "T1499")])] * 20
        a, b = ev.counts(alerts, ev.judge(tp.SIGNATURES)), ev.counts(alerts, ev.judge(tp.SIGNATURES_V2))
        lo, hi = ev.paired_bootstrap(a, b)
        d = ev.bal(b) - ev.bal(a)
        self.assertLessEqual(lo, d); self.assertGreaterEqual(hi, d); self.assertGreater(d, 0)


if __name__ == "__main__":
    unittest.main()
