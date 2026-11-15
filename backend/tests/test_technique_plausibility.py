"""Plan amendment 5: technique plausibility rules, retrieval abstention and the optional verifier check."""
import copy
import unittest
from unittest import mock

from services import technique_plausibility as tp
from services.mitre_service import MitreService
from services.verification_service import verify_record
from test_verification_service import MITRE, analysis, base_report


def feat(name, value, contribution=0.05):
    return {"feature": name, "value": value, "contribution": contribution}


class Rules(unittest.TestCase):
    def test_behaviour_needs_positive_contribution_and_clear_deviation(self):
        seen = tp.observed_behaviours([feat("Rate", 2.0), feat("SSH", 3.0, -0.01), feat("syn_count", 0.5),
                                       feat("flow_duration", -1.5), feat("HTTP", -2.0)])
        self.assertEqual(seen, {("Rate", "high"), ("flow_duration", "low")})   # protocol absence never counts

    def test_flood_supported_login_not_and_unknown_not_judged(self):
        flood = [feat("PacketDensity", 3.1), feat("SYNRatio", 2.4)]
        self.assertTrue(tp.plausible("T1498.001", flood))
        self.assertFalse(tp.plausible("T1110.001", flood))
        self.assertIsNone(tp.plausible("T9999", flood))
        self.assertTrue(tp.plausible("T1110.004", [feat("SSH", 1.8)]))


class RetrievalAbstention(unittest.TestCase):
    def service(self, techniques):
        svc = MitreService.__new__(MitreService)
        svc._retrieve = mock.Mock(return_value={"status": "retrieved", "techniques": techniques})
        return svc

    def test_implausible_removed_unknown_kept_default_unchanged(self):
        ts = [{"technique_id": "T1498.001"}, {"technique_id": "T1110.001"}, {"technique_id": "T9999"}]
        a = {"top_features": [feat("Rate", 2.5)]}
        self.assertEqual(len(self.service(ts).retrieve_behavior(a)["techniques"]), 3)   # default off: live API unchanged
        out = self.service(ts).retrieve_behavior(a, abstain_implausible=True)
        self.assertEqual([t["technique_id"] for t in out["techniques"]], ["T1498.001", "T9999"])
        self.assertEqual(out["removed_as_implausible"], ["T1110.001"])

    def test_abstains_when_nothing_fits(self):
        out = self.service([{"technique_id": "T1110.001"}]).retrieve_behavior({"top_features": [feat("Rate", 2.5)]},
                                                                              abstain_implausible=True)
        self.assertEqual(out["techniques"], [])
        self.assertEqual(out["status"], "abstained_implausible")


class VerifierCheck(unittest.TestCase):
    def test_faithful_but_implausible_citation_is_uncertain_only_with_the_check(self):
        # The flow shows flood behaviour (SYNRatio, PacketDensity high); citing a brute-force technique is faithful
        # to the retrieved candidates but does not fit the flow.
        mitre = copy.deepcopy(MITRE)
        mitre["techniques"].append({"technique_id": "T1110.001", "technique_name": "Password Guessing"})
        reasoning = copy.deepcopy(base_report())
        reasoning["report"]["attack_context"] = list(reasoning["report"]["attack_context"]) + \
            ["The behaviour may be consistent with Password Guessing."]
        self.assertEqual(verify_record(analysis(), mitre, reasoning)["verdict"], "VERIFIED")
        result = verify_record(analysis(), mitre, reasoning, plausibility=True)
        self.assertEqual(result["verdict"], "UNCERTAIN")
        self.assertIn("cited_techniques_plausible", result["failed_checks"])

    def test_plausible_citation_still_passes(self):
        result = verify_record(analysis(), MITRE, base_report(), plausibility=True)
        self.assertEqual(result["verdict"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
