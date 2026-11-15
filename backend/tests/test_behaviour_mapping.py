"""Tests for amendment 7's opt-in behaviour-to-technique mapping."""
import unittest
from pathlib import Path

from services.mitre_service import MitreService

ROOT = Path(__file__).resolve().parents[2]


class BehaviourMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = MitreService(ROOT)

    def mapped_ids(self, features, **kwargs):
        result = self.service.retrieve_behavior({"top_features": features}, behaviour_mapping=True, **kwargs)
        return result, {item["technique_id"].split(".")[0] for item in result["techniques"]}

    def test_rst_scan_adds_network_discovery_technique(self):
        result, ids = self.mapped_ids([{"feature": "rst_count", "value": 2.1, "contribution": 0.7}])
        self.assertTrue({"T1046", "T1595"} & ids)
        self.assertEqual(result["plausibility_rules"], "plausibility-rules-v2")

    def test_arp_flow_adds_adversary_in_the_middle(self):
        _, ids = self.mapped_ids([{"feature": "ARP", "value": 1.8, "contribution": 0.9}])
        self.assertIn("T1557", ids)

    def test_one_way_flood_keeps_denial_of_service_candidates(self):
        _, ids = self.mapped_ids([{"feature": "ack_flag_number", "value": -2.4, "contribution": 1.1}])
        self.assertTrue({"T1498", "T1499"} & ids)

    def test_mapping_off_is_identical_to_the_existing_retrieval_path(self):
        analysis = {"top_features": [{"feature": "rst_count", "value": 2.1, "contribution": 0.7}]}
        self.assertEqual(self.service.retrieve_behavior(analysis), self.service._retrieve(analysis))

    def test_mapping_is_capped_at_five_and_marks_each_candidate_source(self):
        features = [
            {"feature": "rst_count", "value": 2.1, "contribution": 0.7},
            {"feature": "ARP", "value": 1.8, "contribution": 0.6},
            {"feature": "DNS", "value": 1.7, "contribution": 0.5},
            {"feature": "ack_flag_number", "value": -2.4, "contribution": 1.1},
            {"feature": "flow_duration", "value": -2.0, "contribution": 0.4},
        ]
        result = self.service.retrieve_behavior({"top_features": features}, behaviour_mapping=True)
        self.assertLessEqual(len(result["techniques"]), 5)
        self.assertTrue(result["techniques"])
        self.assertTrue(all(item["candidate_source"] in {"tfidf", "mapped", "both"}
                            for item in result["techniques"]))

    def test_mapping_does_not_read_or_depend_on_dataset_labels(self):
        features = [{"feature": "ARP", "value": 1.8, "contribution": 0.9}]
        base = self.service.retrieve_behavior({"top_features": features}, behaviour_mapping=True)
        contaminated = self.service.retrieve_behavior(
            {"top_features": features, "attack_label": "BenignTraffic", "family": "Benign"},
            behaviour_mapping=True)
        self.assertEqual(base, contaminated)


if __name__ == "__main__":
    unittest.main()
