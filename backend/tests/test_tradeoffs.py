"""Trade-off and break-even analysis (plan amendment 4) on synthetic saved decisions."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

import analyze_tradeoffs as at

V2 = {"attack": {"AUTO_REMEDIATE": 5, "CONFIRM_TO_ACT": 3, "HUMAN_REVIEW": 2, "MONITOR_ONLY": -6},
      "benign": {"AUTO_REMEDIATE": -12, "CONFIRM_TO_ACT": -3, "HUMAN_REVIEW": -2, "MONITOR_ONLY": 1}}
OTHER = "Always HUMAN_REVIEW"


def write_seed(root, seed, rows):
    d = root / "study" / at.VERSION / f"seed{seed}"
    d.mkdir(parents=True)
    (d / "reward_table.json").write_text(json.dumps({"version": at.VERSION, "table": V2}), encoding="utf-8")
    with (d / "evaluation_decisions.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["alert_id", "fold", "policy", "selected_action", "reward"])
        for i, (policy, label, action) in enumerate(rows):
            w.writerow([f"a{i}", 0, policy, action, V2[label][action]])


class Tradeoffs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); root = Path(self.tmp.name)
        # 2 attacks + 2 benign. Bandit: one attack missed, one auto-remediated; benign monitored, one wrongly blocked.
        rows = [(at.BANDIT, "attack", "MONITOR_ONLY"), (at.BANDIT, "attack", "AUTO_REMEDIATE"),
                (at.BANDIT, "benign", "MONITOR_ONLY"), (at.BANDIT, "benign", "AUTO_REMEDIATE"),
                (OTHER, "attack", "HUMAN_REVIEW"), (OTHER, "attack", "HUMAN_REVIEW"),
                (OTHER, "benign", "HUMAN_REVIEW"), (OTHER, "benign", "HUMAN_REVIEW")]
        write_seed(root, 1, rows); write_seed(root, 2, rows)
        self.res = at.analyse(root, {"T": "study"})["streams"]["T"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_tradeoff_rates_come_from_labels_recovered_from_rewards(self):
        b = self.res["tradeoff"][at.BANDIT]
        self.assertAlmostEqual(b["attacks missed (MONITOR_ONLY)"]["mean"], 0.5)
        self.assertAlmostEqual(b["benign wrongly AUTO_REMEDIATED"]["mean"], 0.5)
        self.assertAlmostEqual(b["analyst workload (REVIEW or CONFIRM, all alerts)"]["mean"], 0.0)
        self.assertAlmostEqual(self.res["tradeoff"][OTHER]["analyst workload (REVIEW or CONFIRM, all alerts)"]["mean"], 1.0)

    def test_break_even_is_exact_tie_point(self):
        # bandit mean at v2 = (-6 + 5 + 1 - 12)/4 = -3; always-review = (2 + 2 - 2 - 2)/4 = 0; diff -3.
        # Wrongful-block entry w: bandit mean = (-6 + 5 + 1 + w)/4 = w/4, tie with 0 at w = 0; better when w > 0.
        r = self.res["break_even"]["wrongful block (benign AUTO_REMEDIATE value)"][OTHER]
        self.assertAlmostEqual(r["difference_at_v2"], -3.0)
        self.assertAlmostEqual(r["tie_at"], 0.0)
        self.assertIn("> +0.00", r["verdict"])
        # Analyst-cost shift x on both HUMAN_REVIEW entries: review mean = x, bandit -3: tie at x = -3, bandit better below.
        r = self.res["break_even"]["analyst cost (shift added to both HUMAN_REVIEW values)"][OTHER]
        self.assertAlmostEqual(r["tie_at"], -3.0)
        self.assertIn("< -3.00", r["verdict"])

    def test_ambiguous_reward_table_is_refused(self):
        with self.assertRaises(SystemExit):
            at.label_lookup({"attack": {"HUMAN_REVIEW": 2}, "benign": {"HUMAN_REVIEW": 2}})


class ConsoleEncoding(unittest.TestCase):
    def test_main_prints_on_a_cp1252_console(self):
        # bug: on Windows, printing the minus and plus-minus signs crashed main after the files were written
        import io, sys
        from unittest import mock
        fake = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sys, "stdout", fake),              mock.patch.object(at, "analyse", return_value={"note": "n", "streams": {"T": {
                 "seeds": 1, "tradeoff": {"p": {"k": {"mean": 0.5, "std": 0.0}}},
                 "break_even": {"x": {"p": {"difference_at_v2": -1.0, "verdict": "v"}}}}}}):
            at.main(["--out", tmp])
            fake.flush()
        self.assertIn(b"50.0%", fake.buffer.getvalue())  # the row with the plus-minus sign was printed


if __name__ == "__main__":
    unittest.main()
