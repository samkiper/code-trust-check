import unittest

from scripts.run_accuracy_gate import balanced_subset, check_gate, held_out_subset


class AccuracyGateSelectionTests(unittest.TestCase):
    def test_holdout_is_disjoint_from_published_cases(self):
        rows = [
            {"name": f"{category}-{index}", "category": category, "expected": index % 2 == 0}
            for index in range(12)
            for category in ("pathtraver", "xpathi", "xxe")
        ]
        published = balanced_subset(rows, 18)
        holdout = held_out_subset(rows, 18, 12)
        self.assertEqual(len(holdout), 12)
        self.assertTrue(
            {row["name"] for row in published}.isdisjoint({row["name"] for row in holdout})
        )

    def test_no_hint_holdout_threshold_is_enforced(self):
        report = {
            "internal": {"overall": {"cases": 53, "recall": 1.0, "false_positive_rate": 0.0}},
            "owasp": {
                "overall": {"cases": 750, "recall": 1.0, "false_positive_rate": 0.0},
                "by_vulnerability": {},
            },
            "owasp_no_hint_holdout": {
                "overall": {"cases": 300, "recall": 0.95, "false_positive_rate": 0.0}
            },
        }
        thresholds = {
            "internal": {"minimum_cases": 53, "minimum_recall": 1.0, "maximum_false_positive_rate": 0.0},
            "owasp": {"minimum_cases": 750, "minimum_recall": 1.0, "maximum_false_positive_rate": 0.0},
            "owasp_no_hint_holdout": {
                "minimum_cases": 300,
                "minimum_recall": 0.96,
                "maximum_false_positive_rate": 0.0,
            },
        }
        failures = check_gate(report, thresholds)
        self.assertTrue(any("owasp_no_hint_holdout" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
