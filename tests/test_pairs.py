import unittest
from mirrorfang.validator import validate_all, load_rule, rule_matches
from mirrorfang.validator import ROOT

class TestPairs(unittest.TestCase):
    def test_six_pairs_exist_and_pass(self):
        results = validate_all()
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertTrue(r["ok"], r["pair"])
    def test_every_attack_fires(self):
        for r in validate_all():
            self.assertTrue(all(r["attack_fired"]), r["pair"])
    def test_no_benign_fires(self):
        for r in validate_all():
            self.assertFalse(any(r["benign_fired"]), r["pair"])
    def test_rules_are_valid_sigma_shaped_yaml(self):
        for d in sorted((ROOT / "pairs").iterdir()):
            rule = load_rule(d / "rule.yml")
            for key in ("title", "id", "detection", "level"):
                self.assertIn(key, rule, d.name)
            self.assertIn("selection", rule["detection"])

if __name__ == "__main__":
    unittest.main()
