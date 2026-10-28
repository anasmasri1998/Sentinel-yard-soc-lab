import tempfile
import unittest
from pathlib import Path
from soclab.scenarios import build, write_lab
from soclab.detect import read_events, detect
from soclab.triage import make_casebook, update_case

class TestLab(unittest.TestCase):
    def test_seed_reproducible(self):
        self.assertEqual(build(42), build(42))
    def test_three_expected_alert_types(self):
        alerts = detect(build()[0])
        self.assertEqual({a["rule_id"] for a in alerts}, {"AUTH-001", "CLOUD-001", "ENDPOINT-001"})
        self.assertEqual(len(alerts), 3)
    def test_false_positive_context_not_flagged(self):
        alerts = detect(build()[0])
        self.assertFalse(any(a["actor"] == "deploy-service" for a in alerts))
    def test_casebook_requires_analyst(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cases.json"
            case = make_casebook(detect(build()[0]), path)[0]
            self.assertEqual(case["status"], "needs_investigation")
            updated = update_case(path, case["case_id"], "true_positive", "Confirmed against approved simulated scenario")
            self.assertEqual(updated["status"], "true_positive")
    def test_read_invalid_data(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.jsonl"
            p.write_text('{"bad":true}\n')
            with self.assertRaisesRegex(ValueError, "line 1"):
                read_events(p)
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            write_lab(d)
            self.assertEqual(len(read_events(Path(d)/"events.jsonl")), 106)

if __name__ == "__main__":
    unittest.main()
