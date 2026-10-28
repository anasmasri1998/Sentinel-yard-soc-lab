"""Casebook is intentionally analyst-driven: detection != confirmed incident."""
import json
from pathlib import Path

VALID = {"true_positive", "benign_true_positive", "false_positive", "needs_investigation"}

def make_casebook(alerts, path):
    cases = []
    for index, alert in enumerate(alerts, 1):
        cases.append({"case_id": f"CASE-{index:03d}", "alert_id": alert["alert_id"],
                      "title": alert["title"], "severity": alert["severity"],
                      "evidence_ids": alert["evidence_ids"], "status": "needs_investigation",
                      "analyst_notes": "", "next_action": "Check identity, business context and related events"})
    Path(path).write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
    return cases

def update_case(path, case_id, status, notes):
    if status not in VALID:
        raise ValueError("Invalid case status")
    file = Path(path)
    cases = json.loads(file.read_text(encoding="utf-8"))
    for case in cases:
        if case["case_id"] == case_id:
            case["status"], case["analyst_notes"] = status, notes
            file.write_text(json.dumps(cases, indent=2)+"\n", encoding="utf-8")
            return case
    raise ValueError(f"No case named {case_id}")
