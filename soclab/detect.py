"""Transparent detections, with evidence IDs and explicit assumptions."""
from collections import defaultdict
from datetime import datetime, timedelta
import json
from pathlib import Path

RULES = {
    "AUTH-001": {"name": "SSH failures followed by success", "severity": "high", "technique": "T1110"},
    "CLOUD-001": {"name": "AWS administrator policy attachment", "severity": "high", "technique": "T1098"},
    "ENDPOINT-001": {"name": "Encoded PowerShell invocation", "severity": "medium", "technique": "T1059.001"},
}


def read_events(path):
    result = []
    with Path(path).open(encoding="utf-8") as fp:
        for line_no, line in enumerate(fp, start=1):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
                for required in ("event_id", "timestamp", "source", "host", "event_type", "actor"):
                    if required not in ev:
                        raise ValueError(f"missing {required}")
                datetime.fromisoformat(ev["timestamp"])
                result.append(ev)
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"Invalid telemetry line {line_no}: {exc}") from exc
    return sorted(result, key=lambda x: x["timestamp"])


def detect(events):
    alerts = []
    groups = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "ssh_login" and ev.get("ip"):
            groups[(ev["host"], ev["ip"], ev["actor"])].append(ev)
    for (host, ip, actor), group in groups.items():
        for idx, ev in enumerate(group):
            if ev.get("result") != "Success":
                continue
            t = datetime.fromisoformat(ev["timestamp"])
            failures = [x for x in group[:idx] if x.get("result") == "Failure"
                        and timedelta(0) <= t - datetime.fromisoformat(x["timestamp"]) <= timedelta(minutes=5)]
            if len(failures) >= 5:
                alerts.append(make_alert("AUTH-001", host, actor, [x["event_id"] for x in failures]+[ev["event_id"]],
                                         ev["timestamp"], f"{len(failures)} failures then success from {ip} within 5 minutes"))
                break
    for ev in events:
        if ev.get("source") == "cloudtrail" and ev["event_type"] == "AttachUserPolicy" and ev.get("policy") == "AdministratorAccess" and ev.get("result") == "Success":
            alerts.append(make_alert("CLOUD-001", ev["host"], ev["actor"], [ev["event_id"]], ev["timestamp"], "AdministratorAccess attached; requires change-ticket validation"))
        if ev.get("source") == "sysmon" and ev["event_type"] == "process_start":
            cmd = ev.get("command_line", "").lower()
            if "powershell" in ev.get("image", "").lower() and ("-encodedcommand" in cmd or " -enc " in cmd):
                alerts.append(make_alert("ENDPOINT-001", ev["host"], ev["actor"], [ev["event_id"]], ev["timestamp"], "PowerShell encoded-command flag observed; could be legitimate automation"))
    return sorted(alerts, key=lambda a: (a["timestamp"], a["rule_id"]))


def make_alert(rule_id, host, actor, evidence_ids, timestamp, reason):
    rule = RULES[rule_id]
    return {"alert_id": f"{rule_id}-{evidence_ids[-1]}", "rule_id": rule_id, "title": rule["name"],
            "severity": rule["severity"], "mitre_attack": rule["technique"], "host": host,
            "actor": actor, "timestamp": timestamp, "evidence_ids": evidence_ids, "reason": reason,
            "disposition": "untriaged"}
