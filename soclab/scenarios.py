"""Deterministic, synthetic telemetry. No packets are sent, no real attacks happen."""
from datetime import datetime, timedelta, timezone
import json
import random
from pathlib import Path

BASE = datetime(2026, 5, 7, 9, 0, tzinfo=timezone.utc)


def build(seed=42):
    rng = random.Random(seed)
    events = []
    truth = []

    def add(minute, source, host, kind, actor, **fields):
        item = dict(event_id=f"E{len(events)+1:04d}", timestamp=(BASE+timedelta(minutes=minute)).isoformat(),
                    source=source, host=host, event_type=kind, actor=actor, **fields)
        events.append(item)
        return item["event_id"]

    # Routine human activity and expected admin maintenance; intentional benign ambiguity.
    for n in range(90):
        m = rng.randint(0, 180)
        actor = rng.choice(["lee", "maria", "backup-svc", "ci-bot"])
        host = rng.choice(["win-finance-01", "linux-app-01", "aws-prod"])
        if host == "aws-prod":
            add(m, "cloudtrail", host, "ConsoleLogin", actor, result="Success", ip="198.51.100.20")
        elif host.startswith("linux"):
            add(m, "linux_auth", host, "ssh_login", actor, result="Success", ip="192.0.2.19")
        else:
            add(m, "windows_security", host, "logon", actor, result="Success", ip="192.0.2.25")
    # Benign failed login pattern that should not trigger high-severity correlation.
    for m in [7, 42, 75, 127]:
        add(m, "linux_auth", "linux-app-01", "ssh_login", "lee", result="Failure", ip="192.0.2.19")
    # Incident A: burst then successful access from same source.
    a = []
    for m in [40, 40, 41, 41, 42, 42, 43]:
        a.append(add(m, "linux_auth", "linux-app-01", "ssh_login", "root", result="Failure", ip="203.0.113.77"))
    a.append(add(44, "linux_auth", "linux-app-01", "ssh_login", "root", result="Success", ip="203.0.113.77"))
    truth.append({"scenario": "AUTH-BURST-01", "event_ids": a, "description": "Repeated failed SSH logins followed by success"})
    # Incident B: sensitive AWS policy change by unusually located principal (no geolocation claims).
    b = [add(93, "cloudtrail", "aws-prod", "ConsoleLogin", "temp-ops", result="Success", ip="203.0.113.44"),
         add(96, "cloudtrail", "aws-prod", "AttachUserPolicy", "temp-ops", result="Success", ip="203.0.113.44", policy="AdministratorAccess", target="temp-ops")]
    truth.append({"scenario": "IAM-PRIV-01", "event_ids": b, "description": "Administrative IAM policy attachment"})
    # Incident C: suspicious encoded command, deliberately only an observed string, not execution.
    c = [add(125, "sysmon", "win-finance-01", "process_start", "maria", image="powershell.exe", command_line="powershell.exe -EncodedCommand <redacted-synthetic-example>", parent_image="explorer.exe")]
    truth.append({"scenario": "PROC-ENC-01", "event_ids": c, "description": "Encoded PowerShell flag in process telemetry"})
    # Important non-incident: an approved maintenance role gets extra privileges; illustrate false positives.
    add(140, "cloudtrail", "aws-prod", "AttachUserPolicy", "deploy-service", result="Success", ip="198.51.100.20", policy="ReadOnlyAccess", target="deploy-service")
    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return events, truth


def write_lab(directory, seed=42):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    events, truth = build(seed)
    with (directory / "events.jsonl").open("w", encoding="utf-8") as fp:
        for event in events:
            fp.write(json.dumps(event, sort_keys=True) + "\n")
    (directory / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    return len(events)
