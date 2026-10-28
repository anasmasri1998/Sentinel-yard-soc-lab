# Sentinel Yard — an evidence-first SOC lab

A reproducible, **offline SOC investigation exercise** with noisy synthetic events,
transparent detection logic, traceable alerts, and analyst-written incident cases.

**Why this exists:** Many portfolio SOC projects end at a dashboard screenshot. This
one tests the more difficult SOC skill: justifying what an alert means, where the
evidence came from, and when *not* to declare an incident.

## Working features (v0.1)
- Deterministic synthetic telemetry from SSH, CloudTrail-like, and Sysmon-like sources.
- Three runnable detections: SSH failure burst followed by success, AWS admin policy
  attachment, and an encoded-command process observation.
- Alerts carry explicit evidence event IDs, severity, MITRE ATT&CK technique references.
- Analyst casebook starts untriaged; explicit disposition and notes are required.
- Injected benign noisy activity, separate ground-truth file, repeatable unit tests.
- Pure Python standard-library runtime; no services or cloud account required.

## Try it
Requires Python 3.10+ from the repository root:

```bash
python -m soclab.cli generate --out lab-data
python -m soclab.cli analyze --input lab-data/events.jsonl --out lab-data
python -m unittest discover -s tests -v
```

Review the JSON files in `lab-data/`. To record your own conclusion:

```bash
python -m soclab.cli triage --casebook lab-data/cases.json \
  --case CASE-001 --status needs_investigation \
  --notes "Check whether root access was approved and correlate with host process logs"
```

Windows PowerShell: run each command on one line and omit the shell `\` line continuation.

## Repository map

```text
soclab/scenarios.py   deterministic fictional telemetry + ground truth
soclab/detect.py      explainable, evidence-linked detection rules
soclab/triage.py      analyst dispositions and written notes
soclab/cli.py         generate/analyze/triage commands
tests/                runnable tests
docs/ISOLATION.md     offline and VM network isolation plan
docs/DETECTION_NOTES.md  rule thresholds, false positives, exercises
```

## Scope and limitations
This is an **offline detection and triage demonstrator**, not an active EDR, SIEM,
cloud connector, or production incident response product. The events are *fictional*
and do not prove performance on production traffic. The PowerShell command is only
text inside a log record; nothing executes. No attacks, ports, or external network
requests occur when running the Python CLI.

Optional extension: deploy Wazuh in an **isolated VM** and ingest real, authorized
local telemetry with a documented schema adapter. Instructions are in
[`docs/ISOLATION.md`](docs/ISOLATION.md). This integration is a future step, not an
implemented feature.

## Portfolio evidence to publish after testing
1. Rule-to-evidence screenshots including raw source events.
2. Incident write-ups containing hypotheses, timeline, disposition and limitations.
3. Before/after comparisons of tuning rules to reduce noise.
4. Test output and descriptions of cases the detections cannot catch.

## Responsible use
Use only synthetic events or logs from systems you own or are authorized to test.
Do not commit credentials, production data, or personally identifying log records.
