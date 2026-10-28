# Detection engineering notebook

| Rule | Trigger | Noise/limitations | MITRE ATT&CK reference |
|---|---|---|---|
| AUTH-001 | >=5 failed SSH logins by same host, IP, actor within 5 minutes preceding success | Shared gateways and credential rotations may cause benign patterns; no geo-enrichment | T1110 |
| CLOUD-001 | Successful AdministratorAccess attachment in CloudTrail-like synthetic event | Authorized emergency admin tasks may be benign; requires ticket validation | T1098 |
| ENDPOINT-001 | PowerShell executable with -EncodedCommand or -enc command-line flag | Common for legitimate administration; not proof of compromise | T1059.001 |

Each alert links to underlying event IDs. A rule firing is not a confirmed breach.
The casebook starts at `needs_investigation`; a human must record disposition.

## Analyst exercise
1. Run `generate` and `analyze`.
2. Read `lab-data/alerts.json` alongside individual event IDs in `events.jsonl`.
3. Without reading `ground_truth.json`, propose two alternative explanations for each alert.
4. Assign disposition in `cases.json` using the `triage` command.
5. Only then compare with `ground_truth.json` and record false positives and blind spots.

## Improvements worth implementing
- Event-time windowing when data arrives out of order.
- Durable ingestion checkpointing and deduplication across log batches.
- Parser interfaces for real Wazuh/Sysmon/CloudTrail event schemas.
- Test true/false positive rates against a larger labelled and noisy set.
- Export Sigma-style rules and write conversion tests.
