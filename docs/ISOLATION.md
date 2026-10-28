# Isolation playbook

## Phase 0: No VMs required (fully offline)
`python -m soclab.cli generate` produces fictional JSONL events in a local directory.
`python -m soclab.cli analyze` evaluates the files. These commands do **not** use
network APIs, open sockets, contact production systems, execute attack payloads, or
require credentials. The IPs in examples use reserved documentation ranges.
For strongest isolation, disconnect networking before running. This mode is an
**event replay and detection exercise**, not an actual SIEM or endpoint sensor.

## Phase 1: Virtual machine lab (optional)
Use a hypervisor (VirtualBox, Hyper-V, or VMware) on a computer with adequate RAM.
Create two Ubuntu VMs and optionally one Windows evaluation VM. Configure **only an
internal/host-only virtual switch** for the investigation network. Do not bridge to
Wi-Fi/Ethernet. Do not enable port forwarding, shared folders, or shared clipboard.
Use snapshots before each experiment. Install software and update OS images first
on a separate temporary NAT connection, then remove that NIC prior to simulations.

Example subnet for your own private lab: `10.77.77.0/24`.
- SOC VM: `10.77.77.10` (Wazuh manager/dashboard)
- Linux endpoint: `10.77.77.20` (system logs)
- Windows endpoint: `10.77.77.30` (Sysmon + Windows logs; optional)

On the host/hypervisor verify *no default gateway* in the isolated VMs and ensure
no virtual adapter is bridged. Restrict the SOC dashboard to the host or lab subnet.
Avoid real phishing or malware and use deterministic benign telemetry instead.
Do not send synthetic attacker-like traffic toward any external IP.

## Phase 2: Wazuh option
Follow official single-node documentation:
https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
The official minimum is 4 CPU cores, 8 GB RAM and 50 GB disk for a single-node
Docker host. Do not blindly expose its published ports to the LAN/internet.
Use the dedicated SOC VM, internal virtual NIC, and locally scoped access controls.
Configure agents to point **only** to the SOC VM. Validate connectivity with
benign local authentication activity. This repo's JSONL records are not automatically
Wazuh ingestible and require explicit source-specific ingestion mappings.

## Evidence and safety
Capture a screenshot of alerts, rule logic, source event IDs, and a case note for
each scenario. Keep a change log and record why an event was flagged or dismissed.
Never upload real user logs, tokens, domain credentials, or sensitive telemetry.
