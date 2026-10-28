import argparse
import json
from pathlib import Path
from .scenarios import write_lab
from .detect import read_events, detect
from .triage import make_casebook, update_case, VALID

def main(argv=None):
    parser = argparse.ArgumentParser(prog="sentinel-yard", description="Offline SOC exercise: synthesize, detect, investigate")
    sub = parser.add_subparsers(dest="command", required=True)
    synth = sub.add_parser("generate", help="Generate fictional telemetry and a separate ground-truth file")
    synth.add_argument("--out", default="lab-data")
    synth.add_argument("--seed", type=int, default=42)
    run = sub.add_parser("analyze", help="Run detectors and produce alerts and an analyst casebook")
    run.add_argument("--input", default="lab-data/events.jsonl")
    run.add_argument("--out", default="lab-data")
    investigation = sub.add_parser("triage", help="Record human case disposition")
    investigation.add_argument("--casebook", default="lab-data/cases.json")
    investigation.add_argument("--case", required=True)
    investigation.add_argument("--status", choices=sorted(VALID), required=True)
    investigation.add_argument("--notes", required=True)
    args = parser.parse_args(argv)
    if args.command == "generate":
        print(f"Wrote {write_lab(args.out, args.seed)} synthetic events to {args.out}/events.jsonl")
    elif args.command == "analyze":
        events = read_events(args.input)
        alerts = detect(events)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "alerts.json").write_text(json.dumps(alerts, indent=2)+"\n", encoding="utf-8")
        cases = make_casebook(alerts, out / "cases.json")
        print(f"Analyzed {len(events)} events; {len(alerts)} alerts and {len(cases)} cases")
        for alert in alerts:
            print(f"  {alert['alert_id']} [{alert['severity']}] {alert['reason']}")
    elif args.command == "triage":
        case = update_case(args.casebook, args.case, args.status, args.notes)
        print(f"Updated {case['case_id']} -> {case['status']}")

if __name__ == "__main__":
    main()
