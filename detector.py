#!/usr/bin/env python3
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / "soc-lab"
SOURCES = [
    Path.home() / "auth-events.log",
    BASE / "logs" / "auth-live.log",
]
ALERTS = BASE / "alerts" / "alerts.jsonl"

RULES = [
    {
        "id": "AUTH-001",
        "name": "Failed authentication",
        "pattern": re.compile(
            r"authentication failure|FAILED LOGIN|user unknown", re.I
        ),
        "severity": "MEDIUM",
        "description": "A login or authentication attempt failed.",
        "recommended_action": (
            "Review the source and account context; check for repeated "
            "failures and verify whether the attempt was expected."
        ),
    },
    {
        "id": "PRIV-001",
        "name": "Privilege escalation session",
        "pattern": re.compile(
            r"pam_unix\(sudo:session\): session opened", re.I
        ),
        "severity": "LOW",
        "description": "A sudo session opened; verify it was expected.",
        "recommended_action": (
            "Verify the user and reason for privilege use; review available "
            "sudo command records and confirm the activity was authorized."
        ),
    },
]

def parse_timestamp(line):
    match = re.match(r"^(\S+)", line)
    return match.group(1) if match else None

def main():
    alerts = []
    total_events = 0
    seen_events_by_source = {}
    duplicates_skipped = 0

    for source in SOURCES:
        if not source.exists():
            continue

        lines = source.read_text(errors="replace").splitlines()
        total_events += len(lines)

        # Only suppress lines shared with an earlier source.
        previous_source_events = set().union(
            *seen_events_by_source.values()
        ) if seen_events_by_source else set()
        current_source_events = set()

        for line_number, line in enumerate(lines, start=1):
            event_key = line.strip()
            current_source_events.add(event_key)

            if event_key in previous_source_events:
                duplicates_skipped += 1
                continue

            for rule in RULES:
                if rule["pattern"].search(line):
                    alerts.append({
                        "alert_time_utc": datetime.now(timezone.utc).isoformat(),
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "recommended_action": rule["recommended_action"],
                        "event_timestamp": parse_timestamp(line),
                        "source": str(source),
                        "source_line": line_number,
                        "evidence": line,
                    })

        seen_events_by_source[source] = current_source_events

    ALERTS.parent.mkdir(parents=True, exist_ok=True)
    with ALERTS.open("w") as output:
        for alert in alerts:
            output.write(json.dumps(alert) + "\n")

    counts = Counter(alert["severity"] for alert in alerts)

    print("=== SOC LAB DETECTION REPORT ===")
    print(f"Log lines scanned: {total_events}")
    print(f"Duplicate lines skipped: {duplicates_skipped}")
    print(f"Alerts generated: {len(alerts)}")
    for severity in ("HIGH", "MEDIUM", "LOW"):
        print(f"{severity}: {counts[severity]}")

    print(f"\nSaved alerts to: {ALERTS}")
    print("Note: Rule matches require investigation; they do not prove compromise.")

if __name__ == "__main__":
    main()
