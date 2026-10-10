#!/usr/bin/env python3
import re
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path.home() / "soc-lab"
SOURCES = [
    Path.home() / "auth-events.log",
    BASE / "logs" / "auth-live.log",
]
FAIL_RE = re.compile(
    r"authentication failure|FAILED LOGIN|user unknown", re.I
)
WINDOW = timedelta(minutes=10)
THRESHOLD = 3

events = []

for source in SOURCES:
    if not source.exists():
        continue

    for line in source.read_text(errors="replace").splitlines():
        if not FAIL_RE.search(line):
            continue

        match = re.match(r"^(\S+)", line)
        if not match:
            continue

        try:
            timestamp = datetime.fromisoformat(match.group(1))
        except ValueError:
            continue

        events.append((timestamp, str(source), line))

events.sort(key=lambda event: event[0])

print("=== FAILED-LOGIN BURST DETECTOR ===")
print(f"Failed authentication events: {len(events)}")
print(f"Detection threshold: {THRESHOLD} failures within {WINDOW}")

bursts = []
for i, (start, _, _) in enumerate(events):
    matches = [
        event for event in events[i:]
        if event[0] - start <= WINDOW
    ]
    if len(matches) >= THRESHOLD:
        burst = tuple(matches)
        if burst not in bursts:
            bursts.append(burst)

if not bursts:
    print("No burst detected.")
else:
    for number, burst in enumerate(bursts, start=1):
        print(f"\nALERT {number}: {len(burst)} failures within 10 minutes")
        for timestamp, source, line in burst:
            print(f"  Time: {timestamp}")
            print(f"  Source: {source}")
            print(f"  Evidence: {line}")

print("\nNote: A burst warrants investigation; it does not prove an attack.")
