# Local SOC Monitoring & Detection Lab

A lightweight, local Security Operations Center (SOC) lab built with
Python and Linux authentication logs. The project demonstrates log
collection, rule-based detection, failed-login burst detection,
alert reporting, and a local web dashboard for security investigation.

> **Project status:** Local prototype for learning and portfolio
> demonstration. Detection results require human investigation and
> are not proof of compromise.

## Overview

This project simulates a basic SOC analyst workflow:

1. Collect authentication-related events from the Linux journal.
2. Analyse saved logs with Python detection rules.
3. Identify repeated failed authentication attempts within a time window.
4. Generate structured JSONL alerts with evidence and recommended actions.
5. Review alerts through a local dashboard.
6. Demonstrate alert behaviour using clearly labelled synthetic data.

## Features

- **Linux authentication log collection** using `journalctl`.
- **Rule-based detection** for failed authentication and sudo sessions.
- **Failed-login burst detection** using a configurable threshold and time window.
- **Structured alerts** containing severity, rule ID, timestamps, source,
  evidence, and recommended investigation actions.
- **Local web dashboard** built with Python's standard-library HTTP server.
- **Search and severity filtering** for alert investigation.
- **Synthetic alert demonstration** kept separate from real log sources.
- **Automated unit tests** for the burst-detection logic.

## Technology Stack

- Python 3
- Linux and systemd journal (`journalctl`)
- Bash
- HTML, CSS, and JavaScript
- JSON Lines (JSONL)
- Python `unittest`
- Python standard library HTTP server

No third-party Python web framework is required.

## Architecture

```text
Linux authentication events
            |
            v
    journalctl collector
            |
            v
     auth-live.log
            |
            +--------------------+
            |                    |
            v                    v
    Rule-based detector    Burst detector
            |                    |
            v                    v
       alerts.jsonl       Burst status endpoint
            |                    |
            +----------+---------+
                       |
                       v
              Local SOC dashboard
               127.0.0.1:8080
```

The rule-based detector also reads the historical `auth-events.log`
snapshot. The dashboard displays generated alerts and checks burst
status against the configured real-log sources.

## Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| AUTH-001 | Failed authentication indicators, including authentication failures, failed-login messages, and unknown users | MEDIUM |
| PRIV-001 | Sudo session opened | LOW |

Severity indicates the configured priority of a rule match. It does
not establish that an event is malicious.

### Failed-login burst detection

The burst detector identifies at least **3 failed-authentication events
within 10 minutes** by default.

The threshold and time window are configurable in the detection code.
The test suite checks that a qualifying burst is detected, two failures
do not trigger an alert, events outside the window do not trigger an
alert, and the exact window boundary is included.

## Alert Format

Alerts are written as JSON Lines to:

`~/soc-lab/alerts/alerts.jsonl`

Each alert can include:

- Alert generation time in UTC
- Rule ID and rule name
- Configured severity
- Description
- Recommended investigation action
- Event timestamp
- Log source and line number
- Original log evidence

The dashboard escapes displayed values before inserting them into its
HTML table.

## Requirements

- Linux system with `journalctl` and systemd journal access
- Python 3
- Bash
- A modern web browser

Administrator privileges may be required to read some journal entries.
The collector should only be run on systems you are authorised to monitor.

## Setup

The examples below assume the project is located at `~/soc-lab`.

### 1. Inspect the project

```bash
ls -la ~/soc-lab
```

Expected components include:

- `collect-auth.sh`
- `detector.py`
- `burst_detector.py`
- `test_burst_detector.py`
- `run-lab.sh`
- `logs/`
- `alerts/`
- `dashboard/server.py`

Some optional files may not be present in every version.

### 2. Start live authentication log collection

```bash
sudo ~/soc-lab/collect-auth.sh
```

Keep the collector running while collecting events. Stop it with `Ctrl+C`
when finished.

The collector writes authentication-related events to:

`~/soc-lab/logs/auth-live.log`

### 3. Generate rule-based alerts

In another terminal:

```bash
python ~/soc-lab/detector.py
```

This scans the configured log sources and regenerates `alerts.jsonl`.

### 4. Run burst detection

```bash
python ~/soc-lab/burst_detector.py
```

### 5. Run the burst-detector tests

```bash
python ~/soc-lab/test_burst_detector.py
```

### 6. Run both detectors

```bash
~/soc-lab/run-lab.sh
```

### 7. Start the dashboard

```bash
python ~/soc-lab/dashboard/server.py
```

Open this address in your browser:

`http://127.0.0.1:8080`

The dashboard is configured for local access. Use **Refresh alerts** after
running the detector to load the latest saved alert records.

## Testing

The burst-detector test suite currently covers:

1. Three failures within the configured window trigger detection.
2. Two failures do not trigger detection.
3. Failures outside the configured window do not trigger detection.
4. A failure exactly on the time-window boundary is included.

The four tests have passed in the current development environment.

Synthetic demonstration events are fabricated test data. They are not
evidence of real authentication attempts or an actual security incident.

## Security and Limitations

- This is a local learning prototype, not a production SIEM.
- The rule-based detector must be run to regenerate saved alerts.
- The dashboard reads the saved alert file; refresh it after detection runs.
- The collector can write events continuously while it is running, but
  collection alone does not guarantee that alerts are processed in real time.
- Rule-based matches may include legitimate administrative activity.
- Sudo session-open events do not, by themselves, prove privilege abuse.
- Cross-source deduplication currently compares identical full log lines.
  Identical lines are not guaranteed to represent the same real-world event.
- Detection depends on the availability and format of local logs.
- Synthetic demo data must remain distinguishable from real log evidence.
- The dashboard is intended for local use and has not been hardened for
  exposure to untrusted networks.

## Future Improvements

- Add dedicated tests for cross-source deduplication.
- Improve event identity and timestamp normalisation.
- Add richer investigation context and filtering.
- Add configurable detection rules and thresholds.
- Add exportable investigation reports.
- Add broader integration and dashboard tests.

## Author

**Christine Nyambura**

Software development and cybersecurity portfolio project.

Focus areas: Linux security, log analysis, Python automation, detection
engineering fundamentals, and security investigation workflows.
