# Security Log Analyzer

A small rule-based authentication threat detection tool written in Python. It parses synthetic authentication logs, calculates login statistics, and detects two common suspicious patterns: brute-force attempts and password spraying.

The project is intentionally scoped as a compact software/security engineering exercise rather than a SIEM replacement. The focus is on understandable detection logic, modular code, testability, and a practical command-line interface.

## Project Overview

The analyzer reads authentication events from a text log, validates and parses each event, produces summary statistics, applies time-aware detection rules, prints alerts to the terminal, and can export alerts to JSON or CSV.

The included log data is fully synthetic and exists only for demonstration and testing.

## Security Problem

Authentication logs can contain repeated failed sign-in attempts that indicate credential attacks. A raw count alone is often not enough: five failures spread across several hours are different from five failures in one minute.

This project therefore uses time windows and source-IP grouping to detect two distinct behaviors:

- **Brute force:** many failed attempts from one IP in a short period, often against the same account.
- **Password spraying:** one IP tries failed authentications against many different usernames within a broader time window.

## Features

- Parses a simple authentication log format.
- Counts successful and failed authentication attempts.
- Produces per-IP and per-username statistics.
- Shows the IPs with the most failed logins.
- Shows the usernames with the most failed login attempts.
- Detects brute-force behavior with a configurable threshold and time window.
- Detects password spraying using a distinct-username threshold and time window.
- Provides a command-line interface with `argparse`.
- Exports alerts to JSON and CSV.
- Skips malformed lines by default and reports parsing warnings.
- Supports strict parsing mode that stops on malformed input.
- Includes automated tests with `pytest`.
- Includes fully synthetic sample authentication logs.

## Project Structure

```text
security-log-analyzer/
├── .gitignore
├── README.md
├── analyzer.py
├── requirements.txt
├── data/
│   └── sample_auth.log
├── src/
│   ├── __init__.py
│   ├── detection.py
│   ├── parser.py
│   ├── reporting.py
│   └── stats.py
└── tests/
    ├── test_detection.py
    ├── test_parser.py
    └── test_stats.py
```

## Log Format

Each event uses four whitespace-separated fields:

```text
2026-10-06T09:00:00Z status=FAILED username=alice ip=203.0.113.50
```

Required values:

- ISO 8601 timestamp, including timezone information.
- `status=SUCCESS` or `status=FAILED`.
- `username=<value>`.
- `ip=<value>`.

Blank lines and comment lines beginning with `#` are ignored.

## Detection Logic

Only failed authentication events are used by the detection rules. Events are grouped by source IP and ordered by timestamp.

Both rules use a sliding time window. The left edge moves forward whenever the oldest event falls outside the configured window. This means the rules evaluate activity that actually occurred close together in time instead of relying only on a global count.

To avoid producing many nearly identical alerts for the same burst of activity, a source IP is temporarily suppressed for one detection window after an alert fires for that rule. This is a simple noise-reduction mechanism, not a complete alert-correlation system.

### Brute Force Detection

Default rule:

> Alert when at least **5 failed authentication attempts** from the **same source IP** occur within **60 seconds**.

Configuration:

- `--bf-threshold`: required number of failed attempts.
- `--bf-window`: window length in seconds.

The rule does not require the attempts to target the same username. This keeps the rule focused on rapid repeated failures from a source IP. The alert still records all usernames seen in the qualifying window.

Example qualifying pattern:

```text
09:00:00 FAILED alice 203.0.113.50
09:00:10 FAILED alice 203.0.113.50
09:00:20 FAILED alice 203.0.113.50
09:00:30 FAILED alice 203.0.113.50
09:00:40 FAILED alice 203.0.113.50
```

Possible false positives include a shared NAT address, a misconfigured application repeatedly retrying authentication, or several legitimate users behind the same source IP entering incorrect passwords.

### Password Spraying Detection

Default rule:

> Alert when one **source IP** produces failed authentications against at least **5 distinct usernames** within **300 seconds**.

Configuration:

- `--spray-threshold`: required number of distinct usernames.
- `--spray-window`: window length in seconds.

Unlike brute force, the important feature is not simply the number of failures. It is the number of **different accounts** targeted by the same source.

Example qualifying pattern:

```text
09:10:00 FAILED alice   198.51.100.77
09:10:45 FAILED bob     198.51.100.77
09:11:30 FAILED charlie 198.51.100.77
09:12:15 FAILED diana   198.51.100.77
09:13:00 FAILED erin    198.51.100.77
```

Possible false positives include shared gateways, penetration-testing activity, identity-provider health checks, or legitimate applications that authenticate many service/user accounts from one host.

## Installation

Python 3.10+ is recommended.

```bash
git clone <your-repository-url>
cd security-log-analyzer
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows PowerShell, activate the virtual environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Usage

Run the analyzer with the default detection settings:

```bash
python3 analyzer.py data/sample_auth.log
```

Customize both rules:

```bash
python3 analyzer.py data/sample_auth.log \
  --bf-threshold 5 \
  --bf-window 60 \
  --spray-threshold 5 \
  --spray-window 300
```

Export alerts:

```bash
python3 analyzer.py data/sample_auth.log \
  --json-out reports/alerts.json \
  --csv-out reports/alerts.csv
```

Stop immediately on malformed input:

```bash
python3 analyzer.py data/sample_auth.log --strict
```

## CLI Options

```text
usage: analyzer.py [-h] [--bf-threshold BF_THRESHOLD] [--bf-window BF_WINDOW]
                   [--spray-threshold SPRAY_THRESHOLD]
                   [--spray-window SPRAY_WINDOW] [--json-out JSON_OUT]
                   [--csv-out CSV_OUT] [--top TOP] [--strict]
                   log_file
```

| Option | Purpose | Default |
|---|---|---:|
| `log_file` | Path to authentication log | required |
| `--bf-threshold` | Failed attempts needed for brute-force alert | `5` |
| `--bf-window` | Brute-force window in seconds | `60` |
| `--spray-threshold` | Distinct usernames needed for spray alert | `5` |
| `--spray-window` | Password-spraying window in seconds | `300` |
| `--json-out` | Export alert list as JSON | none |
| `--csv-out` | Export alert list as CSV | none |
| `--top` | Number of top IPs/usernames to print | `5` |
| `--strict` | Fail on first malformed log line | off |

## Example Input

From `data/sample_auth.log`:

```text
2026-10-06T09:00:00Z status=FAILED username=alice ip=203.0.113.50
2026-10-06T09:00:10Z status=FAILED username=alice ip=203.0.113.50
2026-10-06T09:00:20Z status=FAILED username=alice ip=203.0.113.50
2026-10-06T09:00:30Z status=FAILED username=alice ip=203.0.113.50
2026-10-06T09:00:40Z status=FAILED username=alice ip=203.0.113.50
```

## Example Output

With the included sample file and default settings, the analyzer reports two alerts: one brute-force pattern and one password-spraying pattern.

```text
=== Security Log Analyzer ===
Events parsed:      20
Successful logins:  7
Failed logins:      13
Malformed skipped:  0

Alerts: 2
  [1] Brute Force | ip=203.0.113.50 | failed=5 | unique_users=1
      window=2026-10-06T09:00:00+00:00 -> 2026-10-06T09:00:40+00:00
      usernames=alice
  [2] Password Spraying | ip=198.51.100.77 | failed=5 | unique_users=5
      window=2026-10-06T09:10:00+00:00 -> 2026-10-06T09:13:00+00:00
      usernames=alice, bob, charlie, diana, erin
```

The full terminal output also includes top source IPs and targeted usernames.

## JSON Alert Example

```json
{
  "rule": "brute_force",
  "source_ip": "203.0.113.50",
  "window_start": "2026-10-06T09:00:00+00:00",
  "window_end": "2026-10-06T09:00:40+00:00",
  "failed_attempts": 5,
  "unique_usernames": 1,
  "usernames": ["alice"]
}
```

## Testing

Run all automated tests from the repository root:

```bash
python3 -m pytest -q
```

The test suite covers:

- valid parsing;
- malformed input;
- non-strict and strict parsing behavior;
- positive brute-force detection;
- negative brute-force detection;
- the exact time-window boundary;
- positive password-spraying detection;
- negative password-spraying detection;
- successful events being excluded from detection;
- summary statistics and ranking.

## Design Decisions

### Why separate thresholds for the two rules?

Brute force and password spraying measure different behaviors. A brute-force threshold counts failed attempts, while a spraying threshold counts distinct usernames. Giving them separate CLI options keeps the semantics explicit and easier to tune.

### Why use source IP as the grouping key?

The project models an external source attempting authentication against one or more accounts. Source IP is a simple and explainable grouping key for that scenario. Real systems would usually combine IP data with identity, device, ASN/network reputation, geolocation, user-agent information, and other context.

### Why use a sliding window?

A sliding window directly answers the security question: "Did enough relevant events occur close together in time?" It is more meaningful than checking a total count across the entire log.

## Limitations

This is a learning/portfolio project, not a production detection system.

Important limitations include:

- The parser supports one intentionally simple synthetic log format.
- IP addresses are treated as strings and are not validated as real IPv4/IPv6 addresses.
- The system processes a file in memory rather than streaming events continuously.
- Thresholds are static and do not adapt to normal behavior for each user or network.
- A single source IP can represent many legitimate users behind NAT or a proxy.
- There is no allowlist, asset context, IP reputation, geolocation, device context, or threat intelligence.
- Alert suppression is intentionally simple and can hide closely spaced repeated bursts.
- There is no persistence layer, dashboard, correlation engine, or distributed processing.

## Future Improvements

Reasonable next steps include:

- add an IP allowlist for trusted sources;
- add alert severity levels;
- add another authentication rule, such as repeated failures followed by a successful login;
- support a common real-world log format;
- stream large files instead of loading all events into memory;
- add richer contextual features and more sophisticated alert de-duplication.

## Synthetic Data Notice

All authentication events included in `data/sample_auth.log` are synthetic. The IP ranges used in the sample are documentation/example ranges and the data is not derived from real users or real authentication systems.
