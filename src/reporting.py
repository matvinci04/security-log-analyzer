"""Terminal and file reporting for analyzer results."""

import csv
import json
from pathlib import Path

from src.stats import top_by_failed


def print_report(summary, alerts, parse_errors=None, top_limit=5):
    """Print a compact human-readable analysis report."""
    parse_errors = parse_errors or []

    print("\n=== Security Log Analyzer ===")
    print(f"Events parsed:      {summary['total_events']}")
    print(f"Successful logins:  {summary['successful_logins']}")
    print(f"Failed logins:      {summary['failed_logins']}")
    print(f"Malformed skipped:  {len(parse_errors)}")

    print("\nTop source IPs by failed logins:")
    _print_top_entries(top_by_failed(summary["by_ip"], top_limit))

    print("\nMost targeted usernames by failed logins:")
    _print_top_entries(top_by_failed(summary["by_username"], top_limit))

    print(f"\nAlerts: {len(alerts)}")
    if not alerts:
        print("  No rule matched the configured thresholds.")
    else:
        for number, alert in enumerate(alerts, start=1):
            rule_name = alert["rule"].replace("_", " ").title()
            usernames = ", ".join(alert["usernames"])
            print(
                f"  [{number}] {rule_name} | ip={alert['source_ip']} | "
                f"failed={alert['failed_attempts']} | unique_users={alert['unique_usernames']}"
            )
            print(f"      window={alert['window_start']} -> {alert['window_end']}")
            print(f"      usernames={usernames}")

    if parse_errors:
        print("\nParsing warnings:")
        for error in parse_errors:
            print(f"  - {error}")


def export_alerts_json(alerts, output_path):
    """Write alerts to a JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(alerts, output_file, indent=2)


def export_alerts_csv(alerts, output_path):
    """Write alerts to a CSV file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rule",
        "source_ip",
        "window_start",
        "window_end",
        "failed_attempts",
        "unique_usernames",
        "usernames",
    ]

    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row = dict(alert)
            row["usernames"] = ";".join(alert["usernames"])
            writer.writerow(row)


def _print_top_entries(entries):
    if not entries:
        print("  No data.")
        return
    for key, stats in entries:
        print(
            f"  {key:<20} failed={stats['failed']:<3} "
            f"success={stats['successful']:<3} total={stats['total']}"
        )
