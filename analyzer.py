"""Command-line entry point for Security Log Analyzer."""

import argparse
import sys

from src.detection import detect_brute_force, detect_password_spraying
from src.parser import load_events
from src.reporting import export_alerts_csv, export_alerts_json, print_report
from src.stats import build_summary


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication logs and detect brute-force and password-spraying behavior."
        )
    )
    parser.add_argument("log_file", help="Path to the authentication log file")
    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        help="Failed attempts required for brute-force detection (default: 5)",
    )
    parser.add_argument(
        "--bf-window",
        type=int,
        default=60,
        help="Brute-force time window in seconds (default: 60)",
    )
    parser.add_argument(
        "--spray-threshold",
        type=int,
        default=5,
        help="Distinct usernames required for password-spraying detection (default: 5)",
    )
    parser.add_argument(
        "--spray-window",
        type=int,
        default=300,
        help="Password-spraying time window in seconds (default: 300)",
    )
    parser.add_argument(
        "--json-out",
        help="Optional path for exporting alerts as JSON",
    )
    parser.add_argument(
        "--csv-out",
        help="Optional path for exporting alerts as CSV",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top IPs/usernames to show in terminal output (default: 5)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Stop on the first malformed log line instead of skipping it",
    )
    return parser


def main(argv=None):
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.top < 0:
        parser.error("--top must be 0 or greater")

    try:
        events, parse_errors = load_events(args.log_file, strict=args.strict)
        brute_force_alerts = detect_brute_force(
            events,
            threshold=args.bf_threshold,
            window_seconds=args.bf_window,
        )
        spraying_alerts = detect_password_spraying(
            events,
            username_threshold=args.spray_threshold,
            window_seconds=args.spray_window,
        )
    except FileNotFoundError:
        print(f"Error: log file not found: {args.log_file}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"Error: permission denied while reading: {args.log_file}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    alerts = sorted(
        brute_force_alerts + spraying_alerts,
        key=lambda alert: (alert["window_start"], alert["rule"], alert["source_ip"]),
    )
    summary = build_summary(events)
    print_report(summary, alerts, parse_errors=parse_errors, top_limit=args.top)

    if args.json_out:
        export_alerts_json(alerts, args.json_out)
        print(f"\nJSON alerts written to: {args.json_out}")
    if args.csv_out:
        export_alerts_csv(alerts, args.csv_out)
        print(f"CSV alerts written to: {args.csv_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
