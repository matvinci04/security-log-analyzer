"""Parsing utilities for the synthetic authentication log format."""

from datetime import datetime
from pathlib import Path

VALID_STATUSES = {"SUCCESS", "FAILED"}
REQUIRED_FIELDS = {"status", "username", "ip"}


def parse_log_line(line, line_number=None):
    """Parse one authentication log line into a dictionary.

    Expected format:
    2026-10-06T09:00:00Z status=FAILED username=alice ip=203.0.113.10

    Raises:
        ValueError: if the line is malformed or contains unsupported values.
    """
    stripped = line.strip()
    if not stripped:
        raise ValueError("empty line")

    parts = stripped.split()
    if len(parts) != 4:
        raise ValueError(_with_line_number("expected 4 whitespace-separated fields", line_number))

    timestamp_text = parts[0]
    fields = {}

    for token in parts[1:]:
        if "=" not in token:
            raise ValueError(_with_line_number(f"invalid field '{token}'", line_number))
        key, value = token.split("=", 1)
        if not key or not value:
            raise ValueError(_with_line_number(f"invalid field '{token}'", line_number))
        if key in fields:
            raise ValueError(_with_line_number(f"duplicate field '{key}'", line_number))
        fields[key] = value

    if set(fields) != REQUIRED_FIELDS:
        missing = sorted(REQUIRED_FIELDS - set(fields))
        extra = sorted(set(fields) - REQUIRED_FIELDS)
        problems = []
        if missing:
            problems.append(f"missing fields: {', '.join(missing)}")
        if extra:
            problems.append(f"unexpected fields: {', '.join(extra)}")
        raise ValueError(_with_line_number("; ".join(problems), line_number))

    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(_with_line_number(f"invalid timestamp '{timestamp_text}'", line_number)) from exc

    if timestamp.utcoffset() is None:
        raise ValueError(
            _with_line_number(
                f"timestamp '{timestamp_text}' must include timezone information",
                line_number,
            )
        )

    status = fields["status"].upper()
    if status not in VALID_STATUSES:
        raise ValueError(
            _with_line_number(
                f"unsupported status '{fields['status']}' (expected SUCCESS or FAILED)",
                line_number,
            )
        )

    return {
        "timestamp": timestamp,
        "status": status,
        "username": fields["username"],
        "ip": fields["ip"],
    }


def load_events(file_path, strict=False):
    """Load events from a log file.

    Blank lines and lines starting with '#' are ignored. Malformed lines are
    skipped by default and returned as human-readable errors. In strict mode,
    the first malformed line raises ValueError.
    """
    path = Path(file_path)
    events = []
    errors = []

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            try:
                events.append(parse_log_line(line, line_number=line_number))
            except ValueError as exc:
                if strict:
                    raise
                errors.append(str(exc))

    return events, errors


def _with_line_number(message, line_number):
    if line_number is None:
        return message
    return f"line {line_number}: {message}"
