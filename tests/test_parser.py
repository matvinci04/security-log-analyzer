from pathlib import Path

import pytest

from src.parser import load_events, parse_log_line


def test_parse_valid_log_line():
    event = parse_log_line(
        "2026-10-06T09:00:00Z status=FAILED username=alice ip=203.0.113.50"
    )

    assert event["status"] == "FAILED"
    assert event["username"] == "alice"
    assert event["ip"] == "203.0.113.50"
    assert event["timestamp"].isoformat() == "2026-10-06T09:00:00+00:00"


def test_parse_requires_timezone_information():
    with pytest.raises(ValueError, match="timezone information"):
        parse_log_line(
            "2026-10-06T09:00:00 status=FAILED username=alice ip=203.0.113.50"
        )


def test_parse_rejects_malformed_line():
    with pytest.raises(ValueError):
        parse_log_line("not-a-valid-log-line")


def test_load_events_skips_malformed_line_by_default(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-10-06T09:00:00Z status=SUCCESS username=alice ip=192.0.2.1\n"
        "malformed line\n",
        encoding="utf-8",
    )

    events, errors = load_events(log_file)

    assert len(events) == 1
    assert len(errors) == 1
    assert errors[0].startswith("line 2:")


def test_load_events_strict_mode_raises(tmp_path: Path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("malformed line\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_events(log_file, strict=True)
