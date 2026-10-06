from datetime import datetime, timezone

from src.stats import build_summary, top_by_failed


def test_build_summary_and_ranking():
    timestamp = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)
    events = [
        {"timestamp": timestamp, "status": "FAILED", "username": "alice", "ip": "1.1.1.1"},
        {"timestamp": timestamp, "status": "FAILED", "username": "alice", "ip": "1.1.1.1"},
        {"timestamp": timestamp, "status": "SUCCESS", "username": "bob", "ip": "2.2.2.2"},
    ]

    summary = build_summary(events)
    top_ips = top_by_failed(summary["by_ip"], limit=1)

    assert summary["total_events"] == 3
    assert summary["successful_logins"] == 1
    assert summary["failed_logins"] == 2
    assert top_ips[0][0] == "1.1.1.1"
    assert top_ips[0][1]["failed"] == 2
