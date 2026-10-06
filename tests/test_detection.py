from datetime import datetime, timezone

from src.detection import detect_brute_force, detect_password_spraying


def event(seconds, username, ip="203.0.113.10", status="FAILED"):
    return {
        "timestamp": datetime(2026, 10, 6, 9, 0, seconds, tzinfo=timezone.utc),
        "status": status,
        "username": username,
        "ip": ip,
    }


def test_brute_force_positive():
    events = [event(second, "alice") for second in [0, 10, 20, 30, 40]]

    alerts = detect_brute_force(events, threshold=5, window_seconds=60)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["source_ip"] == "203.0.113.10"
    assert alerts[0]["failed_attempts"] == 5


def test_brute_force_negative_when_attempts_are_too_spread_out():
    events = [event(second, "alice") for second in [0, 20, 40, 50]]
    events.append(
        {
            "timestamp": datetime(2026, 10, 6, 9, 1, 20, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "alice",
            "ip": "203.0.113.10",
        }
    )

    alerts = detect_brute_force(events, threshold=5, window_seconds=60)

    assert alerts == []


def test_brute_force_boundary_is_inclusive():
    events = [event(second, "alice") for second in [0, 15, 30, 45]]
    events.append(
        {
            "timestamp": datetime(2026, 10, 6, 9, 1, 0, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "alice",
            "ip": "203.0.113.10",
        }
    )

    alerts = detect_brute_force(events, threshold=5, window_seconds=60)

    assert len(alerts) == 1


def test_password_spraying_positive():
    events = [
        event(0, "alice", ip="198.51.100.20"),
        {
            "timestamp": datetime(2026, 10, 6, 9, 0, 45, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "bob",
            "ip": "198.51.100.20",
        },
        {
            "timestamp": datetime(2026, 10, 6, 9, 1, 30, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "charlie",
            "ip": "198.51.100.20",
        },
        {
            "timestamp": datetime(2026, 10, 6, 9, 2, 15, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "diana",
            "ip": "198.51.100.20",
        },
        {
            "timestamp": datetime(2026, 10, 6, 9, 3, 0, tzinfo=timezone.utc),
            "status": "FAILED",
            "username": "erin",
            "ip": "198.51.100.20",
        },
    ]

    alerts = detect_password_spraying(events, username_threshold=5, window_seconds=300)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "password_spraying"
    assert alerts[0]["unique_usernames"] == 5
    assert alerts[0]["failed_attempts"] == 5


def test_password_spraying_negative_when_same_account_is_retried():
    events = [event(second, "alice") for second in [0, 10, 20, 30, 40, 50]]

    alerts = detect_password_spraying(events, username_threshold=5, window_seconds=300)

    assert alerts == []


def test_successful_logins_do_not_count_toward_detection():
    events = [event(second, "alice", status="SUCCESS") for second in [0, 10, 20, 30, 40]]

    brute_force_alerts = detect_brute_force(events, threshold=5, window_seconds=60)
    spray_alerts = detect_password_spraying(events, username_threshold=2, window_seconds=300)

    assert brute_force_alerts == []
    assert spray_alerts == []
