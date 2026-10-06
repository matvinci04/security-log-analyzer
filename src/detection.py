"""Rule-based authentication threat detection."""

from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events, threshold=5, window_seconds=60):
    """Detect repeated failed logins from the same IP inside a time window.

    An alert is emitted when at least ``threshold`` failed authentications from
    one source IP fit inside ``window_seconds``. After an alert, another alert
    for the same IP is suppressed until one full detection window has passed.
    """
    _validate_rule_parameters(threshold, window_seconds)
    grouped = _failed_events_by_ip(events)
    alerts = []
    window = timedelta(seconds=window_seconds)

    for ip, ip_events in grouped.items():
        ordered = sorted(ip_events, key=lambda event: event["timestamp"])
        left = 0
        suppress_until = None

        for right, current in enumerate(ordered):
            while current["timestamp"] - ordered[left]["timestamp"] > window:
                left += 1

            attempts = right - left + 1
            if attempts < threshold:
                continue

            if suppress_until is not None and current["timestamp"] <= suppress_until:
                continue

            window_events = ordered[left : right + 1]
            alerts.append(
                _build_alert(
                    rule="brute_force",
                    ip=ip,
                    window_events=window_events,
                )
            )
            suppress_until = current["timestamp"] + window

    return alerts


def detect_password_spraying(events, username_threshold=5, window_seconds=300):
    """Detect one IP failing authentication against many distinct usernames.

    The sliding window keeps track of distinct usernames. An alert is emitted
    when the number of unique targeted usernames reaches ``username_threshold``.
    Repeated alerts for the same IP are suppressed for one detection window.
    """
    _validate_rule_parameters(username_threshold, window_seconds)
    grouped = _failed_events_by_ip(events)
    alerts = []
    window = timedelta(seconds=window_seconds)

    for ip, ip_events in grouped.items():
        ordered = sorted(ip_events, key=lambda event: event["timestamp"])
        left = 0
        username_counts = defaultdict(int)
        suppress_until = None

        for right, current in enumerate(ordered):
            username_counts[current["username"]] += 1

            while current["timestamp"] - ordered[left]["timestamp"] > window:
                old_username = ordered[left]["username"]
                username_counts[old_username] -= 1
                if username_counts[old_username] == 0:
                    del username_counts[old_username]
                left += 1

            if len(username_counts) < username_threshold:
                continue

            if suppress_until is not None and current["timestamp"] <= suppress_until:
                continue

            window_events = ordered[left : right + 1]
            alerts.append(
                _build_alert(
                    rule="password_spraying",
                    ip=ip,
                    window_events=window_events,
                )
            )
            suppress_until = current["timestamp"] + window

    return alerts


def _failed_events_by_ip(events):
    grouped = defaultdict(list)
    for event in events:
        if event["status"] == "FAILED":
            grouped[event["ip"]].append(event)
    return grouped


def _build_alert(rule, ip, window_events):
    usernames = sorted({event["username"] for event in window_events})
    return {
        "rule": rule,
        "source_ip": ip,
        "window_start": window_events[0]["timestamp"].isoformat(),
        "window_end": window_events[-1]["timestamp"].isoformat(),
        "failed_attempts": len(window_events),
        "unique_usernames": len(usernames),
        "usernames": usernames,
    }


def _validate_rule_parameters(threshold, window_seconds):
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
