"""Summary statistics for authentication events."""

from collections import defaultdict


def build_summary(events):
    """Build global, per-IP, and per-username authentication statistics."""
    by_ip = defaultdict(lambda: {"total": 0, "successful": 0, "failed": 0})
    by_username = defaultdict(lambda: {"total": 0, "successful": 0, "failed": 0})
    successful = 0
    failed = 0

    for event in events:
        status_key = "successful" if event["status"] == "SUCCESS" else "failed"
        if status_key == "successful":
            successful += 1
        else:
            failed += 1

        ip_stats = by_ip[event["ip"]]
        ip_stats["total"] += 1
        ip_stats[status_key] += 1

        user_stats = by_username[event["username"]]
        user_stats["total"] += 1
        user_stats[status_key] += 1

    return {
        "total_events": len(events),
        "successful_logins": successful,
        "failed_logins": failed,
        "by_ip": dict(by_ip),
        "by_username": dict(by_username),
    }


def top_by_failed(stats_by_key, limit=5):
    """Return the entries with the most failed authentications."""
    if limit <= 0:
        return []
    return sorted(
        stats_by_key.items(),
        key=lambda item: (-item[1]["failed"], item[0]),
    )[:limit]
