from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta


SSH_PROCESSES = {"sshd", "sshd-session"}


def count_log_levels(parsed_logs: list[dict]) -> dict:
    counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}

    for log in parsed_logs:
        level = log.get("level")

        if level in counts:
            counts[level] += 1

    return counts


def get_errors(parsed_logs: list[dict]) -> list[str]:
    return [
        log["message"]
        for log in parsed_logs
        if log.get("level") == "ERROR"
    ]


def _is_failed_ssh_message(message: str) -> bool:
    return message.startswith((
        "Invalid user ",
        "Failed password ",
        "Failed publickey ",
        "Connection closed by invalid user ",
        "Connection closed by authenticating user ",
    ))


def _failed_ssh_events(parsed_logs):
    """
    Return one failed event per SSH connection.

    Multiple failure-related messages from the same source IP
    and connection PID count as one attempt.
    """

    events = []
    seen_connections = set()

    for index, log in enumerate(parsed_logs):

        if log.get("process_name") not in SSH_PROCESSES:
            continue

        if not _is_failed_ssh_message(log.get("message", "")):
            continue

        source_ip = log.get("source_ip")

        if source_ip is None:
            continue

        pid = log.get("pid")

        if pid is not None:
            connection_key = (source_ip, str(pid))
        else:
            connection_key = (source_ip, "record", index)

        if connection_key in seen_connections:
            continue

        seen_connections.add(connection_key)
        events.append(log)

    return events


def count_failed_ssh_logins(parsed_logs: list[dict]) -> dict:
    """
    Count unique failed SSH connections grouped by source IP.
    """

    failed_counts = defaultdict(int)

    for log in _failed_ssh_events(parsed_logs):
        failed_counts[log["source_ip"]] += 1

    return dict(failed_counts)


def detect_brute_force(
    parsed_logs: list[dict] | dict,
    threshold: int = 5,
    window_seconds: int = 60,
) -> dict:
    """
    Detect repeated failed SSH connections within a time window.

    Args:
        parsed_logs: Parsed SSH log entries or precomputed IP counts.
        threshold: Minimum failed attempts required.
        window_seconds: Detection window in seconds.

    Returns:
        Dictionary containing suspicious IP addresses and counts.
    """

    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    if window_seconds < 0:
        raise ValueError("Window must not be negative")

    # Backward compatibility with precomputed IP counts.
    if isinstance(parsed_logs, dict):
        return {
            ip: count
            for ip, count in parsed_logs.items()
            if count >= threshold
        }

    window = timedelta(seconds=window_seconds)

    attempts_by_ip = defaultdict(deque)
    suspicious_ips = {}

    for log in _failed_ssh_events(parsed_logs):

        source_ip = log.get("source_ip")
        timestamp = log.get("timestamp")

        if timestamp is None:
            continue

        attempts = attempts_by_ip[source_ip]

        cutoff = timestamp - window

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        attempts.append(timestamp)

        if len(attempts) >= threshold:
            suspicious_ips[source_ip] = len(attempts)

    return suspicious_ips


def detect_successful_login_after_failures(
    parsed_logs: list[dict],
    threshold: int = 5,
    window_seconds: int = 60,
) -> dict:
    """
    Detect successful SSH authentication after repeated failures.
    """

    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    if window_seconds < 0:
        raise ValueError("Window must not be negative")

    window = timedelta(seconds=window_seconds)

    failures_by_ip = defaultdict(deque)
    suspicious_ips = {}

    failed_events = _failed_ssh_events(parsed_logs)
    failed_ids = {id(event) for event in failed_events}

    for log in parsed_logs:

        if log.get("process_name") not in SSH_PROCESSES:
            continue

        source_ip = log.get("source_ip")
        timestamp = log.get("timestamp")

        if source_ip is None or timestamp is None:
            continue

        failures = failures_by_ip[source_ip]

        cutoff = timestamp - window

        while failures and failures[0] < cutoff:
            failures.popleft()

        if id(log) in failed_ids:
            failures.append(timestamp)

        elif log.get("message", "").startswith((
            "Accepted password ",
            "Accepted publickey ",
        )) and len(failures) >= threshold:

            suspicious_ips[source_ip] = len(failures)
            failures.clear()

    return suspicious_ips