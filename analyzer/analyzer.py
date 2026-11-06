from collections import defaultdict, deque
from datetime import timedelta


def count_log_levels(parsed_logs: list[dict]) -> dict:
    counts = {
        "INFO": 0,
        "WARNING": 0,
        "ERROR": 0,
    }

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


def count_failed_ssh_logins(parsed_logs: list[dict]) -> dict:
    failed_counts = defaultdict(int)

    for log in parsed_logs:
        if log.get("process_name") != "sshd":
            continue
        if not log.get("message", "").startswith("Failed password"):
            continue

        source_ip = log.get("source_ip")
        if source_ip is not None:
            failed_counts[source_ip] += 1

    return dict(failed_counts)


def detect_brute_force(
    parsed_logs: list[dict] | dict,
    threshold: int = 5,
    window_seconds: int = 60,
) -> dict:
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    if window_seconds < 0:
        raise ValueError("Window must not be negative")

    # Keep compatibility with callers that pass pre-counted failures.
    if isinstance(parsed_logs, dict):
        return {
            source_ip: count
            for source_ip, count in parsed_logs.items()
            if count >= threshold
        }

    window = timedelta(seconds=window_seconds)
    attempts_by_ip = defaultdict(deque)
    suspicious_ips = {}

    for log in parsed_logs:
        if log.get("process_name") != "sshd":
            continue
        if not log.get("message", "").startswith("Failed password"):
            continue

        source_ip = log.get("source_ip")
        timestamp = log.get("timestamp")
        if source_ip is None or timestamp is None:
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
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")
    if window_seconds < 0:
        raise ValueError("Window must not be negative")

    window = timedelta(seconds=window_seconds)
    failures_by_ip = defaultdict(deque)
    suspicious_ips = {}

    for log in parsed_logs:
        if log.get("process_name") != "sshd":
            continue

        source_ip = log.get("source_ip")
        timestamp = log.get("timestamp")
        if source_ip is None or timestamp is None:
            continue

        failures = failures_by_ip[source_ip]
        cutoff = timestamp - window
        while failures and failures[0] < cutoff:
            failures.popleft()

        message = log.get("message", "")
        if message.startswith("Failed password"):
            failures.append(timestamp)
        elif message.startswith("Accepted password") and len(failures) >= threshold:
            suspicious_ips[source_ip] = len(failures)
            failures.clear()

    return suspicious_ips