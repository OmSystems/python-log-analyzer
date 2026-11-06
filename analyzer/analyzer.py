def count_log_levels(parsed_logs: list[dict]) -> dict:
    counts = {
        "INFO": 0,
        "WARNING": 0,
        "ERROR": 0
    }

    for log in parsed_logs:
        level = log["level"]

        if level in counts:
            counts[level] += 1

    return counts

def get_errors(parsed_logs):
    errors=[]
    for log in parsed_logs:
        if log["level"] == "ERROR":
            errors.append(log["message"])
    return errors

def count_failed_ssh_logins(parsed_logs: list[dict]) -> dict:
    failed_counts = {}

    for log in parsed_logs:
        # Verify it's an SSH process and an authentication failure
        if log.get("process_name") != "sshd":
            continue

        message = log.get("message", "")
        if not message.startswith("Failed password"):
            continue

        ip = log.get("source_ip")
        if ip is None:
            continue

        # Increment count for this IP
        failed_counts[ip] = failed_counts.get(ip, 0) + 1

    return failed_counts

def detect_brute_force(failed_counts: dict, threshold: int = 5) -> dict:
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    suspicious_ips = {}

    for ip, count in failed_counts.items():
        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips