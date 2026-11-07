import ipaddress
import re
from datetime import datetime


# Supported OpenSSH process names.
SSH_PROCESS_NAMES = {"sshd", "sshd-session"}


def _extract_source_ip(message):
    """
    Extract a valid IPv4 or IPv6 address from an OpenSSH message.

    Supports messages containing:
    - from <IP> port <PORT>
    - Connection closed by <IP> port <PORT>
    - Connection closed by authenticating user <USER> <IP> port <PORT>
    """

    candidates = re.findall(
        r"(?<![a-zA-Z0-9_.])(?:"
        r"\d{1,3}(?:\.\d{1,3}){3}"
        r"|[0-9a-fA-F]*:[0-9a-fA-F:.]+"
        r")",
        message,
    )

    # Check candidates from right to left.
    # This prevents usernames containing "from" from being
    # incorrectly interpreted as source addresses.
    for candidate in reversed(candidates):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

    return None


def parse_openssh_log_line(line, year=None):
    """
    Parse an OpenSSH log entry.

    Supports:
    1. Classic syslog timestamps:
       Nov  4 10:15:32 ubuntu sshd[1234]: Failed password ...

    2. ISO 8601 timestamps:
       2026-11-04T10:15:32.123456+00:00 ubuntu sshd[1234]: Failed password ...

    Args:
        line: Raw OpenSSH log entry.
        year: Optional year for classic syslog timestamps.

    Returns:
        Dictionary containing parsed log information,
        or None if the line is invalid or not an SSH log.

    Important:
        Classic syslog timestamps do not contain a year.
        If year is omitted, the current local year is used.
        This can produce incorrect timestamps for archived logs
        collected from a different year. Supply --year when
        processing historical syslog files.
    """

    if not isinstance(line, str):
        return None

    line = line.strip()

    if not line:
        return None

    # --------------------------------------------------
    # 1. ISO 8601 timestamp format
    # --------------------------------------------------

    iso_pattern = re.compile(
        r"^("
        r"\d{4}-\d{2}-\d{2}"
        r"[Tt ]"
        r"\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?"
        r"(?:[Zz]|[+-]\d{2}:?\d{2})?"
        r")\s+"
        r"(\S+)\s+"
        r"(\S+)\[(\d+)\]:\s*"
        r"(.*)$"
    )

    iso_match = iso_pattern.match(line)

    if iso_match:
        timestamp_text = iso_match.group(1)
        hostname = iso_match.group(2)
        process_name = iso_match.group(3)
        pid = iso_match.group(4)
        message = iso_match.group(5)

        try:
            normalized_timestamp = timestamp_text.replace(
                "Z", "+00:00"
            ).replace("z", "+00:00")

            timestamp = datetime.fromisoformat(
                normalized_timestamp
            )

        except ValueError:
            return None

        # Keep the original timestamp timezone information.
        month = timestamp.strftime("%b")
        date = str(timestamp.day)
        time = timestamp.strftime("%H:%M:%S")

    else:

        # --------------------------------------------------
        # 2. Classic syslog timestamp format
        # --------------------------------------------------

        syslog_pattern = re.compile(
            r"^([A-Z][a-z]{2})\s+"
            r"(\d{1,2})\s+"
            r"(\d{2}:\d{2}:\d{2})\s+"
            r"(\S+)\s+"
            r"(\S+)\[(\d+)\]:\s*"
            r"(.*)$"
        )

        syslog_match = syslog_pattern.match(line)

        if not syslog_match:
            return None

        month = syslog_match.group(1)
        date = syslog_match.group(2)
        time = syslog_match.group(3)
        hostname = syslog_match.group(4)
        process_name = syslog_match.group(5)
        pid = syslog_match.group(6)
        message = syslog_match.group(7)

        # Syslog timestamps do not contain a year.
        # Use the supplied year or the current local year.
        if year is None:
            year = datetime.now().year

        if not isinstance(year, int):
            return None

        try:
            timestamp = datetime.strptime(
                f"{month} {date} {time} {year}",
                "%b %d %H:%M:%S %Y",
            )

        except ValueError:
            return None

    # --------------------------------------------------
    # 3. Validate SSH process
    # --------------------------------------------------

    if process_name not in SSH_PROCESS_NAMES:
        return None

    # --------------------------------------------------
    # 4. Extract source IP
    # --------------------------------------------------

    source_ip = _extract_source_ip(message)

    # --------------------------------------------------
    # 5. Return parsed log entry
    # --------------------------------------------------

    return {
        "month": month,
        "date": date,
        "time": time,
        "hostname": hostname,
        "process_name": process_name,
        "pid": pid,
        "message": message,
        "source_ip": source_ip,
        "timestamp": timestamp,
    }