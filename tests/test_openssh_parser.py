from analyzer.openssh_parser import parse_openssh_log_line
def test_parse_iso8601_timestamp_with_timezone():
    log_line = (
        "2026-11-04T10:15:32.123456+00:00 "
        "ubuntu sshd-session[1234]: "
        "Failed password for admin from 203.0.113.5 port 52222 ssh2"
    )

    result = parse_openssh_log_line(log_line)

    assert result is not None
    assert result["process_name"] == "sshd-session"
    assert result["timestamp"].year == 2026
    assert result["timestamp"].microsecond == 123456
    assert result["timestamp"].utcoffset().total_seconds() == 0


def test_parse_syslog_timestamp_with_explicit_year():
    log_line = (
        "Nov  4 10:15:32 ubuntu sshd[1234]: "
        "Failed password for admin from 203.0.113.5 port 52222 ssh2"
    )

    result = parse_openssh_log_line(log_line, year=2025)

    assert result is not None
    assert result["timestamp"].year == 2025
    assert result["timestamp"].month == 11
    assert result["timestamp"].day == 4