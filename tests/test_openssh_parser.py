from analyzer.openssh_parser import parse_openssh_log_line

def test_parse_failed_ssh_login():
    result = "Nov  4 10:15:32 ubuntu sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52222 ssh2"

    parsed = parse_openssh_log_line(result)
    assert parsed["hostname"] == "ubuntu"
    assert parsed["process_name"] == "sshd"
    assert parsed["pid"] == "1234"
    assert parsed["message"] == "Failed password for invalid user admin from 203.0.113.5 port 52222 ssh2"
    assert parsed["month"] == "Nov"
    assert parsed["date"] == "4"
    assert parsed["time"] == "10:15:32"
    assert parsed["source_ip"] == "203.0.113.5"


def test_parse_invalid_ssh_log():
    result = "this is not a valid SSH log entry"
    parsed = parse_openssh_log_line(result)

    assert parsed is None


def test_parse_non_ssh_process():
    log_line = "Nov  4 10:15:32 ubuntu cron[1234]: (root) CMD (/usr/bin/some-job)"
    parsed = parse_openssh_log_line(log_line)

    assert parsed is None

def test_parse_successful_ssh_login():
    log_line = "Nov  4 10:16:32 ubuntu sshd[1235]: Accepted password for om from 203.0.113.5 port 52222 ssh2"
    result = parse_openssh_log_line(log_line)

    # 1. The returned result is not None
    assert result is not None

    # 2. hostname equals ubuntu
    assert result["hostname"] == "ubuntu"

    # 3. process_name equals sshd
    assert result["process_name"] == "sshd"

    # 4. pid equals 1235
    assert result["pid"] == "1235"

    # 5. The message contains Accepted password
    assert "Accepted password" in result["message"]

    # 6. source_ip equals 203.0.113.5
    assert result["source_ip"] == "203.0.113.5"

def test_parse_ipv6_source_address():
    log_line = "Nov  4 10:17:32 ubuntu sshd[1236]: Failed password for invalid user admin from 2001:db8::1 port 52222 ssh2"
    result = parse_openssh_log_line(log_line)

    # 1. The result is not None
    assert result is not None

    # 2. The process name is sshd
    assert result["process_name"] == "sshd"

    # 3. The source IP equals 2001:db8::1
    assert result["source_ip"] == "2001:db8::1"

def test_parse_invalid_source_ip():
    raw_log = "Nov  4 10:15:32 ubuntu sshd[1234]: Failed password for invalid user admin from 999.999.999.999 port 52222 ssh2"
    result = parse_openssh_log_line(raw_log)

    assert result is not None
    assert result["process_name"] == "sshd"
    assert result["source_ip"] is None