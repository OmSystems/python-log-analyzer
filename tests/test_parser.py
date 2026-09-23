from analyzer.parser import parse_log_line
from analyzer.parser import parse_log_lines
from analyzer.analyzer import count_log_levels
from analyzer.analyzer import get_errors


def test_parsing_a_valid_log_line():
    parse_log_lines_demo = "2026-08-26T12:30:01 INFO 192.168.1.10 Server started"
    result = parse_log_line(parse_log_lines_demo)

    assert result == {
        'timestamp': '2026-08-26T12:30:01',
        'level': 'INFO',
        'ip': '192.168.1.10',
        'message': 'Server started'
    }

def test_parsing_a_invalid_log_line():
    parse_log_lines_demo = "This is not a valid log line."

    result = parse_log_line(parse_log_lines_demo)

    assert result is None

def test_perfect_log_line():
    valid_log_line = "2026-08-26T12:32:45 ERROR 192.168.1.50 Database connection failed"
    result = parse_log_line(valid_log_line)

    assert result == {
        'timestamp': '2026-08-26T12:32:45',
        'level': 'ERROR',
        'ip': '192.168.1.50',
        'message': 'Database connection failed'
    }

def test_empty_log():
    empty_log = " "
    result = parse_log_line(empty_log)

    assert result is None

def test_parsing_a_warning_log_line():
    warning_log = "2026-08-26T12:30:15 WARNING 192.168.1.10 Disk space is lows"
    result = parse_log_line(warning_log)

    assert result == {
        'timestamp': '2026-08-26T12:30:15',
        'level': 'WARNING',
        'ip': '192.168.1.10',
        'message': 'Disk space is lows'
    }

def test_parsing_an_unknown_log_level():
    unknown_log = "DEBUG User authentication started"

    result = parse_log_line(unknown_log)

    assert result is None

def test_log_line_with_no_message():
    log_line="ERROR"

    result = parse_log_line(log_line)

    assert result is None

def test_multiline_logs():
    multi_line_logs = [
        "2026-08-26T12:30:01 INFO 192.168.1.10 Server started",
        "2026-08-26T12:30:15 WARNING 192.168.1.10 Disk space is low",
        "2026-08-26T12:32:45 ERROR 192.168.1.50 Database connection failed"
    ]


def test_log_line_with_extra_spaces_in_message():
    log_line = "2026-08-26T12:30:15 WARNING 192.168.1.10 Disk   space   is low"
    result = parse_log_line(log_line)

    assert result == {
        'timestamp': '2026-08-26T12:30:15',
        'level': 'WARNING',
        'ip': '192.168.1.10',
        'message': 'Disk   space   is low'
    }


def test_empty_string():
    result = parse_log_line("")

    assert result is None
    

def test_multiline_logs_with_invalid_line():
    multi_line_logs = [
        "2026-08-26T12:30:01 INFO 192.168.1.10 Server started",
        "This is not a valid log",
        "2026-08-26T12:32:45 ERROR 192.168.1.50 Database connection failed"
    ]

    result = parse_log_lines(multi_line_logs)

    assert result == [
        {'timestamp': '2026-08-26T12:30:01', 'level': 'INFO', 'ip': '192.168.1.10', 'message': 'Server started'},
        {'timestamp': '2026-08-26T12:32:45', 'level': 'ERROR', 'ip': '192.168.1.50', 'message': 'Database connection failed'}
    ]

def test_parsing_security_log_line():
    log_line = "2026-08-26T12:31:02 ERROR 192.168.1.50 Authentication failed"

    result = parse_log_line(log_line)

    assert result == {
        "timestamp": "2026-08-26T12:31:02",
        "level": "ERROR",
        "ip": "192.168.1.50",
        "message": "Authentication failed"
    }