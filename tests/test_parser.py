from analyzer.parser import parse_log_line
from analyzer.parser import parse_log_lines

def test_parsing_a_valid_log_line():
    parse_log_lines_demo = "INFO Server started"
    result  =  parse_log_line(parse_log_lines_demo)

    assert result == {
                'level' : 'INFO',
                'message' : 'Server started'
            }

def test_parsing_a_invalid_log_line():
    parse_log_lines_demo = "This is not a valid log line."

    result = parse_log_line(parse_log_lines_demo)

    assert result == None

def test_perfect_log_line():
    valid_log_line = "ERROR Database connection failed"

    result = parse_log_line(valid_log_line)

    assert result == {
        'level' : 'ERROR',
        'message' : 'Database connection failed'
    }

def test_empty_log():
    Demo_empty_log = " "
    result = parse_log_line(Demo_empty_log)

    assert result == None

def test_parsing_a_warning_log_line():
    Demo_warning_log = "WARNING Disk space is lows"
    result = parse_log_line(Demo_warning_log)

    assert result == {
        'level' : "WARNING",
        'message' : "Disk space is lows"
    }

def test_parsing_an_unknown_log_level():
    Demo_unknown_log = "DEBUG User authentication started"

    result = parse_log_line(Demo_unknown_log)

    assert result == None

def test_log_line_with_no_message():
    Demo_log_line="ERROR"

    result = parse_log_line(Demo_log_line)

    assert result == None
def test_multiline_logs():
    multi_line_logs = ["INFO Server started", "WARNING Disk space is low", "ERROR Database connection failed"]

    result = parse_log_lines(multi_line_logs)

    assert result == [
    {'level': 'INFO', 'message': 'Server started'},
    {'level': 'WARNING', 'message': 'Disk space is low'},
    {'level': 'ERROR', 'message': 'Database connection failed'}
]

def test_log_line_with_extra_spaces():
    demo_log = "   WARNING Disk space is low   "

    result = parse_log_line(demo_log)

    assert result == {
        'level': 'WARNING',
        'message': 'Disk space is low'
    }

def test_multiline_logs_with_invalid_line():
    multi_line_logs = [
        "INFO Server started",
        "This is not a valid log",
        "ERROR Database connection failed"
    ]

    result = parse_log_lines(multi_line_logs)

    assert result == [
        {
            'level': 'INFO',
            'message': 'Server started'
        },
        {
            'level': 'ERROR',
            'message': 'Database connection failed'
        }
    ]