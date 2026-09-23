from analyzer.analyzer import count_log_levels
from analyzer.analyzer import get_errors

def test_count_log_levels():
    set1 = [
    {
        "level": "ERROR",
        "message": "Database connection failed"
    },
    {
        "level": "INFO",
        "message": "Server started"
    }
]

    result = count_log_levels(set1)

    assert result == {
        "INFO": 1,
        "WARNING": 0,
        "ERROR": 1
    }

def test_get_errors():

    test_set = [
        {
            "level": "INFO",
            "message": "Server started"
        },
        {
            "level": "ERROR",
            "message": "Database connection failed"
        },
        {
            "level": "WARNING",
            "message": "Disk space is low"
        },
        {
            "level": "ERROR",
            "message": "Authentication failed"
        }
    ]
    result = get_errors(test_set)

    assert result == [
        "Database connection failed",
        "Authentication failed"
    ]

    