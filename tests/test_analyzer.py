from analyzer.analyzer import count_log_levels
from analyzer.analyzer import get_errors
from analyzer.analyzer import count_failed_ssh_logins
from analyzer.analyzer import detect_brute_force

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

def test_count_failed_ssh_logins_same_ip():
    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for invalid user admin",
            "source_ip": "203.0.113.5"
        },
        {
            "process_name": "sshd",
            "message": "Failed password for invalid user root",
            "source_ip": "203.0.113.5"
        },
        {
            "process_name": "sshd",
            "message": "Failed password for invalid user test",
            "source_ip": "203.0.113.5"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {"203.0.113.5": 3}

def test_count_failed_ssh_logins_multiple_ips():
    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5"
        },
        {
            "process_name": "sshd",
            "message": "Failed password for root",
            "source_ip": "198.51.100.20"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {
        "203.0.113.5": 1,
        "198.51.100.20": 1
    }

def test_ignore_successful_ssh_logins():
    logs = [
        {
            "process_name": "sshd",
            "message": "Accepted password for admin",
            "source_ip": "203.0.113.5"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {}

def test_detect_brute_force():
    failed_counts = {
        "203.0.113.5": 5,
        "198.51.100.30": 1
    }

    result = detect_brute_force(failed_counts)

    assert result == {"203.0.113.5": 5}

def test_no_brute_force():
    failed_counts = {
        "203.0.113.5": 2,
        "198.51.100.30": 1
    }

    result = detect_brute_force(failed_counts)

    assert result == {}

def test_custom_brute_force_threshold():
    failed_counts = {
        "203.0.113.5": 3,
        "198.51.100.30": 2
    }

    result = detect_brute_force(failed_counts, threshold=3)

    assert result == {"203.0.113.5": 3}

def test_brute_force_below_threshold():
    failed_counts = {
        "203.0.113.5": 4
    }

    result = detect_brute_force(failed_counts)

    assert result == {}

def test_brute_force_above_threshold():
    failed_counts = {
        "203.0.113.5": 6
    }

    result = detect_brute_force(failed_counts)

    assert result == {"203.0.113.5": 6}