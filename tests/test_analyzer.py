from datetime import datetime, timedelta

from analyzer.analyzer import count_log_levels
from analyzer.analyzer import get_errors
from analyzer.analyzer import count_failed_ssh_logins
from analyzer.analyzer import detect_brute_force
from analyzer.analyzer import detect_successful_login_after_failures


def test_count_log_levels():
    logs = [
        {"level": "ERROR", "message": "Database connection failed"},
        {"level": "INFO", "message": "Server started"}
    ]

    result = count_log_levels(logs)

    assert result == {
        "INFO": 1,
        "WARNING": 0,
        "ERROR": 1
    }


def test_get_errors():
    logs = [
        {"level": "INFO", "message": "Server started"},
        {"level": "ERROR", "message": "Database connection failed"},
        {"level": "WARNING", "message": "Disk space is low"},
        {"level": "ERROR", "message": "Authentication failed"}
    ]

    result = get_errors(logs)

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
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(5)
    ]

    result = detect_brute_force(logs)

    assert result == {"203.0.113.5": 5}


def test_no_brute_force():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time
        },
        {
            "process_name": "sshd",
            "message": "Failed password for root",
            "source_ip": "198.51.100.30",
            "timestamp": start_time + timedelta(seconds=10)
        }
    ]

    result = detect_brute_force(logs)

    assert result == {}


def test_custom_brute_force_threshold():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(3)
    ]

    result = detect_brute_force(
        logs,
        threshold=3,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 3}


def test_brute_force_below_threshold():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(4)
    ]

    result = detect_brute_force(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {}


def test_brute_force_above_threshold():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(6)
    ]

    result = detect_brute_force(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 6}


def test_detect_brute_force_within_time_window():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(5)
    ]

    result = detect_brute_force(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 5}


def test_no_brute_force_when_attempts_are_outside_window():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 70)
        }
        for i in range(5)
    ]

    result = detect_brute_force(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {}


def test_detect_successful_login_after_failed_attempts():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = []

    # Five failed login attempts.
    for i in range(5):
        logs.append({
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "timestamp": start_time + timedelta(seconds=i * 10)
        })

    # Successful login from the same IP.
    logs.append({
        "process_name": "sshd",
        "message": "Accepted password for admin",
        "source_ip": "203.0.113.5",
        "timestamp": start_time + timedelta(seconds=50)
    })

    result = detect_successful_login_after_failures(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 5}
def test_count_different_ssh_failure_types():
    logs = [
        {
            "process_name": "sshd",
            "message": "Invalid user admin from 203.0.113.5",
            "source_ip": "203.0.113.5",
            "pid": "1001"
        },
        {
            "process_name": "sshd",
            "message": "Failed publickey for root from 203.0.113.6",
            "source_ip": "203.0.113.6",
            "pid": "1002"
        },
        {
            "process_name": "sshd",
            "message": "Connection closed by invalid user test 203.0.113.7 port 22",
            "source_ip": "203.0.113.7",
            "pid": "1003"
        },
        {
            "process_name": "sshd",
            "message": "Connection closed by authenticating user admin 203.0.113.8 port 22 [preauth]",
            "source_ip": "203.0.113.8",
            "pid": "1004"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {
        "203.0.113.5": 1,
        "203.0.113.6": 1,
        "203.0.113.7": 1,
        "203.0.113.8": 1
    }


def test_count_sshd_session_failures():
    logs = [
        {
            "process_name": "sshd-session",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "pid": "2001"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {"203.0.113.5": 1}


def test_deduplicate_failures_from_same_pid():
    logs = [
        {
            "process_name": "sshd",
            "message": "Invalid user admin from 203.0.113.5",
            "source_ip": "203.0.113.5",
            "pid": "3001"
        },
        {
            "process_name": "sshd-session",
            "message": "Failed password for invalid user admin",
            "source_ip": "203.0.113.5",
            "pid": "3001"
        },
        {
            "process_name": "sshd-session",
            "message": "Connection closed by invalid user admin",
            "source_ip": "203.0.113.5",
            "pid": "3001"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {"203.0.113.5": 1}


def test_count_separate_connections_from_same_ip():
    logs = [
        {
            "process_name": "sshd",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "pid": "4001"
        },
        {
            "process_name": "sshd-session",
            "message": "Failed password for root",
            "source_ip": "203.0.113.5",
            "pid": "4002"
        }
    ]

    result = count_failed_ssh_logins(logs)

    assert result == {"203.0.113.5": 2}

def test_detect_brute_force_with_sshd_session():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = [
        {
            "process_name": "sshd-session",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "pid": str(5000 + i),
            "timestamp": start_time + timedelta(seconds=i * 10)
        }
        for i in range(5)
    ]

    result = detect_brute_force(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 5}

def test_successful_login_after_failures_with_sshd_session():
    start_time = datetime(2026, 11, 4, 10, 15, 0)

    logs = []

    for i in range(5):
        logs.append({
            "process_name": "sshd-session",
            "message": "Failed password for admin",
            "source_ip": "203.0.113.5",
            "pid": str(6000 + i),
            "timestamp": start_time + timedelta(seconds=i * 10)
        })

    logs.append({
        "process_name": "sshd-session",
        "message": "Accepted password for admin",
        "source_ip": "203.0.113.5",
        "pid": "6005",
        "timestamp": start_time + timedelta(seconds=50)
    })

    result = detect_successful_login_after_failures(
        logs,
        threshold=5,
        window_seconds=60
    )

    assert result == {"203.0.113.5": 5}