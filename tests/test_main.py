import sys
import pytest
import subprocess
from pathlib import Path
from main import main


def test_valid_log_file_runs_successfully(tmp_path, capsys, monkeypatch):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
    "2026-09-27T10:00:00 INFO 10.0.0.1 Starting up\n"
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", str(log_file)]
    )

    main()

    captured = capsys.readouterr()

    assert "Total log entries: 1" in captured.out
    assert "'INFO': 1" in captured.out

def test_missing_file_shows_graceful_error(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "nonexistent.log"]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()

    assert "error" in captured.err.lower() or "not found" in captured.err.lower()
    assert exc_info.value.code != 0

def test_no_argument_shows_usage(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py"]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()

    assert "usage" in captured.err.lower()
    assert exc_info.value.code != 0

def test_empty_log_file(tmp_path, capsys, monkeypatch):
    log_file = tmp_path / "empty.log"
    log_file.write_text("")

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", str(log_file)]
    )

    main()

    captured = capsys.readouterr()

    assert "Total log entries: 0" in captured.out


def test_cli_end_to_end(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "2026-09-27T10:00:00 ERROR 10.0.0.1 Disk full\n"
    )

    result = subprocess.run(
        [sys.executable, "main.py", str(log_file)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert result.returncode == 0
    assert "'ERROR': 1" in result.stdout
    assert "Disk full" in result.stdout

#cli argument

def test_cli_custom_threshold_window_and_year(tmp_path, capsys, monkeypatch):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Nov  4 10:15:00 ubuntu sshd[1001]: Failed password for admin from 203.0.113.5 port 5001 ssh2\n"
        "Nov  4 10:15:20 ubuntu sshd[1002]: Failed password for root from 203.0.113.5 port 5002 ssh2\n"
        "Nov  4 10:15:40 ubuntu sshd[1003]: Failed password for test from 203.0.113.5 port 5003 ssh2\n"
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            str(log_file),
            "--threshold", "3",
            "--window", "60",
            "--year", "2026"
        ]
    )

    main()

    captured = capsys.readouterr()

    assert "203.0.113.5: 3 failed attempts" in captured.out
    assert "detected with 3 failed attempts within 60 seconds" in captured.out

def test_cli_rejects_invalid_threshold(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "sample.log", "--threshold", "0"]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2

def test_cli_rejects_negative_window(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "sample.log", "--window", "-10"]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2