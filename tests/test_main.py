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
