from analyzer.file_reader import read_log_file
import pytest

def test_read_valid_log_file(tmp_path):
    log_file = tmp_path / "sample.log"

    log_file.write_text(
    "2026-08-26T12:30:01 INFO 192.168.1.10 Server started\n"
    "2026-08-26T12:30:15 ERROR 192.168.1.50 Authentication failed\n",
    encoding="utf-8"
)

    result = read_log_file(str(log_file))

    assert result == [
    "2026-08-26T12:30:01 INFO 192.168.1.10 Server started\n",
    "2026-08-26T12:30:15 ERROR 192.168.1.50 Authentication failed\n"
]

def test_missing_log_file(tmp_path):
    log_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        read_log_file(str(log_file))

def test_empty_file_path():
    log_file = ""
    with pytest.raises(ValueError):
        read_log_file(str(log_file))

def test_read_empty_file(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    result = read_log_file(str(log_file))

    assert result == []

def test_directory_path_raises_error(tmp_path):
    directory = tmp_path / "logs"
    directory.mkdir()

    with pytest.raises(IsADirectoryError):
        read_log_file(str(directory))