from pathlib import Path


def read_log_file(path: str) -> list[str]:
    if not path:
        raise ValueError("A log file path is required.")

    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Log file '{path}' does not exist.")

    with file_path.open("r", encoding="utf-8") as file:
        return file.readlines()