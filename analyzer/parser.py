from typing import Optional

VALID_LEVELS = {"INFO", "WARNING", "ERROR"}

def parse_log_line(text: str) -> Optional[dict]:
    cleaned_text = text.strip()
    parts = cleaned_text.split(maxsplit=3)

    if len(parts) < 4:
        return None

    timestamp = parts[0]
    level = parts[1]
    ip = parts[2]
    message = parts[3]

    if level not in VALID_LEVELS:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "ip": ip,
        "message": message
    }

def parse_log_lines(lines : list[str]) -> list[dict]:

    parsed_logs = []

    for line_number, each_line in enumerate(lines, start=1):
        parsed_log = parse_log_line(each_line)

        if parsed_log is None:
            continue

        parsed_logs.append(parsed_log)

    return parsed_logs