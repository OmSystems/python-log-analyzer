from typing import Optional

VALID_LEVELS = {"INFO", "WARNING", "ERROR" , "WARNING"}

def parse_log_line(text : str) -> Optional[dict]:
        cleaned_text = text.strip()
        parts = cleaned_text.split(" ", 1)

        if len(parts) < 2:
            return None

        level = parts[0]

        if level not in VALID_LEVELS:
            return None

        message = parts[1]

        return {
            "level": level,
            "message": message
        }

def parse_log_lines(lines : list[str]) -> list[dict]:

    list1=[]

    for line_number, each_line in enumerate(lines, start=1):
        dictionary_answer = parse_log_line(each_line)

        if dictionary_answer is None:
            print(f"Malformed log at line {line_number}")
            continue

        list1.append(dictionary_answer)

    return list1