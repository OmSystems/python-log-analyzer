from analyzer.file_reader import read_log_file
from analyzer.parser import parse_log_lines
from analyzer.analyzer import count_log_levels
from analyzer.analyzer import get_errors

lines = read_log_file("sample_logs/app.log")

parsed_logs = parse_log_lines(lines)

print(parsed_logs)

log_counts = count_log_levels(parsed_logs)

print(log_counts)

errors = get_errors(parsed_logs)
print(errors)