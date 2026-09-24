import argparse
import sys
from analyzer.file_reader import read_log_file
from analyzer.parser import parse_log_lines
from analyzer.analyzer import count_log_levels, get_errors

parser = argparse.ArgumentParser(description="Analyze log files.")
parser.add_argument("file", help="Path to the log file")
args = parser.parse_args()

try:
    lines = read_log_file(args.file)
except (FileNotFoundError, ValueError) as e:
    print(f"Error: {e}")
    sys.exit(1)

parsed_logs = parse_log_lines(lines)

print(f"Total log entries: {len(parsed_logs)} ({len(lines)} read, {len(lines) - len(parsed_logs)} skipped as invalid)")

log_counts = count_log_levels(parsed_logs)
print(log_counts)

errors = get_errors(parsed_logs)
print(errors)