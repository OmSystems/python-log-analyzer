import argparse
import sys

from analyzer.file_reader import read_log_file
from analyzer.parser import parse_log_lines
from analyzer.analyzer import (
    count_log_levels,
    get_errors,
    count_failed_ssh_logins,
    detect_brute_force
)
from analyzer.openssh_parser import parse_openssh_log_line


def main():
    parser = argparse.ArgumentParser(description="Analyze log files.")
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    try:
        lines = read_log_file(args.file)
    except (OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Application log parsing
    parsed_logs = parse_log_lines(lines)

    # OpenSSH log parsing
    ssh_parsed_logs = []

    for line in lines:
        parsed = parse_openssh_log_line(line)

        if parsed is not None:
            ssh_parsed_logs.append(parsed)

    # Calculate total valid and invalid entries
    total_valid_entries = len(parsed_logs) + len(ssh_parsed_logs)
    invalid_entries = len(lines) - total_valid_entries

    print(
        f"Total log entries: {total_valid_entries} "
        f"({len(lines)} read, {invalid_entries} skipped as invalid)"
    )

    # Application log analysis
    log_counts = count_log_levels(parsed_logs)
    print(log_counts)

    errors = get_errors(parsed_logs)
    print(errors)

    # SSH failed login analysis
    print("\n--- SSH Failed Login Analysis ---")

    failed_ssh = count_failed_ssh_logins(ssh_parsed_logs)

    if failed_ssh:
        for ip, count in failed_ssh.items():
            print(f"{ip}: {count} failed attempts")
    else:
        print("No failed SSH login attempts found.")

    # Brute-force detection
    print("\n--- Brute-Force Detection ---")

    suspicious_ips = detect_brute_force(failed_ssh)

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"ALERT: {ip} detected with {count} failed attempts")
    else:
        print("No brute-force activity detected.")


if __name__ == "__main__":
    main()