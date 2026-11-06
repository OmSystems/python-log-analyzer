import argparse
import sys

from analyzer.file_reader import read_log_file
from analyzer.parser import parse_log_lines

from analyzer.analyzer import (
    count_log_levels,
    get_errors,
    count_failed_ssh_logins,
    detect_brute_force,
    detect_successful_login_after_failures
)

from analyzer.openssh_parser import parse_openssh_log_line


def main():
    parser = argparse.ArgumentParser(
        description="Analyze application and OpenSSH authentication logs."
    )

    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    # Read log file
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

    # Calculate valid and invalid entries
    total_valid_entries = len(parsed_logs) + len(ssh_parsed_logs)
    invalid_entries = len(lines) - total_valid_entries

    print(
        f"Total log entries: {total_valid_entries} "
        f"({len(lines)} read, {invalid_entries} skipped as invalid)"
    )

    # --------------------------------------------------
    # APPLICATION LOG ANALYSIS
    # --------------------------------------------------

    print("\n--- Application Log Analysis ---")

    log_counts = count_log_levels(parsed_logs)
    print("Log levels:", log_counts)

    errors = get_errors(parsed_logs)
    print("Error messages:", errors)

    # --------------------------------------------------
    # SSH FAILED LOGIN ANALYSIS
    # --------------------------------------------------

    print("\n--- SSH Failed Login Analysis ---")

    failed_ssh = count_failed_ssh_logins(ssh_parsed_logs)

    if failed_ssh:
        for ip, count in failed_ssh.items():
            print(f"{ip}: {count} failed attempts")
    else:
        print("No failed SSH login attempts found.")

    # --------------------------------------------------
    # TIME-WINDOW BRUTE-FORCE DETECTION
    # --------------------------------------------------

    print("\n--- Brute-Force Detection ---")

    threshold = 5
    window_seconds = 70

    suspicious_ips = detect_brute_force(
        ssh_parsed_logs,
        threshold=threshold,
        window_seconds=window_seconds
    )

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(
                f"ALERT: {ip} detected with {count} failed attempts "
                f"within {window_seconds} seconds"
            )
    else:
        print("No brute-force activity detected.")

    # --------------------------------------------------
    # SUCCESSFUL LOGIN AFTER FAILED ATTEMPTS
    # --------------------------------------------------

    print("\n--- Successful Login After Failed Attempts ---")

    suspicious_logins = detect_successful_login_after_failures(
        ssh_parsed_logs,
        threshold=threshold,
        window_seconds=window_seconds
    )

    if suspicious_logins:
        for ip, count in suspicious_logins.items():
            print(
                f"ALERT: {ip} successfully authenticated after "
                f"{count} failed attempts within {window_seconds} seconds"
            )
    else:
        print("No suspicious successful login events detected.")


if __name__ == "__main__":
    main()