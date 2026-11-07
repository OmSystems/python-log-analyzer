import argparse
import sys

from analyzer.file_reader import read_log_file
from analyzer.parser import parse_log_line

from analyzer.analyzer import (
    count_log_levels,
    get_errors,
    count_failed_ssh_logins,
    detect_brute_force,
    detect_successful_login_after_failures,
)

from analyzer.openssh_parser import parse_openssh_log_line


def main():
    parser = argparse.ArgumentParser(
        description="Analyze application and OpenSSH authentication logs."
    )

    parser.add_argument("file", help="Path to the log file")

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Minimum failed attempts required for an alert (default: 5)",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection time window in seconds (default: 60)",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year for classic syslog timestamps (default: current local year)",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if args.window < 0:
        parser.error("--window cannot be negative")

    # --------------------------------------------------
    # READ LOG FILE
    # --------------------------------------------------

    try:
        lines = read_log_file(args.file)

    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    # --------------------------------------------------
    # PARSE APPLICATION AND OPENSSH LOGS
    # --------------------------------------------------

    parsed_logs = []
    ssh_parsed_logs = []
    parsed_line_count = 0

    for line in lines:

        app_log = parse_log_line(line)
        ssh_log = parse_openssh_log_line(
            line,
            year=args.year,
        )

        if app_log is not None:
            parsed_logs.append(app_log)

        if ssh_log is not None:
            ssh_parsed_logs.append(ssh_log)

        if app_log is not None or ssh_log is not None:
            parsed_line_count += 1

    total_lines = len(lines)
    skipped_lines = total_lines - parsed_line_count

    # --------------------------------------------------
    # PARSING STATISTICS
    # --------------------------------------------------

    print(
        f"Total log entries: {parsed_line_count} "
        f"({total_lines} read, "
        f"{parsed_line_count} parsed, "
        f"{skipped_lines} skipped as invalid)"
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
        for ip, count in sorted(
            failed_ssh.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"{ip}: {count} failed attempts")
    else:
        print("No failed SSH login attempts found.")

    # --------------------------------------------------
    # BRUTE-FORCE DETECTION
    # --------------------------------------------------

    print("\n--- Brute-Force Detection ---")

    suspicious_ips = detect_brute_force(
        ssh_parsed_logs,
        threshold=args.threshold,
        window_seconds=args.window,
    )

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(
                f"ALERT: {ip} detected with {count} failed attempts "
                f"within {args.window} seconds"
            )
    else:
        print("No brute-force activity detected.")

    # --------------------------------------------------
    # SUCCESSFUL LOGIN AFTER FAILED ATTEMPTS
    # --------------------------------------------------

    print("\n--- Successful Login After Failed Attempts ---")

    suspicious_logins = detect_successful_login_after_failures(
        ssh_parsed_logs,
        threshold=args.threshold,
        window_seconds=args.window,
    )

    if suspicious_logins:
        for ip, count in suspicious_logins.items():
            print(
                f"ALERT: {ip} successfully authenticated after "
                f"{count} failed attempts "
                f"within {args.window} seconds"
            )
    else:
        print("No suspicious successful login events detected.")


if __name__ == "__main__":
    main()