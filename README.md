# Python Log Analyzer

A Python command-line tool for parsing and analyzing application logs and OpenSSH authentication logs. It provides log-level statistics, error extraction, failed SSH login analysis, and basic brute-force detection.

Built using Python's standard library, with pytest for automated testing.

## Features

### Application Log Analysis

- Parses application log entries into structured records.
- Supports `INFO`, `WARNING`, and `ERROR` log levels.
- Counts entries by log level.
- Extracts error messages.
- Skips malformed entries without terminating execution.
- Reports the number of successfully parsed and invalid entries.

### OpenSSH Authentication Analysis

- Parses OpenSSH authentication log entries.
- Extracts hostname, timestamp, process name, PID, message, and source IP.
- Identifies failed password authentication attempts.
- Counts failed login attempts per source IP.
- Supports IPv4 and IPv6 source addresses in tested log formats.
- Ignores successful SSH authentication events during failed-login counting.

### Brute-Force Detection

- Identifies IP addresses with repeated failed SSH login attempts.
- Uses a configurable detection threshold.
- Defaults to 5 failed attempts per IP address.
- Reports suspicious IP addresses with their corresponding attempt counts.

**Note:** Current brute-force detection uses total failed attempts in the supplied log file. It does not yet implement time-window-based detection.

## Application Log Format

Application log entries follow this format:

```text
<timestamp> <LEVEL> <ip_address> <message>
```

Example:

```text
2026-08-26T12:30:01 INFO 192.168.1.10 Server started
2026-08-26T12:31:02 ERROR 192.168.1.50 Authentication failed
2026-08-26T12:32:15 WARNING 192.168.1.10 Disk space is low
```

The timestamp must be a single token without spaces. Supported log levels are uppercase `INFO`, `WARNING`, and `ERROR`.

Malformed entries are skipped.

## OpenSSH Log Analysis

The project also supports OpenSSH authentication logs using the standard syslog-style format.

Example:

```text
Nov  4 10:15:32 ubuntu sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52222 ssh2
Nov  4 10:16:32 ubuntu sshd[1235]: Accepted password for om from 203.0.113.5 port 52222 ssh2
```

The analyzer extracts relevant authentication information and identifies failed password attempts.

Successful authentication events are parsed but excluded from failed-login counts.

## Brute-Force Detection Example

Given the following failed authentication counts:

| Source IP | Failed attempts |
|---|---:|
| 203.0.113.5 | 5 |
| 198.51.100.30 | 1 |

The default detection threshold is 5.

The analyzer reports:

```text
--- SSH Failed Login Analysis ---

203.0.113.5: 5 failed attempts
198.51.100.30: 1 failed attempts

--- Brute-Force Detection ---

ALERT: 203.0.113.5 detected with 5 failed attempts
```

This is basic threshold-based detection, not a complete intrusion detection system.

## Requirements

- Python 3.9 or newer
- Git
- pytest (for running tests)

No third-party runtime dependencies are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/OmSystems/python-log-analyzer.git
cd python-log-analyzer
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

## Usage

The application accepts a log file path as a command-line argument.

### 1. Analyze application logs

```bash
python3 main.py sample_logs/app.log
```

Example output:

```text
Total log entries: 7 (8 read, 1 skipped as invalid)

{'INFO': 2, 'WARNING': 1, 'ERROR': 4}

['Authentication failed',
 'Authentication failed',
 'Authentication failed',
 'Database connection failed']

--- SSH Failed Login Analysis ---

No failed SSH login attempts found.

--- Brute-Force Detection ---

No brute-force activity detected.
```

### 2. Analyze OpenSSH authentication logs

```bash
python3 main.py sample_logs/auth.log
```

Example output:

```text
Total log entries: 10 (10 read, 0 skipped as invalid)

{'INFO': 0, 'WARNING': 0, 'ERROR': 0}

[]

--- SSH Failed Login Analysis ---

203.0.113.5: 5 failed attempts
198.51.100.30: 1 failed attempts

--- Brute-Force Detection ---

ALERT: 203.0.113.5 detected with 5 failed attempts
```

## Error Handling

The application handles missing and unreadable files without displaying a Python traceback.

Example:

```bash
python3 main.py does_not_exist.log
```

Expected output:

```text
Error: Log file 'does_not_exist.log' does not exist.
```

The application exits with status code `1`.

Running the application without a required file argument displays the command-line usage information.

## Running Tests

Run the complete test suite:

```bash
pytest -v
```

The test suite covers:

- Application log parsing.
- Log-level counting and error extraction.
- File reading and error handling.
- OpenSSH authentication log parsing.
- IPv4 and IPv6 source address extraction.
- Failed SSH login counting.
- Successful SSH login exclusion.
- Brute-force detection and threshold handling.
- Command-line interface behaviour.
- End-to-end execution.

Current test status: **38 tests passing.**

## Project Structure

```text
python-log-analyzer/
│
├── analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── file_reader.py
│   ├── openssh_parser.py
│   └── parser.py
│
├── sample_logs/
│   ├── app.log
│   └── auth.log
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_file_reader.py
│   ├── test_main.py
│   ├── test_openssh_parser.py
│   └── test_parser.py
│
├── conftest.py
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── .gitignore
└── LICENSE
```

## Current Limitations

- Brute-force detection uses cumulative failed attempts rather than a time-based detection window.
- Detection currently focuses on failed password authentication events.
- OpenSSH parsing supports the tested syslog-style formats, not every possible SSH log format.
- The tool performs offline log analysis and does not monitor live authentication events.
- Detection results are indicative and require further investigation before treating an IP address as malicious.

## Future Improvements

- Time-window-based brute-force detection.
- Improved authentication event classification.
- Additional validation of extracted IP addresses.
- Structured JSON reporting.
- Log filtering by date, IP address, and event type.
- Improved detection rules and reporting.

## License

See [LICENSE](LICENSE).