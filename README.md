# Python Log Analyzer

A Python command-line tool for parsing and analyzing application logs and OpenSSH authentication logs.

The analyzer provides log-level statistics, error extraction, SSH authentication analysis, failed-login counting, time-window-based brute-force detection, and suspicious successful-login detection.

Built using Python's standard library, with pytest for automated testing.

## Features

### 1. Application Log Analysis

- Parses application log entries into structured records.
- Supports `INFO`, `WARNING`, and `ERROR` log levels.
- Counts entries by log level.
- Extracts error messages.
- Skips malformed entries without terminating execution.
- Reports successfully parsed and invalid entries.

### 2. OpenSSH Authentication Analysis

- Parses OpenSSH authentication logs.
- Extracts hostname, timestamp, process name, PID, message, and source IP.
- Identifies failed password authentication attempts.
- Counts failed login attempts per source IP.
- Supports IPv4 and IPv6 addresses in tested log formats.
- Identifies successful password and public-key authentication events.

### 3. Brute-Force Detection

- Identifies repeated failed SSH authentication attempts.
- Groups attempts by source IP.
- Uses a configurable detection threshold.
- Uses a configurable time window.
- Reports suspicious IP addresses and their attempt counts.

The CLI currently uses:
- Detection threshold: 5 failed attempts.
- Detection window: 70 seconds.

### 4. Successful Login After Failed Attempts

Identifies successful SSH authentication following repeated failed login attempts from the same IP address.

Detection considers:
- Source IP address.
- Failed password authentication events.
- Successful password authentication events.
- Successful public-key authentication events.
- Configurable attempt threshold.
- Configurable time window.

This helps identify potentially suspicious authentication sequences that require further investigation.

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

The timestamp must be a single token without spaces.

Supported log levels are uppercase `INFO`, `WARNING`, and `ERROR`.

Malformed entries are skipped.

## OpenSSH Log Format

The project supports OpenSSH authentication logs using the syslog-style format.

Example:

```text
Nov  4 10:15:32 ubuntu sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52222 ssh2
Nov  4 10:16:40 ubuntu sshd[1260]: Accepted password for admin from 203.0.113.5 port 52230 ssh2
```

The parser extracts relevant authentication information, including source IP addresses and timestamps.

Successful authentication events are parsed but excluded from failed-login counts.

## Detection Example

Consider the following authentication events:

| Time | Event | Source IP |
|---|---|---|
| 10:15:32 | Failed password | 203.0.113.5 |
| 10:15:48 | Failed password | 203.0.113.5 |
| 10:16:05 | Failed password | 203.0.113.5 |
| 10:16:20 | Failed password | 203.0.113.5 |
| 10:16:35 | Failed password | 203.0.113.5 |
| 10:16:40 | Accepted password | 203.0.113.5 |

With a threshold of 5 attempts and a 70-second detection window, the analyzer identifies the repeated failures and subsequent successful authentication.

Example output:

```text
--- SSH Failed Login Analysis ---

203.0.113.5: 5 failed attempts
198.51.100.30: 1 failed attempts

--- Brute-Force Detection ---

ALERT: 203.0.113.5 detected with 5 failed attempts within 70 seconds

--- Successful Login After Failed Attempts ---

ALERT: 203.0.113.5 successfully authenticated after 5 failed attempts within 70 seconds
```

These alerts indicate suspicious authentication activity, not confirmed malicious access.

## Requirements

- Python 3.9 or newer
- Git
- pytest (for development and testing)

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

--- Application Log Analysis ---

Log levels: {'INFO': 2, 'WARNING': 1, 'ERROR': 4}

Error messages: ['Authentication failed', 'Authentication failed',
'Authentication failed', 'Database connection failed']

--- SSH Failed Login Analysis ---

No failed SSH login attempts found.

--- Brute-Force Detection ---

No brute-force activity detected.

--- Successful Login After Failed Attempts ---

No suspicious successful login events detected.
```

### 2. Analyze OpenSSH authentication logs

```bash
python3 main.py sample_logs/auth.log
```

Example output:

```text
Total log entries: 10 (10 read, 0 skipped as invalid)

--- Application Log Analysis ---

Log levels: {'INFO': 0, 'WARNING': 0, 'ERROR': 0}

Error messages: []

--- SSH Failed Login Analysis ---

203.0.113.5: 5 failed attempts
198.51.100.30: 1 failed attempts

--- Brute-Force Detection ---

ALERT: 203.0.113.5 detected with 5 failed attempts within 70 seconds

--- Successful Login After Failed Attempts ---

ALERT: 203.0.113.5 successfully authenticated after 5 failed attempts within 70 seconds
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

Running the application without a required file argument displays command-line usage information.

## Running Tests

Run the complete test suite:

```bash
pytest -v
```

The test suite covers:

- Application log parsing.
- Valid and invalid log entries.
- Log-level counting and error extraction.
- File reading and error handling.
- OpenSSH authentication log parsing.
- IPv4 and IPv6 source address extraction.
- Failed SSH login counting.
- Successful SSH login exclusion from failed-login counts.
- Brute-force detection.
- Configurable detection thresholds.
- Time-window-based detection.
- Successful login after repeated failed attempts.
- Command-line interface behaviour.
- End-to-end execution.

**Current test status: 44 tests passing.**

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

- Detection focuses primarily on failed password authentication events.
- Successful-login detection supports password and public-key authentication events.
- Time-window detection depends on timestamps being correctly parsed.
- OpenSSH parsing supports tested syslog-style formats, not every possible SSH log format.
- The tool performs offline log analysis and does not monitor live authentication events.
- Detection results are indicative and require further investigation before treating an IP address as malicious.
- The analyzer does not automatically block suspicious IP addresses.

## Future Improvements

- JSON-based structured reporting.
- Improved authentication event classification.
- Additional validation of extracted log fields.
- Log filtering by date, IP address, and event type.
- Support for additional authentication event formats.
- Improved detection rules and reporting.
- Real-time log monitoring.

## License

See [LICENSE](LICENSE).