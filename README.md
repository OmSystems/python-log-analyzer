# Python Log Analyzer

A command-line tool that parses application log files, counts log levels, and extracts error messages.

## What it does

Given a log file where each line follows the format:

```
<timestamp> <LEVEL> <ip_address> <message>
```

for example:

```
2026-08-26T12:30:01 INFO 192.168.1.10 Server started
2026-08-26T12:31:02 ERROR 192.168.1.50 Authentication failed
```

the tool:
- Parses each line into a structured record (timestamp, level, IP, message)
- Skips and ignores malformed lines instead of crashing
- Counts how many lines fall into each level (INFO / WARNING / ERROR)
- Extracts and lists all ERROR messages

## Setup

```bash
git clone https://github.com/OmSystems/python-log-analyzer.git
cd python-log-analyzer
```

No external dependencies are required to run the tool itself (standard library only). `pytest` is only needed if you want to run the tests — see below.

## Usage

```bash
python3 main.py <path_to_log_file>
```

Example, using the sample log included in the repo:

```bash
python3 main.py sample_logs/app.log
```

This prints:
1. Total log entries parsed, out of total lines read, with how many were skipped as invalid
2. A count of log levels, e.g. `{'INFO': 2, 'WARNING': 1, 'ERROR': 4}`
3. A list of all error messages

If the given path doesn't exist, the tool prints a clear error and exits (no crash/traceback):

```bash
python3 main.py does_not_exist.log
# Error: Log file 'does_not_exist.log' does not exist.
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Project structure

```
analyzer/
  file_reader.py   # reads the raw log file
  parser.py        # parses individual lines into structured records
  analyzer.py       # counts levels, extracts errors
tests/
  test_parser.py
  test_analyzer.py
sample_logs/
  app.log           # example log file
main.py             # entry point
```
