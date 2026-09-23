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

## Usage

```bash
python3 main.py
```

This reads `sample_logs/app.log` and prints:
1. The list of parsed log entries
2. A count of log levels, e.g. `{'INFO': 2, 'WARNING': 1, 'ERROR': 4}`
3. A list of all error messages

## Running tests

```bash
pip install pytest
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
