# Python Log Analyzer

A command-line tool that parses application log files, counts log levels, and extracts error messages. Standard library only, no runtime dependencies.

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
- Skips malformed lines instead of crashing, and reports how many were skipped
- Counts how many entries fall into each level (`INFO`, `WARNING`, `ERROR`)
- Extracts and lists all `ERROR` messages

Notes on the format: the timestamp must be a single token with no spaces (e.g. `2026-08-26T12:30:01`), and the level must be uppercase `INFO`, `WARNING` or `ERROR`. Any line that doesn't match is counted as skipped.

## Setup

Requires Python 3.9 or newer.

```bash
git clone https://github.com/OmSystems/python-log-analyzer.git
cd python-log-analyzer
```

Optional but recommended, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Usage

```bash
python3 main.py <path_to_log_file>
```

Example, using the sample log included in the repo:

```bash
python3 main.py sample_logs/app.log
```

Output:

```
Total log entries: 7 (8 read, 1 skipped as invalid)
{'INFO': 2, 'WARNING': 1, 'ERROR': 4}
['Authentication failed', 'Authentication failed', 'Authentication failed', 'Database connection failed']
```

The three lines are: the parsed/read/skipped summary, the count per level, and the list of error messages.

### Error handling

A missing or unreadable file prints a one-line error to stderr and exits with status `1`, with no traceback:

```bash
python3 main.py does_not_exist.log
# Error: Log file 'does_not_exist.log' does not exist.
```

Running with no argument prints the usage message and exits non-zero.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

The suite covers the parser, the analyzer functions, and the CLI (valid file, missing file, missing argument, empty file, and an end-to-end run through `subprocess`).

## Project structure

```
analyzer/
  file_reader.py   # reads the raw log file
  parser.py        # parses individual lines into structured records
  analyzer.py      # counts levels, extracts errors
tests/
  test_parser.py
  test_analyzer.py
  test_main.py     # CLI behaviour
sample_logs/
  app.log          # example log file
conftest.py        # lets pytest find the analyzer package from the repo root
main.py            # CLI entry point
requirements.txt
requirements-dev.txt
```

## License

See [LICENSE](LICENSE).