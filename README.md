# Log File Analyzer

A Python command-line tool for analyzing application and web-server log files.

## Features
- Reads multiple `.log` and `.txt` files from an input directory.
- Parses timestamped application logs and Apache-style access logs.
- Counts ERROR, WARNING, INFO, DEBUG, CRITICAL and unrecognized entries.
- Finds the top 10 most frequent error messages.
- Calculates timestamped requests per minute from access logs.
- Calculates execution-time statistics when a duration field is present.
- Exports a detailed CSV and JSON summary.
- Displays a console dashboard.
- Uses object-oriented design, type hints, logging, exception handling and a thread pool.
- Streams files line-by-line for lower memory use.
- Includes sample logs and automated unit tests.

## Requirements
- Python 3.10+
- No third-party packages required.

## Run the analyzer
Open a terminal in this folder and run:

```powershell
python log_analyzer.py --input logs --output reports
```

On Windows, if `python` is not recognized, try:

```powershell
py log_analyzer.py --input logs --output reports
```

The program creates:
- `reports/summary.json`
- `reports/records.csv`

## Run tests

```powershell
python -m unittest discover -s tests -v
```

Or use `py -m unittest discover -s tests -v` on Windows.

## Supported input formats

Application logs:
```text
2026-10-28 10:01:00 ERROR Database connection failed
2026-10-28T10:01:30 INFO Request complete duration=125ms
```

Apache-style access logs:
```text
127.0.0.1 - - [28/Oct/2026:10:02:00 +0000] "GET /health HTTP/1.1" 200 14
```

Execution durations can be expressed as `duration=125ms`, `execution_time=0.25s`, or `response_time=45ms`.

## Project layout
```text
log-file-analyzer/
├── log_analyzer.py
├── logs/
│   ├── app.log
│   └── access.log
├── reports/
├── tests/
│   └── test_log_analyzer.py
├── README.md
└── .gitignore
```

## Design and performance notes
- Files are read line-by-line rather than loaded wholly into memory.
- A thread pool processes separate files concurrently; the `--workers` option controls the worker count.
- Parsing uses compiled regular expressions.
- Counters and dictionaries aggregate metrics in a single pass over parsed records.
- Malformed lines are retained as `UNKNOWN` entries rather than silently discarded.
- Requests per minute are calculated from access-log timestamps.
- Execution-time metrics only include lines with a supported duration field.
- For very large datasets, consider incremental aggregation instead of retaining all records for CSV output; benchmark worker counts for your storage device.
