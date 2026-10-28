"""Log analyzer supporting application logs and Apache-style access logs."""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean, median
from typing import Iterable, Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger("log_analyzer")

APP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(?P<message>.*)$",
    re.IGNORECASE,
)
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
DURATION_RE = re.compile(
    r"\b(?:duration|execution_time|response_time)\s*[=:]\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s|sec|seconds)?\b",
    re.IGNORECASE,
)

@dataclass
class LogRecord:
    source: str
    timestamp: Optional[datetime]
    level: str
    message: str
    is_request: bool = False
    duration_ms: Optional[float] = None

def parse_timestamp(value: str, apache: bool = False) -> Optional[datetime]:
    """Convert supported timestamp text into datetime, returning None if invalid."""
    try:
        if apache:
            return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        normalized = value.replace(",", ".")
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
    except (ValueError, TypeError):
        return None
    return None

def parse_line(line: str, source: str = "<memory>") -> Optional[LogRecord]:
    """Parse one application/access log line, or retain an unknown-format line."""
    line = line.strip()
    if not line:
        return None

    match = APP_RE.match(line)
    if match:
        timestamp = parse_timestamp(match.group("timestamp"))
        level = match.group("level").upper()
        if level == "WARN":
            level = "WARNING"
        if level == "FATAL":
            level = "CRITICAL"
        message = match.group("message").strip()
        duration_match = DURATION_RE.search(message)
        duration_ms = None
        if duration_match:
            duration_ms = float(duration_match.group("value"))
            unit = (duration_match.group("unit") or "ms").lower()
            if unit in {"s", "sec", "seconds"}:
                duration_ms *= 1000
        return LogRecord(source, timestamp, level, message, False, duration_ms)

    match = APACHE_RE.match(line)
    if match:
        timestamp = parse_timestamp(match.group("timestamp"), apache=True)
        status = int(match.group("status"))
        request = match.group("request")
        level = "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO"
        return LogRecord(source, timestamp, level, f"HTTP {status} {request}", True, None)

    return LogRecord(source, None, "UNKNOWN", line, False, None)

class LogAnalyzer:
    """Read, analyze and export logs from a directory."""

    def __init__(self, input_dir: Path, output_dir: Path, workers: Optional[int] = None):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.workers = workers

    @staticmethod
    def _read_file(path: Path) -> list[LogRecord]:
        records: list[LogRecord] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    record = parse_line(line, path.name)
                    if record is not None:
                        records.append(record)
        except OSError as exc:
            LOGGER.warning("Skipping unreadable file %s: %s", path, exc)
        return records

    def collect_records(self) -> list[LogRecord]:
        if not self.input_dir.exists() or not self.input_dir.is_dir():
            raise FileNotFoundError(f"Input folder does not exist: {self.input_dir}")
        paths = sorted(p for p in self.input_dir.iterdir()
                       if p.is_file() and p.suffix.lower() in {".log", ".txt"})
        if not paths:
            raise FileNotFoundError(f"No .log or .txt files found in {self.input_dir}")
        records: list[LogRecord] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self._read_file, path): path for path in paths}
            for future in as_completed(futures):
                try:
                    records.extend(future.result())
                except Exception:
                    LOGGER.exception("Unexpected error while processing %s", futures[future])
        records.sort(key=lambda item: (item.source, item.timestamp or datetime.min))
        return records

    @staticmethod
    def build_summary(records: Iterable[LogRecord]) -> dict:
        rows = list(records)
        counts = Counter(row.level for row in rows)
        error_counts = Counter(
            re.sub(r"\b\d+\b", "<n>", row.message.lower()).strip()
            for row in rows if row.level in {"ERROR", "CRITICAL"}
        )
        requests_per_minute: Counter[str] = Counter()
        for row in rows:
            if row.is_request and row.timestamp:
                requests_per_minute[row.timestamp.strftime("%Y-%m-%d %H:%M")] += 1
        durations = [row.duration_ms for row in rows if row.duration_ms is not None]
        duration_summary = {
            "count": len(durations),
            "min_ms": min(durations) if durations else None,
            "max_ms": max(durations) if durations else None,
            "mean_ms": round(mean(durations), 2) if durations else None,
            "median_ms": round(median(durations), 2) if durations else None,
        }
        return {
            "total_entries": len(rows),
            "level_counts": {level: counts.get(level, 0) for level in
                             ("ERROR", "WARNING", "INFO", "DEBUG", "CRITICAL", "UNKNOWN")},
            "top_10_errors": [{"message": msg, "count": count}
                              for msg, count in error_counts.most_common(10)],
            "requests_per_minute": dict(sorted(requests_per_minute.items())),
            "execution_time_ms": duration_summary,
            "files_processed": sorted({row.source for row in rows if row.source != "<memory>"}),
        }

    def export_reports(self, records: list[LogRecord], summary: dict) -> tuple[Path, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.output_dir / "summary.json"
        csv_path = self.output_dir / "records.csv"
        with json_path.open("w", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2)
        with csv_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=[
                "source", "timestamp", "level", "message", "is_request", "duration_ms"
            ])
            writer.writeheader()
            for record in records:
                row = asdict(record)
                row["timestamp"] = record.timestamp.isoformat(sep=" ") if record.timestamp else ""
                writer.writerow(row)
        return json_path, csv_path

    @staticmethod
    def print_dashboard(summary: dict) -> None:
        print("\n" + "=" * 52)
        print("              LOG FILE ANALYZER")
        print("=" * 52)
        print(f"Total entries: {summary['total_entries']}")
        print("\nLog level counts:")
        for level, count in summary["level_counts"].items():
            if count:
                print(f"  {level:<10} {count}")
        print("\nTop 10 errors:")
        errors = summary["top_10_errors"]
        if errors:
            for item in errors:
                print(f"  {item['count']:>4}  {item['message']}")
        else:
            print("  No errors found.")
        stats = summary["execution_time_ms"]
        print("\nExecution time (ms):")
        print(f"  Samples: {stats['count']} | Min: {stats['min_ms']} | Max: {stats['max_ms']}")
        print(f"  Mean: {stats['mean_ms']} | Median: {stats['median_ms']}")
        print("\nRequests per minute:")
        if summary["requests_per_minute"]:
            for minute, count in summary["requests_per_minute"].items():
                print(f"  {minute}: {count}")
        else:
            print("  No timestamped access-log requests found.")
        print("=" * 52 + "\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze log files and export CSV/JSON reports.")
    parser.add_argument("--input", default="logs", help="Input folder (default: logs)")
    parser.add_argument("--output", default="reports", help="Output folder (default: reports)")
    parser.add_argument("--workers", type=int, default=None, help="Concurrent file workers")
    args = parser.parse_args()
    try:
        analyzer = LogAnalyzer(Path(args.input), Path(args.output), args.workers)
        records = analyzer.collect_records()
        summary = analyzer.build_summary(records)
        json_path, csv_path = analyzer.export_reports(records, summary)
        analyzer.print_dashboard(summary)
        print(f"JSON report: {json_path}")
        print(f"CSV report : {csv_path}")
        return 0
    except (OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
