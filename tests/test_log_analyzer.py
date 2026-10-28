import tempfile
import unittest
from pathlib import Path
from log_analyzer import LogAnalyzer, parse_line

class ParserTests(unittest.TestCase):
    def test_application_error(self):
        row = parse_line("2026-10-28 10:01:00 ERROR Database connection failed")
        self.assertEqual(row.level, "ERROR")
        self.assertEqual(row.message, "Database connection failed")

    def test_warning_and_seconds_duration(self):
        row = parse_line("2026-10-28T10:01:30 WARN Slow request execution_time=0.25s")
        self.assertEqual(row.level, "WARNING")
        self.assertEqual(row.duration_ms, 250.0)

    def test_apache_request_and_status(self):
        row = parse_line('127.0.0.1 - - [28/Oct/2026:10:02:00 +0000] "GET /health HTTP/1.1" 503 14')
        self.assertTrue(row.is_request)
        self.assertEqual(row.level, "ERROR")
        self.assertIsNotNone(row.timestamp)

    def test_blank_lines_ignored(self):
        self.assertIsNone(parse_line("   "))

class AnalyzerTests(unittest.TestCase):
    def test_summary_counts_errors_requests_and_durations(self):
        rows = [
            parse_line("2026-10-28 10:01:00 ERROR Database connection failed"),
            parse_line("2026-10-28 10:01:10 ERROR Database connection failed"),
            parse_line("2026-10-28 10:01:30 INFO Request complete duration=125ms"),
            parse_line('127.0.0.1 - - [28/Oct/2026:10:02:00 +0000] "GET /health HTTP/1.1" 200 14'),
        ]
        summary = LogAnalyzer.build_summary(rows)
        self.assertEqual(summary["total_entries"], 4)
        self.assertEqual(summary["level_counts"]["ERROR"], 2)
        self.assertEqual(summary["top_10_errors"][0]["count"], 2)
        self.assertEqual(summary["execution_time_ms"]["mean_ms"], 125.0)
        self.assertEqual(sum(summary["requests_per_minute"].values()), 1)

    def test_reports_created(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inp, out = root / "logs", root / "reports"
            inp.mkdir()
            (inp / "sample.log").write_text(
                "2026-10-28 10:01:00 INFO ready duration=10ms\n", encoding="utf-8"
            )
            analyzer = LogAnalyzer(inp, out)
            records = analyzer.collect_records()
            summary = analyzer.build_summary(records)
            json_file, csv_file = analyzer.export_reports(records, summary)
            self.assertTrue(json_file.exists())
            self.assertTrue(csv_file.exists())

if __name__ == "__main__":
    unittest.main()
