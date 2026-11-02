import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from scripts import process_filters as filters


class RuleTests(unittest.TestCase):
    def test_line_iteration_handles_crlf_empty_lines_and_missing_final_newline(self):
        self.assertEqual([line.strip() for line in filters.iter_lines("a\r\n\r\nb")], ["a", "", "b"])
        self.assertEqual(list(filters.iter_lines("")), [])
        self.assertEqual(list(filters.iter_lines("a\n")), ["a"])

    def test_case_sensitive_rules_are_preserved(self):
        pairs = [
            ("##.Ad", "##.ad"),
            ('example.com##[data-id="ABC"]', 'example.com##[data-id="abc"]'),
            ("example.com##+js(set, Key, Value)", "example.com##+js(set, key, value)"),
            ("/Tracker/", "/tracker/"),
            ("/Ad.js$match-case", "/ad.js$match-case"),
        ]
        for first, second in pairs:
            with self.subTest(first=first):
                self.assertEqual(filters.deduplicate([first, second, first]), [first, second])

    def test_dns_deduplication_preserves_first_spelling_and_order(self):
        self.assertEqual(
            filters.deduplicate(iter(["||Example.com^", "||other.com^", "||example.com^"]),
                                case_insensitive=True),
            ["||Example.com^", "||other.com^"],
        )

    def test_metadata_is_excluded_and_unknown_rules_are_preserved(self):
        lines = iter(["\ufeff[Adblock Plus 2.0]\n", "[Adblock]\n", "! title\n", "# comment\n",
                      "\n", "||example.com^\n", "##.Ad\n", "example.com#@#.Ad\n",
                      "@@||allowed.com^\n", "unrecognized-pattern\n"])
        categories, counts, validation = filters.classify_rules(lines)
        self.assertEqual(categories["dns"], ["||example.com^"])
        self.assertEqual(categories["cosmetic"], ["##.Ad", "example.com#@#.Ad"])
        self.assertEqual(categories["network"], ["@@||allowed.com^", "unrecognized-pattern"])
        self.assertEqual(counts["comment"], 4)
        self.assertEqual(counts["empty"], 1)
        self.assertEqual(validation["total_rules"], 5)
        self.assertEqual(validation["invalid"], 1)
        self.assertEqual(sum(validation["format_distribution"].values()), validation["valid"])

    def test_format_detection_runs_once_per_rule(self):
        with patch.object(filters, "is_valid_rule", wraps=filters.is_valid_rule) as detect:
            filters.classify_rules(iter(["! metadata", "||example.com^", "##.ad", "/ads$script"]))
        self.assertEqual(detect.call_count, 3)


class DownloadTests(unittest.TestCase):
    @staticmethod
    def response(payload):
        return io.BytesIO(payload)

    def test_utf8_bom_is_decoded(self):
        with patch.object(filters, "urlopen", return_value=self.response(b"\xef\xbb\xbf! title\n||example.com^\n")):
            self.assertEqual(filters.download("https://example.com/list", "test"), "! title\n||example.com^\n")

    def test_empty_html_and_metadata_only_sources_are_rejected(self):
        for content in ["", " \n", "<!DOCTYPE html><html>error</html>",
                        "<html>error</html>", "! title\n[Adblock Plus 2.0]\n", "Bad Gateway"]:
            with self.subTest(content=content), self.assertRaises(ValueError):
                filters.validate_source(content, "test")

    def test_known_rule_after_metadata_is_accepted(self):
        filters.validate_source("[Adblock Plus 2.0]\n! title\n##.ad\n", "test")

    def test_permanent_http_error_is_not_retried(self):
        error = HTTPError("https://example.com", 404, "Not Found", {}, None)
        with patch.object(filters, "urlopen", side_effect=error) as request, \
                patch.object(filters.time, "sleep") as sleep, self.assertRaises(RuntimeError):
            filters.download("https://example.com/list", "test")
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()

    def test_transient_http_error_is_retried(self):
        error = HTTPError("https://example.com", 503, "Unavailable", {}, None)
        with patch.object(filters, "urlopen", side_effect=[error, self.response(b"||example.com^\n")]) as request, \
                patch.object(filters.time, "sleep") as sleep:
            self.assertEqual(filters.download("https://example.com/list", "test"), "||example.com^\n")
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(filters.RETRY_DELAY)

    def test_corrupt_or_empty_responses_exhaust_retries(self):
        for payload in [b"", b"||example.com^\xff\n"]:
            with self.subTest(payload=payload), \
                    patch.object(filters, "urlopen", side_effect=lambda *a, **kw: self.response(payload)) as request, \
                    patch.object(filters.time, "sleep"), self.assertRaises(RuntimeError):
                filters.download("https://example.com/list", "test")
            self.assertEqual(request.call_count, filters.MAX_RETRIES)

    def test_network_failure_is_retried(self):
        with patch.object(filters, "urlopen", side_effect=URLError("timeout")) as request, \
                patch.object(filters.time, "sleep"), self.assertRaises(RuntimeError):
            filters.download("https://example.com/list", "test")
        self.assertEqual(request.call_count, filters.MAX_RETRIES)

    def test_incomplete_response_is_retried(self):
        with patch.object(filters, "urlopen", side_effect=filters.IncompleteRead(b"partial", 100)) as request, \
                patch.object(filters.time, "sleep"), self.assertRaises(RuntimeError):
            filters.download("https://example.com/list", "test")
        self.assertEqual(request.call_count, filters.MAX_RETRIES)


class PipelineTests(unittest.TestCase):
    def test_complete_pipeline_counts_sizes_case_and_timestamps(self):
        sources = {
            filters.URL_DNS: "[Adblock Plus 2.0]\n||Example.com^\n||example.com^\n",
            filters.URL_FILTERS: "! title\n##.Ad\n##.ad\n##.Ad\n/Ad$match-case\n/ad$match-case\nunknown\n",
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(filters, "download", side_effect=lambda url, _: sources[url]), \
                contextlib.redirect_stdout(io.StringIO()):
            filters.main(["--output-dir", directory])
            root = Path(directory)
            stats = json.loads((root / "stats.json").read_text(encoding="utf-8"))
            self.assertEqual(stats["total_rules"], 6)
            self.assertEqual(stats["deduplication"], {"before": 8, "after": 6, "removed": 2})
            versions = set()
            for name, expected in [("dns.txt", 1), ("cosmetic.txt", 2), ("network.txt", 3)]:
                payload = (root / name).read_bytes()
                self.assertNotIn(b"\r\n", payload)
                self.assertEqual(stats["output_files"][name]["size_bytes"], len(payload))
                text = payload.decode("utf-8")
                self.assertIn(f"! Rule count: {expected}\n", text)
                versions.add(next(line for line in text.splitlines() if line.startswith("! Version:")))
            self.assertEqual(len(versions), 1)
            self.assertIn("##.Ad\n##.ad\n", (root / "cosmetic.txt").read_text(encoding="utf-8"))
            self.assertEqual(list(root.glob("*.tmp")), [])

    def test_download_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "dns.txt"
            destination.write_bytes(b"previous output\n")
            with patch.object(filters, "download", side_effect=RuntimeError("offline")), \
                    self.assertRaises(RuntimeError):
                filters.main(["--output-dir", directory])
            self.assertEqual(destination.read_bytes(), b"previous output\n")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_staging_failure_preserves_all_existing_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dns.txt").write_bytes(b"old dns\n")
            (root / "network.txt").write_bytes(b"old network\n")
            with self.assertRaises(TypeError):
                filters.write_outputs(root, {"dns.txt": "new dns\n", "network.txt": object()})
            self.assertEqual((root / "dns.txt").read_bytes(), b"old dns\n")
            self.assertEqual((root / "network.txt").read_bytes(), b"old network\n")
            self.assertEqual(list(root.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
