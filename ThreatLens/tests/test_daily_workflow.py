"""Daily journal, interactive command and Iranian UI regression tests (offline)."""

import contextlib
import io
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cli
import ui
from config import application_dir, load_config
from detector import IOCType
from engine import Scanner
from models import NetworkContext, ProviderResult, Verdict
from reporting import load_report, record, report_path, save_report
from rich.console import Console
from test_threatlens import Isolated


class DailyTests(Isolated):
    def scanner(self, **overrides):
        provider = Mock()
        provider.name = "Fake"
        provider.api_key = "test-key"
        provider.SUPPORTED_TYPES = set(IOCType) - {IOCType.UNKNOWN}
        provider.collect.side_effect = lambda *args: ProviderResult(
            "Fake", Verdict.NO_HIT, "complete"
        )
        return Scanner(self.config(**overrides), providers=[provider]), provider

    def test_same_day_reuse_survives_new_scanner_and_does_not_append(self):
        scanner, provider = self.scanner()
        first = scanner.scan("EXAMPLE.COM.", report_directory=self.path)
        path = save_report(first, self.path)
        before = path.read_bytes()
        scanner2, provider2 = self.scanner()
        second = scanner2.scan("example.com", report_directory=self.path)
        self.assertTrue(second.reused)
        self.assertEqual(first.created_at, second.created_at)
        provider2.collect.assert_not_called()
        self.assertEqual(save_report(second, self.path).read_bytes(), before)
        provider.collect.assert_called_once()

    def test_day_rollover_ignores_previous_report_and_ti_cache(self):
        scanner, provider = self.scanner()
        with patch("engine.local_day", return_value="2026-09-16"):
            one = scanner.scan("8.8.8.8", report_directory=self.path)
            path1 = save_report(one, self.path)
        with patch("engine.local_day", return_value="2026-09-17"):
            two = scanner.scan("8.8.8.8", report_directory=self.path)
            path2 = save_report(two, self.path)
        self.assertFalse(two.reused)
        self.assertFalse(two.results[0].cached)
        self.assertNotEqual(path1, path2)
        self.assertEqual(provider.collect.call_count, 2)

    def test_refresh_skips_report_and_cache_but_preserves_history(self):
        scanner, provider = self.scanner()
        one = scanner.scan("8.8.8.8", report_directory=self.path)
        path = save_report(one, self.path)
        two = scanner.scan("8.8.8.8", report_directory=self.path, refresh=True)
        save_report(two, self.path)
        self.assertFalse(two.reused)
        self.assertEqual(provider.collect.call_count, 2)
        self.assertEqual(path.read_text().count("THREATLENS_RECORD_V1 "), 2)

    def test_incomplete_report_does_not_prevent_retry(self):
        scanner, provider = self.scanner()
        provider.collect.side_effect = [
            ProviderResult("Fake", Verdict.ERROR, "timeout"),
            ProviderResult("Fake", Verdict.NO_HIT, "complete"),
        ]
        save_report(scanner.scan("8.8.8.8", report_directory=self.path), self.path)
        two = scanner.scan("8.8.8.8", report_directory=self.path)
        self.assertFalse(two.reused)
        self.assertEqual(two.results[0].verdict, Verdict.NO_HIT)
        self.assertEqual(provider.collect.call_count, 2)

    def test_organization_or_enrichment_change_invalidates_report(self):
        scanner, provider = self.scanner()
        save_report(scanner.scan("8.8.8.8", report_directory=self.path), self.path)
        scanner.organization = self.org(
            [{"cidr": "8.8.8.8/32", "label": "APN", "external_lookup": False}]
        )
        report = scanner.scan("8.8.8.8", report_directory=self.path)
        self.assertFalse(report.reused)
        self.assertFalse(report.context.external_allowed)
        self.assertEqual(provider.collect.call_count, 1)

    def test_hash_file_identity_is_recomputed(self):
        scanner, provider = self.scanner()
        sample = self.path / "sample.bin"
        sample.write_bytes(b"first")
        one = scanner.scan(str(sample), file=True, report_directory=self.path)
        save_report(one, self.path)
        sample.write_bytes(b"changed")
        two = scanner.scan(str(sample), file=True, report_directory=self.path)
        self.assertFalse(two.reused)
        self.assertNotEqual(one.ioc, two.ioc)
        self.assertEqual(provider.collect.call_count, 2)

    def test_category_grouping_and_url_case_preservation(self):
        scanner, _ = self.scanner()
        reports = [
            scanner.scan(x)
            for x in [
                "8.8.8.8",
                "2001:4860:4860::8888",
                "a" * 32,
                "b" * 64,
                "example.com",
                "https://example.com/Path",
            ]
        ]
        paths = [save_report(r, self.path) for r in reports]
        self.assertEqual(paths[0], paths[1])
        self.assertEqual(paths[2], paths[3])
        self.assertEqual(len(set(paths)), 4)
        url = reports[-1]
        self.assertIsNone(
            load_report(self.path, "https://example.com/path", url.ioc_type, url.reuse_key)
        )

    def test_corrupt_structured_record_is_miss_and_plain_text_is_not_an_index(self):
        scanner, _ = self.scanner()
        one = scanner.scan("8.8.8.8")
        path = report_path(self.path, one.ioc_type, one.report_day)
        path.write_text(
            "IOC: 8.8.8.8\nTHREATLENS_RECORD_V1 {broken}\n"
            + record(one).replace('"sha256": "', '"sha256": "bad'),
            encoding="utf-8",
        )
        self.assertIsNone(load_report(self.path, one.ioc, one.ioc_type, one.reuse_key))

    def test_concurrent_writers_preserve_complete_records(self):
        scanner, _ = self.scanner()
        one = scanner.scan("8.8.8.8")
        with ThreadPoolExecutor(max_workers=4) as pool:
            paths = list(pool.map(lambda _: save_report(one, self.path), range(8)))
        lines = paths[0].read_text().splitlines()
        records = [line for line in lines if line.startswith("THREATLENS_RECORD_V1 ")]
        self.assertEqual(len(records), 8)
        for line in records:
            json.loads(line.split(" ", 1)[1])
        self.assertIsNotNone(load_report(self.path, one.ioc, one.ioc_type, one.reuse_key))

    def test_no_cache_skips_daily_reuse(self):
        scanner, _ = self.scanner()
        save_report(scanner.scan("8.8.8.8", report_directory=self.path), self.path)
        scanner2, provider = self.scanner(no_cache=True)
        self.assertFalse(scanner2.scan("8.8.8.8", report_directory=self.path).reused)
        provider.collect.assert_called_once()

    def test_offline_can_reuse_complete_today_but_refresh_is_rejected(self):
        scanner, _ = self.scanner()
        save_report(scanner.scan("8.8.8.8", report_directory=self.path), self.path)
        scanner2, provider = self.scanner(offline=True)
        self.assertTrue(scanner2.scan("8.8.8.8", report_directory=self.path).reused)
        provider.collect.assert_not_called()
        with self.assertRaises(ValueError):
            scanner2.scan("8.8.8.8", refresh=True)


class InteractiveTests(Isolated):
    def test_windows_tokenization_and_unclosed_quotes(self):
        self.assertEqual(
            cli.split_command(r'--file "C:\Samples\a file.exe" --timeout 5'),
            ["--file", r"C:\Samples\a file.exe", "--timeout", "5"],
        )
        self.assertEqual(
            cli.split_command('--env-file="C:\\SOC\\keys.env"'), [r"--env-file=C:\SOC\keys.env"]
        )
        with self.assertRaises(ValueError):
            cli.split_command('--file "unclosed')

    def test_help_errors_one_shot_and_session_defaults(self):
        observed = []

        def execute(session, args, configured=None):
            observed.append((args.ioc, args.timeout))
            return 0

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("cli.Session.execute", execute),
            patch(
                "builtins.input",
                side_effect=[
                    "-h",
                    "--bad-flag",
                    "--timeout 5",
                    "8.8.8.8 --timeout 7",
                    "1.1.1.1",
                    '"unclosed',
                    "exit",
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()) as out,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(cli.main(["--data-dir", str(self.path)]), 0)
        self.assertEqual(observed, [("8.8.8.8", 7), ("1.1.1.1", 5)])
        self.assertIn("--refresh", out.getvalue())

    def test_env_switch_does_not_inherit_previous_file_values(self):
        first, second = self.path / "one.env", self.path / "two.env"
        first.write_text("VT_API_KEY=one\n")
        second.write_text("VT_API_KEY=two\n")
        with patch.dict(os.environ, {"THREATLENS_DATA_DIR": str(self.path)}, clear=True):
            self.assertEqual(load_config(first).keys["virustotal"], "one")
            self.assertEqual(load_config(second).keys["virustotal"], "two")
            self.assertNotIn("VT_API_KEY", os.environ)

    def test_frozen_report_default_is_beside_exe(self):
        with (
            patch("sys.frozen", True, create=True),
            patch("sys.executable", str(self.path / "ThreatLens.exe")),
        ):
            self.assertEqual(application_dir(), self.path.resolve())
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                cli.main(["127.0.0.1", "--offline", "--data-dir", str(self.path)])
        self.assertEqual(len(list(self.path.glob("ThreatLens_IP_*.txt"))), 1)

    def test_rate_limiter_transport_survives_setting_changes(self):
        session = cli.Session()
        _, one = session.configure(cli.parser().parse_args(["--data-dir", str(self.path)]))
        _, two = session.configure(
            cli.parser().parse_args(["--data-dir", str(self.path), "--timeout", "5"])
        )
        for a, b in zip(one.providers, two.providers):
            self.assertIs(a.transport, b.transport)
            self.assertEqual(b.transport.timeout, 5)


class AlertTests(Isolated):
    def test_red_blink_alerts_use_existing_classification_only(self):
        for isp in ("Irancell", "MCI / Hamrah Aval", "Telecommunication Company of Iran"):
            context = NetworkContext(address="1.2.3.4", country_code="IR", isp=isp, asn="123")
            before = replace(context)
            output = io.StringIO()
            console = Console(
                file=output,
                width=120,
                height=40,
                force_terminal=True,
                color_system="truecolor",
                no_color=False,
            )
            with patch.object(ui, "console", console):
                ui.print_context(context)
            self.assertIn(isp, output.getvalue())
            self.assertIn("ATTENTION: IRANIAN ISP", output.getvalue())
            self.assertRegex(output.getvalue(), r"\x1b\[[0-9;]*5[;m]")
            self.assertRegex(output.getvalue(), r"\x1b\[[0-9;]*31[;m]")
            self.assertEqual(context, before)
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=120)):
            ui.print_context(
                NetworkContext(address="1.2.3.4", infrastructure=["ArvanCloud"], country_code="US")
            )
        self.assertIn("IRANIAN CDN", output.getvalue())
        self.assertIn("do not block", output.getvalue())
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=120)):
            ui.print_context(
                NetworkContext(address="1.2.3.4", infrastructure=["Cloudflare"], country_code="US")
            )
        self.assertNotIn("ATTENTION: IRANIAN", output.getvalue())
