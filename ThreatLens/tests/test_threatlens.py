"""Offline regression/contract suite. Synthetic responses; no credentials or live TI."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from assessment import assess
from config import AppConfig, load_config
from detector import IOCType as T
from detector import detect_ioc_type, normalize_ioc
from engine import Scanner
from models import NetworkContext
from models import ProviderResult as R
from models import Verdict as V
from network import CloudRegistry, apply_network_policy, ip_category, local_context, parse_feed
from organization import Organization
from providers.abuseipdb import AbuseIPDBProvider
from providers.malwarebazaar import MalwareBazaarProvider
from providers.otx import OTXProvider
from providers.pulsedive import PulsediveProvider
from providers.threatfox import ThreatFoxProvider
from providers.urlhaus import URLhausProvider
from providers.virustotal import VirusTotalProvider
from reporting import compact, save_report
from storage import Cache
from transport import LookupFailure, Transport
from utils import calculate_file_hashes


class Isolated(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.net = patch("requests.request", side_effect=AssertionError("Unexpected network"))
        self.net.start()
        self.addCleanup(self.net.stop)

    def tearDown(self):
        import logging

        logger = logging.getLogger("threatlens")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    def config(self, **kwargs):
        return AppConfig(keys={}, data_dir=self.path, enrichment=False, **kwargs)

    def org(self, entries):
        path = self.path / "org.json"
        path.write_text(
            json.dumps({"schema_version": 1, "organization": "SOC", "networks": entries}),
            encoding="utf-8",
        )
        return Organization(path)


class ConfigTests(Isolated):
    def test_default_env_beside_exe_or_script_independent_of_cwd(self):
        app = self.path / "app with spaces"
        app.mkdir()
        (app / ".env").write_text("VT_API_KEY=beside-app\n", encoding="utf-8")
        (self.path / ".env").write_text("VT_API_KEY=wrong-cwd\n", encoding="utf-8")
        previous = Path.cwd()
        try:
            os.chdir(self.path)
            for frozen in (False, True):
                with (
                    self.subTest(frozen=frozen),
                    patch.dict(os.environ, {"THREATLENS_DATA_DIR": str(self.path)}, clear=True),
                    patch("sys.frozen", frozen, create=True),
                    patch("sys.executable", str(app / "ThreatLens.exe")),
                    patch("config.__file__", str((self.path if frozen else app) / "config.py")),
                ):
                    self.assertEqual(load_config().keys["virustotal"], "beside-app")
        finally:
            os.chdir(previous)

    def test_explicit_env_wins_and_missing_explicit_does_not_fall_back(self):
        (self.path / ".env").write_text("VT_API_KEY=default\n", encoding="utf-8")
        explicit = self.path / "selected.env"
        explicit.write_text("VT_API_KEY=selected\n", encoding="utf-8")
        for path, expected in ((explicit, "selected"), (self.path / "missing.env", "")):
            with (
                self.subTest(path=path),
                patch.dict(os.environ, {"THREATLENS_DATA_DIR": str(self.path)}, clear=True),
                patch("sys.frozen", True, create=True),
                patch("sys.executable", str(self.path / "ThreatLens.exe")),
            ):
                self.assertEqual(load_config(path).keys["virustotal"], expected)

    def test_existing_environment_keeps_precedence(self):
        env = self.path / ".env"
        env.write_text("VT_API_KEY=from-file\n", encoding="utf-8")
        with patch.dict(
            os.environ,
            {"VT_API_KEY": "from-process", "THREATLENS_DATA_DIR": str(self.path)},
            clear=True,
        ):
            self.assertEqual(load_config(env).keys["virustotal"], "from-process")


class DetectionTests(Isolated):
    def test_defanging_and_idna(self):
        self.assertEqual(
            normalize_ioc("hxxps://EXAMPLE[.]com/Case?q=ABC"),
            ("https://example.com/Case?q=ABC", T.URL),
        )
        self.assertEqual(normalize_ioc("EXAMPLE.COM."), ("example.com", T.DOMAIN))
        self.assertEqual(normalize_ioc("2001:4860:4860::8888")[1], T.IPV6)
        self.assertTrue(normalize_ioc("مثال.com")[0].startswith("xn--"))

    def test_invalid_inputs(self):
        for value in (
            "https://",
            "https://bad host",
            "https://example.com:99999",
            "https://u:p@example.com",
            "bad\x1b.com",
            "-bad.com",
            "a" * 128,
        ):
            with self.subTest(value=value):
                self.assertEqual(detect_ioc_type(value), T.UNKNOWN)

    def test_supported_hashes(self):
        for size, kind in ((32, T.MD5), (40, T.SHA1), (64, T.SHA256)):
            self.assertEqual(normalize_ioc("A" * size), ("a" * size, kind))
        self.assertNotIn(T.SHA1, ThreatFoxProvider.SUPPORTED_TYPES)
        self.assertIn(T.SHA1, MalwareBazaarProvider.SUPPORTED_TYPES)

    def test_hash_stream(self):
        file = self.path / "file with spaces.bin"
        file.write_bytes(b"abc")
        hashes = calculate_file_hashes(str(file))
        self.assertEqual(
            hashes["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(hashes["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hashes["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(hashes["size"], 3)
        with self.assertRaises(ValueError):
            calculate_file_hashes(str(self.path))

    def test_changed_file_rejected(self):
        file = self.path / "sample"
        file.write_bytes(b"abc")
        before, after = Mock(), Mock()
        import stat

        before.st_mode = stat.S_IFREG
        before.st_size, before.st_mtime_ns = 3, 10
        after.st_size, after.st_mtime_ns = 3, 11
        with patch("utils.os.fstat", side_effect=[before, after]), self.assertRaises(ValueError):
            calculate_file_hashes(str(file))


class NetworkTests(Isolated):
    def test_special_addresses(self):
        samples = {
            "10.1.2.3": "private",
            "169.254.2.3": "apipa",
            "255.255.255.255": "limited_broadcast",
            "127.0.0.1": "loopback",
            "0.0.0.0": "unspecified",
            "224.0.0.1": "multicast",
            "100.64.2.3": "shared_cgnat",
            "192.0.2.1": "documentation_or_benchmark",
            "::1": "loopback",
            "fe80::1": "link_local",
            "fc00::1": "private",
            "8.8.8.8": "public",
        }
        for address, expected in samples.items():
            with self.subTest(address=address):
                self.assertEqual(ip_category(address), expected)
        self.assertNotEqual(ip_category("::ffff:10.0.0.1"), "public")

    def test_org_longest_prefix(self):
        org = self.org(
            [
                {"cidr": "8.8.8.0/24", "label": "parent"},
                {"cidr": "8.8.8.8/32", "label": "APN", "kind": "apn", "external_lookup": False},
            ]
        )
        context = local_context("8.8.8.8", T.IPV4, org)
        self.assertEqual(context.organization["label"], "APN")
        self.assertTrue(context.protected)
        self.assertFalse(context.external_allowed)

    def test_directed_broadcast_requires_known_mask(self):
        org = self.org([{"cidr": "8.8.8.0/24", "label": "subnet"}])
        self.assertEqual(local_context("8.8.8.255", T.IPV4, org).category, "directed_broadcast")
        self.assertEqual(local_context("8.8.8.255", T.IPV4, Organization()).category, "public")

    def test_org_invalid_policy_fails(self):
        for rule in (
            {"cidr": "8.8.8.1/24", "label": "bad mask"},
            {"cidr": "8.8.8.8/32", "label": "bad", "protect": "false"},
            {"cidr": "8.8.8.8/32", "label": "bad", "external_lookpu": False},
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.org([rule])

    def test_private_cannot_be_overridden(self):
        org = self.org([{"cidr": "10.0.0.0/8", "label": "APN", "external_lookup": True}])
        self.assertFalse(local_context("10.2.3.4", T.IPV4, org).external_allowed)

    def test_feed_parsers_and_rejection(self):
        self.assertEqual(parse_feed("8.8.8.0/24\n", "lines"), ["8.8.8.0/24"])
        self.assertEqual(
            parse_feed(
                {
                    "prefixes": [
                        {"service": "CLOUDFRONT", "ip_prefix": "8.8.8.0/24"},
                        {"service": "EC2", "ip_prefix": "9.9.9.0/24"},
                    ]
                },
                "aws",
            ),
            ["8.8.8.0/24"],
        )
        self.assertEqual(
            parse_feed({"addresses": ["8.8.8.0/24"], "ipv6_addresses": []}, "fastly"),
            ["8.8.8.0/24"],
        )
        self.assertEqual(
            parse_feed({"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}]}, "google"), ["8.8.8.0/24"]
        )
        for body in ("", "<html>bad</html>", "0.0.0.0/0", "10.0.0.0/8"):
            with self.assertRaises(ValueError):
                parse_feed(body, "lines")

    def test_failed_refresh_preserves_old(self):
        clock = Mock(return_value=100)
        cache = Cache(self.path, clock=clock)
        cache.put("cloud-feed-v1", "https://feed", ["8.8.8.0/24"], 10)
        clock.return_value = 200
        registry = CloudRegistry(cache)
        with patch(
            "network.Transport.request", side_effect=LookupFailure("network", "unavailable")
        ):
            name, ranges, warning = registry._source(("ArvanCloud", "https://feed", "lines"))
        self.assertEqual(ranges, ["8.8.8.0/24"])
        self.assertIn("stale", warning)
        self.assertEqual(cache.get("cloud-feed-v1", "https://feed", stale=True)["value"], ranges)

    def test_cloud_sources_independent(self):
        registry = CloudRegistry(Cache(self.path))

        def fetch(_self, method, url, **kwargs):
            if url == "https://a":
                raise LookupFailure("network", "down")
            return "8.8.8.0/24"

        with (
            patch(
                "network.FEEDS",
                {"ArvanCloud": [("https://a", "lines")], "Fastly": [("https://b", "lines")]},
            ),
            patch.object(Transport, "request", fetch),
        ):
            matches, warnings = registry.lookup("8.8.8.8")
        self.assertEqual(matches, ["Fastly"])
        self.assertIn("unknown", warnings[0])


class AssessmentTests(Isolated):
    def result(self, provider="VirusTotal", observed=None):
        return R(
            provider,
            V.MALICIOUS,
            "signal",
            {"malicious": 70, "suspicious": 0, "total": 70},
            observed_at=observed,
        )

    def test_no_data_never_clean(self):
        for results, expected in (
            ([R("x", V.ERROR, "down")], "UNKNOWN"),
            ([R("x", V.NOT_FOUND, "none")], "NO_KNOWN_THREAT"),
            ([R("x", V.SKIPPED, "no key")], "UNKNOWN"),
            ([R("x", V.NO_HIT, "none"), R("y", V.ERROR, "down")], "INCONCLUSIVE"),
            ([], "UNKNOWN"),
        ):
            a = assess(results, NetworkContext(), "IPv4")
            self.assertEqual(a.verdict, expected)
            self.assertNotIn("No action required", " ".join(a.recommendations))

    def test_positive_cannot_disappear(self):
        r = R("URLhaus", V.SUSPICIOUS, "offline", {"status": "offline"})
        a = assess([r], NetworkContext(), "URL")
        self.assertEqual(a.verdict, "SUSPICIOUS")
        self.assertGreater(a.score, 0)

    def test_detection_strength_and_decay(self):
        now = datetime.now(timezone.utc)
        low = R("VirusTotal", V.MALICIOUS, "one", {"malicious": 1, "suspicious": 0, "total": 70})
        high = self.result()
        old = self.result(observed=(now - timedelta(days=365)).isoformat())
        self.assertLess(
            assess([low], NetworkContext(), "IPv4").score,
            assess([high], NetworkContext(), "IPv4").score,
        )
        self.assertLess(
            assess([old], NetworkContext(), "IPv4", now).score,
            assess([high], NetworkContext(), "IPv4", now).score,
        )
        self.assertEqual(assess([high], NetworkContext(), "IPv4").verdict, "HIGH_RISK")

    def test_correlation_discount(self):
        results = [
            R("ThreatFox", V.FOUND, "match", {"confidence": 100}),
            R("URLhaus", V.MALICIOUS, "online", {"status": "online"}),
        ]
        a = assess(results, NetworkContext(), "URL")
        self.assertLessEqual(a.score, 100)
        self.assertEqual({x["group"] for x in a.contributions}, {"abuse.ch"})

    def test_arvan_never_recommends_ip_block(self):
        context = apply_network_policy(
            NetworkContext(category="public", address="8.8.8.8", infrastructure=["ArvanCloud"])
        )
        a = assess([self.result()], context, "IPv4")
        self.assertEqual(a.verdict, "HIGH_RISK")
        self.assertTrue(any("Do not block the ArvanCloud" in x for x in a.recommendations))
        self.assertFalse(any(x.startswith("Block this IP") for x in a.recommendations))

    def test_foreign_cloud_block_allowed(self):
        for cloud in ("Cloudflare", "Fastly", "Amazon CloudFront", "Google Cloud"):
            c = apply_network_policy(
                NetworkContext(category="public", country_code="US", infrastructure=[cloud])
            )
            a = assess([self.result()], c, "IPv4")
            self.assertTrue(any(x.startswith("Block this IP") for x in a.recommendations))

    def test_domestic_and_apn(self):
        org = self.org(
            [
                {
                    "cidr": "8.8.8.8/32",
                    "label": "Company APN",
                    "kind": "apn",
                    "country_code": "IR",
                    "isp": "Irancell",
                }
            ]
        )
        c = apply_network_policy(local_context("8.8.8.8", T.IPV4, org))
        a = assess([self.result()], c, "IPv4")
        self.assertEqual(a.verdict, "HIGH_RISK")
        self.assertTrue(any("Irancell" in x for x in c.warnings))
        self.assertTrue(any("Do not block this protected" in x for x in a.recommendations))


class ProviderTests(Isolated):
    def call(self, cls, kind, payload, ioc="8.8.8.8"):
        t = Mock()
        t.request.return_value = payload
        p = cls("FAKE_KEY", transport=t)
        return p.collect(kind, ioc), t

    def test_malformed_responses_are_errors(self):
        for cls, kind in (
            (VirusTotalProvider, T.IPV4),
            (AbuseIPDBProvider, T.IPV4),
            (OTXProvider, T.IPV4),
            (ThreatFoxProvider, T.IPV4),
            (URLhausProvider, T.URL),
            (MalwareBazaarProvider, T.SHA256),
            (PulsediveProvider, T.IPV4),
        ):
            for payload in ({}, [], None, {"data": None}):
                with self.subTest(provider=cls.name, payload=payload):
                    r, _ = self.call(cls, kind, payload)
                    self.assertEqual(r.verdict, V.ERROR)

    def test_missing_keys_do_not_request(self):
        for cls in (
            VirusTotalProvider,
            AbuseIPDBProvider,
            OTXProvider,
            ThreatFoxProvider,
            URLhausProvider,
            MalwareBazaarProvider,
            PulsediveProvider,
        ):
            t = Mock()
            p = cls(None, transport=t)
            self.assertEqual(p.collect(next(iter(p.SUPPORTED_TYPES)), "x").verdict, V.SKIPPED)
            t.request.assert_not_called()

    def test_vt_metrics(self):
        r, _ = self.call(
            VirusTotalProvider,
            T.IPV4,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1, "suspicious": 2, "harmless": 67}
                    }
                }
            },
        )
        self.assertEqual(r.evidence["total"], 70)
        self.assertNotIn("confidence", r.evidence)
        r, _ = self.call(VirusTotalProvider, T.IPV4, {"data": {"attributes": {}}})
        self.assertEqual(r.verdict, V.ERROR)

    def test_abuse_and_otx(self):
        r, _ = self.call(
            AbuseIPDBProvider, T.IPV4, {"data": {"abuseConfidenceScore": 0, "totalReports": 2}}
        )
        self.assertEqual(r.verdict, V.SUSPICIOUS)
        r, _ = self.call(OTXProvider, T.IPV4, {"pulse_info": {"count": 1}})
        self.assertEqual(r.verdict, V.SUSPICIOUS)

    def test_threatfox_request_and_exactness(self):
        r, t = self.call(ThreatFoxProvider, T.SHA256, {"query_status": "no_result"}, "a" * 64)
        self.assertEqual(
            t.request.call_args.kwargs["json_body"], {"query": "search_hash", "hash": "a" * 64}
        )
        r, t = self.call(
            ThreatFoxProvider,
            T.IPV4,
            {"query_status": "ok", "data": [{"ioc": "18.8.8.8:443", "confidence_level": 100}]},
        )
        self.assertTrue(t.request.call_args.kwargs["json_body"]["exact_match"])
        self.assertEqual(r.verdict, V.NOT_FOUND)
        r, t = self.call(
            ThreatFoxProvider,
            T.IPV4,
            {"query_status": "ok", "data": [{"ioc": "8.8.8.8:443", "confidence_level": 100}]},
        )
        self.assertEqual(r.verdict, V.FOUND)

    def test_urlhaus_offline_not_zero_confidence(self):
        r, _ = self.call(
            URLhausProvider,
            T.URL,
            {"query_status": "ok", "url_status": "offline"},
            "https://example.com/",
        )
        self.assertEqual(r.verdict, V.SUSPICIOUS)
        self.assertNotIn("0%", r.details)

    def test_malwarebazaar_hash_validation(self):
        r, t = self.call(
            MalwareBazaarProvider,
            T.SHA256,
            {"query_status": "ok", "data": [{"sha256_hash": "a" * 64, "signature": "Test"}]},
            "a" * 64,
        )
        self.assertEqual(r.verdict, V.FOUND)
        self.assertEqual(t.request.call_args.kwargs["headers"]["Auth-Key"], "FAKE_KEY")
        r, _ = self.call(
            MalwareBazaarProvider,
            T.SHA256,
            {"query_status": "ok", "data": [{"sha256_hash": "b" * 64}]},
            "a" * 64,
        )
        self.assertEqual(r.verdict, V.ERROR)

    def test_pulsedive_error_is_not_notfound(self):
        r, _ = self.call(PulsediveProvider, T.IPV4, {"error": "Invalid API key FAKE_KEY"})
        self.assertEqual(r.verdict, V.ERROR)
        self.assertNotIn("FAKE_KEY", r.details)
        r, _ = self.call(PulsediveProvider, T.IPV4, {"error": "Indicator not found."})
        self.assertEqual(r.verdict, V.NOT_FOUND)
        r, _ = self.call(PulsediveProvider, T.IPV4, {"risk": "retired"})
        self.assertEqual(r.verdict, V.SUSPICIOUS)


class EngineTests(Isolated):
    def provider(self, verdict=V.NO_HIT):
        p = Mock()
        p.name = "Fake"
        p.SUPPORTED_TYPES = {T.IPV4, T.IPV6, T.URL, T.DOMAIN, T.SHA256}
        p.collect.return_value = R("Fake", verdict, "fixture")
        return p

    def test_success_cache_and_negative_expiry(self):
        clock = Mock(return_value=10)
        cache = Cache(self.path, clock=clock)
        p = self.provider()
        scanner = Scanner(self.config(negative_ttl=5), providers=[p], cache=cache)
        first = scanner.scan("8.8.8.8")
        second = scanner.scan("8.8.8.8")
        self.assertFalse(first.results[0].cached)
        self.assertTrue(second.results[0].cached)
        self.assertEqual(p.collect.call_count, 1)
        clock.return_value = 16
        scanner.scan("8.8.8.8")
        self.assertEqual(p.collect.call_count, 2)

    def test_errors_never_cached(self):
        p = self.provider(V.ERROR)
        scanner = Scanner(self.config(), providers=[p])
        scanner.scan("8.8.8.8")
        scanner.scan("8.8.8.8")
        self.assertEqual(p.collect.call_count, 2)

    def test_private_and_private_url_no_collection(self):
        p = self.provider()
        scanner = Scanner(self.config(), providers=[p])
        for ioc in (
            "10.1.2.3",
            "169.254.1.1",
            "https://10.2.3.4/a",
            "https://host.internal/a",
            "host.internal",
        ):
            report = scanner.scan(ioc)
            self.assertFalse(report.context.external_allowed)
            self.assertEqual(report.results[0].verdict, V.SKIPPED)
        p.collect.assert_not_called()

    def test_org_first_and_public_apn_still_scanned(self):
        org = self.org([{"cidr": "8.8.8.8/32", "label": "APN", "kind": "apn"}])
        p = self.provider(V.SUSPICIOUS)
        scanner = Scanner(self.config(), providers=[p], organization=org)
        with patch.object(org, "match", wraps=org.match) as match:

            def collect(*args):
                self.assertTrue(match.called)
                return R("Fake", V.SUSPICIOUS, "signal")

            p.collect.side_effect = collect
            report = scanner.scan("8.8.8.8")
        self.assertTrue(report.context.protected)
        self.assertEqual(report.assessment.verdict, "SUSPICIOUS")
        p.collect.assert_called_once()

    def test_no_provider_and_offline(self):
        report = Scanner(self.config(), providers=[]).scan("8.8.8.8")
        self.assertEqual(report.assessment.verdict, "UNKNOWN")
        p = self.provider()
        report = Scanner(self.config(offline=True), providers=[p]).scan("8.8.8.8")
        p.collect.assert_not_called()
        self.assertEqual(report.results[0].verdict, V.SKIPPED)

    def test_sensitive_urls_rejected(self):
        p = self.provider()
        scanner = Scanner(self.config(), providers=[p])
        for value in (
            "https://example.com/?token=SECRET",
            "https://example.com/#access_token=SECRET",
        ):
            with self.assertRaises(ValueError):
                scanner.scan(value)
        p.collect.assert_not_called()

    def test_report_and_markup_are_safe(self):
        import ui
        from rich.console import Console

        p = self.provider()
        report = Scanner(self.config(), providers=[p]).scan("https://example.com/[/bold]")
        sink = io.StringIO()
        with patch.object(ui, "console", Console(file=sink, width=100)):
            ui.display(report)
        self.assertIn("[/bold]", sink.getvalue())
        one = save_report(report, self.path / "reports")
        two = save_report(report, self.path / "reports")
        self.assertNotEqual(one, two)
        self.assertIn("Assessment:", one.read_text(encoding="utf-8"))
        self.assertIn("ACTION 1:", one.read_text(encoding="utf-8"))

    def test_bad_provider_isolated(self):
        p = self.provider()
        p.collect.side_effect = RuntimeError("key=SECRET")
        r = Scanner(self.config(), providers=[p]).scan("8.8.8.8")
        self.assertEqual(r.results[0].verdict, V.ERROR)
        self.assertNotIn("SECRET", compact(r))

    def test_file_scans_sha256_only(self):
        p = self.provider()
        file = self.path / "sample file"
        file.write_bytes(b"abc")
        report = Scanner(self.config(), providers=[p]).scan(str(file), file=True)
        self.assertEqual(report.ioc_type, "SHA256")
        self.assertEqual(len(report.ioc), 64)
        self.assertEqual(p.collect.call_args.args[1], report.ioc)


class TransportTests(Isolated):
    def response(self, status=200, body=b"{}", headers=None):
        r = Mock()
        r.__enter__ = Mock(return_value=r)
        r.__exit__ = Mock(return_value=False)
        r.status_code = status
        r.headers = headers or {}
        r.iter_content.return_value = iter([body])
        return r

    def test_http_auth_no_url_or_key(self):
        with patch("requests.request", return_value=self.response(401)):
            with self.assertRaises(LookupFailure) as error:
                Transport().request("GET", "https://example.com/?key=SECRET")
        self.assertEqual(error.exception.code, "authentication")
        self.assertNotIn("SECRET", str(error.exception))

    def test_rate_limit_cooldown(self):
        with patch(
            "requests.request", return_value=self.response(429, headers={"Retry-After": "60"})
        ) as req:
            t = Transport()
            for _ in range(2):
                with self.assertRaises(LookupFailure) as error:
                    t.request("GET", "https://example.com")
                self.assertEqual(error.exception.code, "rate_limited")
            self.assertEqual(req.call_count, 1)

    def test_retry_and_redirect_rejection(self):
        with (
            patch("requests.request", side_effect=[self.response(503), self.response()]) as req,
            patch("transport.time.sleep"),
        ):
            self.assertEqual(Transport().request("GET", "https://example.com"), {})
            self.assertEqual(req.call_count, 2)
        with patch("requests.request", return_value=self.response(302)):
            with self.assertRaises(LookupFailure):
                Transport().request("GET", "https://example.com")

    def test_body_limits_and_invalid_json(self):
        for body in (b"x" * 10_000_001, b"not JSON"):
            with patch("requests.request", return_value=self.response(body=body)):
                with self.assertRaises(LookupFailure):
                    Transport().request("GET", "https://example.com")


class UITests(Isolated):
    def test_classic_panels_and_literal_warnings_at_terminal_widths(self):
        import ui
        from rich.console import Console

        report = Scanner(self.config(offline=True)).scan("8.8.8.8")
        report.context.warnings.append("[red]literal notice[/red]")
        for width in (80, 120):
            sink = io.StringIO()
            with patch.object(ui, "console", Console(file=sink, width=width)):
                ui.print_banner()
                ui.display(report)
            output = sink.getvalue()
            for label in (
                "THREAT INTELLIGENCE AGGREGATOR CLI",
                "Provided by Amirhossein Mousavi",
                "IOC INFORMATION",
                "IP CONTEXT",
                "SCAN RESULTS",
                "OVERALL ASSESSMENT",
                "API WARNINGS",
                "Execution Time:",
                "[red]literal notice[/red]",
                "N/A",
            ):
                self.assertIn(label, output)
            self.assertNotIn("CLEAN", output)
            self.assertNotIn("\x1b[2J", output)
            self.assertTrue(all(len(line) <= width for line in output.splitlines()))

    def test_native_signal_does_not_turn_abuse_reports_into_confidence(self):
        import ui

        result = R("AbuseIPDB", V.SUSPICIOUS, "201 reports", {"abuse_score": 0, "reports": 201})
        self.assertEqual(ui.confidence(result), "0% abuse")


class CLITests(Isolated):
    def test_interactive_multiple_scans_with_adjacent_frozen_env(self):
        import cli

        (self.path / ".env").write_text("VT_API_KEY=beside-exe\n", encoding="utf-8")
        output = io.StringIO()
        with (
            patch.dict(os.environ, {"THREATLENS_DATA_DIR": str(self.path)}, clear=True),
            patch("sys.frozen", True, create=True),
            patch("sys.executable", str(self.path / "ThreatLens.exe")),
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", side_effect=["127.0.0.1", "169.254.1.1", "exit"]) as prompt,
            patch("cli.load_config", wraps=load_config) as config_loader,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = cli.main(["--offline", "--no-enrichment", "--data-dir", str(self.path)])
            self.assertEqual(os.environ["VT_API_KEY"], "beside-exe")
        self.assertEqual(code, 0)
        self.assertEqual(prompt.call_count, 3)
        config_loader.assert_called_once()
        self.assertIn("Enter IOC or file path", output.getvalue())
        reports = list((self.path / "reports").glob("*.txt"))
        self.assertEqual(len(reports), 2)

    def test_real_cli_offline_json_and_txt(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "ThreatLens.py"),
                "8.8.8.8",
                "--offline",
                "--no-enrichment",
                "--json",
                "--data-dir",
                str(self.path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["assessment"]["verdict"], "UNKNOWN")
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(list((self.path / "reports").glob("*.txt"))), 1)

    def test_real_cli_file_with_spaces(self):
        file = self.path / "a file.bin"
        file.write_bytes(b"abc")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "ThreatLens.py"),
                "--file",
                str(file),
                "--offline",
                "--json",
                "--data-dir",
                str(self.path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["ioc_type"], "SHA256")

    def test_eof_exits_without_reprompt(self):
        import cli

        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", side_effect=EOFError()) as prompt,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = cli.main(["--data-dir", str(self.path), "--offline"])
        self.assertEqual(code, 0)
        self.assertEqual(prompt.call_count, 1)

    def test_json_requires_input(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "ThreatLens.py"), "--json", "--data-dir", str(self.path)],
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Supply an IOC", completed.stderr)


class AdditionalRegressionTests(Isolated):
    def test_empty_fresh_cloud_cache_refreshes(self):
        cache = Cache(self.path)
        cache.put("cloud-feed-v1", "https://feed", [], 86400)
        with patch("network.Transport.request", return_value="8.8.8.0/24") as request:
            _, ranges, warning = CloudRegistry(cache)._source(
                ("ArvanCloud", "https://feed", "lines")
            )
        request.assert_called_once()
        self.assertEqual(ranges, ["8.8.8.0/24"])
        self.assertIsNone(warning)

    def test_cached_ti_available_offline(self):
        p = Mock(name="provider")
        p.name = "Fake"
        p.SUPPORTED_TYPES = {T.IPV4}
        p.collect.return_value = R("Fake", V.NO_HIT, "complete")
        Scanner(self.config(), providers=[p]).scan("8.8.8.8")
        p.collect.reset_mock()
        report = Scanner(self.config(offline=True), providers=[p]).scan("8.8.8.8")
        self.assertTrue(report.results[0].cached)
        p.collect.assert_not_called()

    def test_no_cache_and_corrupt_cache(self):
        p = Mock()
        p.name = "Fake"
        p.SUPPORTED_TYPES = {T.IPV4}
        p.collect.return_value = R("Fake", V.NO_HIT, "complete")
        scanner = Scanner(self.config(no_cache=True), providers=[p])
        scanner.scan("8.8.8.8")
        scanner.scan("8.8.8.8")
        self.assertEqual(p.collect.call_count, 2)
        self.assertFalse((self.path / "cache.sqlite3").exists())
        (self.path / "cache.sqlite3").write_bytes(b"not sqlite")
        with self.assertRaises(ValueError):
            Cache(self.path)

    def test_context_failure_does_not_suppress_ti(self):
        p = Mock()
        p.name = "Fake"
        p.SUPPORTED_TYPES = {T.IPV4}
        p.collect.return_value = R("Fake", V.SUSPICIOUS, "complete")
        scanner = Scanner(self.config(), providers=[p])
        with patch.object(scanner, "_context", side_effect=RuntimeError("test")):
            report = scanner.scan("8.8.8.8")
        self.assertEqual(report.assessment.verdict, "SUSPICIOUS")
        self.assertTrue(any("Context collection failed" in w for w in report.context.warnings))

    def test_https_geo_and_local_isp_override(self):
        from enrichment import enrich_ip

        transport = Mock()
        transport.request.return_value = {
            "ip": "8.8.8.8",
            "success": True,
            "country_code": "IR",
            "connection": {"isp": "Mobile Communication Company", "asn": 197207},
        }
        data = enrich_ip("8.8.8.8", transport)
        self.assertEqual(data["country_code"], "IR")
        self.assertTrue(transport.request.call_args.args[1].startswith("https://"))
        org = self.org(
            [{"cidr": "8.8.8.8/32", "label": "APN", "country_code": "IR", "isp": "Local operator"}]
        )
        config = AppConfig(keys={}, data_dir=self.path, enrichment=True)
        scanner = Scanner(config, providers=[], organization=org)
        with (
            patch.object(scanner.clouds, "lookup", return_value=([], [])),
            patch(
                "engine.enrich_ip",
                return_value={"country_code": "US", "isp": "Remote operator", "asn": "1"},
            ),
        ):
            report = scanner.scan("8.8.8.8")
        self.assertEqual(report.context.isp, "Local operator")
        self.assertEqual(report.context.country_code, "IR")

    def test_whois_structured_events_without_dns(self):
        from enrichment import enrich_domain

        transport = Mock()
        transport.request.return_value = {
            "payload": {
                "registrar": {"name": "Example"},
                "events": [{"event_action": "registration", "event_date": "2020-01-01"}],
            }
        }
        result = enrich_domain("sub.example.com", "FAKE", transport)
        self.assertEqual(result["root_domain"], "example.com")
        self.assertEqual(result["created"], "2020-01-01")
        self.assertEqual(transport.request.call_count, 1)

    def test_redaction_precedes_cache_and_render(self):
        secret = 'FAKE_"SPECIAL_KEY'
        p = Mock()
        p.name = "Fake"
        p.SUPPORTED_TYPES = {T.IPV4}
        p.collect.return_value = R("Fake", V.SUSPICIOUS, "echo " + secret, {"note": secret})
        config = AppConfig(keys={"fake": secret}, data_dir=self.path, enrichment=False)
        report = Scanner(config, providers=[p]).scan("8.8.8.8")
        self.assertNotIn(secret, compact(report))
        self.assertEqual(report.results[0].evidence["note"], "[REDACTED]")
        cached = Cache(self.path).get("provider-v2:Fake", "IPv4:8.8.8.8")
        self.assertNotIn(secret, json.dumps(cached))

    def test_unexpected_404_is_error_for_post_apis(self):
        transport = Mock()
        transport.request.side_effect = LookupFailure("not_found", "HTTP 404")
        self.assertEqual(
            URLhausProvider("FAKE", transport=transport)
            .collect(T.URL, "https://example.com")
            .verdict,
            V.ERROR,
        )
        self.assertEqual(
            VirusTotalProvider("FAKE", transport=transport).collect(T.IPV4, "8.8.8.8").verdict,
            V.NOT_FOUND,
        )

    def test_nonfinite_metric_is_error(self):
        transport = Mock()
        transport.request.return_value = {
            "data": {"abuseConfidenceScore": float("nan"), "totalReports": 1}
        }
        self.assertEqual(
            AbuseIPDBProvider("FAKE", transport=transport).collect(T.IPV4, "8.8.8.8").verdict,
            V.ERROR,
        )

    def test_domestic_unprotected_high_risk(self):
        c = apply_network_policy(
            NetworkContext(category="public", country_code="IR", isp="Irancell")
        )
        r = R("VirusTotal", V.MALICIOUS, "many", {"malicious": 70, "suspicious": 0, "total": 70})
        a = assess([r], c, "IPv4")
        self.assertTrue(any("Irancell" in w for w in c.warnings))
        self.assertTrue(any(x.startswith("Block this IP") for x in a.recommendations))

    def test_hash_recommendations_do_not_block_ip(self):
        r = R("MalwareBazaar", V.FOUND, "exact", {"exact_sample": True})
        a = assess([r], NetworkContext(), "SHA256")
        self.assertEqual(a.verdict, "HIGH_RISK")
        self.assertTrue(any("Quarantine" in x for x in a.recommendations))
        self.assertFalse(any("Block this IP" in x for x in a.recommendations))

    def test_batch_json_and_txt(self):
        inputs = self.path / "iocs.txt"
        inputs.write_text("# note\n8.8.8.8\n\n1.1.1.1\n", encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "ThreatLens.py"),
                "--input",
                str(inputs),
                "--offline",
                "--no-enrichment",
                "--json",
                "--data-dir",
                str(self.path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(len([json.loads(line) for line in completed.stdout.splitlines()]), 2)
        self.assertEqual(len(list((self.path / "reports").glob("*.txt"))), 2)

    def test_report_write_failure_is_visible(self):
        import cli

        err = io.StringIO()
        with (
            patch("cli.save_report", side_effect=OSError("disk full")),
            contextlib.redirect_stderr(err),
        ):
            code = cli.main(
                ["8.8.8.8", "--offline", "--no-enrichment", "--data-dir", str(self.path)]
            )
        self.assertEqual(code, 1)
        self.assertIn("disk full", err.getvalue())
        self.assertNotIn("Report saved", err.getvalue())


if __name__ == "__main__":
    unittest.main()
