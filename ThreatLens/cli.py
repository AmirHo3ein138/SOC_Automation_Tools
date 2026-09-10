"""Interactive and scriptable entry points share exactly the same scanner."""

import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path

import ui
from config import VERSION, load_config
from engine import Scanner
from reporting import save_report
from security import safe_text
from utils import setup_logging


def parser():
    p = argparse.ArgumentParser(
        description="ThreatLens: evidence-aware IOC enrichment (never an automatic blocking tool)."
    )
    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "ioc", nargs="?", help="IP, domain, URL, MD5/SHA1/SHA256, or existing file path"
    )
    group.add_argument(
        "-f", "--file", help="Hash a local file and look up its SHA256; never upload contents"
    )
    group.add_argument("--input", type=Path, help="UTF-8 file containing one IOC per line")
    p.add_argument("--org-config", type=Path, help="Organization IP/CIDR policy JSON")
    p.add_argument(
        "--env-file", type=Path, help="Explicit .env file; default: beside the EXE or ThreatLens.py"
    )
    p.add_argument("--data-dir", type=Path, help="Cache/log directory (default ~/.threatlens)")
    p.add_argument(
        "--report-dir", type=Path, help="Automatic compact TXT reports (default DATA_DIR/reports)"
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit one JSON object per scan on stdout; notices go to stderr",
    )
    p.add_argument(
        "--offline", action="store_true", help="Use fresh cached TI only; no network requests"
    )
    p.add_argument("--no-cache", action="store_true", help="Disable cache reads and writes")
    p.add_argument(
        "--clear-cache", action="store_true", help="Delete local cached entries before scanning"
    )
    p.add_argument(
        "--no-enrichment", action="store_true", help="Skip external cloud/ISP/WHOIS context"
    )
    p.add_argument(
        "--timeout", type=float, default=4, help="Per-request connect/read timeout, 1-60 seconds"
    )
    p.add_argument("--cache-ttl", type=int, default=3600, help="Positive TI cache TTL in seconds")
    p.add_argument(
        "--negative-ttl", type=int, default=300, help="No-hit/not-found cache TTL in seconds"
    )
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if not 1 <= args.timeout <= 60 or args.cache_ttl < 1 or args.negative_ttl < 1:
        parser().error("Timeout must be 1-60 seconds and TTLs must be positive")
    if args.clear_cache and args.no_cache:
        parser().error("--clear-cache cannot be combined with --no-cache")
    try:
        config = load_config(
            args.env_file,
            data_dir=args.data_dir.expanduser() if args.data_dir else None,
            org_file=args.org_config.expanduser() if args.org_config else None,
            timeout=args.timeout,
            cache_ttl=args.cache_ttl,
            negative_ttl=args.negative_ttl,
            offline=args.offline,
            no_cache=args.no_cache,
            enrichment=not args.no_enrichment,
        )
        scanner = Scanner(config)
        setup_logging(config.data_dir)
        if args.clear_cache:
            scanner.cache.clear()
        report_dir = (
            args.report_dir.expanduser() if args.report_dir else config.data_dir / "reports"
        )
    except (OSError, ValueError, TypeError) as exc:
        print("Configuration error: " + safe_text(str(exc)), file=sys.stderr)
        return 1

    def run(value, force_file=False):
        try:
            is_file = force_file
            if not force_file and "://" not in value:
                try:
                    is_file = Path(value).expanduser().is_file()
                except OSError:
                    is_file = False
            with ui.scan_status() if not args.json and ui.console.is_terminal else nullcontext():
                report = scanner.scan(value, file=is_file)
            # Always save before claiming success. Report failure is visible and nonzero.
            path = save_report(report, report_dir)
            if args.json:
                print(json.dumps(report.to_dict(), ensure_ascii=False))
            else:
                ui.display(report, file_path=value if is_file else None)
            print("Report saved: " + str(path), file=sys.stderr)
            return (
                2
                if report.assessment.coverage["errors"]
                or report.assessment.coverage["skipped"]
                or report.assessment.verdict == "UNKNOWN"
                else 0
            )
        except (OSError, ValueError, UnicodeError) as exc:
            message = "Scan error: " + safe_text(str(exc), config.secrets)
            if args.json:
                print(message, file=sys.stderr)
            else:
                ui.print_error(message)
            return 1

    try:
        if not args.json:
            ui.print_banner()
        if args.file or args.ioc:
            return run(args.file or args.ioc, bool(args.file))
        if args.input:
            codes = []
            with args.input.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip() and not line.lstrip().startswith("#"):
                        codes.append(run(line.strip()))
            return 1 if 1 in codes else max(codes, default=0)
        if args.clear_cache:
            print("Cache cleared.", file=sys.stderr)
            return 0
        if args.json or not sys.stdin.isatty():
            parser().error("Supply an IOC, --file or --input for non-interactive use")
        ui.print_ready()
        while True:
            try:
                ui.console.print("[bold cyan]IOC> [/bold cyan]", end="")
                value = input().strip()
            except EOFError:
                break
            if value.lower() in {"exit", "quit", "q"}:
                break
            if not value:
                continue
            if value.startswith("file "):
                path = value[5:].strip().strip('"').strip("'")
                run(path, True)
            else:
                run(value.strip('"').strip("'"))
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except OSError as exc:
        print("Input/report error: " + safe_text(str(exc), config.secrets), file=sys.stderr)
        return 1
