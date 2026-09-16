"""Interactive and scriptable entry points share exactly the same scanner."""

import argparse
import copy
import json
import sys
from contextlib import nullcontext
from pathlib import Path

import ui
from config import VERSION, application_dir, load_config
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
        "--report-dir",
        type=Path,
        help="Daily categorized TXT reports (default beside EXE or script)",
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
        "--timeout", type=float, default=2, help="Per-request connect/read timeout, 1-60 seconds"
    )
    p.add_argument("--cache-ttl", type=int, default=3600, help="Positive TI cache TTL in seconds")
    p.add_argument(
        "--negative-ttl", type=int, default=300, help="No-hit/not-found cache TTL in seconds"
    )
    p.add_argument(
        "--refresh", action="store_true", help="Bypass saved reports and caches for this scan"
    )
    p.add_argument("--use-cache", action="store_false", dest="no_cache", help="Re-enable caching")
    p.add_argument(
        "--enrichment", action="store_false", dest="no_enrichment", help="Re-enable context"
    )
    p.add_argument("--text", action="store_false", dest="json", help="Use the Rich console output")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def validate(args):
    if not 1 <= args.timeout <= 60 or args.cache_ttl < 1 or args.negative_ttl < 1:
        raise ValueError("Timeout must be 1-60 seconds and TTLs must be positive")
    if args.clear_cache and args.no_cache:
        raise ValueError("--clear-cache cannot be combined with --no-cache")
    if args.refresh and args.offline:
        raise ValueError("--refresh cannot be combined with --offline")


class Session:
    """Reusable source transports keep rate limits across interactive commands."""

    def __init__(self):
        self.transports = {}

    def configure(self, args):
        validate(args)
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
        for provider in scanner.providers:
            key = (provider.name, provider.api_key)
            if key in self.transports:
                provider.transport = self.transports[key]
                provider.transport.timeout = config.timeout
            else:
                self.transports[key] = provider.transport
        setup_logging(config.data_dir)
        return config, scanner

    def execute(self, args, configured=None):
        config, scanner = configured or self.configure(args)
        report_dir = args.report_dir.expanduser() if args.report_dir else application_dir()
        if args.clear_cache:
            scanner.cache.clear()
            print(
                "Provider cache cleared; daily journals retained. Use --refresh to bypass them.",
                file=sys.stderr,
            )

        def run(value, force_file=False):
            try:
                is_file = force_file
                if not force_file and "://" not in value:
                    try:
                        is_file = Path(value).expanduser().is_file()
                    except OSError:
                        pass
                with (
                    ui.scan_status() if not args.json and ui.console.is_terminal else nullcontext()
                ):
                    report = scanner.scan(
                        value, file=is_file, report_directory=report_dir, refresh=args.refresh
                    )
                path = save_report(report, report_dir)
                if args.json:
                    print(json.dumps(report.to_dict(), ensure_ascii=False))
                else:
                    ui.display(report, file_path=value if is_file else None)
                label = "Today's report reused" if report.reused else "Report saved"
                print(label + ": " + str(path), file=sys.stderr)
                return (
                    2
                    if report.assessment.coverage["errors"]
                    or report.assessment.coverage["skipped"]
                    or report.assessment.verdict == "UNKNOWN"
                    else 0
                )
            except (OSError, ValueError, UnicodeError, TimeoutError) as exc:
                message = "Scan error: " + safe_text(str(exc), config.secrets)
                if args.json:
                    print(message, file=sys.stderr)
                else:
                    ui.print_error(message)
                return 1

        if args.ioc or args.file:
            return run(args.file or args.ioc, bool(args.file))
        if args.input:
            codes = []
            with args.input.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip() and not line.lstrip().startswith("#"):
                        codes.append(run(line.strip()))
            return 1 if 1 in codes else max(codes, default=0)
        return 0


def split_command(line):
    """Whitespace and quoted arguments, preserving literal Windows backslashes.

    This is an argument parser, not a shell: no expansion or command execution.
    """
    tokens, current, quote = [], [], None
    for char in line:
        if quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in {'"', "'"}:
            quote = char
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if quote:
        raise ValueError("Unclosed quote in command")
    if current:
        tokens.append("".join(current))
    return tokens


def main(argv=None):
    args = parser().parse_args(argv)
    session = Session()
    try:
        configured = session.configure(args)
        if not args.json:
            ui.print_banner()
        if args.ioc or args.file or args.input or args.clear_cache:
            return session.execute(args, configured)
        if args.refresh:
            parser().error("Supply an IOC, --file or --input with --refresh")
        if args.json or not sys.stdin.isatty():
            parser().error("Supply an IOC, --file or --input for non-interactive use")
        ui.print_ready()
        defaults = copy.copy(args)
        while True:
            try:
                ui.console.print("[bold cyan]IOC> [/bold cyan]", end="")
                line = input().strip()
            except EOFError:
                break
            if line.lower() in {"exit", "quit", "q"}:
                break
            if not line:
                continue
            try:
                # Preserve convenient unquoted file paths when the whole line is a file.
                try:
                    whole_file = Path(line.strip('"').strip("'")).expanduser().is_file()
                except OSError:
                    whole_file = False
                if line.startswith("file "):
                    tokens = ["--file", line[5:].strip().strip('"').strip("'")]
                elif whole_file:
                    tokens = ["--file", line.strip('"').strip("'")]
                else:
                    tokens = split_command(line)
                command = parser().parse_args(tokens, namespace=copy.copy(defaults))
                validate(command)
                if command.ioc or command.file or command.input or command.clear_cache:
                    session.execute(command)
                elif command.refresh:
                    raise ValueError("Supply an IOC, --file or --input with --refresh")
                else:
                    session.configure(command)
                    defaults = command
                    ui.console.print("[bold green]Session settings updated.[/bold green]")
            except SystemExit:
                # argparse help/version and errors must not terminate the REPL.
                continue
            except (ValueError, OSError, TypeError, TimeoutError) as exc:
                ui.print_error(safe_text(str(exc)))
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except (OSError, ValueError, TypeError, TimeoutError) as exc:
        print("Configuration/input error: " + safe_text(str(exc)), file=sys.stderr)
        return 1
