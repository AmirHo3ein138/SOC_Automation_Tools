"""Original Stealth presentation adapted to the current report contracts.

External values are always literal Text, never executable Rich markup.
"""

from config import VERSION
from models import Verdict
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from security import safe_text
from ui_art import BANNER, VERDICTS

console = Console()
VERDICT_STYLES = {
    "MALICIOUS": "bold red3",
    "FOUND": "bold red3",
    "HIGH_RISK": "bold red3",
    "SUSPICIOUS": "bold dark_orange",
    "NO_HIT": "bold spring_green3",
    "NOT_FOUND": "bold spring_green3",
    "NO_KNOWN_THREAT": "bold spring_green3",
    "ERROR": "bold magenta",
    "SKIPPED": "dim",
    "UNSUPPORTED": "dim",
    "INCONCLUSIVE": "bold dark_orange",
    "UNKNOWN": "bold magenta",
}


def literal(value, style="grey84"):
    return Text(safe_text(str(value)), style=style, overflow="fold")


def panel(body, title, border="dodger_blue2"):
    console.print(
        Panel(
            body,
            title=Text(title, style="bold grey84"),
            title_align="left",
            border_style=border,
            padding=(1, 2),
            box=box.ROUNDED,
        )
    )
    console.print()


def grid(rows):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold steel_blue1")
    table.add_column(overflow="fold")
    for key, value in rows:
        table.add_row(literal(key, "bold steel_blue1"), literal(value))
    return table


def print_banner():
    width = max(map(len, BANNER.splitlines()))
    banner = Text()
    if width > console.width - 6:
        banner = Text("THREATLENS", style="bold cyan")
    else:
        for line in BANNER.splitlines():
            for col, char in enumerate(line):
                t = col / max(width - 1, 1)
                color = f"#{int(138 * t):02x}{int(255 - 212 * t):02x}{int(255 - 29 * t):02x}"
                banner.append(char, style="bold " + color)
            banner.append("\n")
        banner.rstrip()
    console.print(
        Panel(Align.center(banner), border_style="deep_sky_blue4", padding=(1, 2), box=box.ROUNDED)
    )
    subtitle = Text("THREAT INTELLIGENCE AGGREGATOR CLI\n", style="bold grey84")
    subtitle.append("Multi-Provider IOC Reputation Checker\n", style="italic bright_black")
    subtitle.append(f"Version {VERSION}\n\n", style="dim")
    subtitle.append("Provided by Amirhossein Mousavi\n", style="bold spring_green3")
    subtitle.append(
        "LinkedIn: https://linkedin.com/in/amirhossein-mousavi-877685359/\n", style="steel_blue1"
    )
    subtitle.append("GitHub: https://github.com/AmirHo3ein138", style="dodger_blue2")
    console.print(Align.center(subtitle))
    console.print()


def print_ready():
    console.print("[bold green]Ready.[/bold green] Enter IOC or file path.")
    console.print("[dim]IPv4 / IPv6, Domain, URL, MD5, SHA1, SHA256, or file PATH.[/dim]")
    console.print(
        "Type [bold yellow]'exit'[/bold yellow] or [bold yellow]'quit'[/bold yellow] to close.\n"
    )


def scan_status():
    return console.status(
        "[bold dodger_blue2]Scanning IOC...[/bold dodger_blue2] [grey84]Collecting evidence and context[/grey84]",
        spinner="bouncingBar",
        spinner_style="bold dodger_blue2",
    )


def confidence(result):
    """Native provider metric, not an invented cross-provider probability."""
    e = result.evidence
    if result.verdict in {Verdict.ERROR, Verdict.SKIPPED, Verdict.UNSUPPORTED, Verdict.NOT_FOUND}:
        return "--"
    if result.provider == "VirusTotal" and e.get("total"):
        return f"{100 * e.get('malicious', 0) / e['total']:.1f}% detections"
    if result.provider == "AbuseIPDB" and "abuse_score" in e:
        return f"{e['abuse_score']}% abuse"
    if result.provider == "ThreatFox" and "confidence" in e:
        return f"{e['confidence']}%"
    if result.provider == "AlienVault OTX" and "pulses" in e:
        return f"{e['pulses']} pulses"
    if "risk" in e:
        return str(e["risk"]).upper()
    if "status" in e:
        return str(e["status"]).upper()
    if e.get("exact_sample"):
        return "Exact match"
    return "--"


def print_context(context):
    if context.organization:
        panel(grid(context.organization.items()), "ORGANIZATION / APN POLICY", "dark_orange")
    if context.address:
        panel(
            grid(
                [
                    ("Address", context.address),
                    ("Network", context.category),
                    ("Country", context.country_code or "Unknown"),
                    ("ISP", context.isp or "Unknown"),
                    ("ASN", context.asn or "Unknown"),
                    ("Protected asset", "Yes" if context.protected else "No"),
                    ("External lookups", "Allowed" if context.external_allowed else "Disabled"),
                ]
            ),
            "IP CONTEXT",
            "magenta",
        )
    if context.infrastructure:
        panel(literal(" | ".join(context.infrastructure)), "CLOUD / CDN DETECTED", "dark_orange")
    whois = context.metadata.get("whois", {})
    if whois.get("data"):
        panel(grid(whois["data"].items()), "DOMAIN WHOIS", "magenta")
    if context.warnings:
        panel(
            Group(*(literal("• " + w, "dark_orange") for w in context.warnings)),
            "CONTEXT & POLICY NOTICES",
            "dark_orange",
        )


def print_error(message):
    Console(stderr=True).print(
        Panel(
            literal(message, "bold red3"), title="SCAN ERROR", border_style="red3", box=box.ROUNDED
        )
    )


def display(report, file_path=None):
    if report.file_info:
        rows = [("Filename", report.file_info["filename"])]
        if file_path is not None:
            rows.append(("Path", file_path))
        size = float(report.file_info["size"])
        for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
            if size < 1024 or unit == "PB":
                break
            size /= 1024
        rows.append(("Size", f"{size:g} {unit}"))
        rows.extend((key.upper(), report.file_info[key]) for key in ("md5", "sha1", "sha256"))
        panel(grid(rows), "FILE INFORMATION")
    panel(
        grid(
            [
                ("IOC", report.ioc),
                ("IOC Type", report.ioc_type),
                ("IOC Length", f"{len(report.ioc)} characters"),
                ("Timestamp", report.created_at),
            ]
        ),
        "IOC INFORMATION",
    )
    print_context(report.context)
    table = Table(
        title="SCAN RESULTS",
        title_style="bold dodger_blue2",
        title_justify="left",
        header_style="bold steel_blue1",
        border_style="deep_sky_blue4",
        show_lines=True,
        padding=(0, 1),
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("PROVIDER", style="bold grey84")
    table.add_column("VERDICT", justify="center")
    table.add_column("CONFIDENCE / SIGNAL", justify="center")
    table.add_column("DETAILS", overflow="fold", ratio=3)
    for result in report.results:
        details = result.details
        if result.cached:
            details = "[CACHE] " + details
        table.add_row(
            literal(result.provider, "bold grey84"),
            literal(result.verdict.value.replace("_", " "), VERDICT_STYLES[result.verdict.value]),
            literal(confidence(result), "bold steel_blue1"),
            literal(details),
        )
    console.print(table)
    console.print()
    a = report.assessment
    style = VERDICT_STYLES[a.verdict]
    label = a.verdict.replace("_", " ")
    art = VERDICTS[label]
    if max(map(len, art.splitlines())) > console.width - 6:
        art = label
    cov = a.coverage
    rows = [
        ("Overall Risk Score", "N/A" if a.score is None else f"{a.score}/100"),
        ("Score Meaning", "Heuristic evidence score; not a probability"),
        ("Sources Applicable", cov["applicable"]),
        ("Sources Successful", f"{cov['successful']}/{cov['applicable']}"),
        ("Sources Matched", cov["positive"]),
        ("Errors / Skipped", f"{cov['errors']} / {cov['skipped']}"),
        ("Cached Results", cov["cached"]),
        ("IOC Type", report.ioc_type),
    ]
    panel(
        Group(
            Align.center(Text(art, style=style)),
            Text(""),
            grid(rows),
            Text(""),
            Text("Recommendation", style="bold dodger_blue2"),
            *(literal("• " + item) for item in a.recommendations),
        ),
        "OVERALL ASSESSMENT",
        style,
    )
    failed = [r for r in report.results if r.verdict in {Verdict.ERROR, Verdict.SKIPPED}]
    if failed:
        panel(
            Group(*(literal(f"• {r.provider}: {r.details}") for r in failed)),
            "API WARNINGS",
            "dark_orange",
        )
    footer = Text(f"Execution Time: {report.elapsed_seconds:.2f}s\n", style="bright_black")
    footer.append("Powered by: ", style="bright_black")
    footer.append(
        " | ".join(safe_text(r.provider) for r in report.results), style="bold steel_blue1"
    )
    console.print(Align.center(footer))
    console.print()
