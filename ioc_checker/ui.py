"""
ui.py

Terminal Presentation Layer
---------------------------
Author: Amirhossein Mousavi

Description:
Handles all visual output and terminal rendering using the 'Rich' library. It abstracts 
the complexity of drawing tables, dynamic progress spinners, gradient banners, and 
color-coded risk assessments. This module ensures the analyst receives data in a clean, 
highly readable, and visually prioritized format.
"""

from __future__ import annotations

import re
from datetime import datetime

import pyfiglet
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from config import VERSION
from detector import IOCType
from utils import FileHashes, ProviderResult, Verdict

console = Console()

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_FONT = "ansi_shadow"
_BANNER_TEXT = "IOC CHECKER"

# Endpoints of the red -> blue cyberpunk gradient (RGB)
_GRADIENT_START = (255, 30, 60)     # crimson red
_GRADIENT_END = (40, 90, 255)       # electric blue


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def _gradient_color(t: float) -> str:
    r = _lerp(_GRADIENT_START[0], _GRADIENT_END[0], t)
    g = _lerp(_GRADIENT_START[1], _GRADIENT_END[1], t)
    b = _lerp(_GRADIENT_START[2], _GRADIENT_END[2], t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _render_gradient_banner(figlet_text: str) -> Text:
    """Apply a left-to-right red -> blue gradient across the figlet art."""
    lines = figlet_text.rstrip("\n").split("\n")
    width = max((len(line) for line in lines), default=1) or 1

    banner = Text()
    for i, line in enumerate(lines):
        for col, char in enumerate(line):
            if char == " ":
                banner.append(" ")
                continue
            t = col / max(width - 1, 1)
            banner.append(char, style=f"bold {_gradient_color(t)}")
        if i != len(lines) - 1:
            banner.append("\n")
    return banner


def print_banner() -> None:
    panel_overhead = 6
    figlet_width = max(console.width - panel_overhead, 40)

    try:
        figlet_text = pyfiglet.figlet_format(_BANNER_TEXT, font=_BANNER_FONT, width=figlet_width)
    except pyfiglet.FontNotFound:
        figlet_text = pyfiglet.figlet_format(_BANNER_TEXT, width=figlet_width)

    banner_text = _render_gradient_banner(figlet_text)
    banner_text.no_wrap = True
    banner_text.overflow = "crop"

    subtitle = Text()
    subtitle.append("THREAT INTELLIGENCE AGGREGATOR CLI\n", style="bold bright_white")
    subtitle.append("Multi-Provider IOC Reputation Checker\n", style="italic bright_black")
    subtitle.append(f"Version {VERSION}\n\n", style="dim")

    # Provider Information
    subtitle.append("Provided by Amirhossein Mousavi\n", style="bold green")
    subtitle.append("LinkedIn: https://linkedin.com/in/amirhossein-mousavi-877685359/\n", style="blue")
    subtitle.append("GitHub: https://github.com/AmirHo3ein138", style="cyan")
    # -----------------------------------------------------------------

    console.print(
        Panel(
            Align.center(banner_text),
            border_style="blue",
            padding=(1, 2),
        )
    )
    console.print(Align.center(subtitle))
    console.print()


VERDICT_STYLES = {
    Verdict.MALICIOUS: "bold red",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.CLEAN: "bold green",
    Verdict.FOUND: "bold red",
    Verdict.NOT_FOUND: "bold green",
    Verdict.ERROR: "bold magenta",
    Verdict.UNSUPPORTED: "dim",
}


# ---------------------------------------------------------------------------
# IOC Information
# ---------------------------------------------------------------------------

def print_ioc_info(ioc: str, ioc_type: IOCType) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold cyan", min_width=16)
    table.add_column(justify="left", style="bold white")

    table.add_row("IOC", ioc)
    table.add_row("IOC Type", ioc_type.value)
    table.add_row("IOC Length", f"{len(ioc)} characters")
    table.add_row("Timestamp", timestamp)

    console.print(
        Panel(
            table,
            title="[bold white]IOC INFORMATION[/bold white]",
            title_align="left",
            border_style="blue",
            padding=(1, 2),
        )
    )
    console.print()


def _human_readable_size(num_bytes: int) -> str:
    """
    Format a byte count as a human-readable string (e.g. '2.14 MB').

    Uses binary (1024-based) units and falls back to the largest available
    unit for very large files.
    """
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    # Unreachable, but keeps type checkers satisfied.
    return f"{num_bytes} B"


def print_file_info(path: str, hashes: FileHashes) -> None:
    """
    Render the FILE INFORMATION panel shown before any provider output
    when the user scans a local file with -f/--file.

    Displays the filename, full path, human-readable size, and the three
    calculated digests (MD5, SHA1, SHA256).
    """
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold cyan", min_width=10)
    table.add_column(justify="left", style="bold white", overflow="fold")

    table.add_row("Filename", hashes["filename"])
    table.add_row("Path", path)
    table.add_row("Size", _human_readable_size(hashes["size"]))
    table.add_row("MD5", hashes["md5"])
    table.add_row("SHA1", hashes["sha1"])
    table.add_row("SHA256", hashes["sha256"])

    console.print(
        Panel(
            table,
            title="[bold white]FILE INFORMATION[/bold white]",
            title_align="left",
            border_style="blue",
            padding=(1, 2),
        )
    )
    console.print()


def print_file_error(path: str, message: str) -> None:
    """Render an error panel when a supplied file cannot be read/hashed."""
    console.print(
        Panel(
            f"[bold red]Could not process file:[/bold red] {path}\n{message}",
            title="File Error",
            border_style="red",
        )
    )


def print_unsupported_ioc(ioc: str) -> None:
    console.print(
        Panel(
            f"[bold red]Could not classify IOC:[/bold red] {ioc}\n"
            "Supported types: IPv4, Domain, URL, MD5, SHA1, SHA256",
            title="Unsupported IOC",
            border_style="red",
        )
    )

# ---------------------------------------------------------------------------
# Context & Enrichment
# ---------------------------------------------------------------------------

def print_cdn_warning(cdn_name: str) -> None:
    console.print(
        Panel(
            f"[bold white]This IP belongs to the infrastructure of [/bold white][bold yellow]{cdn_name}[/bold yellow].\n"
            "[bold white]You are scanning a CDN/WAF. You must find the true origin IP for accurate assessment![/bold white]",
            title="[blink bold red]⚠ CDN DETECTED ⚠[/blink bold red]",
            border_style="red",
            style="on bright_red"
        )
    )
    console.print()

from rich.console import Group # این را بالای فایل کنار بقیه ایمپورت‌های rich اضافه کن

def print_enrichment_info(data: dict, title: str, is_cloud: bool, error: str | None) -> None:
    if error:
        console.print(
            Panel(
                f"[bold red]Failed to retrieve context:[/bold red] {error}",
                title=f"[bold white]{title}[/bold white]",
                border_style="red"
            )
        )
        console.print()
        return

    if not data:
        return

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold cyan", min_width=16)
    table.add_column(justify="left", style="bold white")

    for key, value in data.items():
        table.add_row(key, str(value))

    panel_content = [table]
    if is_cloud:
        panel_content.append(Text(""))
        panel_content.append(Text("Atention!! This IP blongs to Cloud Provider", style="bold yellow blink"))

    console.print(
        Panel(
            Group(*panel_content),
            title=f"[bold white]{title}[/bold white]",
            title_align="left",
            border_style="magenta",
            padding=(1, 2),
        )
    )
    console.print()

    
# ---------------------------------------------------------------------------
# Scanning (transient progress bar, removed once the scan completes)
# ---------------------------------------------------------------------------

def create_scan_progress(total: int) -> Progress:
    """
    Build a transient Rich Progress instance for the scanning phase.
    'transient=True' means the progress display is cleared from the
    terminal as soon as the `with` block exits, leaving only the final
    report behind.
    """
    return Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold cyan]Scanning IOC...[/bold cyan]"),
        TextColumn("[white]{task.fields[detail]}[/white]"),
        console=console,
        transient=True,
    )


# ---------------------------------------------------------------------------
# Scan Results
# ---------------------------------------------------------------------------

_VT_PCT_RE = re.compile(r"\(([\d.]+)%\)")
_OTX_PULSE_RE = re.compile(r"Threat Pulses:\s*(\d+)")
_TF_CONFIDENCE_RE = re.compile(r"Confidence:\s*(\d+)(?!%)")
_GENERIC_CONFIDENCE_RE = re.compile(r"Confidence:\s*([\d.]+)%")
_GENERIC_CONFIDENCE_NA_RE = re.compile(r"Confidence:\s*N/A", re.IGNORECASE)

_OTX_CONFIDENCE_STYLES = {
    "NONE": "dim white",
    "LOW": "yellow",
    "MEDIUM": "bright_yellow",
    "HIGH": "bright_red",
}

# Pulsedive returns a categorical risk level rather than a numeric score, so
# its Confidence column shows a qualitative label (matching the OTX approach)
# instead of a fabricated percentage.
_PULSEDIVE_RISK_RE = re.compile(r"Risk:\s*(\w+)", re.IGNORECASE)
_PULSEDIVE_CONFIDENCE_STYLES = {
    "CRITICAL": "bright_red",
    "HIGH": "bright_red",
    "MEDIUM": "bright_yellow",
    "LOW": "yellow",
    "NONE": "dim white",
    "RETIRED": "dim white",
    "UNKNOWN": "dim white",
}


def _otx_pulse_count(details: str) -> int:
    """Extract the pulse count from OTX details text (0 if none found)."""
    match = _OTX_PULSE_RE.search(details)
    if match:
        return int(match.group(1))
    return 0


def _otx_confidence_label(pulse_count: int) -> str:
    """Map an OTX pulse count to a qualitative confidence label."""
    if pulse_count == 0:
        return "NONE"
    if pulse_count <= 2:
        return "LOW"
    if pulse_count <= 5:
        return "MEDIUM"
    return "HIGH"


def _pulsedive_confidence_label(details: str) -> str:
    """Extract Pulsedive's risk level from its details as an upper-case label."""
    match = _PULSEDIVE_RISK_RE.search(details)
    if match:
        return match.group(1).upper()
    return "UNKNOWN"


def _extract_confidence(result: ProviderResult) -> Text:
    """Derive a Confidence column value from a provider's details text."""
    if result.verdict in (Verdict.ERROR, Verdict.UNSUPPORTED, Verdict.NOT_FOUND):
        return Text("--", style="bold cyan", justify="center")

    if result.provider == "VirusTotal":
        match = _VT_PCT_RE.search(result.details)
        value = f"{match.group(1)}%" if match else "--"
        return Text(value, style="bold cyan", justify="center")

    if result.provider == "ThreatFox":
        match = _TF_CONFIDENCE_RE.search(result.details)
        value = f"{match.group(1)}%" if match else "--"
        return Text(value, style="bold cyan", justify="center")

    if result.provider == "AlienVault OTX":
        # OTX has no native confidence percentage; map pulse count to a
        # qualitative label instead of inventing a numeric value.
        pulse_count = _otx_pulse_count(result.details)
        label = _otx_confidence_label(pulse_count)
        style = _OTX_CONFIDENCE_STYLES.get(label, "white")
        return Text(label, style=f"bold {style}", justify="center")

    if result.provider == "Pulsedive":
        # Pulsedive reports a categorical risk level, not a percentage, so
        # surface that level as the confidence label (coloured by severity).
        label = _pulsedive_confidence_label(result.details)
        style = _PULSEDIVE_CONFIDENCE_STYLES.get(label, "white")
        return Text(label, style=f"bold {style}", justify="center")

    # Generic path: AbuseIPDB, URLhaus, MalwareBazaar, and
    # any future provider that includes an explicit "Confidence: X%" (or
    # "Confidence: N/A") line in its details text.
    if _GENERIC_CONFIDENCE_NA_RE.search(result.details):
        return Text("N/A", style="bold cyan", justify="center")

    match = _GENERIC_CONFIDENCE_RE.search(result.details)
    if match:
        return Text(f"{match.group(1)}%", style="bold cyan", justify="center")

    return Text("--", style="bold cyan", justify="center")


def _clean_details(result: ProviderResult) -> str:
    """Strip redundant percentage info from details now shown in Confidence."""
    if result.provider == "VirusTotal":
        return _VT_PCT_RE.sub("", result.details).replace("()", "").strip()
    return result.details


def print_results_table(results: list[ProviderResult]) -> None:
    table = Table(
        title="[bold cyan]SCAN RESULTS[/bold cyan]",
        title_justify="left",
        header_style="bold cyan",
        border_style="blue",
        show_lines=True,
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("PROVIDER", style="bold white", no_wrap=True)
    table.add_column("VERDICT", justify="center", no_wrap=True)
    table.add_column("CONFIDENCE", justify="center", no_wrap=True)
    table.add_column("DETAILS", overflow="fold")

    for result in results:
        style = VERDICT_STYLES.get(result.verdict, "white")
        table.add_row(
            result.provider,
            Text(result.verdict.value, style=style, justify="center"),
            _extract_confidence(result),
            _clean_details(result),
        )

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Summary / Overall Assessment
# ---------------------------------------------------------------------------

_ASSESSMENT_STYLES = {
    "CLEAN": "bold green",
    "SUSPICIOUS": "bold yellow",
    "HIGH RISK": "bold red",
}


def _big_verdict(overall_verdict: str, style: str) -> Text:
    try:
        figlet_text = pyfiglet.figlet_format(overall_verdict, font="big", width=100)
    except pyfiglet.FontNotFound:
        figlet_text = pyfiglet.figlet_format(overall_verdict, width=100)
    return Text(figlet_text.rstrip("\n"), style=style)


def print_summary(
    risk_score: int,
    overall_verdict: str,
    sources_hit: int,
    total_sources: int,
    recommendation: list[str],
    ioc_type: IOCType | None = None,
) -> None:
    verdict_style = _ASSESSMENT_STYLES.get(overall_verdict, "white")

    info = Table.grid(padding=(0, 2))
    info.add_column(justify="left", style="bold cyan", min_width=18)
    info.add_column(justify="left")

    info.add_row("Overall Risk Score", f"[bold white]{risk_score}/100[/bold white]")
    info.add_row("Sources Queried", f"[bold white]{total_sources}[/bold white]")
    info.add_row("Sources Matched", f"[bold white]{sources_hit}/{total_sources}[/bold white]")
    if ioc_type is not None:
        info.add_row("IOC Type", f"[bold white]{ioc_type.value}[/bold white]")

    rec_lines = "\n".join(f"[white]•[/white] {item}" for item in recommendation)

    body_parts = [
        Align.center(_big_verdict(overall_verdict, verdict_style)),
        Text(""),
        info,
        Text(""),
        Text("Recommendation", style="bold cyan"),
        Text.from_markup(rec_lines),
    ]

    grid = Table.grid()
    grid.add_column()
    for part in body_parts:
        grid.add_row(part)

    console.print(
        Panel(
            grid,
            title="[bold white]OVERALL ASSESSMENT[/bold white]",
            title_align="left",
            border_style=verdict_style,
            padding=(1, 2),
        )
    )


# ---------------------------------------------------------------------------
# Warnings (replaces the old API Status panel - only shown when needed)
# ---------------------------------------------------------------------------

def print_warnings(results: list[ProviderResult]) -> None:
    """
    Print a compact warnings section listing only the providers that
    errored out during this scan. If every provider succeeded, this
    prints nothing at all.
    """
    failed = [r for r in results if r.verdict == Verdict.ERROR]
    if not failed:
        return

    lines = []
    for result in failed:
        # Details may be multi-line (e.g. "HTTP 401\nInvalid API Key");
        # collapse to a single readable bullet line.
        first_line = result.details.splitlines()[0] if result.details else "Unknown error"
        lines.append(f"[bold yellow]•[/bold yellow] [bold white]{result.provider}[/bold white] : {first_line}")

    body = "\n".join(lines)
    console.print(
        Panel(
            body,
            title="[bold yellow]⚠ API WARNINGS[/bold yellow]",
            title_align="left",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def print_footer(elapsed_seconds: float, provider_names: list[str]) -> None:
    console.print()
    footer = Text()
    footer.append(f"Execution Time: {elapsed_seconds:.2f}s", style="bright_black")
    footer.append("\n")
    footer.append("Powered by: ", style="bright_black")
    footer.append(" | ".join(provider_names), style="bold cyan")
    console.print(Align.center(footer))
