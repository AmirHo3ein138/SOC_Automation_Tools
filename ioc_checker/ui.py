"""
ui.py

Terminal Presentation Layer (ThreatLens)
----------------------------------------
Author: Amirhossein Mousavi

Description:
Handles all visual output and terminal rendering using the 'Rich' library. It abstracts 
the complexity of drawing tables, dynamic progress spinners, gradient banners, and 
color-coded risk assessments. This module ensures the analyst receives data in a clean, 
highly readable, and visually prioritized format using the 'Stealth' color scheme.
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
from rich.console import Group
from rich import box  # Added for better table styling

from config import VERSION
from detector import IOCType
from utils import FileHashes, ProviderResult, Verdict

console = Console()

# ---------------------------------------------------------------------------
# Banner (ThreatLens Theme)
# ---------------------------------------------------------------------------

_BANNER_FONT = "ansi_shadow"
_BANNER_TEXT = "THREATLENS"

_GRADIENT_START = (0, 255, 255)   
_GRADIENT_END = (138, 43, 226)     


def _lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)


def _gradient_color(t: float) -> str:
    r = _lerp(_GRADIENT_START[0], _GRADIENT_END[0], t)
    g = _lerp(_GRADIENT_START[1], _GRADIENT_END[1], t)
    b = _lerp(_GRADIENT_START[2], _GRADIENT_END[2], t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _render_gradient_banner(figlet_text: str) -> Text:
    """Apply a left-to-right Stealth gradient across the figlet art."""
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
    subtitle.append("THREAT INTELLIGENCE AGGREGATOR CLI\n", style="bold grey84")
    subtitle.append("Multi-Provider IOC Reputation Checker\n", style="italic bright_black")
    subtitle.append(f"Version {VERSION}\n\n", style="dim")

    # Provider Information
    subtitle.append("Provided by Amirhossein Mousavi\n", style="bold spring_green3")
    subtitle.append("LinkedIn: https://linkedin.com/in/amirhossein-mousavi-877685359/\n", style="steel_blue1")
    subtitle.append("GitHub: https://github.com/AmirHo3ein138", style="dodger_blue2")
    # -----------------------------------------------------------------

    console.print(
        Panel(
            Align.center(banner_text),
            border_style="deep_sky_blue4",
            padding=(1, 2),
            box=box.ROUNDED
        )
    )
    console.print(Align.center(subtitle))
    console.print()


VERDICT_STYLES = {
    Verdict.MALICIOUS: "bold red3",
    Verdict.SUSPICIOUS: "bold dark_orange",
    Verdict.CLEAN: "bold spring_green3",
    Verdict.FOUND: "bold red3",
    Verdict.NOT_FOUND: "bold spring_green3",
    Verdict.ERROR: "bold magenta",
    Verdict.UNSUPPORTED: "dim",
}


# ---------------------------------------------------------------------------
# IOC Information
# ---------------------------------------------------------------------------

def print_ioc_info(ioc: str, ioc_type: IOCType) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold steel_blue1", min_width=16)
    table.add_column(justify="left", style="bold grey84")

    table.add_row("IOC", ioc)
    table.add_row("IOC Type", ioc_type.value)
    table.add_row("IOC Length", f"{len(ioc)} characters")
    table.add_row("Timestamp", timestamp)

    console.print(
        Panel(
            table,
            title="[bold grey84]IOC INFORMATION[/bold grey84]",
            title_align="left",
            border_style="dodger_blue2",
            padding=(1, 2),
            box=box.ROUNDED
        )
    )
    console.print()


def _human_readable_size(num_bytes: int) -> str:
    """
    Format a byte count as a human-readable string (e.g. '2.14 MB').
    """
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{num_bytes} B"


def print_file_info(path: str, hashes: FileHashes) -> None:
    """
    Render the FILE INFORMATION panel shown before any provider output
    when the user scans a local file with -f/--file.
    """
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold steel_blue1", min_width=10)
    table.add_column(justify="left", style="bold grey84", overflow="fold")

    table.add_row("Filename", hashes["filename"])
    table.add_row("Path", path)
    table.add_row("Size", _human_readable_size(hashes["size"]))
    table.add_row("MD5", hashes["md5"])
    table.add_row("SHA1", hashes["sha1"])
    table.add_row("SHA256", hashes["sha256"])

    console.print(
        Panel(
            table,
            title="[bold grey84]FILE INFORMATION[/bold grey84]",
            title_align="left",
            border_style="dodger_blue2",
            padding=(1, 2),
            box=box.ROUNDED
        )
    )
    console.print()


def print_file_error(path: str, message: str) -> None:
    """Render an error panel when a supplied file cannot be read/hashed."""
    console.print(
        Panel(
            f"[bold red3]Could not process file:[/bold red3] {path}\n{message}",
            title="File Error",
            border_style="red3",
            box=box.ROUNDED
        )
    )


def print_unsupported_ioc(ioc: str) -> None:
    console.print(
        Panel(
            f"[bold red3]Could not classify IOC:[/bold red3] {ioc}\n"
            "Supported types: IPv4, Domain, URL, MD5, SHA1, SHA256",
            title="Unsupported IOC",
            border_style="red3",
            box=box.ROUNDED
        )
    )

# ---------------------------------------------------------------------------
# Context & Enrichment
# ---------------------------------------------------------------------------

def print_cdn_warning(cdn_name: str) -> None:
    console.print(
        Panel(
            f"[bold grey84]This IP belongs to the infrastructure of [/bold grey84][bold dark_orange]{cdn_name}[/bold dark_orange].\n"
            "[bold grey84]You are scanning a CDN/WAF. You must find the true origin IP for accurate assessment![/bold grey84]",
            title="[blink bold red3]⚠ CDN DETECTED ⚠[/blink bold red3]",
            border_style="red3",
            style="on bright_black",
            box=box.ROUNDED
        )
    )
    console.print()


def print_enrichment_info(data: dict, title: str, is_cloud: bool, error: str | None) -> None:
    if error:
        console.print(
            Panel(
                f"[bold red3]Failed to retrieve context:[/bold red3] {error}",
                title=f"[bold grey84]{title}[/bold grey84]",
                border_style="red3",
                box=box.ROUNDED
            )
        )
        console.print()
        return

    if not data:
        return

    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style="bold steel_blue1", min_width=16)
    table.add_column(justify="left", style="bold grey84")

    for key, value in data.items():
        table.add_row(key, str(value))

    panel_content = [table]
    if is_cloud:
        panel_content.append(Text(""))
        panel_content.append(Text("Attention!! This IP/Domain belongs to a Cloud Provider", style="bold dark_orange blink"))

    console.print(
        Panel(
            Group(*panel_content),
            title=f"[bold grey84]{title}[/bold grey84]",
            title_align="left",
            border_style="magenta",
            padding=(1, 2),
            box=box.ROUNDED
        )
    )
    console.print()

    
# ---------------------------------------------------------------------------
# Scanning (transient progress bar, removed once the scan completes)
# ---------------------------------------------------------------------------

def create_scan_progress(total: int) -> Progress:
    """
    Build a transient Rich Progress instance for the scanning phase.
    """
    return Progress(
        SpinnerColumn(spinner_name="bouncingBar", style="bold dodger_blue2"),
        TextColumn("[bold dodger_blue2]Scanning IOC...[/bold dodger_blue2]"),
        TextColumn("[grey84]{task.fields[detail]}[/grey84]"),
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
    "NONE": "dim grey84",
    "LOW": "yellow",
    "MEDIUM": "dark_orange",
    "HIGH": "red3",
}

_PULSEDIVE_RISK_RE = re.compile(r"Risk:\s*(\w+)", re.IGNORECASE)
_PULSEDIVE_CONFIDENCE_STYLES = {
    "CRITICAL": "red3",
    "HIGH": "red3",
    "MEDIUM": "dark_orange",
    "LOW": "yellow",
    "NONE": "dim grey84",
    "RETIRED": "dim grey84",
    "UNKNOWN": "dim grey84",
}


def _otx_pulse_count(details: str) -> int:
    match = _OTX_PULSE_RE.search(details)
    if match:
        return int(match.group(1))
    return 0


def _otx_confidence_label(pulse_count: int) -> str:
    if pulse_count == 0:
        return "NONE"
    if pulse_count <= 2:
        return "LOW"
    if pulse_count <= 5:
        return "MEDIUM"
    return "HIGH"


def _pulsedive_confidence_label(details: str) -> str:
    match = _PULSEDIVE_RISK_RE.search(details)
    if match:
        return match.group(1).upper()
    return "UNKNOWN"


def _extract_confidence(result: ProviderResult) -> Text:
    if result.verdict in (Verdict.ERROR, Verdict.UNSUPPORTED, Verdict.NOT_FOUND):
        return Text("--", style="bold steel_blue1", justify="center")

    if result.provider == "VirusTotal":
        match = _VT_PCT_RE.search(result.details)
        value = f"{match.group(1)}%" if match else "--"
        return Text(value, style="bold steel_blue1", justify="center")

    if result.provider == "ThreatFox":
        match = _TF_CONFIDENCE_RE.search(result.details)
        value = f"{match.group(1)}%" if match else "--"
        return Text(value, style="bold steel_blue1", justify="center")

    if result.provider == "AlienVault OTX":
        pulse_count = _otx_pulse_count(result.details)
        label = _otx_confidence_label(pulse_count)
        style = _OTX_CONFIDENCE_STYLES.get(label, "grey84")
        return Text(label, style=f"bold {style}", justify="center")

    if result.provider == "Pulsedive":
        label = _pulsedive_confidence_label(result.details)
        style = _PULSEDIVE_CONFIDENCE_STYLES.get(label, "grey84")
        return Text(label, style=f"bold {style}", justify="center")

    if _GENERIC_CONFIDENCE_NA_RE.search(result.details):
        return Text("N/A", style="bold steel_blue1", justify="center")

    match = _GENERIC_CONFIDENCE_RE.search(result.details)
    if match:
        return Text(f"{match.group(1)}%", style="bold steel_blue1", justify="center")

    return Text("--", style="bold steel_blue1", justify="center")


def _clean_details(result: ProviderResult) -> str:
    if result.provider == "VirusTotal":
        return _VT_PCT_RE.sub("", result.details).replace("()", "").strip()
    return result.details


def print_results_table(results: list[ProviderResult]) -> None:
    table = Table(
        title="[bold dodger_blue2]SCAN RESULTS[/bold dodger_blue2]",
        title_justify="left",
        header_style="bold steel_blue1",
        border_style="deep_sky_blue4",
        show_lines=True,
        pad_edge=True,
        padding=(0, 1),
        box=box.ROUNDED
    )
    table.add_column("PROVIDER", style="bold grey84", no_wrap=True)
    table.add_column("VERDICT", justify="center", no_wrap=True)
    table.add_column("CONFIDENCE", justify="center", no_wrap=True)
    table.add_column("DETAILS", overflow="fold")

    for result in results:
        style = VERDICT_STYLES.get(result.verdict, "grey84")
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
    "CLEAN": "bold spring_green3",
    "SUSPICIOUS": "bold dark_orange",
    "HIGH RISK": "bold red3",
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
    verdict_style = _ASSESSMENT_STYLES.get(overall_verdict, "grey84")

    info = Table.grid(padding=(0, 2))
    info.add_column(justify="left", style="bold steel_blue1", min_width=18)
    info.add_column(justify="left")

    info.add_row("Overall Risk Score", f"[bold grey84]{risk_score}/100[/bold grey84]")
    info.add_row("Sources Queried", f"[bold grey84]{total_sources}[/bold grey84]")
    info.add_row("Sources Matched", f"[bold grey84]{sources_hit}/{total_sources}[/bold grey84]")
    if ioc_type is not None:
        info.add_row("IOC Type", f"[bold grey84]{ioc_type.value}[/bold grey84]")

    rec_lines = "\n".join(f"[grey84]•[/grey84] {item}" for item in recommendation)

    body_parts = [
        Align.center(_big_verdict(overall_verdict, verdict_style)),
        Text(""),
        info,
        Text(""),
        Text("Recommendation", style="bold dodger_blue2"),
        Text.from_markup(rec_lines),
    ]

    grid = Table.grid()
    grid.add_column()
    for part in body_parts:
        grid.add_row(part)

    console.print(
        Panel(
            grid,
            title="[bold grey84]OVERALL ASSESSMENT[/bold grey84]",
            title_align="left",
            border_style=verdict_style,
            padding=(1, 2),
            box=box.ROUNDED
        )
    )


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

def print_warnings(results: list[ProviderResult]) -> None:
    failed = [r for r in results if r.verdict == Verdict.ERROR]
    if not failed:
        return

    lines = []
    for result in failed:
        first_line = result.details.splitlines()[0] if result.details else "Unknown error"
        lines.append(f"[bold dark_orange]•[/bold dark_orange] [bold grey84]{result.provider}[/bold grey84] : {first_line}")

    body = "\n".join(lines)
    console.print(
        Panel(
            body,
            title="[bold dark_orange]⚠ API WARNINGS[/bold dark_orange]",
            title_align="left",
            border_style="dark_orange",
            padding=(1, 2),
            box=box.ROUNDED
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
    footer.append(" | ".join(provider_names), style="bold steel_blue1")
    console.print(Align.center(footer))
