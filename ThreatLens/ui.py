"""Small terminal-only renderer. Untrusted strings are never Rich markup."""

from rich.console import Console
from rich.table import Table
from rich.text import Text
from security import safe_text

console = Console()


def display(report):
    a = report.assessment
    console.print(Text(f"\nThreatLens {report.version} | {report.created_at}", style="bold cyan"))
    console.print(Text(f"{report.ioc_type}: {safe_text(report.ioc)}"))
    table = Table("Source", "Result", "Origin", "Evidence", expand=False)
    for result in report.results:
        table.add_row(
            Text(result.provider),
            Text(result.verdict.value),
            Text(
                "cache"
                if result.cached
                else "live"
                if result.verdict.value not in {"SKIPPED", "UNSUPPORTED"}
                else "skip"
            ),
            Text(safe_text(result.details)),
        )
    console.print(table)
    score = "N/A" if a.score is None else f"{a.score}/100"
    color = "red" if a.verdict == "HIGH_RISK" else "yellow" if a.verdict == "SUSPICIOUS" else "cyan"
    console.print(
        Text(f"{a.verdict} | Evidence score {score} (not a probability)", style="bold " + color)
    )
    cov = a.coverage
    console.print(
        Text(
            f"Successful {cov['successful']}/{cov['applicable']} | Errors {cov['errors']} | Skipped {cov['skipped']} | Cached {cov['cached']}"
        )
    )
    c = report.context
    if c.address:
        console.print(
            Text(
                f"Network: {c.category} | Country: {c.country_code or 'unknown'} | ISP: {safe_text(c.isp or 'unknown')} | ASN: {c.asn or 'unknown'}"
            )
        )
    if report.file_info:
        console.print(
            Text("File digests: " + " | ".join(f"{k}={v}" for k, v in report.file_info.items()))
        )
    for warning in c.warnings:
        console.print(Text("Notice: " + safe_text(warning), style="yellow"))
    for i, recommendation in enumerate(a.recommendations, 1):
        console.print(Text(f"{i}. " + safe_text(recommendation)))
