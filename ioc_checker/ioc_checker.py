"""
ioc_checker.py

Threat Intelligence Aggregator - Interactive CLI
-----------------------------------------------
Author: Amirhossein Mousavi

Description:
The main entry point for the IOC Checker tool, designed to streamline alert triage 
and threat hunting operations. This module runs a continuous interactive loop (REPL) 
that accepts IP addresses, domains, URLs, hashes, or local files. It orchestrates 
the flow of data between the enrichment module, threat intelligence providers, and 
the presentation layer to deliver a unified and actionable risk assessment.
"""

from __future__ import annotations

import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console

import ui
import enrichment
from config import load_config
from detector import IOCType, detect_ioc_type
from providers import BaseProvider
from providers.manager import get_providers_for_type
from utils import ProviderResult, Verdict, calculate_file_hashes, setup_logging

console = Console()
logger = setup_logging()

_LOOKUP_METHOD = {
    IOCType.IPV4: "lookup_ip",
    IOCType.DOMAIN: "lookup_domain",
    IOCType.URL: "lookup_url",
    IOCType.MD5: "lookup_hash",
    IOCType.SHA1: "lookup_hash",
    IOCType.SHA256: "lookup_hash",
}

def query_provider(provider: BaseProvider, method_name: str, ioc: str) -> ProviderResult:
    try:
        method = getattr(provider, method_name)
        return method(ioc)
    except Exception as exc:
        logger.exception("Unhandled error in provider %s", provider.name)
        return ProviderResult(
            provider=provider.name,
            verdict=Verdict.ERROR,
            details=f"Unhandled error: {exc}",
        )

def run_scan(providers: list[BaseProvider], method_name: str, ioc: str) -> list[ProviderResult]:
    results: list[ProviderResult] = []
    total = len(providers)
    progress = ui.create_scan_progress(total)
    with progress:
        task_id = progress.add_task("scan", total=total, detail=f"[0/{total}]")
        with ThreadPoolExecutor(max_workers=total) as executor:
            futures = {
                executor.submit(query_provider, provider, method_name, ioc): provider
                for provider in providers
            }
            completed = 0
            for future in as_completed(futures):
                provider = futures[future]
                result = future.result()
                results.append(result)
                completed += 1
                progress.update(task_id, advance=1, detail=f"[{completed}/{total}] {provider.name}")

    order = {p.name: i for i, p in enumerate(providers)}
    results.sort(key=lambda r: order.get(r.provider, 99))
    return results

def calculate_verdict(results: list[ProviderResult]) -> tuple[int, str, int]:
    risk_score = sum(r.risk_contribution for r in results)
    risk_score = max(0, min(risk_score, 100))
    hit_verdicts = {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND}
    sources_hit = sum(1 for r in results if r.verdict in hit_verdicts)

    if risk_score <= 20: overall = "CLEAN"
    elif risk_score <= 50: overall = "SUSPICIOUS"
    else: overall = "HIGH RISK"
    return risk_score, overall, sources_hit

def build_recommendation(overall_verdict: str) -> list[str]:
    if overall_verdict == "HIGH RISK":
        return ["Block IOC immediately", "Investigate affected hosts", "Search historical logs", "Add IOC to SIEM watchlists"]
    if overall_verdict == "SUSPICIOUS":
        return ["Perform manual investigation", "Search historical logs", "Monitor related hosts"]
    return ["No action required"]

def resolve_file_to_sha256(path: str) -> str | None:
    try:
        hashes = calculate_file_hashes(path)
    except Exception as exc:
        ui.print_file_error(path, str(exc))
        return None
    ui.print_file_info(path, hashes)
    return hashes["sha256"]


def main() -> int:
    # 1. Clear screen at startup
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
        
    ui.print_banner()
    config = load_config()

    console.print("[dim italic]Initializing enrichment caches...[/dim italic]")
    enrichment.update_cdn_cache_if_needed()
    
    console.print("\n[bold green]Ready.[/bold green] Enter an IP, Domain, URL, Hash, or path to a local file.")
    console.print("Type [bold yellow]'exit'[/bold yellow] or [bold yellow]'quit'[/bold yellow] to close the program.\n")

    while True:
        try:
            raw_input = console.input("[bold cyan]IOC> [/bold cyan]").strip()
            
            if raw_input.lower() in ("exit", "quit", "q"):
                console.print("[dim]Exiting... Goodbye![/dim]")
                break
                
            if not raw_input:
                continue

            start_time = time.perf_counter()
            
            # 2. Clear screen before displaying new scan results
            if os.name == 'nt':
                os.system('cls')
            else:
                os.system('clear')
                
            ui.print_banner()
            
            if os.path.isfile(raw_input):
                sha256 = resolve_file_to_sha256(raw_input)
                if not sha256:
                    continue
                ioc = sha256
            else:
                ioc = raw_input

            ioc_type = detect_ioc_type(ioc)
            if ioc_type == IOCType.UNKNOWN:
                ui.print_unsupported_ioc(ioc)
                continue

            ui.print_ioc_info(ioc, ioc_type)

            # ENRICHMENT PHASE
            used_sources = []
            if ioc_type == IOCType.IPV4:
                cdn_name = enrichment.check_cdn(ioc)
                if cdn_name:
                    ui.print_cdn_warning(cdn_name)
                
                data, is_cloud, err = enrichment.enrich_ip(ioc)
                ui.print_enrichment_info(data, "IP CONTEXT", is_cloud, err)
                used_sources.append("ip-api")
                
            elif ioc_type == IOCType.DOMAIN:
                data, is_cloud, err = enrichment.enrich_domain(ioc, config.whois_api_key)
                ui.print_enrichment_info(data, "DOMAIN WHOIS", is_cloud, err)
                used_sources.append("who.is")

            # SCANNING PHASE
            providers = get_providers_for_type(ioc_type, config)
            method_name = _LOOKUP_METHOD[ioc_type]
            used_sources.extend([p.name for p in providers])

            results = run_scan(providers, method_name, ioc)
            ui.print_results_table(results)

            risk_score, overall_verdict, sources_hit = calculate_verdict(results)
            ui.print_summary(
                risk_score=risk_score, overall_verdict=overall_verdict,
                sources_hit=sources_hit, total_sources=len(providers),
                recommendation=build_recommendation(overall_verdict), ioc_type=ioc_type,
            )

            ui.print_warnings(results)
            elapsed = time.perf_counter() - start_time
            ui.print_footer(elapsed, used_sources)

        except KeyboardInterrupt:
            console.print("\n[dim]Exiting... Goodbye![/dim]")
            break
        except Exception as exc:
            logger.exception("Unexpected error in main loop")
            console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {exc}\n")

    return 0

if __name__ == "__main__":
    sys.exit(main())