# ThreatLens

## Overview

ThreatLens is an intelligent assistant and command-line (CLI) tool built to speed up alert triage and threat hunting. In a typical workflow, checking a single Indicator of Compromise (IOC) means opening dozens of browser tabs (VirusTotal, AbuseIPDB, OTX, and so on) and manually comparing the results. ThreatLens replaces this by aggregating all of these sources into a single tool: feed it any type of IOC — IP, domain, URL, hash, or even a local file — and it runs every check automatically in a fraction of a second, returning one clean, unified report.

This tool is the first module in the [SOC Automation Tools](../README.md) repository, and it was built directly around the day-to-day enrichment and triage needs of a SOC Analyst.

## Architecture & Workflow

### 1. Smart Input Detection

ThreatLens never asks the user what kind of data they're providing. In the `detector.py` module, precise regular expressions combined with Python's built-in libraries automatically determine the input type: IPv4, domain, full URL, or hash (MD5/SHA1/SHA256). If the input is a path to a local file, the file is read in chunks to avoid overloading system memory, its SHA256 hash is computed, and that hash — not the file itself — is what gets scanned.

### 2. Context & Enrichment

Before checking whether an IOC is malicious, its identity needs to be understood first. The `enrichment.py` module handles two critical tasks:

- **Cloud infrastructure detection (CDN/WAF):** the tool checks whether an IP belongs to a service like Cloudflare or ArvanCloud. This prevents a common and costly SOC mistake — blocking a shared IP and taking down unrelated, innocent services in the process.
- **Smart WHOIS extraction:** for domains, registrant information and relevant dates are extracted. For country-code domains (like `.cn` or `.ir`) where standard APIs often struggle, a regex fallback mechanism pulls the dates directly out of the raw data.

### 3. Concurrent Provider Scanning

The core of the tool lives in the `providers` module. Instead of calling APIs one after another, ThreatLens uses a `ThreadPoolExecutor` to send requests to all supported sources concurrently — so total scan time is bound by the slowest API, not the sum of all of them. Provider selection is also dynamic: for a domain, only domain-supporting sources (like VT and OTX) are called, while IP-specific sources like AbuseIPDB are skipped.

### 4. Data Normalization & Risk Scoring

Every provider speaks its own language: one returns a risk percentage, another a pulse count, another labels like "Critical." The `utils.py` module takes all of these inconsistent outputs and converts them into a single standard structure. Based on the weight of each signal (for example, VT Malicious scores 40, URLhaus Offline scores 15), it calculates one unified Risk Score from 0 to 100 and classifies the final verdict into three levels: **Clean**, **Suspicious**, and **High Risk**.

### 5. Presentation & Error Handling

The presentation layer (`ui.py`) uses the Rich library to deliver a professional "Stealth" theme suited to security environments:

- **Clean environment:** the terminal is fully cleared before every new scan to reduce analyst eye fatigue.
- **Robustness:** a dropped internet connection, an expired API key, or hitting a rate limit never crashes the tool. Instead, that specific source is skipped and tagged `ERROR`, results from the remaining sources are still shown, and a warning box at the bottom of the report explains exactly which source failed and why.

## Modular Architecture & Extensibility

ThreatLens isn't a simple Python script — it's built on a fully modular architecture, so adding a new provider (say, Shodan or CrowdStrike) never requires touching the core codebase. All it takes is:

1. Add the new provider's file to the `providers` folder.
2. Add its API key to the `.env` file.

## Results

With ThreatLens, IOC analysis time drops from several minutes to a few seconds, and because data from multiple sources is aggregated and normalized automatically, the analyst's decision-making accuracy improves significantly.

## Installation

```bash
git clone <repository-url>
cd ThreatLens
pip install -r requirements.txt
```

Add the required API keys (VirusTotal, AbuseIPDB, OTX, etc.) to a `.env` file in the project root.

## Usage

```bash
python threatlens.py <IOC-or-file-path>
```

The input can be an IP, domain, URL, hash, or the path to a local file — the type is detected automatically.

## Contributing

Suggestions, bug reports, and pull requests for new providers or improvements to the risk-scoring logic are all welcome.
