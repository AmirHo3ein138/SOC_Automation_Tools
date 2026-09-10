# SOC Automation Tools

Practical tools for SOC analysts: collect evidence, reduce repetitive lookups, and
keep investigation records. The repository currently contains **ThreatLens 2.1.0**,
a Python CLI for multi-source IOC enrichment.

| Tool | Purpose | Documentation |
| --- | --- | --- |
| ThreatLens | IOC lookups, organization/APN context, network-aware recommendations, TTL caching, compact TXT reports and JSON output | [ThreatLens README](ThreatLens/README.md) |

ThreatLens is an analyst aid. It does not block IPs, upload samples, perform active
scans of IOC hosts, or establish that an unknown IOC is safe. Its evidence score is
an explainable heuristic, **not a calibrated probability of maliciousness**.

## Quick start

Python **3.11 or newer** is required. The CI matrix targets Python 3.11–3.13 on
Linux and Windows. From this repository's root:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -r ThreatLens/requirements-lock.txt
```

Copy `ThreatLens/.env.example` to `ThreatLens/.env` and fill in your own API keys.
For a PyInstaller console build, place `.env` beside `ThreatLens.exe` instead;
it is found there even when launched from another directory. `--env-file PATH`
selects a different file and takes priority over this default. Running the EXE
without scan arguments opens the interactive `IOC>` prompt.
Run a lookup or start the interactive prompt:

The original Stealth UI includes its gradient banner, rounded information panels,
colored results and large assessment display. Scan history stays in the terminal.
Artwork is bundled in Python; the EXE needs no separate font files.

```bash
python ThreatLens/ThreatLens.py 8.8.8.8
python ThreatLens/ThreatLens.py
python ThreatLens/ThreatLens.py --help
```

Reports are automatically saved as individual UTF-8 TXT files under
`~/.threatlens/reports`. Runtime data and credentials are ignored by Git.

## Repository layout

- `ThreatLens/`: application, provider adapters, configuration examples and tests.
- `ThreatLens/ARCHITECTURE.md`: module boundaries, scoring formula and policy order.
- `ThreatLens/CHANGELOG.md`: release behavior changes and migration notes.
- `.github/workflows/tests.yml`: offline regression suite and CLI checks.

See the [architecture](ThreatLens/ARCHITECTURE.md) and
[release notes](ThreatLens/CHANGELOG.md) before integrating output into an
operational workflow. JSON exit status indicates collection completeness, not
whether an IOC is malicious.

## Development

```bash
python -m pip install -r ThreatLens/requirements-dev.txt
ruff check ThreatLens
ruff format --check ThreatLens
python -m unittest discover -s ThreatLens/tests -v
```

The tests use synthetic API responses and disposable local storage. They cover
failure states, provider contracts, network policies, scoring, cache expiry,
file hashing, report persistence and command-line behavior. They do not prove
live API availability or real-world detection accuracy. Authenticated integration
checks require your service keys and account permissions.

For new adapters, add a provider class, register it in `providers/manager.py`, add
its environment key in `config.py`, document supported IOC types, and add contract
tests. Significant scoring changes also require updating the policy version and
its explanation.

## License status

Source is publicly available. This repository does not currently include a license
grant; the owner has not selected a license. No license was inferred or introduced
as part of the 2.1.0 code changes.
