# ThreatLens 2.1.0

A scriptable and interactive **IOC evidence collector** for SOC workflows. It
queries seven TI providers, checks local organization policy before any external
lookup, adds optional IP/WHOIS context, and produces explainable recommendations.
It never performs firewall changes or uploads local file contents.

## Install and configure

Requires Python 3.11+. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r ThreatLens/requirements-lock.txt
```

Copy `.env.example` in this folder to `.env`, then set the keys you have. All seven
TI adapters require keys. Missing keys produce `SKIPPED`, not an apparently clean
result. Configuration file selection is:

1. `--env-file PATH`, when supplied (relative paths use the working directory).
2. Otherwise, `.env` beside the executable in PyInstaller builds, or beside
   `ThreatLens.py` when running the Python source, regardless of the working directory.

Only the selected file is loaded; a missing explicit file does not fall back to
another `.env`. Existing environment variables take precedence over file values.
WHOIS is optional. A console-enabled EXE can be distributed with just a sibling
`.env` containing the user's keys; do not embed keys in the executable. Launching
without an IOC or batch arguments opens the interactive `IOC>` prompt. Keep
PyInstaller's `--console` option enabled. Organization JSON is optional; cache,
logs and reports are created automatically under `~/.threatlens` by default.

`requirements.txt` contains direct version bounds. `requirements-lock.txt` records
the tested exact dependency set. There is no pyfiglet dependency in this release.

| Provider | Environment variable | IPv4 / IPv6 | Domain | URL | MD5 | SHA1 | SHA256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| VirusTotal | `VT_API_KEY` | Yes / Yes | Yes | Yes | Yes | Yes | Yes |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Yes / Yes | — | — | — | — | — |
| AlienVault OTX | `OTX_API_KEY` | Yes / Yes | Yes | Yes | Yes | Yes | Yes |
| ThreatFox | `THREATFOX_API_KEY` | Yes / Yes | Yes | Yes | Yes | — | Yes |
| URLhaus | `URLHAUS_API_KEY` | — / — | — | Yes | — | — | — |
| MalwareBazaar | `MALWAREBAZAAR_API_KEY` | — / — | — | — | Yes | Yes | Yes |
| Pulsedive | `PULSEDIVE_API_KEY` | Yes / Yes | Yes | Yes | — | — | — |

This table describes implemented adapter routes, not account entitlements or a
claim that every source will have data. ThreatFox hash searches return associated
network IOCs. They are explicitly labelled as associations. SHA1 is excluded from
that adapter because its documented hash endpoint accepts MD5/SHA256.

## Usage

```bash
# Interactive: previous results stay visible; EOF, exit, quit and q leave the prompt.
python ThreatLens/ThreatLens.py

# One lookup; quote URLs so the shell does not interpret & or other characters.
python ThreatLens/ThreatLens.py 8.8.8.8
python ThreatLens/ThreatLens.py 'https://example.com/path'
python ThreatLens/ThreatLens.py 'hxxps://example[.]com/path'

# Batch: one IOC per line, empty lines and lines beginning with # are ignored.
python ThreatLens/ThreatLens.py --input iocs.txt --json

# Only use fresh cached TI results; no outbound requests.
python ThreatLens/ThreatLens.py 8.8.8.8 --offline --json

# Disable all cache reads/writes; skip only external context enrichment.
python ThreatLens/ThreatLens.py 8.8.8.8 --no-cache --no-enrichment
```

`--json` emits one object per scan on stdout (JSON Lines for batches). Report paths
and errors go to stderr. JSON without an IOC/file/batch argument is rejected.
Exit codes: **0** = completed collection (even if high risk), **2** = incomplete or
unknown collection, or command usage error, **1** = invalid input/configuration or
report failure, **130** = interrupted. Interactive mode returns 0 when closed;
each scan displays its own completeness. No exit code means “safe”.

### Local files and hashes

```bash
python ThreatLens/ThreatLens.py --file '/path/to/sample with spaces.exe'
# Windows:
python ThreatLens/ThreatLens.py --file 'C:\Samples\sample.exe'
```

In the interactive prompt, enter an existing path directly, or use:

```text
IOC> file "C:\Samples\sample with spaces.exe"
```

The file is read **once in 64-KiB chunks**. MD5, SHA1 and SHA256 are computed in
parallel during that single read; all three digests are included in the report.
Only the **SHA256 string** is sent for reputation lookup. No sample is uploaded,
executed or downloaded. Changes in size/modification time during the read reject
the result. For forensic consistency, use a stable copy or snapshot; metadata
checks cannot prevent every concurrent write.

Direct MD5/SHA1/SHA256 input remains supported where the provider supports it.
SHA512, fuzzy hashes and other hash formats are not advertised or accepted.
An existing path takes precedence over automatic IOC classification; `--file`
removes ambiguity and supports paths beginning with a dash.

## Organization / APN policy

Copy `organization.example.json` to an untracked `organization.json`. Replace the
example documentation ranges with your real IPs/CIDRs; examples are deliberately
non-routable and are never sent to TI. Select it using:

```bash
python ThreatLens/ThreatLens.py 8.8.8.8 --org-config /absolute/path/organization.json
```

Alternatively set `THREATLENS_ORG_FILE`. Example policy structure:

```json
{
  "schema_version": 1,
  "organization": "My SOC",
  "networks": [
    {
      "cidr": "203.0.113.42/32",
      "label": "Corporate APN egress - replace this address",
      "kind": "apn",
      "protect": true,
      "external_lookup": true,
      "country_code": "IR",
      "isp": "Contracted mobile operator",
      "notes": "Check subscriber/NAT mapping at the incident timestamp."
    }
  ]
}
```

Rules are evaluated **before cache lookups or network calls**, with longest-prefix
match winning. Duplicate networks, invalid CIDRs, unknown fields and incorrect
boolean types fail configuration validation. `kind` accepts `asset`, `apn`,
`critical` or `internal`. `protect` defaults to true and changes recommendations;
it **does not erase positive TI evidence or reduce the risk score**.
`external_lookup` defaults to true for eligible public addresses. Set false to
keep the IOC local, including avoiding reuse of external TI cache data.

Optional local `country_code` and `isp` take precedence over geolocation results.
They can supply known domestic/APN identity when an external database is wrong.

## Network handling and recommendations

| Network context | Behavior |
| --- | --- |
| Protected organization/APN IP | Identify the asset first; still scan public addresses if allowed; preserve threat evidence; recommend internal correlation and owner-coordinated containment, not IP blocking. |
| ArvanCloud | Warn and recommend **not blocking the shared IP**, even when TI risk is high. Investigate the specific host, URL, application and affected assets. |
| Foreign CDN/cloud | Show membership information; no blocking exemption. High-risk public IPs can receive the normal IP-block recommendation. |
| Iranian IP (`country_code=IR`) | Show domestic-network warning, ISP/operator and ASN. This alone does not change the evidence score or prohibit blocking. |
| Private, APIPA/link-local, loopback, multicast, CGNAT, unspecified, reserved, documentation/benchmark, mapped IPv6 | Skip external queries; recommend internal telemetry. |
| Limited broadcast (`255.255.255.255`) | Skip external queries. |
| Directed broadcast | Detect only when a matching organization subnet mask is known (IPv4 /30 or larger subnet); never assume every `.255` is broadcast. |

Built-in official feeds: **ArvanCloud, Cloudflare IPv4/IPv6, Amazon CloudFront,
Fastly and Google Cloud**. Google Cloud indicates cloud infrastructure, not
necessarily a CDN. This list does not cover all cloud providers. Membership does
not prove the physical location of an IP or the identity of a tenant.

Each feed refreshes independently. Validated ranges are cached for 24 hours;
a failed refresh retains the previous valid ranges with a stale warning. With no
usable ranges, membership is explicitly unknown. There is no committed empty
cache that delays the first refresh. Unavailability can prevent recognizing
ArvanCloud; for critical known ranges add a protected local organization rule.

Country/ISP/ASN uses HTTPS `ipwho.is` and a 24-hour cache. It displays the source's
operator identity (for example Irancell or Mobile Communication Company/MCI),
without inventing an operator based on broad string matching. Geolocation is
fallible; local overrides are available. WHOIS uses an optional `WHOIS_API_KEY`
for `who.is`, parses structured fields/events, and makes no raw-text regex claims.

URLs with a literal IP receive that IP's policy. Domain URLs receive optional
WHOIS. ThreatLens **does not resolve DNS or visit IOC hosts**, so organization
IP policy cannot be applied to a hostname's unknown resolved address. Known
internal/special-use suffixes are not sent to external TI. Credential-bearing
URLs and recognizable secret query/fragment parameters are rejected. This is
not a complete DLP classifier: review arbitrary URLs before sharing externally.

## Evidence score and result interpretation

The central assessment module combines native signal strength, explicit source
reliability weights, observation age and discounted corroboration. Correlated
abuse.ch sources share a group. It distinguishes one VT detection from many,
retains historical signals, and never converts a positive signal to “clean”.

- `HIGH_RISK`: heuristic score at least 70.
- `SUSPICIOUS`: positive evidence exists but score is below 70.
- `NO_KNOWN_THREAT`: all applicable sources completed and returned no positive evidence.
- `INCONCLUSIVE`: some successful results with no positive evidence, but coverage is incomplete.
- `UNKNOWN`: no successful TI results, including local-only cases.

Coverage counts applicable, successful, failed, skipped, positive and cached
results separately. Missing keys do not count as successful queries. A cached
result is successful evidence with its original fetched/observed timestamps; it
is not labelled a live query. The score is **not a measured detection accuracy,
confidence percentage, or probability**. See the exact formulas and limitations
in [ARCHITECTURE.md](ARCHITECTURE.md).

## Caching, records and operational settings

Default runtime directory: `~/.threatlens` (override with `--data-dir` or
`THREATLENS_DATA_DIR`). It contains:

- `cache.sqlite3`: normalized successful TI and enrichment/feed entries.
- `reports/*.txt`: one uniquely named compact UTF-8 file per completed scan.
- `threatlens.log`: rotating diagnostic log (1 MB, three backups).

Positive TI TTL defaults to **3600 seconds**; no-hit/not-found TTL to **300 seconds**.
Use `--cache-ttl` and `--negative-ttl` to change them. Errors and missing credentials
are not cached as TI results. Expired TI is never used as fresh evidence, including
in offline mode. Feed caches alone may fall back to stale last-known-good ranges.
Cache writes use SQLite transactions and independent connections per operation.
Expired entries older than 30 days are pruned at startup.

```bash
python ThreatLens/ThreatLens.py --clear-cache
python ThreatLens/ThreatLens.py 8.8.8.8 --report-dir /path/to/case-reports
```

The TXT report includes normalized IOC, file digests when applicable, network and
organization context, each provider's metrics and timestamps, score contributions,
coverage and recommendations. Report write failures are reported and return a
failure exit status; the application never claims a report was saved when it was
not. Reports are retained until you remove them; there is no automatic deletion.

Cache and report data are local **plaintext**, not encrypted storage. Cache keys
hash IOC identities, but normalized results and reports can still contain
sensitive investigation data. Keep the runtime directory protected and outside
Git. New cache/report files use owner-only permissions where supported; on Windows
apply appropriate filesystem ACLs. API keys and raw request exceptions are not
written into reports/cache. Rotating diagnostics avoid raw URLs and credentials.

HTTP uses HTTPS only, bounded connect/read timeouts, at most one retry for
connection failures/5xx, no redirect following, a response-size limit, and 429
cooldowns respecting Retry-After up to one day. VT requests are spaced by at least
15 seconds within one scanner process. Other account quotas are not predicted;
429 cooldowns are per process, not a distributed quota coordinator. Concurrent
processes can share the cache but do not share provider rate-limit timers.
Ctrl-C can wait for in-flight bounded requests; this is a threaded CLI, not a
hard-cancellable asynchronous request engine.

## Tests and development

```bash
python -m pip install -r ThreatLens/requirements-dev.txt
ruff check ThreatLens
ruff format --check ThreatLens
python -m unittest discover -s ThreatLens/tests -v
```

Tests are offline and use synthetic provider contracts. Live authenticated TI
checks require keys and are not performed by CI. Tests cannot establish real-world
accuracy of the heuristic score; calibration requires a labelled SOC dataset.
Do not interpret a green test suite as proof of service availability.

[Architecture](ARCHITECTURE.md) · [Changelog](CHANGELOG.md) · [Repository](../README.md)

## Provider/reference documentation

- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [OTX Python SDK and examples](https://github.com/AlienVault-OTX/OTX-Python-SDK)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
- [URLhaus API](https://urlhaus.abuse.ch/api/)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [Pulsedive API](https://pulsedive.com/api/)
- [IP context API](https://ipwhois.io/documentation)
- [Cloudflare ranges](https://www.cloudflare.com/ips/)
- [CloudFront ranges](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html)
- [Fastly public IP list](https://api.fastly.com/public-ip-list)
- [Google Cloud IP ranges](https://www.gstatic.com/ipranges/cloud.json)
- [ArvanCloud ranges](https://www.arvancloud.ir/en/ips.txt)
