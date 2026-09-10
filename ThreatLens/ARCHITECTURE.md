# ThreatLens architecture and evidence policy

## Module boundaries

| Module | Responsibility |
| --- | --- |
| `ThreatLens.py` | Thin executable entry point. |
| `cli.py` | Arguments, REPL, batch input, exit status and report destination. |
| `detector.py` | Defanging, IPv4/IPv6/domain/URL/hash validation and normalization. |
| `models.py` | Serializable provider results, network context, assessment and scan report. |
| `organization.py` | Strict local policy validation and longest-prefix IP/CIDR matching. |
| `network.py` | Special-address classification, official feed parsing/cache refresh and network policy. |
| `enrichment.py` | HTTPS IP metadata and optional structured WHOIS; no UI dependency. |
| `providers/` | Seven API adapters; native metrics only, no final score or blocking policy. |
| `transport.py` | TLS, bounded retries, cooldowns, response limits and safe HTTP diagnostics. |
| `storage.py` | Transactional TTL cache with per-operation SQLite connections. |
| `engine.py` | Local checks, concurrent collection, cache coordination and assessment invocation. |
| `assessment.py` | Versioned deterministic evidence score, coverage and contextual recommendations. |
| `reporting.py` | Compact TXT serialization and unique persistent report files. |
| `ui.py` | Rich rendering of typed results; untrusted content rendered as plain Text. |
| `ui_art.py` | Pre-rendered original FIGlet banner and verdict artwork, bundled with the EXE. |
| `security.py` | Diagnostic redaction and recognizable secret URL checks. |
| `utils.py` | Streaming file hashes and explicit rotating logging setup. |

The architecture is a modular single-process application. The explicit provider
registry is deliberate: adding an adapter also changes configuration and tests.
No plugin auto-discovery, database service, daemon or web API is required.

## Execution order

1. Load configuration and validate the entire organization file. Invalid policy
   aborts before any external request.
2. If a local file was selected, compute its digests and use SHA256 as the IOC.
3. Normalize the IOC. For IP/literal-IP URLs, match the organization rule first,
   classify special network ranges, then determine whether external data is allowed.
4. Start eligible provider collection and optional context collection concurrently.
   Each provider checks fresh cache before requesting; skipped local policy is
   checked before either cache or network.
5. Wait for results in deterministic registry order. Provider/context errors are
   isolated. Enrichment failures cannot suppress successful TI evidence.
6. Apply ArvanCloud/organization/domestic context policy, then assess the evidence.
7. Save one unique TXT report, then emit terminal or JSON output.

The core `Scanner.scan()` has no Rich dependency. Only the CLI imports the UI.
Requests go to known TI/context providers, never to the IOC itself. Hostnames are
not DNS-resolved, so there is no inferred IP ownership for domain URLs.

## Evidence-v1 formula

This is a **transparent heuristic**, not a statistically calibrated classifier.
Reliability constants are policy choices, not empirical accuracy measurements.
No confidence percentage is fabricated from a URL's availability or a pulse count.

Native strength `S` is on a 0–100 scale:

| Source | Native strength |
| --- | --- |
| VirusTotal | `100 * (1-exp(-(m+0.4*s)/5)) * (0.65+0.35*(m+s)/total)`, where `m` and `s` are malicious and suspicious vendor counts. |
| AbuseIPDB | Abuse confidence score, with a floor of 10 when reports exist. |
| OTX | `min(45, 10+10*log2(1+pulses))` for positive pulse association. |
| ThreatFox | `30+0.6*confidence_level` for matching/associated records. |
| URLhaus | Online 90, offline 45, unknown availability 35. |
| MalwareBazaar | Exact sample hash match 98. |
| Pulsedive | Critical 95, high 80, medium 45, low 20, retired 20, none 0. |

Non-positive verdicts contribute zero. Zero contribution from errors/missing data
never counts as a successful clean observation.

Reliability `R`: VT 0.95, AbuseIPDB 0.90, OTX 0.65, ThreatFox 0.90, URLhaus 0.95,
MalwareBazaar 0.98, Pulsedive 0.80. New unmodelled adapters default to 0.50 and a
small positive strength, but must receive a documented policy before production use.

Freshness `F = max(floor, 2^(-age_days/half_life))`:

- Network/domain/URL observations: half-life 90 days, floor 0.35.
- Hash observations: half-life 730 days, floor 0.80, because a file digest identifies
  the same bytes even when evidence is old.
- Missing/invalid observation times: factor 1, explicitly labelled unknown; a
  timestamp is never invented. Future times more than one day ahead are flagged
  `future/invalid` in contribution metadata. Cache fetch time is not last-seen time.
- OTX pulse publication/update dates are retained as metadata but are not used as
  IOC last-seen dates.

Per-source points are `P=S*R*F`. ThreatFox, URLhaus and MalwareBazaar share an
`abuse.ch` group to reduce obvious correlated-source double counting. Within each
group: `G=min(100, max(P)+0.25*(sum(P)-max(P)))`.

Sort group scores descending. Start with the strongest group, then add each
remaining group using `score += (100-score)*(G/100)*0.5`. This gives diminishing
corroboration without claiming independence. Round to an integer, cap at 100 and
retain at least 1 when positive evidence exists.

At 70 or above: HIGH_RISK. Any lower positive signal: SUSPICIOUS. No positive
signal: NO_KNOWN_THREAT only when all applicable providers successfully returned;
otherwise INCONCLUSIVE, or UNKNOWN when none succeeded. UNKNOWN has a null score.
Coverage is separate from severity: failed sources never dilute a positive score,
and missing sources are explicitly counted rather than silently treated as benign.

TXT/JSON reports include each source's strength, reliability, freshness, points and
group, plus coverage. Replaying the same metrics and assessment time reproduces the
score. Scores age over time, including cached observations. A labelled local SOC
dataset is needed before claiming improved precision/recall or probability calibration.

## Recommendation precedence

Network context does not subtract threat evidence. Recommendation precedence is:

1. Non-public or external-disabled addresses: internal investigation; no outbound TI.
2. Protected organization/APN assets: no IP-block recommendation; correlate ownership,
   subscriber/NAT mappings, timestamps and service impact with the owner.
3. ArvanCloud membership: no shared-IP block recommendation; investigate a narrower
   domain/URL/application target. This applies even when another rule has protect=false.
4. Country IR: identify domestic ISP/ASN and shared-service implications. This alone
   is informational, not a blanket allowlist.
5. Other public addresses, including foreign cloud/CDN: high-risk results receive the
   ordinary block recommendation. Cloud membership alone does not exempt them.
6. Hashes: high risk recommends file quarantine/EDR investigation and a validated
   hash rule. Domain/URL recommendations target that indicator rather than a guessed IP.

These are textual recommendations only. ThreatLens has no enforcement integration.
A foreign cloud operator can have infrastructure in multiple countries; geolocation
and infrastructure identity remain separate fields. Organization country/ISP
metadata overrides external context when provided.

## Cache and failure semantics

Provider cache namespaces are versioned independently of the app version. Keys
contain a SHA256 digest of normalized IOC identity plus provider namespace; values
hold sanitized, normalized results, not raw API payloads or credentials. Reports
still contain plaintext IOCs, so hashed cache keys are not encryption or anonymization.

Default TTLs: positive TI 1 hour; no-hit/not-found 5 minutes; IP/WHOIS/feed context
24 hours. Only successful provider results enter the TI cache. Each SQLite operation
owns its connection, so worker threads don't share connection state. Writes are
transactional. Individual read/write failures become cache misses/warnings.

Official feed refreshes are independent and validate every subnet. Empty, HTML,
non-global or dangerously broad data is rejected before replacement. Last-known-good
ranges survive failed refreshes; stale usage is identified to the analyst. TI cache
has no stale fallback because old observations must not look newly queried.

Transport uses HTTPS, does not follow redirects, rejects responses above 10 MB,
and limits connect/read and streaming duration. There is at most one retry for
network failure or 5xx. A 429 triggers a bounded Retry-After cooldown rather than a
long blocking sleep. These are bounded individual operations, not a hard wall-clock
scan SLA. VT's 15-second spacing is local to one Scanner; concurrent processes need
an external quota coordinator if strict account-wide control is required.

## Security and operational limits

- No automatic trust from absence of evidence; no auto-block integration.
- No execution/upload/download of samples; only local digests and reputation lookup.
- No raw request exceptions in output. Keys are additionally redacted before results
  enter cache. Plain Rich Text prevents markup interpretation of external strings.
- Input rejects credential URLs and common secret parameters, but arbitrary path or
  parameter data may still be confidential. This is not full content classification.
- Special ranges are filtered. Directed broadcast needs a known subnet mask; a
  single IP alone does not reveal its broadcast semantics.
- Only listed infrastructure feeds are covered. Missing/stale feeds and geolocation
  gaps are reported; they cannot guarantee ArvanCloud or domestic detection offline.
- Public-suffix extraction uses the tldextract bundled snapshot without implicit
  network updates; dependency updates refresh that snapshot.
- No legal license was selected by the implementation; repository license status
  is stated explicitly in the root README.
