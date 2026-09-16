# Changelog

## 2.2.0 — 2026-09-16

### Analyst workflow

- Red panels with blinking titles for existing Iranian ISP/ASN and ArvanCloud
  classifications; detection, scoring and blocking recommendations are unchanged.
- Shared startup/interactive argument parser: help/version and errors stay inside
  the REPL; one-shot scan switches and persistent session-only settings.
- Preserve Windows paths, existing interactive styling, and source rate-limit state.
- Keep the owner's 2-second CLI timeout; switching .env no longer inherits file keys.

### Daily journals and API reuse

- Reports default beside the EXE/script. Four daily TXT categories: IP, HASH,
  DOMAIN and URL; local system date is evaluated at each scan start.
- Store readable sections plus validated checksummed JSON records. Complete same-day
  reports are reused without API calls or duplicate entries, with visible provenance.
- Retry incomplete reports. Add --refresh to bypass report/provider/context caches.
- Date-scoped TI cache prevents previous-day hits. Retain existing context/feed TTLs.
- File locks protect concurrent appends. Organization/configuration fingerprints
  prevent reuse after relevant policy changes. Recompute file hashes before reuse.

### Migration and validation

- Existing reports/cache are retained; old unique reports are not imported.
- --report-dir overrides the new destination; cache/log paths remain unchanged.
- New JSON fields: report_day, reuse_key, reused. --clear-cache retains TXT journals.
- Regression coverage includes day rollover, restart reuse, failed-source retries,
  refresh, concurrent writes, policy changes, Windows paths and visual alerts.
- Actual Windows EXE and authenticated live-provider validation remain separate.

### Previously unreleased compatibility fixes

- Restore the original Stealth CLI: gradient banner, author links, rounded panels,
  colored provider table, large assessment, warnings, spinner and timing footer.
  Preserve scan history and all 2.1 features; bundle artwork without external fonts.

- Restore external `.env` discovery beside PyInstaller executables, independent
  of the working directory and temporary bundle extraction directory.
- Preserve explicit `--env-file` selection and process-environment precedence.
- Cover source/frozen discovery, explicit selection and multi-scan interactive
  operation with regression tests; update CLI help and both READMEs.

## 2.1.0 — 2026-09-10

A minor feature release from 2.0.1: the interactive invocation remains supported,
and script/batch/file arguments are now implemented. Assessment labels and the
internal Python interfaces deliberately change; this project has no stable library
API. Consumers must adopt the documented JSON schema/exit semantics.

### Correctness and policy

- Separate ERROR, SKIPPED, NOT_FOUND and NO_HIT; never conclude CLEAN from missing data.
- Central evidence-v1 scoring with native strength, reliability, observation-age
  decay, correlated-source grouping and diminishing corroboration.
- Preserve positive signals even when old, retired, offline or weak.
- Context-aware recommendations: organization/APN protection first, ArvanCloud
  no-IP-block policy, domestic ISP notice, normal treatment of foreign cloud/CDN IPs.
- Validate organization policy before lookups; longest-prefix rule selection.
- Skip private/special addresses and recognizable sensitive/internal URL inputs.

### Collection and persistence

- SQLite TTL cache for successful normalized TI and context, with shorter negative TTL.
- Independent validated cloud-feed refresh and stale last-known-good fallback.
- Add CloudFront, Fastly, Google Cloud and IPv6 ranges alongside ArvanCloud/Cloudflare.
- HTTPS IP context with ISP/ASN/country; optional structured WHOIS.
- Automatic compact TXT reports per scan, JSON Lines batch output and explicit exit codes.
- Keep previous terminal results; EOF exits correctly.

### Provider and security fixes

- ThreatFox documented hash query, exact IOC matching and SHA1 capability removal.
- Require Auth-Key for URLhaus/MalwareBazaar; validate MalwareBazaar sample identity.
- Reject malformed/missing metrics; preserve Pulsedive API failures as errors.
- Remove invented 0%/100% confidence and OTX pulse-as-proof assumptions.
- Central safe transport, 429 cooldowns, retry limits and per-process VT spacing.
- Prevent credentials in request diagnostics and Rich markup interpretation.

### Maintenance

- Split orchestration, assessment, network policy, storage, reporting and CLI.
- Keep MD5/SHA1/SHA256 single-pass hashing; detect ordinary file changes while reading.
- Remove tracked Python bytecode and empty runtime CDN cache; add Git exclusions.
- Remove unused pyfiglet runtime dependency; document current runtime architecture.
- Add pinned runtime requirements, offline regression tests and Linux/Windows CI matrix.
- Correct README paths, commands and unsupported capability/performance claims.

### Validation boundaries

Automated tests use synthetic API fixtures and temporary local directories. They
verify control flow and regression behavior, not live account entitlement or real
threat-detection accuracy. Authenticated provider checks require the operator's
keys. The evidence formula remains an uncalibrated policy until measured against a
representative labelled dataset. Live feed availability may vary by network.
