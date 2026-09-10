# Changelog

## Unreleased

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
