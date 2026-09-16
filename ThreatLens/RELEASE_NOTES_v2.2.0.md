## 🚀 ThreatLens v2.2.0

ThreatLens v2.2.0 adds daily investigation journals, same-day report reuse, and command-line switches inside the interactive console. The original Stealth UI, seven-provider integration, explainable scoring, organization/APN policies, and standalone `.env` workflow remain available.

### ✨ What's New

* **Prominent Iranian Network Alerts:** Red panels with blinking titles highlight already-identified Iranian ISP/operator and ArvanCloud infrastructure. Alerts show available IP, ISP and ASN context. ArvanCloud retains its shared-IP protection recommendation. These are presentation improvements; detection and scoring rules are unchanged. Blinking depends on terminal support.
* **Daily, Categorized TXT Journals:** Reports are saved beside `ThreatLens.exe` by default, grouped into IP, HASH, DOMAIN and URL files using the system's local date. Each scan has a readable section with timestamps, source results and recommendations.
* **Same-Day Report Reuse:** A complete matching report from today is displayed without another API request or duplicate journal entry. The original scan time and saved-report status are clearly shown. Previous-day journals are not used for this lookup.
* **Fresh Lookups When Needed:** `--refresh` bypasses saved reports and caches. Incomplete reports do not prevent retries. Provider TI cache entries are date-scoped, so yesterday's TI cannot satisfy today's first lookup. Shared context/feed caches keep their normal TTL unless refreshed.
* **Interactive Switches:** Use `--help`, `-h`, scan options and configuration switches directly at `IOC>`. Options with an IOC apply once; options alone update session defaults. Help and invalid arguments return to the prompt.
* **Safer Persistence:** Journal writes use file locks. Structured records have checksums for accidental-corruption detection, and relevant configuration changes invalidate report reuse. These checksums are not cryptographic proof of TI authenticity.

### 🛠️ Standalone Windows Setup

1. Download `ThreatLens_v2.2.0_Windows.zip` from **Assets**.
2. Extract the archive to a writable folder.
3. Rename `.env.example` to `.env` and add your provider API keys.
4. Keep `.env` beside `ThreatLens.exe` and launch the executable.

No Python installation is required for the standalone build. The optional organization JSON file is needed only when using organization/APN policies.

### 💻 Interactive Examples

```text
IOC> --help
IOC> --timeout 5
IOC> 8.8.8.8
IOC> 8.8.8.8 --refresh
IOC> --file "C:\Samples\sample.exe"
IOC> --report-dir "C:\SOC\Reports"
IOC> exit
```

Startup arguments remain supported:

```powershell
.\ThreatLens.exe 8.8.8.8 --refresh --timeout 5
.\ThreatLens.exe --input ".\iocs.txt" --json
.\ThreatLens.exe --org-config "C:\SOC\organization.json"
```

### 📁 Reports & Migration

Daily files follow `ThreatLens_IP_YYYY-MM-DD.txt`, `ThreatLens_HASH_YYYY-MM-DD.txt`, `ThreatLens_DOMAIN_YYYY-MM-DD.txt` and `ThreatLens_URL_YYYY-MM-DD.txt`. IPv4/IPv6 share the IP journal; supported hash types share HASH. Small `.txt.lock` sidecars coordinate writes.

* `--report-dir` overrides the report location. Cache/log files still default to `~/.threatlens`.
* Earlier reports are retained but are not imported into daily reuse.
* `--clear-cache` clears SQLite entries and keeps TXT journals. Use `--refresh` to bypass a saved report.
* `--offline` can use today's complete reports or fresh same-day TI cache; it cannot be combined with `--refresh`.
* Daily report reuse preserves the earlier assessment until refreshed or the local date changes. It is distinct from the shorter provider-cache TTL.
* The CLI's existing 2-second connect/read timeout is retained. Rate-limit waits and retries mean this is not a total scan deadline.

### 📝 Important Notes

Missing keys and failed sources remain visible. Unknown or incomplete results are never automatically considered safe. Local file contents are hashed, not uploaded or executed. ThreatLens provides recommendations and does not automatically block indicators.

Keep API keys and investigation journals out of release archives. Source regression tests use synthetic data; live-provider access and the built Windows executable require separate validation.
