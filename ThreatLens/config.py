"""Runtime configuration loaded explicitly; no import-time filesystem effects."""

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

VERSION = "2.2.0"
REQUEST_TIMEOUT = 12
PROVIDERS = {
    "virustotal": ("VirusTotal", "VT_API_KEY"),
    "otx": ("AlienVault OTX", "OTX_API_KEY"),
    "threatfox": ("ThreatFox", "THREATFOX_API_KEY"),
    "abuseipdb": ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
    "urlhaus": ("URLhaus", "URLHAUS_API_KEY"),
    "malwarebazaar": ("MalwareBazaar", "MALWAREBAZAAR_API_KEY"),
    "pulsedive": ("Pulsedive", "PULSEDIVE_API_KEY"),
}


@dataclass(frozen=True)
class AppConfig:
    keys: dict
    data_dir: Path
    org_file: Path | None = None
    timeout: float = REQUEST_TIMEOUT
    cache_ttl: int = 3600
    negative_ttl: int = 300
    context_ttl: int = 86400
    offline: bool = False
    no_cache: bool = False
    enrichment: bool = True
    whois_api_key: str | None = None

    @property
    def secrets(self):
        return [*self.keys.values(), self.whois_api_key]


def application_dir() -> Path:
    entry = sys.executable if getattr(sys, "frozen", False) else __file__
    return Path(entry).resolve().parent


def load_config(env_file=None, **overrides) -> AppConfig:
    if env_file is not None:
        env_path = Path(env_file).expanduser()
    else:
        # Frozen __file__ points inside the bundle, not beside the user's EXE.
        env_path = application_dir() / ".env"
    # Keep file values local so switching --env-file never inherits old keys.
    source = {**dotenv_values(env_path), **os.environ}
    org = source.get("THREATLENS_ORG_FILE")
    values = dict(
        keys={name: (source.get(env) or "").strip() for name, (_, env) in PROVIDERS.items()},
        data_dir=Path((source.get("THREATLENS_DATA_DIR") or "~/.threatlens")).expanduser(),
        org_file=Path(org).expanduser() if org else None,
        whois_api_key=source.get("WHOIS_API_KEY"),
    )
    values.update({k: v for k, v in overrides.items() if v is not None})
    return AppConfig(**values)
