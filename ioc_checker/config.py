"""
config.py

Centralized Configuration Loader
--------------------------------
Author: Amirhossein Mousavi

Description:
Manages the application's configuration state by securely loading API keys and runtime 
settings from the environment variables (.env). It defines structured dataclasses for 
provider settings, enabling easy tracking of which APIs require authentication and 
managing global variables like request timeouts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load environment variables from .env file in the current working directory
load_dotenv()

VERSION: str = "2.0.1"
REQUEST_TIMEOUT: int = 15 


@dataclass(frozen=True)
class ProviderConfig:
    display_name: str
    env_var: str
    api_key: str | None
    requires_key: bool = True

    @property
    def is_configured(self) -> bool:
        if not self.requires_key:
            return True
        return bool(self.api_key)


@dataclass(frozen=True)
class AppConfig:
    virustotal: ProviderConfig
    otx: ProviderConfig
    threatfox: ProviderConfig
    abuseipdb: ProviderConfig
    urlhaus: ProviderConfig
    malwarebazaar: ProviderConfig
    pulsedive: ProviderConfig
    whois_api_key: str | None  

    def all_providers(self) -> list[ProviderConfig]:
        return [
            self.virustotal,
            self.otx,
            self.threatfox,
            self.abuseipdb,
            self.urlhaus,
            self.malwarebazaar,
            self.pulsedive,
        ]


def load_config() -> AppConfig:
    return AppConfig(
        virustotal=ProviderConfig("VirusTotal", "VT_API_KEY", os.getenv("VT_API_KEY") or None),
        otx=ProviderConfig("AlienVault OTX", "OTX_API_KEY", os.getenv("OTX_API_KEY") or None),
        threatfox=ProviderConfig("ThreatFox", "THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY") or None),
        abuseipdb=ProviderConfig("AbuseIPDB", "ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY") or None),
        urlhaus=ProviderConfig("URLhaus", "URLHAUS_API_KEY", os.getenv("URLHAUS_API_KEY") or None, False),
        malwarebazaar=ProviderConfig("MalwareBazaar", "MALWAREBAZAAR_API_KEY", os.getenv("MALWAREBAZAAR_API_KEY") or None, False),
        pulsedive=ProviderConfig("Pulsedive", "PULSEDIVE_API_KEY", os.getenv("PULSEDIVE_API_KEY") or None),
        whois_api_key=os.getenv("WHOIS_API_KEY") or None,
    )
