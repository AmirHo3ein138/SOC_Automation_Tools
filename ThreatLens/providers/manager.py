"""
providers/manager.py

Dynamic Provider Registry
-------------------------
Author: Amirhossein Mousavi

Description:
Acts as the central registry and orchestrator for all Threat Intelligence providers. 
Instead of hardcoding routing logic, this module dynamically selects and instantiates 
only the providers that support a specific IOC type. This architecture makes the tool 
highly modular and easy to extend with new sources.
"""

from __future__ import annotations

from config import REQUEST_TIMEOUT, AppConfig
from detector import IOCType
from providers import BaseProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.malwarebazaar import MalwareBazaarProvider
from providers.otx import OTXProvider
from providers.pulsedive import PulsediveProvider
from providers.threatfox import ThreatFoxProvider
from providers.urlhaus import URLhausProvider
from providers.virustotal import VirusTotalProvider

# Each entry maps the AppConfig field name holding that provider's
# ProviderConfig to the provider class that consumes it.
_PROVIDER_SPECS: list[tuple[str, type[BaseProvider]]] = [
    ("virustotal", VirusTotalProvider),
    ("otx", OTXProvider),
    ("threatfox", ThreatFoxProvider),
    ("abuseipdb", AbuseIPDBProvider),
    ("urlhaus", URLhausProvider),
    ("malwarebazaar", MalwareBazaarProvider),
    ("pulsedive", PulsediveProvider),
]


def build_all_providers(config: AppConfig) -> list[BaseProvider]:
    """Instantiate every registered provider, regardless of IOC type."""
    providers: list[BaseProvider] = []
    for field_name, provider_cls in _PROVIDER_SPECS:
        provider_cfg = getattr(config, field_name)
        providers.append(provider_cls(provider_cfg.api_key, timeout=REQUEST_TIMEOUT))
    return providers


def get_providers_for_type(ioc_type: IOCType, config: AppConfig) -> list[BaseProvider]:
    """
    Return only the providers whose SUPPORTED_TYPES includes the given
    IOC type. Providers that don't support this IOC type are never
    instantiated for the scan and never appear in the results.
    """
    return [
        provider
        for provider in build_all_providers(config)
        if ioc_type in provider.SUPPORTED_TYPES
    ]
