"""Explicit registry: adding a provider requires a registration and configuration key."""

from transport import Transport

from providers.abuseipdb import AbuseIPDBProvider
from providers.malwarebazaar import MalwareBazaarProvider
from providers.otx import OTXProvider
from providers.pulsedive import PulsediveProvider
from providers.threatfox import ThreatFoxProvider
from providers.urlhaus import URLhausProvider
from providers.virustotal import VirusTotalProvider

REGISTRY = {
    "virustotal": VirusTotalProvider,
    "abuseipdb": AbuseIPDBProvider,
    "otx": OTXProvider,
    "threatfox": ThreatFoxProvider,
    "urlhaus": URLhausProvider,
    "malwarebazaar": MalwareBazaarProvider,
    "pulsedive": PulsediveProvider,
}


def build_all_providers(config):
    # VT public tier commonly allows four requests/minute; cache hits bypass this gate.
    return [
        cls(
            config.keys.get(key),
            transport=Transport(config.timeout, min_interval=15 if key == "virustotal" else 0),
        )
        for key, cls in REGISTRY.items()
    ]


def get_providers_for_type(ioc_type, config):
    return [p for p in build_all_providers(config) if ioc_type in p.SUPPORTED_TYPES]
