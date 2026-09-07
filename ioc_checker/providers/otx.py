"""
providers/otx.py

AlienVault OTX API Integration
------------------------------
Author: Amirhossein Mousavi

Description:
Implements the BaseProvider interface to query the AlienVault Open Threat Exchange (OTX). 
It evaluates the risk of an IOC by checking its association with known threat pulses, 
translating pulse counts into normalized risk scores and confidence levels.
"""
from __future__ import annotations

import logging

import requests

from providers import BaseProvider
from utils import ProviderResult, Verdict
from detector import IOCType

logger = logging.getLogger("ioc_checker")

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


class OTXProvider(BaseProvider):
    name = "AlienVault OTX"
    SUPPORTED_TYPES = {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key or ""}

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _safe_lookup(self, path: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            response = requests.get(
                f"{BASE_URL}{path}/general",
                headers=self._headers(),
                timeout=self.timeout,
            )
            if response.status_code == 404:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No report found",
                )
            response.raise_for_status()
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                verdict = Verdict.MALICIOUS
                risk = 30
                details = f"Threat Pulses: {pulse_count}"
            else:
                verdict = Verdict.CLEAN
                risk = 0
                details = "No Threat Pulses Found"

            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=data,
            )
        except requests.RequestException as exc:
            logger.error("OTX request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("OTX parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/IPv4/{ioc}")

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/domain/{ioc}")

    def lookup_url(self, ioc: str) -> ProviderResult:
        # OTX expects the raw URL as a path-encoded parameter via its "url" endpoint.
        try:
            import urllib.parse

            encoded = urllib.parse.quote(ioc, safe="")
            return self._safe_lookup(f"/url/{encoded}")
        except Exception as exc:  # noqa: BLE001
            logger.error("OTX URL encoding failed: %s", exc)
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, details=str(exc)
            )

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/file/{ioc}")
