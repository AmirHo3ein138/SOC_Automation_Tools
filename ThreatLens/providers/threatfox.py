"""
providers/threatfox.py

ThreatFox API Integration
-------------------------
Author: Amirhossein Mousavi

Description:
Implements the BaseProvider interface to query abuse.ch's ThreatFox database. 
It utilizes a single POST endpoint to search for IPs, Domains, URLs, and Hashes, 
extracting malware family associations and confidence levels for identified threats.
"""

from __future__ import annotations

import logging

import requests

from providers import BaseProvider
from utils import ProviderResult, Verdict
from detector import IOCType

logger = logging.getLogger("ioc_checker")

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(BaseProvider):
    name = "ThreatFox"
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
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _search_ioc(self, ioc: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            response = requests.post(
                API_URL,
                json={"query": "search_ioc", "search_term": ioc},
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            query_status = data.get("query_status")
            if query_status == "no_result":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No match found",
                )
            if query_status != "ok":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details=f"API status: {query_status}",
                )

            entries = data.get("data", [])
            if not entries:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No match found",
                )

            top = entries[0]
            malware = top.get("malware_printable", "Unknown")
            confidence = top.get("confidence_level", "N/A")
            ioc_type_str = top.get("ioc_type", "N/A")
            details = (
                f"Malware Family: {malware}\n"
                f"Confidence: {confidence}\n"
                f"IOC Type: {ioc_type_str}"
            )

            return ProviderResult(
                provider=self.name,
                verdict=Verdict.FOUND,
                details=details,
                risk_contribution=30,
                raw=data,
            )
        except requests.RequestException as exc:
            logger.error("ThreatFox request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("ThreatFox parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        return self._search_ioc(ioc)

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._search_ioc(ioc)

    def lookup_url(self, ioc: str) -> ProviderResult:
        return self._search_ioc(ioc)

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._search_ioc(ioc)
