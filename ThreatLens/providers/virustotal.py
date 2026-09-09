"""
providers/virustotal.py

VirusTotal API Integration
--------------------------
Author: Amirhossein Mousavi

Description:
Implements the BaseProvider interface to query the VirusTotal v3 API. It handles 
request authentication, URL base64 encoding specific to VT, and parses the 
'last_analysis_stats' to calculate an accurate risk contribution score based on 
community and vendor detections.
"""
from __future__ import annotations

import base64
import logging

import requests

from providers import BaseProvider
from utils import ProviderResult, Verdict
from detector import IOCType

logger = logging.getLogger("ioc_checker")

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
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
        return {"x-apikey": self.api_key or ""}

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _request(self, path: str) -> requests.Response:
        return requests.get(
            f"{BASE_URL}{path}", headers=self._headers(), timeout=self.timeout
        )

    def _parse_stats(self, data: dict) -> ProviderResult:
        try:
            attributes = data["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            if malicious > 0:
                verdict = Verdict.MALICIOUS
                risk = 40
            elif suspicious > 0:
                verdict = Verdict.SUSPICIOUS
                risk = 20
            else:
                verdict = Verdict.CLEAN
                risk = 0

            percentage = (malicious / total) * 100 if total else 0.0
            details = f"{malicious}/{total} detections ({percentage:.1f}%)"
            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=data,
            )
        except (KeyError, TypeError) as exc:
            logger.error("VirusTotal parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def _safe_lookup(self, path: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            response = self._request(path)
            if response.status_code == 404:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No report found",
                )
            response.raise_for_status()
            return self._parse_stats(response.json())
        except requests.RequestException as exc:
            logger.error("VirusTotal request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/ip_addresses/{ioc}")

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/domains/{ioc}")

    def lookup_url(self, ioc: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return self._safe_lookup(f"/urls/{url_id}")

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(f"/files/{ioc}")
