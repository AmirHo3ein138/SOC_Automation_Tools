"""
providers/urlhaus.py

URLhaus API Integration
-----------------------
Author: Amirhossein Mousavi

Description:
Implements the BaseProvider interface to query abuse.ch's URLhaus. Dedicated strictly 
to URL lookups, this public API integration checks the operational status (online/offline) 
of malicious URLs and retrieves associated threat tags to assist in context-aware blocking.
"""

from __future__ import annotations

import logging

import requests

from detector import IOCType
from providers import BaseProvider
from utils import ProviderResult, Verdict

logger = logging.getLogger("ioc_checker")

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausProvider(BaseProvider):
    name = "URLhaus"
    SUPPORTED_TYPES = {IOCType.URL}

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        # URLhaus is a public API; the key (if provided) only raises rate limits.
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _unsupported(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNSUPPORTED,
            details="URLhaus only supports URL lookups",
        )

    def lookup_url(self, ioc: str) -> ProviderResult:
        try:
            response = requests.post(
                API_URL,
                data={"url": ioc},
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            query_status = data.get("query_status")
            if query_status == "no_results":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="URL not found in URLhaus",
                )
            if query_status != "ok":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details=f"API status: {query_status}",
                )

            url_status = data.get("url_status", "unknown")
            threat = data.get("threat", "N/A")
            tags = data.get("tags") or []
            tags_str = ", ".join(tags) if tags else "None"

            if url_status == "online":
                verdict = Verdict.MALICIOUS
                risk = 30
                confidence_display = "100%"
            elif url_status == "offline":
                verdict = Verdict.SUSPICIOUS
                risk = 15
                confidence_display = "0%"
            else:
                verdict = Verdict.FOUND
                risk = 15
                confidence_display = "N/A"

            details = (
                f"URL Status: {url_status}\n"
                f"Threat: {threat}\n"
                f"Tags: {tags_str}\n"
                f"Confidence: {confidence_display}"
            )

            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=data,
            )
        except requests.RequestException as exc:
            logger.error("URLhaus request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("URLhaus parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        return self._unsupported()

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._unsupported()

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._unsupported()
