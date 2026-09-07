"""
providers/pulsedive.py

Pulsedive API Integration
-------------------------
Author: Amirhossein Mousavi

Description:
Implements the BaseProvider interface to query Pulsedive's community threat intelligence 
platform. It maps Pulsedive's qualitative risk levels (e.g., critical, high, retired) 
directly onto the application's unified verdict model for IPs, domains, and URLs.
"""

from __future__ import annotations

import logging

import requests

from detector import IOCType
from providers import BaseProvider
from utils import ProviderResult, Verdict

logger = logging.getLogger("ioc_checker")

API_URL = "https://pulsedive.com/api/info.php"

# Map Pulsedive's normalized risk levels onto the project's verdict model.
# Each entry is (Verdict, risk_contribution).
_RISK_MAP: dict[str, tuple[Verdict, int]] = {
    "critical": (Verdict.MALICIOUS, 40),
    "high": (Verdict.MALICIOUS, 30),
    "medium": (Verdict.SUSPICIOUS, 20),
    "low": (Verdict.SUSPICIOUS, 10),
    "none": (Verdict.CLEAN, 0),
    # 'retired' means the indicator was once flagged but is no longer active;
    # treat it as clean but note it in the details.
    "retired": (Verdict.CLEAN, 0),
}


class PulsediveProvider(BaseProvider):
    name = "Pulsedive"
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.DOMAIN, IOCType.URL}

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _unsupported(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNSUPPORTED,
            details="Pulsedive only supports IP, domain, and URL lookups",
        )

    def _request(self, ioc: str) -> requests.Response:
        """Issue the indicator lookup request (query-by-value)."""
        return requests.get(
            API_URL,
            params={"indicator": ioc, "key": self.api_key or "", "pretty": "1"},
            timeout=self.timeout,
        )

    def _parse_response(self, payload: dict) -> ProviderResult:
        """
        Turn a Pulsedive indicator payload into a normalized ProviderResult.

        The relevant fields are:
            risk     -> normalized risk level (see _RISK_MAP)
            threats  -> list of associated threat objects (may be absent)
            type     -> Pulsedive's own IOC type classification
        """
        # An indicator that isn't in the database comes back with an 'error'
        # field (e.g. "Indicator not found.") - report it as NOT_FOUND.
        if "error" in payload:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.NOT_FOUND,
                details="Indicator not found in Pulsedive",
                raw=payload,
            )

        risk = str(payload.get("risk", "unknown")).lower()
        verdict, risk_contribution = _RISK_MAP.get(
            risk, (Verdict.NOT_FOUND, 0)
        )

        # Collect associated threat names, if any, for the details panel.
        threats = payload.get("threats") or []
        threat_names = [
            t.get("name")
            for t in threats
            if isinstance(t, dict) and t.get("name")
        ]

        detail_lines = [f"Risk: {risk.capitalize()}"]

        indicator_type = payload.get("type")
        if indicator_type:
            detail_lines.append(f"Type: {indicator_type}")

        if threat_names:
            shown = ", ".join(threat_names[:5])
            if len(threat_names) > 5:
                shown += f", +{len(threat_names) - 5} more"
            detail_lines.append(f"Threats: {shown}")
        else:
            detail_lines.append("Threats: None")

        last_seen = payload.get("stamp_seen") or payload.get("lastseen")
        if last_seen:
            detail_lines.append(f"Last Seen: {last_seen}")

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            details="\n".join(detail_lines),
            risk_contribution=risk_contribution,
            raw=payload,
        )

    def _safe_lookup(self, ioc: str) -> ProviderResult:
        """Shared lookup pipeline for every supported IOC type."""
        if not self.api_key:
            return self._not_configured()
        try:
            response = self._request(ioc)
            if response.status_code == 404:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="Indicator not found in Pulsedive",
                )
            response.raise_for_status()
            return self._parse_response(response.json())
        except requests.Timeout:
            logger.error("Pulsedive request timed out for %s", ioc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Request timed out",
            )
        except requests.RequestException as exc:
            logger.error("Pulsedive request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("Pulsedive parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(ioc)

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(ioc)

    def lookup_url(self, ioc: str) -> ProviderResult:
        return self._safe_lookup(ioc)

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._unsupported()
