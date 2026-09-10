"""Pulsedive errors remain errors; retired records retain historic evidence."""

from detector import IOCType
from models import Verdict
from transport import LookupFailure

from providers import BaseProvider


class PulsediveProvider(BaseProvider):
    name = "Pulsedive"
    HTTP_404_IS_MISS = True
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL}

    def lookup(self, ioc_type, ioc):
        payload = self.transport.request(
            "GET",
            "https://pulsedive.com/api/info.php",
            params={"indicator": ioc, "key": self.api_key},
        )
        if not isinstance(payload, dict):
            raise ValueError("Expected object")
        if "error" in payload:
            error = str(payload["error"]).strip().lower().rstrip(".")
            if error in {"indicator not found", "indicator does not exist"}:
                return self.result(Verdict.NOT_FOUND, "Indicator not found in Pulsedive")
            raise LookupFailure(
                "api_error", "Pulsedive returned an API error; check credentials/quota"
            )
        risk = payload["risk"]
        if risk not in {"critical", "high", "medium", "low", "none", "retired"}:
            raise ValueError("Unknown Pulsedive risk")
        verdict = (
            Verdict.MALICIOUS
            if risk in {"critical", "high"}
            else Verdict.NO_HIT
            if risk == "none"
            else Verdict.SUSPICIOUS
        )
        return self.result(
            verdict,
            f"Native risk: {risk}"
            + ("; historical signal, not proof of safety" if risk == "retired" else ""),
            {"risk": risk},
            payload.get("stamp_seen") or payload.get("lastseen"),
        )
