"""AbuseIPDB IPv4/IPv6 reputation; keep confidence and report count as native metrics."""

from detector import IOCType
from models import Verdict

from providers import BaseProvider, number


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.IPV6}

    def lookup(self, ioc_type, ioc):
        payload = self.transport.request(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90},
        )
        data = payload["data"]
        score, reports = (
            number(data, "abuseConfidenceScore", maximum=100),
            number(data, "totalReports"),
        )
        verdict = (
            Verdict.MALICIOUS
            if score >= 75
            else Verdict.SUSPICIOUS
            if reports > 0
            else Verdict.NO_HIT
        )
        return self.result(
            verdict,
            f"Abuse confidence {score:g}/100; reports {reports:g}; ISP: {data.get('isp') or 'Unknown'}",
            {"abuse_score": score, "reports": reports},
            data.get("lastReportedAt"),
        )
