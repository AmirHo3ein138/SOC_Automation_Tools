"""VirusTotal v3: observed vendor counts, not invented confidence percentages."""

import base64

from detector import IOCType
from models import Verdict

from providers import BaseProvider, number


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    HTTP_404_IS_MISS = True
    SUPPORTED_TYPES = set(IOCType) - {IOCType.UNKNOWN}

    def lookup(self, ioc_type, ioc):
        if ioc_type == IOCType.URL:
            endpoint, identifier = (
                "urls",
                base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("="),
            )
        else:
            endpoint = {
                IOCType.IPV4: "ip_addresses",
                IOCType.IPV6: "ip_addresses",
                IOCType.DOMAIN: "domains",
            }.get(ioc_type, "files")
            identifier = ioc
        data = self.transport.request(
            "GET",
            f"https://www.virustotal.com/api/v3/{endpoint}/{identifier}",
            headers={"x-apikey": self.api_key},
        )
        return self.parse(data)

    def parse(self, data):
        attr = data["data"]["attributes"]
        stats = attr["last_analysis_stats"]
        malicious, suspicious = number(stats, "malicious"), number(stats, "suspicious")
        total = sum(number(stats, key) for key in stats)
        if total <= 0:
            raise ValueError("No analysis available")
        verdict = (
            Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS if suspicious else Verdict.NO_HIT
        )
        return self.result(
            verdict,
            f"{malicious:g} malicious, {suspicious:g} suspicious / {total:g} vendor results",
            {"malicious": malicious, "suspicious": suspicious, "total": total},
            attr.get("last_analysis_date"),
        )
