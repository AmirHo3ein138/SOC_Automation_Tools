"""OTX pulse association is a contextual signal, not a definitive malicious verdict."""

from urllib.parse import quote

from detector import IOCType
from models import Verdict

from providers import BaseProvider, number, timestamp


class OTXProvider(BaseProvider):
    name = "AlienVault OTX"
    HTTP_404_IS_MISS = True
    SUPPORTED_TYPES = set(IOCType) - {IOCType.UNKNOWN}

    def lookup(self, ioc_type, ioc):
        kind = {
            IOCType.IPV4: "IPv4",
            IOCType.IPV6: "IPv6",
            IOCType.DOMAIN: "domain",
            IOCType.URL: "url",
        }.get(ioc_type, "file")
        data = self.transport.request(
            "GET",
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(ioc, safe='')}/general",
            headers={"X-OTX-API-KEY": self.api_key},
        )
        info = data["pulse_info"]
        count = number(info, "count")
        dates = [
            timestamp(p.get("modified") or p.get("created"))
            for p in info.get("pulses", [])
            if isinstance(p, dict)
        ]
        # Pulse modification time isn't IOC last-seen: retain as a native metric only.
        return self.result(
            Verdict.SUSPICIOUS if count else Verdict.NO_HIT,
            f"Associated threat pulses: {count:g}; investigate relationship and publication context",
            {"pulses": count, "pulse_updated_at": max((d for d in dates if d), default=None)},
        )
