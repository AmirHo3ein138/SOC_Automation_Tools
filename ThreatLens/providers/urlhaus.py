"""URLhaus: distinguish historic malicious hosting from current online status."""

from detector import IOCType
from models import Verdict

from providers import BaseProvider


class URLhausProvider(BaseProvider):
    name = "URLhaus"
    SUPPORTED_TYPES = {IOCType.URL}

    def lookup(self, ioc_type, ioc):
        data = self.transport.request(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": ioc},
            headers={"Auth-Key": self.api_key},
        )
        if data["query_status"] == "no_results":
            return self.result(Verdict.NOT_FOUND, "No URLhaus record")
        if data["query_status"] != "ok" or data.get("url_status") not in {
            "online",
            "offline",
            "unknown",
        }:
            raise ValueError("Unexpected URLhaus result")
        status = data["url_status"]
        return self.result(
            Verdict.MALICIOUS if status == "online" else Verdict.SUSPICIOUS,
            f"Malware URL record; availability: {status}; threat: {data.get('threat') or 'Unknown'}",
            {"status": status},
            data.get("last_online") or data.get("date_added"),
        )
