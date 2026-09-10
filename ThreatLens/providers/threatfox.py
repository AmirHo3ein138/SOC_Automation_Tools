"""Exact IOC lookup and documented MD5/SHA256 association search."""

import ipaddress

from detector import IOCType
from models import Verdict

from providers import BaseProvider, number, timestamp


def matches(query, value, kind):
    if kind in {IOCType.MD5, IOCType.SHA256}:
        return True  # search_hash returns related network IOCs, not the hash itself.
    if kind in {IOCType.IPV4, IOCType.IPV6}:
        try:
            candidate = value
            if value.startswith("["):
                candidate = value[1 : value.index("]")]
            elif kind == IOCType.IPV4:
                candidate = value.split(":")[0]
            return ipaddress.ip_address(candidate) == ipaddress.ip_address(query)
        except (ValueError, TypeError):
            return False
    return (
        value.lower().rstrip(".") == query.lower().rstrip(".")
        if kind == IOCType.DOMAIN
        else value == query
    )


class ThreatFoxProvider(BaseProvider):
    name = "ThreatFox"
    SUPPORTED_TYPES = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA256,
    }

    def lookup(self, ioc_type, ioc):
        is_hash = ioc_type in {IOCType.MD5, IOCType.SHA256}
        query = (
            {"query": "search_hash", "hash": ioc}
            if is_hash
            else {"query": "search_ioc", "search_term": ioc, "exact_match": True}
        )
        data = self.transport.request(
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            json_body=query,
            headers={"Auth-Key": self.api_key},
        )
        if data["query_status"] == "no_result":
            return self.result(
                Verdict.NOT_FOUND, "No matching record in current ThreatFox API dataset"
            )
        if (
            data["query_status"] != "ok"
            or not isinstance(data.get("data"), list)
            or not data["data"]
        ):
            raise ValueError("Unexpected ThreatFox result")
        entries = [
            e
            for e in data["data"]
            if isinstance(e, dict) and matches(ioc, e.get("ioc", ""), ioc_type)
        ]
        if not entries:
            return self.result(
                Verdict.NOT_FOUND, "Returned records did not match the requested IOC"
            )
        top = max(entries, key=lambda e: number(e, "confidence_level", maximum=100))
        confidence = number(top, "confidence_level", maximum=100)
        related = "associated network IOC" if is_hash else "matched IOC"
        dates = [timestamp(e.get("last_seen") or e.get("first_seen")) for e in entries]
        return self.result(
            Verdict.FOUND,
            f"{len(entries)} {related} record(s); family: {top.get('malware_printable') or 'Unknown'}; confidence {confidence:g}/100",
            {
                "confidence": confidence,
                "matches": len(entries),
                "relationship": "hash_association" if is_hash else "exact",
            },
            max((d for d in dates if d), default=None),
        )
