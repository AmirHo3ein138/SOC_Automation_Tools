"""Optional HTTPS context. Failures never abort threat intelligence collection."""

import ipaddress

import tldextract
from transport import LookupFailure, Transport

# Use the bundled public suffix snapshot; never perform hidden network calls.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def enrich_ip(address, transport=None):
    data = (transport or Transport()).request("GET", "https://ipwho.is/" + address)
    if not isinstance(data, dict) or data.get("success") is not True:
        raise LookupFailure("invalid_response", "IP context unavailable")
    try:
        if ipaddress.ip_address(data["ip"]) != ipaddress.ip_address(address):
            raise ValueError("IP mismatch")
        conn = data["connection"]
        country = data["country_code"]
        if not isinstance(country, str) or len(country) != 2 or not isinstance(conn, dict):
            raise ValueError("Missing context")
        return {
            "country_code": country.upper(),
            "isp": str(conn.get("isp") or conn.get("org") or "Unknown"),
            "asn": str(conn.get("asn") or "Unknown"),
        }
    except (KeyError, TypeError, ValueError):
        raise LookupFailure("invalid_response", "Unexpected IP context format") from None


def enrich_domain(domain, api_key, transport=None):
    ext = _EXTRACT(domain)
    root = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
    data = (transport or Transport()).request(
        "GET",
        f"https://api.who.is/v1/whois/{root}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    if not isinstance(data, dict):
        raise LookupFailure("invalid_response", "Unexpected WHOIS format")
    payload = data.get("payload", data)
    if not isinstance(payload, dict) or not any(
        k in payload for k in ("registrar", "created", "registered", "events")
    ):
        raise LookupFailure("invalid_response", "WHOIS fields missing")
    registrar = payload.get("registrar")
    if isinstance(registrar, dict):
        registrar = registrar.get("name")
    result = {
        "root_domain": root,
        "registrar": registrar or "Unknown",
        "created": payload.get("created") or payload.get("registered"),
        "updated": payload.get("updated"),
        "expires": payload.get("expires") or payload.get("expiration"),
    }
    events = payload.get("events") or []
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        action = event.get("event_action", event.get("eventAction"))
        key = {
            "registration": "created",
            "expiration": "expires",
            "last changed": "updated",
            "updated": "updated",
        }.get(action)
        if key and not result[key]:
            result[key] = event.get("event_date", event.get("eventDate"))
    return result
