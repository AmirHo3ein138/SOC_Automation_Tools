"""Network classification and independently refreshed, validated official cloud feeds."""

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from detector import IOCType
from models import NetworkContext
from transport import LookupFailure, Transport

# Feed identity identifies infrastructure, not geolocation. Google Cloud is not labelled a CDN.
FEEDS = {
    "ArvanCloud": [("https://www.arvancloud.ir/en/ips.txt", "lines")],
    "Cloudflare": [
        ("https://www.cloudflare.com/ips-v4", "lines"),
        ("https://www.cloudflare.com/ips-v6", "lines"),
    ],
    "Amazon CloudFront": [("https://ip-ranges.amazonaws.com/ip-ranges.json", "aws")],
    "Fastly": [("https://api.fastly.com/public-ip-list", "fastly")],
    "Google Cloud": [("https://www.gstatic.com/ipranges/cloud.json", "google")],
}


def ip_category(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version == 6 and ip.ipv4_mapped:
        return "ipv4_mapped:" + ip_category(str(ip.ipv4_mapped))
    if ip.version == 4 and ip == ipaddress.ip_address("255.255.255.255"):
        return "limited_broadcast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "apipa" if ip.version == 4 else "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "shared_cgnat"
    if ip.version == 4 and any(
        ip in ipaddress.ip_network(n)
        for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")
    ):
        return "documentation_or_benchmark"
    if ip.version == 6 and ip in ipaddress.ip_network("2001:db8::/32"):
        return "documentation_or_benchmark"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "non_global"
    return "public"


def local_context(ioc, ioc_type, organization):
    address = ioc
    context = NetworkContext()
    if ioc_type == IOCType.URL:
        address = urlsplit(ioc).hostname
    elif ioc_type not in {IOCType.IPV4, IOCType.IPV6}:
        return context
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        # No DNS resolution: avoid leaking internal names or contacting IOC hosts.
        if address and (
            address.endswith(
                (".local", ".internal", ".localhost", ".lan", ".home", ".test", ".invalid")
            )
            or address == "localhost"
        ):
            context.external_allowed = False
            context.warnings.append("Internal/special-use hostname: external queries skipped")
        return context
    context.address = str(ip)
    context.organization = organization.match(ip)
    context.category = ip_category(str(ip))
    context.external_allowed = context.category == "public"
    if context.organization:
        rule = context.organization
        context.protected = rule["protect"]
        context.country_code = rule.get("country_code", "").upper() or None
        context.isp = rule.get("isp") or None
        context.external_allowed = context.external_allowed and rule["external_lookup"]
        context.warnings.append(
            f"Organization match FIRST: {rule['label']} ({rule['kind']}, {rule['cidr']})"
        )
        if rule.get("notes"):
            context.warnings.append(rule["notes"])
        network = ipaddress.ip_network(rule["cidr"])
        if ip.version == 4 and network.prefixlen <= 30 and ip == network.broadcast_address:
            context.category = "directed_broadcast"
            context.external_allowed = False
    if not context.external_allowed:
        context.warnings.append(
            f"External lookups disabled by network class or organization policy ({context.category})"
        )
    return context


def parse_feed(payload, kind):
    if kind == "lines":
        values = [line.strip() for line in payload.splitlines() if line.strip()]
    elif kind == "aws":
        values = [p["ip_prefix"] for p in payload["prefixes"] if p.get("service") == "CLOUDFRONT"]
        values += [
            p["ipv6_prefix"]
            for p in payload.get("ipv6_prefixes", [])
            if p.get("service") == "CLOUDFRONT"
        ]
    elif kind == "fastly":
        values = payload["addresses"] + payload.get("ipv6_addresses", [])
    elif kind == "google":
        values = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in payload["prefixes"]]
    else:
        raise ValueError("Unknown feed format")
    if not values or len(values) > 100000:
        raise ValueError("Empty or oversized network feed")
    networks = [ipaddress.ip_network(v, strict=True) for v in values]
    # Reject accidental catch-all ranges or non-global feed records.
    if any(
        n.prefixlen < (8 if n.version == 4 else 16) or not n.network_address.is_global
        for n in networks
    ):
        raise ValueError("Unsafe network feed")
    return sorted({str(n) for n in networks})


class CloudRegistry:
    def __init__(self, cache, offline=False, timeout=12):
        self.cache, self.offline, self.timeout = cache, offline, timeout

    def _source(self, item):
        name, url, kind = item
        namespace = "cloud-feed-v1"
        entry = self.cache.get(namespace, url)
        if entry:
            try:
                valid = parse_feed("\n".join(entry["value"]), "lines")
                return name, valid, None
            except (ValueError, TypeError):
                pass
        try:
            if self.offline:
                raise LookupFailure("offline", "Offline")
            payload = Transport(self.timeout).request("GET", url, text=kind == "lines")
            values = parse_feed(payload, kind)
            self.cache.put(namespace, url, values, 86400)
            return name, values, None
        except (LookupFailure, ValueError, KeyError, TypeError):
            old = self.cache.get(namespace, url, stale=True)
            if old:
                try:
                    valid = parse_feed("\n".join(old["value"]), "lines")
                    return (
                        name,
                        valid,
                        f"{name}: using stale last-known-good ranges; verify ownership",
                    )
                except (ValueError, TypeError):
                    pass
            return name, [], f"{name}: ranges unavailable; membership is unknown"

    def lookup(self, address):
        sources = [(name, url, kind) for name, feeds in FEEDS.items() for url, kind in feeds]
        with ThreadPoolExecutor(max_workers=6) as pool:
            loaded = list(pool.map(self._source, sources))
        ip = ipaddress.ip_address(address)
        matches, warnings = set(), []
        for name, ranges, warning in loaded:
            if warning and warning not in warnings:
                warnings.append(warning)
            for cidr in ranges:
                try:
                    network = ipaddress.ip_network(cidr)
                    if ip.version == network.version and ip in network:
                        matches.add(name)
                        break
                except ValueError:
                    continue
        return sorted(matches), warnings


def apply_network_policy(context):
    if "ArvanCloud" in context.infrastructure:
        context.protected = True
        context.warnings.append(
            "ArvanCloud shared infrastructure: do not block this IP; investigate the specific host/URL"
        )
    others = [x for x in context.infrastructure if x != "ArvanCloud"]
    if others:
        context.warnings.append(
            "Infrastructure information: "
            + ", ".join(others)
            + "; foreign infrastructure is not exempt from blocking"
        )
    if context.country_code == "IR":
        context.warnings.append(
            f"Iranian domestic network: ISP={context.isp or 'unknown'}, ASN={context.asn or 'unknown'}. Consider shared subscribers/APN impact."
        )
    return context
