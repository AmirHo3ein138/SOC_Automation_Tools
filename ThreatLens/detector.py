"""Normalize defanged IOCs without changing case-sensitive URL paths or queries."""

import ipaddress
import re
from enum import Enum
from urllib.parse import urlsplit, urlunsplit


class IOCType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "Unknown"


HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}


def domain_name(value: str) -> str:
    name = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(name) > 253 or "." not in name:
        raise ValueError("Expected a fully qualified domain name")
    labels = name.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Invalid domain label")
    if labels[-1].isdigit():
        raise ValueError("Invalid top-level domain")
    return name


def normalize_ioc(raw: str) -> tuple[str, IOCType]:
    value = raw.strip().replace("[.]", ".").replace("(.)", ".")
    value = re.sub(r"^hxxps:", "https:", value, flags=re.I)
    value = re.sub(r"^hxxp:", "http:", value, flags=re.I)
    value = value.replace("[:]", ":")
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Empty input or control characters")
    if len(value) > 8192:
        raise ValueError("IOC exceeds 8192 characters")
    try:
        if "%" in value:
            raise ValueError("Scoped addresses are not supported")
        ip = ipaddress.ip_address(value)
        return str(ip), IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]+", value) and len(value) in HASH_TYPES:
        return value.lower(), HASH_TYPES[len(value)]
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https", "ftp"} or not parts.hostname:
            raise ValueError("URL needs a supported scheme and hostname")
        if any(c.isspace() for c in value) or "\\" in value:
            raise ValueError("Invalid URL characters")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Credential-bearing URLs cannot be sent to external TI services")
        host = parts.hostname
        try:
            ip = ipaddress.ip_address(host)
            host = f"[{ip}]" if ip.version == 6 else str(ip)
        except ValueError:
            host = domain_name(host)
        port = parts.port  # Also validates invalid/out-of-range ports.
        netloc = host + (f":{port}" if port is not None else "")
        return urlunsplit(
            (parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment)
        ), IOCType.URL
    return domain_name(value), IOCType.DOMAIN


def detect_ioc_type(raw: str) -> IOCType:
    try:
        return normalize_ioc(raw)[1]
    except (ValueError, UnicodeError):
        return IOCType.UNKNOWN
