"""
detector.py

IOC Type Detection Engine
-------------------------
Author: Amirhossein Mousavi

Description:
Responsible for analyzing raw user input and accurately classifying it into a supported 
Indicator of Compromise (IOC) type: IPv4, Domain, URL, MD5, SHA1, or SHA256. It utilizes 
strict regular expressions and the built-in ipaddress module to ensure only valid data 
is passed to the upstream APIs.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum

class IOCType(str, Enum):
    IPV4 = "IPv4"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "Unknown"


_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://", "ftp://"))


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def detect_ioc_type(raw_value: str) -> IOCType:
    """
    Inspect the given string and classify it as one of the supported
    IOC types. Order of checks matters: hashes are unambiguous fixed-length
    hex strings, so they are checked before domain/URL/IP.
    """
    value = raw_value.strip()

    if not value:
        return IOCType.UNKNOWN

    if _is_url(value):
        return IOCType.URL

    if _is_ipv4(value):
        return IOCType.IPV4

    if _SHA256_RE.match(value):
        return IOCType.SHA256

    if _SHA1_RE.match(value):
        return IOCType.SHA1

    if _MD5_RE.match(value):
        return IOCType.MD5

    if _is_domain(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN
