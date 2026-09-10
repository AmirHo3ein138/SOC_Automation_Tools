"""Local organization rules, validated before any IOC leaves the process."""

import ipaddress
import json
from pathlib import Path


class Organization:
    def __init__(self, path: Path | None = None):
        self.name = "Unconfigured organization"
        self.rules = []
        if path is None:
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise ValueError("Organization file must use schema_version 1")
        self.name = data.get("organization", "Organization")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("organization must be a non-empty name")
        entries = data.get("networks")
        if not isinstance(entries, list):
            raise ValueError("networks must be a list")
        seen = set()
        allowed = {
            "cidr",
            "label",
            "kind",
            "protect",
            "external_lookup",
            "notes",
            "country_code",
            "isp",
        }
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) - allowed:
                raise ValueError("Unknown or invalid organization network fields")
            network = ipaddress.ip_network(entry.get("cidr", ""), strict=True)
            if str(network) in seen:
                raise ValueError("Duplicate organization network: " + str(network))
            seen.add(str(network))
            for key in ("protect", "external_lookup"):
                if key in entry and not isinstance(entry[key], bool):
                    raise ValueError(key + " must be a JSON boolean")
            if not isinstance(entry.get("label"), str) or not entry["label"].strip():
                raise ValueError("Every organization network needs a label")
            if entry.get("kind", "asset") not in {"asset", "apn", "critical", "internal"}:
                raise ValueError("Invalid network kind")
            for key in ("notes", "isp", "country_code"):
                if key in entry and not isinstance(entry[key], str):
                    raise ValueError(key + " must be text")
            if entry.get("country_code") and (
                len(entry["country_code"]) != 2 or not entry["country_code"].isalpha()
            ):
                raise ValueError("country_code must be a two-letter code")
            rule = {
                "kind": "asset",
                "protect": True,
                "external_lookup": True,
                **entry,
                "cidr": str(network),
                "organization": self.name,
            }
            self.rules.append((network, rule))
        self.rules.sort(key=lambda item: item[0].prefixlen, reverse=True)

    def match(self, address):
        address = ipaddress.ip_address(address)
        return next(
            (
                dict(rule)
                for network, rule in self.rules
                if address.version == network.version and address in network
            ),
            None,
        )
