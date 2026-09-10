"""Serializable contracts. Collection status, threat evidence and policy stay separate."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    FOUND = "FOUND"
    NO_HIT = "NO_HIT"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"


SUCCESS = {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND, Verdict.NO_HIT, Verdict.NOT_FOUND}
POSITIVE = {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND}


@dataclass
class ProviderResult:
    provider: str
    verdict: Verdict
    details: str
    evidence: dict = field(default_factory=dict)
    observed_at: str | None = None
    fetched_at: str = field(default_factory=utcnow)
    cached: bool = False
    error_code: str | None = None
    source_url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        data = dict(data)
        data["verdict"] = Verdict(data["verdict"])
        return cls(**data)


@dataclass
class NetworkContext:
    address: str | None = None
    category: str = "not_applicable"
    organization: dict | None = None
    country_code: str | None = None
    isp: str | None = None
    asn: str | None = None
    infrastructure: list[str] = field(default_factory=list)
    protected: bool = False
    external_allowed: bool = True
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class Assessment:
    score: int | None
    verdict: str
    coverage: dict
    contributions: list[dict]
    recommendations: list[str]
    policy_version: str = "evidence-v1"


@dataclass
class ScanReport:
    ioc: str
    ioc_type: str
    context: NetworkContext
    results: list[ProviderResult]
    assessment: Assessment
    file_info: dict | None = None
    created_at: str = field(default_factory=utcnow)
    elapsed_seconds: float = 0
    version: str = "2.1.0"

    def to_dict(self) -> dict:
        return asdict(self)
