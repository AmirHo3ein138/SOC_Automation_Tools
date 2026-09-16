"""Serializable contracts. Collection status, threat evidence and policy stay separate."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum

from config import VERSION


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
    version: str = VERSION
    report_day: str | None = None
    reuse_key: str = ""
    reused: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        """Read versioned local records; malformed records are cache misses."""
        if not isinstance(data, dict) or data.get("version") != VERSION:
            raise ValueError("Unsupported report version")
        data = dict(data)
        for key in ("ioc", "ioc_type", "created_at", "report_day", "reuse_key"):
            if not isinstance(data.get(key), str):
                raise ValueError("Invalid report identity")
        datetime.fromisoformat(data["created_at"])
        context = NetworkContext(**data["context"])
        if not isinstance(context.warnings, list) or not all(
            isinstance(w, str) for w in context.warnings
        ):
            raise ValueError("Invalid context warnings")
        if not isinstance(context.infrastructure, list) or not all(
            isinstance(w, str) for w in context.infrastructure
        ):
            raise ValueError("Invalid infrastructure")
        if not isinstance(context.metadata, dict):
            raise ValueError("Invalid context metadata")
        results = [ProviderResult.from_dict(item) for item in data["results"]]
        for result in results:
            if (
                not isinstance(result.provider, str)
                or not isinstance(result.details, str)
                or not isinstance(result.evidence, dict)
            ):
                raise ValueError("Invalid source data")
        assessment = Assessment(**data["assessment"])
        if assessment.verdict not in {
            "HIGH_RISK",
            "SUSPICIOUS",
            "NO_KNOWN_THREAT",
            "INCONCLUSIVE",
            "UNKNOWN",
        }:
            raise ValueError("Invalid assessment")
        for key in (
            "applicable",
            "successful",
            "errors",
            "skipped",
            "cached",
            "positive",
            "percent",
        ):
            if type(assessment.coverage[key]) is not int or assessment.coverage[key] < 0:
                raise ValueError("Invalid coverage")
        if assessment.score is not None and (
            type(assessment.score) is not int or not 0 <= assessment.score <= 100
        ):
            raise ValueError("Invalid score")
        if not isinstance(assessment.recommendations, list) or not all(
            isinstance(x, str) for x in assessment.recommendations
        ):
            raise ValueError("Invalid recommendations")
        data.update(context=context, results=results, assessment=assessment)
        return cls(**data)
