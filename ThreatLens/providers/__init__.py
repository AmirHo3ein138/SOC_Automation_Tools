"""Explicit provider contract; unsupported methods do not need repeated implementations."""

import math
from datetime import datetime, timezone

from models import ProviderResult, Verdict
from security import safe_text
from transport import LookupFailure, Transport


def number(data, key, *, maximum=None):
    value = data[key]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError("Invalid numeric metric")
    if maximum is not None and value > maximum:
        raise ValueError("Metric out of range")
    return value


def timestamp(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        date = datetime.fromisoformat(str(value).replace(" UTC", "+00:00").replace("Z", "+00:00"))
        return date.replace(tzinfo=date.tzinfo or timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class BaseProvider:
    name = "BaseProvider"
    SUPPORTED_TYPES = set()
    HTTP_404_IS_MISS = False

    def __init__(self, api_key=None, timeout=12, transport=None):
        self.api_key = api_key
        self.transport = transport or Transport(timeout)

    def collect(self, ioc_type, ioc):
        if ioc_type not in self.SUPPORTED_TYPES:
            return ProviderResult(self.name, Verdict.UNSUPPORTED, "IOC type not supported")
        if not self.api_key:
            return ProviderResult(
                self.name, Verdict.SKIPPED, "API key not configured", error_code="unconfigured"
            )
        try:
            result = self.lookup(ioc_type, ioc)
            result.details = safe_text(result.details, [self.api_key])
            return result
        except LookupFailure as exc:
            verdict = (
                Verdict.NOT_FOUND
                if exc.code == "not_found" and self.HTTP_404_IS_MISS
                else Verdict.ERROR
            )
            return ProviderResult(self.name, verdict, str(exc), error_code=exc.code)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError):
            return ProviderResult(
                self.name,
                Verdict.ERROR,
                "Unexpected response format",
                error_code="invalid_response",
            )

    def lookup(self, ioc_type, ioc):
        raise NotImplementedError

    def result(self, verdict, details, evidence=None, observed=None, source_url=None):
        return ProviderResult(
            self.name, verdict, details, evidence or {}, timestamp(observed), source_url=source_url
        )
