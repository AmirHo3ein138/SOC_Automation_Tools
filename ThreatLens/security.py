"""Safe diagnostics: never interpolate request URLs, headers or credentials in errors."""

import re
from enum import Enum
from urllib.parse import parse_qsl, urlsplit

SENSITIVE = {
    "key",
    "apikey",
    "api_key",
    "api-key",
    "token",
    "access_token",
    "auth",
    "authorization",
    "password",
    "secret",
    "signature",
    "sig",
    "credential",
}


def secret_parameter(name: str) -> bool:
    lower = name.lower()
    return lower in SENSITIVE or any(
        x in lower for x in ("token", "secret", "password", "credential", "signature")
    )


def sensitive_url(value: str) -> bool:
    p = urlsplit(value)
    return bool(
        p.username
        or p.password
        or any(secret_parameter(k) for k, _ in parse_qsl(p.query + "&" + p.fragment))
    )


def safe_text(value: object, secrets=()) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(
        r"(?i)((?:api[_-]?key|access_token|token|password|secret|key)=)[^&\s]+",
        r"\1[REDACTED]",
        text,
    )
    return "".join(
        c if c in "\n\t" or (ord(c) >= 32 and ord(c) != 127 and not 0x80 <= ord(c) < 0xA0) else "?"
        for c in text
    )


def sanitize(value, secrets=()):
    """Recursively redact text without changing metric types or JSON escaping."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str):
        return safe_text(value, secrets)
    if isinstance(value, dict):
        return {key: sanitize(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, secrets) for item in value]
    return value
