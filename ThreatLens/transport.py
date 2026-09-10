"""Bounded retries, response sizes, TLS and per-source cooldowns; no raw error URLs."""

import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests


class LookupFailure(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


class Transport:
    def __init__(self, timeout=12, retries=1, min_interval=0):
        self.timeout = timeout
        self.retries = retries
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._next = 0.0
        self._cooldown = 0.0

    def _gate(self):
        with self._lock:
            now = time.monotonic()
            if now < self._cooldown:
                raise LookupFailure(
                    "rate_limited", "Source is in a rate-limit cooldown; retry later"
                )
            delay = max(0, self._next - now)
            self._next = max(now, self._next) + self.min_interval
        if delay:
            time.sleep(delay)

    def request(
        self, method, url, *, json_body=None, data=None, params=None, headers=None, text=False
    ):
        if not url.startswith("https://"):
            raise LookupFailure("insecure_endpoint", "HTTPS is required")
        for attempt in range(self.retries + 1):
            self._gate()
            try:
                with requests.request(
                    method,
                    url,
                    json=json_body,
                    data=data,
                    params=params,
                    headers=headers,
                    timeout=(self.timeout, self.timeout),
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    status = response.status_code
                    if status == 429:
                        retry = response.headers.get("Retry-After", "60")
                        try:
                            seconds = float(retry)
                        except ValueError:
                            try:
                                seconds = (
                                    parsedate_to_datetime(retry) - datetime.now(timezone.utc)
                                ).total_seconds()
                            except (TypeError, ValueError):
                                seconds = 60
                        with self._lock:
                            self._cooldown = time.monotonic() + max(1, min(seconds, 86400))
                        raise LookupFailure(
                            "rate_limited", "HTTP 429: source quota exceeded; retry later"
                        )
                    if status in (401, 403):
                        raise LookupFailure(
                            "authentication",
                            f"HTTP {status}: check API key and account permissions",
                        )
                    if status == 404:
                        raise LookupFailure("not_found", "HTTP 404: no report found")
                    if status >= 500 and attempt < self.retries:
                        time.sleep(0.25 * (attempt + 1))
                        continue
                    if status != 200:
                        raise LookupFailure("http_error", f"Unexpected HTTP status {status}")
                    body = bytearray()
                    started = time.monotonic()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > 10_000_000:
                            raise LookupFailure("response_size", "Response exceeds 10 MB")
                        if time.monotonic() - started > self.timeout:
                            raise LookupFailure("timeout", "Response read deadline exceeded")
                    decoded = body.decode("utf-8-sig")
                    if text:
                        return decoded
                    import json

                    return json.loads(decoded)
            except LookupFailure:
                raise
            except (requests.Timeout, requests.ConnectionError):
                if attempt < self.retries:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise LookupFailure("network", "Connection failed or timed out") from None
            except requests.RequestException:
                raise LookupFailure("network", "Request failed") from None
            except (ValueError, UnicodeError):
                raise LookupFailure("invalid_response", "Invalid JSON or text encoding") from None
        raise LookupFailure("network", "Request failed")
