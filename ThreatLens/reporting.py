"""Readable daily journals with validated embedded records for same-day reuse."""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from filelock import FileLock
from models import SUCCESS, ScanReport
from security import safe_text


def compact(report):
    a, c = report.assessment, report.context
    score = "N/A" if a.score is None else f"{a.score}/100"
    lines = [
        f"ThreatLens {report.version} | {report.created_at}",
        f"IOC: {report.ioc} | Type: {report.ioc_type}",
        f"Assessment: {a.verdict} | Evidence score: {score} (heuristic, not probability)",
        f"Coverage: {a.coverage['successful']}/{a.coverage['applicable']} successful; "
        f"{a.coverage['errors']} errors; {a.coverage['skipped']} skipped; {a.coverage['cached']} cached",
        f"Policy: {a.policy_version} | Network: {c.category} | Country: {c.country_code or 'unknown'} | "
        f"ISP: {c.isp or 'unknown'} | ASN: {c.asn or 'unknown'}",
    ]
    if c.organization:
        lines.append(
            "Organization: " + json.dumps(c.organization, ensure_ascii=False, sort_keys=True)
        )
    if c.infrastructure:
        lines.append("Infrastructure: " + ", ".join(c.infrastructure))
    if report.file_info:
        lines.append("File: " + json.dumps(report.file_info, ensure_ascii=False, sort_keys=True))
    if c.metadata:
        lines.append("Context: " + json.dumps(c.metadata, ensure_ascii=False, sort_keys=True))
    lines.extend("NOTICE: " + w for w in c.warnings)
    for r in report.results:
        metrics = json.dumps(r.evidence, ensure_ascii=False, sort_keys=True)
        lines.append(
            f"{r.provider} | {r.verdict.value} | {'CACHE' if r.cached else 'LIVE' if r.verdict.value not in {'SKIPPED', 'UNSUPPORTED'} else 'SKIP'} | "
            f"{r.details.replace(chr(10), ' ')} | metrics={metrics} | observed={r.observed_at or 'unknown'} | fetched={r.fetched_at}"
        )
    for item in a.contributions:
        if item["points"]:
            lines.append(
                f"EVIDENCE: {item['provider']} strength={item['strength']} reliability={item['reliability']} "
                f"freshness={item['freshness']} points={item['points']} group={item['group']}"
            )
    lines.extend(f"ACTION {i}: {r}" for i, r in enumerate(a.recommendations, 1))
    lines.append(f"Elapsed: {report.elapsed_seconds:.3f}s")
    return safe_text("\n".join(lines)) + "\n"


def local_day():
    return datetime.now().astimezone().date().isoformat()


def report_path(directory, ioc_type, day):
    category = {
        "IPv4": "IP",
        "IPv6": "IP",
        "MD5": "HASH",
        "SHA1": "HASH",
        "SHA256": "HASH",
        "Domain": "DOMAIN",
        "URL": "URL",
    }[ioc_type]
    return Path(directory) / f"ThreatLens_{category}_{day}.txt"


def reusable(report):
    return bool(report.results) and all(r.verdict in SUCCESS for r in report.results)


PREFIX = "THREATLENS_RECORD_V1 "


def record(report):
    payload = json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, allow_nan=False)
    envelope = {"sha256": hashlib.sha256(payload.encode()).hexdigest(), "payload": payload}
    return PREFIX + json.dumps(envelope, ensure_ascii=False) + "\n"


def load_report(directory, ioc, ioc_type, reuse_key, day=None):
    """Only the newest matching record in today's journal can be reused.

    Checksums detect accidental damage, not deliberate editing by a local user.
    Human-readable text is never parsed as an IOC index.
    """
    day = day or local_day()
    path = report_path(directory, ioc_type, day)
    if not path.is_file():
        return None
    latest = None
    with FileLock(str(path) + ".lock", timeout=5):
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.startswith(PREFIX):
                    continue
                try:
                    envelope = json.loads(line[len(PREFIX) :])
                    payload = envelope["payload"]
                    if hashlib.sha256(payload.encode()).hexdigest() != envelope["sha256"]:
                        continue
                    item = ScanReport.from_dict(json.loads(payload))
                    if (item.ioc, item.ioc_type, item.reuse_key, item.report_day) == (
                        ioc,
                        ioc_type,
                        reuse_key,
                        day,
                    ):
                        latest = item
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue
    if latest is not None and reusable(latest):
        latest.reused = True
        return latest
    return None


def save_report(report, directory: Path):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    report.report_day = report.report_day or local_day()
    path = report_path(directory, report.ioc_type, report.report_day)
    if report.reused:
        return path
    block = (
        "\n"
        + "=" * 78
        + "\n"
        + compact(report)
        + "--- Structured record (do not edit) ---\n"
        + record(report)
    )
    with FileLock(str(path) + ".lock", timeout=5):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
    return path
