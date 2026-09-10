"""Compact, append-free TXT reports: each scan gets an immutable, unique local file."""

import json
import os
import uuid
from pathlib import Path

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


def save_report(report, directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = report.created_at.replace(":", "").replace("+", "_")
    path = directory / f"{stamp}_{uuid.uuid4().hex[:12]}.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(compact(report))
    return path
