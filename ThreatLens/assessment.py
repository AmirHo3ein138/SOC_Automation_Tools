"""Auditable heuristic evidence-v1. Scores are NOT calibrated probabilities."""

import math
from datetime import datetime, timezone

from models import POSITIVE, SUCCESS, Assessment, Verdict

RELIABILITY = {
    "VirusTotal": 0.95,
    "AbuseIPDB": 0.9,
    "AlienVault OTX": 0.65,
    "ThreatFox": 0.9,
    "URLhaus": 0.95,
    "MalwareBazaar": 0.98,
    "Pulsedive": 0.8,
}
GROUPS = {"ThreatFox": "abuse.ch", "URLhaus": "abuse.ch", "MalwareBazaar": "abuse.ch"}


def strength(result):
    e = result.evidence
    if result.verdict not in POSITIVE:
        return 0.0
    if result.provider == "VirusTotal":
        m, s, total = e["malicious"], e["suspicious"], e["total"]
        return min(100, 100 * (1 - math.exp(-(m + 0.4 * s) / 5)) * (0.65 + 0.35 * (m + s) / total))
    if result.provider == "AbuseIPDB":
        return max(10 if e["reports"] else 0, e["abuse_score"])
    if result.provider == "AlienVault OTX":
        return min(45, 10 + 10 * math.log2(1 + e["pulses"]))
    if result.provider == "ThreatFox":
        return 30 + 0.6 * e["confidence"]
    if result.provider == "URLhaus":
        return {"online": 90, "offline": 45, "unknown": 35}[e["status"]]
    if result.provider == "MalwareBazaar":
        return 98 if e["exact_sample"] else 0
    if result.provider == "Pulsedive":
        return {"critical": 95, "high": 80, "medium": 45, "low": 20, "retired": 20, "none": 0}[
            e["risk"]
        ]
    return 15  # Conservative uncalibrated signal for future adapters.


def freshness(observed_at, is_hash, now):
    if not observed_at:
        return 1.0, "unknown"
    try:
        date = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        date = date.replace(tzinfo=date.tzinfo or timezone.utc)
        days = (now - date).total_seconds() / 86400
        if days < -1:
            return 1.0, "future/invalid"
        days = max(0, days)
        # Hash identities persist; historical IP ownership is substantially less stable.
        half_life, floor = (730, 0.8) if is_hash else (90, 0.35)
        return max(floor, 2 ** (-days / half_life)), round(days, 1)
    except (ValueError, TypeError):
        return 1.0, "unknown"


def assess(results, context, ioc_type, now=None):
    now = now or datetime.now(timezone.utc)
    is_hash = ioc_type in {"MD5", "SHA1", "SHA256"}
    successful = sum(r.verdict in SUCCESS for r in results)
    applicable = len(results)
    coverage = {
        "applicable": applicable,
        "successful": successful,
        "errors": sum(r.verdict == Verdict.ERROR for r in results),
        "skipped": sum(r.verdict == Verdict.SKIPPED for r in results),
        "cached": sum(r.cached for r in results),
        "positive": sum(r.verdict in POSITIVE for r in results),
        "percent": round(100 * successful / applicable) if applicable else 0,
    }
    groups, contributions = {}, []
    for r in results:
        native = strength(r)
        decay, age = freshness(r.observed_at, is_hash, now)
        reliability = RELIABILITY.get(r.provider, 0.5)
        points = native * reliability * decay
        group = GROUPS.get(r.provider, r.provider)
        if points:
            groups.setdefault(group, []).append(points)
        contributions.append(
            {
                "provider": r.provider,
                "strength": round(native, 2),
                "reliability": reliability,
                "freshness": round(decay, 3),
                "age_days": age,
                "points": round(points, 2),
                "group": group,
            }
        )
    # Within a correlated family: strongest plus 25% of additional signals, capped at 100.
    pooled = sorted(
        (min(100, max(v) + 0.25 * (sum(v) - max(v))) for v in groups.values()), reverse=True
    )
    if pooled:
        score = pooled[0]
        # Diminishing support; do not assume sources are fully independent.
        for evidence in pooled[1:]:
            score += (100 - score) * (evidence / 100) * 0.5
        score = max(1, min(100, round(score)))
        verdict = "HIGH_RISK" if score >= 70 else "SUSPICIOUS"
    elif not successful:
        score, verdict = None, "UNKNOWN"
    else:
        score = 0
        verdict = "NO_KNOWN_THREAT" if successful == applicable else "INCONCLUSIVE"
    recommendations = recommend(verdict, context, is_hash)
    if coverage["errors"] or coverage["skipped"]:
        recommendations.append(
            "Coverage is incomplete: resolve skipped/failed sources and rerun; lack of data is not evidence of safety."
        )
    return Assessment(score, verdict, coverage, contributions, recommendations)


def recommend(verdict, context, is_hash):
    rec = []
    if not context.external_allowed:
        rec.append(
            "Use internal SIEM/EDR, DHCP/NAT/APN and asset records; external TI queries were skipped."
        )
    if context.organization:
        rec.append(
            "Organization asset: "
            + context.organization["label"]
            + ". Correlate TI with internal ownership, APN/NAT mappings and incident time."
        )
    if context.protected:
        if "ArvanCloud" in context.infrastructure:
            rec.append(
                "Do not block the ArvanCloud shared IP. Investigate the specific domain/URL, application and affected hosts."
            )
        else:
            rec.append(
                "Do not block this protected organization/APN IP. Coordinate scoped containment with its service owner."
            )
    if context.country_code == "IR":
        rec.append(
            f"Iranian ISP: {context.isp or 'unknown'} (ASN {context.asn or 'unknown'}). Check shared subscribers and domestic service impact."
        )
    if verdict == "HIGH_RISK":
        if is_hash:
            rec.append(
                "Quarantine matching files and investigate affected hosts; consider a hash-based EDR block after validation."
            )
        elif context.external_allowed and not context.protected:
            if context.category == "public":
                rec.append(
                    "Block this IP according to the incident workflow; foreign CDN/cloud membership does not exempt it from blocking."
                )
            else:
                rec.append(
                    "Block the specific domain/URL according to the incident workflow; investigate affected hosts."
                )
        rec.extend(
            [
                "Search historical logs and validate the IOC against current activity.",
                "Record evidence and escalate the incident.",
            ]
        )
    elif verdict == "SUSPICIOUS":
        rec.extend(
            [
                "Investigate the positive evidence manually; correlate timestamps and affected assets.",
                "Monitor related activity and use scoped containment if corroborated.",
            ]
        )
    else:
        rec.append(
            "Do not close the investigation solely on this result. Review internal telemetry and IOC context."
        )
    return rec
