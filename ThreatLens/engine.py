"""UI-free scan orchestration: local policy -> concurrent collection -> assessment."""

import hashlib
import ipaddress
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from assessment import assess
from config import VERSION
from detector import IOCType, normalize_ioc
from enrichment import enrich_domain, enrich_ip
from models import SUCCESS, ProviderResult, ScanReport, Verdict, utcnow
from network import CloudRegistry, apply_network_policy, local_context
from organization import Organization
from providers.manager import build_all_providers
from reporting import load_report, local_day
from security import sanitize, sensitive_url
from storage import Cache
from transport import LookupFailure, Transport
from utils import calculate_file_hashes

logger = logging.getLogger("threatlens")


class Scanner:
    def __init__(self, config, *, providers=None, cache=None, organization=None):
        self.config = config
        # A malformed policy fails before cache initialization or external lookups.
        self.organization = (
            organization if organization is not None else Organization(config.org_file)
        )
        self.cache = cache if cache is not None else Cache(config.data_dir, not config.no_cache)
        self.providers = providers if providers is not None else build_all_providers(config)
        self.clouds = CloudRegistry(self.cache, config.offline, config.timeout)

    def _query(self, provider, ioc_type, ioc, external_allowed, day=None, refresh=False):
        if not external_allowed:
            return ProviderResult(
                provider.name,
                Verdict.SKIPPED,
                "External lookup disabled by local policy",
                error_code="local_policy",
            )
        identity = ioc_type.value + ":" + ioc
        namespace = "provider-v3:" + (day or local_day()) + ":" + provider.name
        entry = None if refresh else self.cache.get(namespace, identity)
        if entry:
            try:
                result = ProviderResult.from_dict(entry["value"])
                if result.provider == provider.name and result.verdict in SUCCESS:
                    result.cached = True
                    return result
            except (ValueError, TypeError, KeyError):
                pass
        if self.config.offline:
            return ProviderResult(
                provider.name,
                Verdict.SKIPPED,
                "Offline: no fresh cached result",
                error_code="offline",
            )
        try:
            result = provider.collect(ioc_type, ioc)
            if not isinstance(result, ProviderResult) or result.provider != provider.name:
                raise ValueError("Invalid provider result")
            # Sanitize the entire normalized payload before persistence or presentation.
            result = ProviderResult.from_dict(sanitize(result.to_dict(), self.config.secrets))
        except Exception:
            logger.error(
                "Provider failed: %s (details omitted to protect credentials)", provider.name
            )
            return ProviderResult(
                provider.name,
                Verdict.ERROR,
                "Unexpected provider failure",
                error_code="provider_failure",
            )
        if result.verdict in SUCCESS:
            ttl = (
                self.config.negative_ttl
                if result.verdict in {Verdict.NOT_FOUND, Verdict.NO_HIT}
                else self.config.cache_ttl
            )
            self.cache.put(namespace, identity, result.to_dict(), ttl)
        return result

    def _context(self, context, ioc, ioc_type, refresh=False):
        if not context.external_allowed:
            return apply_network_policy(context)
        if not self.config.enrichment:
            context.warnings.append(
                "External context enrichment disabled; cloud/ISP ownership may be unknown"
            )
            return apply_network_policy(context)
        if context.address:
            clouds = (
                CloudRegistry(
                    Cache(self.config.data_dir, False), self.config.offline, self.config.timeout
                )
                if refresh
                else self.clouds
            )
            names, warnings = clouds.lookup(context.address)
            context.infrastructure.extend(names)
            context.warnings.extend(warnings)
            try:
                data, meta = self._cached_context(
                    "ip-context-v1",
                    context.address,
                    lambda: enrich_ip(context.address, Transport(self.config.timeout)),
                    refresh=refresh,
                )
                context.country_code = context.country_code or data["country_code"]
                context.isp = context.isp or data["isp"]
                context.asn = data["asn"]
                context.metadata["ip_context"] = meta
            except (LookupFailure, KeyError, ValueError, TypeError):
                context.warnings.append(
                    "IP country/ISP context unavailable; domestic/foreign classification may be unknown"
                )
        else:
            domain = urlsplit(ioc).hostname if ioc_type == IOCType.URL else ioc
            if ioc_type in {IOCType.DOMAIN, IOCType.URL} and self.config.whois_api_key:
                try:
                    ipaddress.ip_address(domain)
                except ValueError:
                    try:
                        data, meta = self._cached_context(
                            "whois-v1",
                            domain,
                            lambda: enrich_domain(
                                domain, self.config.whois_api_key, Transport(self.config.timeout)
                            ),
                            refresh=refresh,
                        )
                        context.metadata["whois"] = {"data": data, **meta}
                    except (LookupFailure, ValueError, TypeError):
                        context.warnings.append("WHOIS context unavailable")
        return apply_network_policy(context)

    def _cached_context(self, namespace, key, loader, refresh=False):
        entry = None if refresh else self.cache.get(namespace, key)
        if entry:
            return entry["value"], {"cached": True, "saved_at_epoch": entry["saved"]}
        if self.config.offline:
            raise LookupFailure("offline", "No cached context")
        payload = loader()
        payload = sanitize(payload, self.config.secrets)
        self.cache.put(namespace, key, payload, self.config.context_ttl)
        return payload, {"cached": False, "fetched_at": utcnow()}

    def scan(self, value, *, file=False, report_directory=None, refresh=False):
        started = time.monotonic()
        day = local_day()
        if refresh and self.config.offline:
            raise ValueError("--refresh cannot be combined with --offline")
        file_info = calculate_file_hashes(value) if file else None
        ioc, ioc_type = normalize_ioc(file_info["sha256"] if file else value)
        context = local_context(ioc, ioc_type, self.organization)
        if ioc_type == IOCType.DOMAIN and ioc.endswith(
            (".local", ".internal", ".localhost", ".lan", ".home", ".test", ".invalid")
        ):
            context.external_allowed = False
            context.warnings.append("Internal/special-use domain: external lookups skipped")
        if ioc_type == IOCType.URL and sensitive_url(ioc):
            raise ValueError(
                "URL contains a potentially sensitive query/fragment; remove secrets before scanning"
            )
        applicable = [p for p in self.providers if ioc_type in p.SUPPORTED_TYPES]
        scope = {
            "version": VERSION,
            "organization": [(str(net), rule) for net, rule in self.organization.rules],
            "providers": [(p.name, bool(getattr(p, "api_key", None))) for p in applicable],
            "enrichment": self.config.enrichment,
            "whois": bool(self.config.whois_api_key),
            "external_allowed": context.external_allowed,
        }
        reuse_key = hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()
        if report_directory is not None and not refresh and not self.config.no_cache:
            previous = load_report(report_directory, ioc, ioc_type.value, reuse_key, day)
            if previous is not None:
                # A file path is not its identity: always hash current bytes first.
                previous.file_info = file_info
                return previous
        # Local organization lookup has already completed before either collection task starts.
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(applicable) + 1))) as pool:
            context_future = pool.submit(self._context, context, ioc, ioc_type, refresh)
            pending = [
                pool.submit(self._query, p, ioc_type, ioc, context.external_allowed, day, refresh)
                for p in applicable
            ]
            results = [f.result() for f in pending]
            try:
                context = context_future.result()
            except Exception:
                context.warnings.append(
                    "Context collection failed; threat results are still available"
                )
                context = apply_network_policy(context)
        assessment = assess(results, context, ioc_type.value)
        return ScanReport(
            ioc,
            ioc_type.value,
            context,
            results,
            assessment,
            file_info,
            elapsed_seconds=round(time.monotonic() - started, 3),
            report_day=day,
            reuse_key=reuse_key,
        )
