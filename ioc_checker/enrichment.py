"""
enrichment.py

Context & Infrastructure Enrichment Module
------------------------------------------
Author: Amirhossein Mousavi

Description:
Provides crucial contextual data for IOCs to reduce false positives during analysis. 
This module identifies known CDN/Cloud infrastructures (e.g., ArvanCloud, Cloudflare) 
to warn analysts against scanning shared WAF IPs. It also handles domain WHOIS lookups 
(intelligently parsing ccTLDs via regex fallbacks) and retrieves ASN/ISP data for IPs.
"""

import json
import logging
import os
import ipaddress
import requests
from datetime import datetime

logger = logging.getLogger("ioc_checker")

CACHE_FILE = "cdn_subnets.json"
CACHE_AGE_LIMIT = 86400

ARVAN_URL = "https://www.arvancloud.ir/en/ips.txt"
CF_URL = "https://www.cloudflare.com/ips-v4"

def _download_cdn_ips() -> dict:
    subnets = {"ArvanCloud": [], "Cloudflare": []}
    try:
        arvan_resp = requests.get(ARVAN_URL, timeout=10)
        if arvan_resp.ok:
            subnets["ArvanCloud"] = [line.strip() for line in arvan_resp.text.splitlines() if line.strip()]
            
        cf_resp = requests.get(CF_URL, timeout=10)
        if cf_resp.ok:
            subnets["Cloudflare"] = [line.strip() for line in cf_resp.text.splitlines() if line.strip()]
    except requests.RequestException as exc:
        logger.error("Failed to fetch CDN lists: %s", exc)
    return subnets

def update_cdn_cache_if_needed():
    needs_update = True
    if os.path.exists(CACHE_FILE):
        file_age = datetime.now().timestamp() - os.path.getmtime(CACHE_FILE)
        if file_age < CACHE_AGE_LIMIT:
            needs_update = False
    if needs_update:
        data = _download_cdn_ips()
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

def check_cdn(ip_str: str) -> str | None:
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for cdn_name, cidr_list in data.items():
            for cidr in cidr_list:
                try:
                    if ip_obj in ipaddress.IPv4Network(cidr):
                        return cdn_name
                except ValueError:
                    continue
    except Exception as exc:
        logger.error("Error checking CDN for %s: %s", ip_str, exc)
    return None

def _is_cloud(values: list[str]) -> bool:
    """Check if any of the values contain 'cloud' (case-insensitive)."""
    return any("cloud" in str(val).lower() for val in values if val)

def enrich_ip(ip: str) -> tuple[dict, bool, str | None]:
    """Returns (data_dict, is_cloud_provider, error_message)"""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("status") == "fail":
            err = data.get("message", "API fail status")
            logger.error("IP-API error for %s: %s", ip, err)
            return {}, False, err

        isp = data.get("isp", "Unknown")
        org = data.get("org", "Unknown")
        asn = data.get("as", "Unknown")
        
        result = {
            "Country": data.get("country", "Unknown"),
            "ISP": isp,
            "Organization": org,
            "ASN": asn
        }
        return result, _is_cloud([isp, org, asn]), None

    except requests.RequestException as exc:
        logger.error("IP enrichment request failed: %s", exc)
        return {}, False, f"HTTP Error: {exc}"

import tldextract
import requests
import logging

logger = logging.getLogger("ioc_checker")

def enrich_domain(domain: str, api_key: str | None) -> tuple[dict, bool, str | None]:
    """Returns (data_dict, is_cloud_provider, error_message)"""
    if not api_key:
        return {}, False, "WHOIS_API_KEY not configured in .env"
        
    # Extract root domain intelligently (e.g., rnwm.fpewppc.cn -> fpewppc.cn)
    ext = tldextract.extract(domain)
    root_domain = f"{ext.domain}.{ext.suffix}"
    if not root_domain or not ext.suffix:
        root_domain = domain
        
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json"
    }
        
    try:
        url = f"https://api.who.is/v1/whois/{root_domain}"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        # Extract payload
        payload = data.get("payload", data)
        
        # 1. Extract Registrar
        registrar = payload.get("registrar", "Unknown")
        if isinstance(registrar, dict):
            registrar = registrar.get("name", "Unknown")
            
        # 2. Extract Dates (Standard fields)
        created = payload.get("created") or payload.get("registered") or "Unknown"
        updated = payload.get("updated", "Unknown")
        expires = payload.get("expires") or payload.get("expiration") or "Unknown"
        
        # Fallback: Extract dates from 'events' array (used by ccTLDs like .cn)
        events = payload.get("events", [])
        if isinstance(events, list):
            for event in events:
                action = str(event.get("event_action", "")).lower()
                date_val = event.get("event_date", "Unknown")
                
                if action == "registration" and created == "Unknown":
                    created = date_val
                elif action == "expiration" and expires == "Unknown":
                    expires = date_val
                elif action in ["last changed", "updated"] and updated == "Unknown":
                    updated = date_val
                    
        # 3. Extract Email
        email = "Unknown"
        contacts = payload.get("contacts", {})
        if isinstance(contacts, dict):
            # Check registrant first (common in ccTLDs)
            if "registrant" in contacts and isinstance(contacts["registrant"], dict):
                email = contacts["registrant"].get("email", "Unknown")
            # Fallback to admin
            elif email == "Unknown" and "admin" in contacts and isinstance(contacts["admin"], dict):
                email = contacts["admin"].get("email", "Unknown")
        elif isinstance(contacts, list) and len(contacts) > 0:
            email = contacts[0].get("email", "Unknown")
            
        result = {
            "Root Domain": root_domain,
            "Registrar": registrar,
            "Creation Date": created,
            "Updated Date": updated,
            "Expiration Date": expires,
            "Contact Email": email
        }
        
        # Check for the presence of the word 'cloud' in registrar or email
        return result, _is_cloud([registrar, email]), None

    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 401:
            err_msg = "Unauthorized: Invalid or expired API Key."
        elif status == 404:
            err_msg = "Domain not found in WHOIS database."
        else:
            err_msg = f"HTTP Error: {status}"
            
        logger.error("who.is API error for %s: %s", root_domain, exc)
        return {}, False, err_msg
        
    except requests.RequestException as exc:
        logger.error("Domain WHOIS request failed: %s", exc)
        return {}, False, f"Connection Error: {exc}"
    except Exception as exc:
        logger.error("Unexpected parsing error: %s", exc)
        return {}, False, "Unexpected response format"