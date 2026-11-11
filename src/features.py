"""
features.py
------------
Extracts heuristic phishing-indicator features from a normalized URL
(see deobfuscate.normalize) and produces a risk score + verdict.

This is a transparent, explainable rule-based scorer on purpose:
for a portfolio project, "here's exactly why it flagged this" is
more valuable than a black-box ML model you can't explain in an
interview.
"""

import re
import math
from difflib import SequenceMatcher

# Common high-value brands attackers impersonate. Extend as you like.
BRAND_TARGETS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
    "dhl", "fedex", "coinbase", "binance", "outlook", "office365",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "ga", "cf", "work",
    "click", "link", "country", "stream", "download",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
}

SENSITIVE_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "signin",
    "banking", "confirm", "password", "suspend", "unlock", "billing",
]


def shannon_entropy(s: str) -> float:
    """Higher entropy = more random-looking string (common in auto-generated phishing domains)."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def brand_similarity_flags(host: str) -> list:
    """
    Flags lookalike / typosquatted brand names, e.g. 'paypa1.com',
    'micros0ft-support.com'. Uses simple fuzzy string similarity
    rather than an exact match so near-misses are still caught.
    """
    flags = []
    host_core = re.sub(r"\.(com|net|org|co|io|info|biz).*$", "", host)
    # also check individual hyphen/dot-separated tokens, since typosquats
    # often live in one segment, e.g. "paypa1-secure-login.com"
    tokens = re.split(r"[.\-]", host_core)

    for brand in BRAND_TARGETS:
        if brand in host_core:
            # exact brand present but NOT as the registrable domain itself
            # e.g. "paypal-secure-login.com" contains "paypal" but isn't paypal.com
            if not host.endswith(f".{brand}.com") and host_core != brand:
                flags.append(f"contains brand name '{brand}' but is not the official domain")
            continue

        best_ratio = SequenceMatcher(None, brand, host_core).ratio()
        best_token = host_core
        for tok in tokens:
            if not tok:
                continue
            r = SequenceMatcher(None, brand, tok).ratio()
            if r > best_ratio:
                best_ratio, best_token = r, tok

        if best_ratio > 0.75:
            flags.append(
                f"looks very similar to brand '{brand}' (segment '{best_token}', similarity {best_ratio:.2f})"
            )
    return flags


def extract_features(normalized: dict) -> dict:
    """Takes the dict from deobfuscate.normalize() and computes all features."""
    url = normalized["normalized_url"]
    host = normalized["host"]
    path = normalized.get("path", "") or ""
    query = normalized.get("query", "") or ""

    subdomain_count = max(host.count(".") - 1, 0)
    tld = host.split(".")[-1] if "." in host else ""

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "subdomain_count": subdomain_count,
        "is_ip_host": normalized["is_ip_host"],
        "has_userinfo_trick": normalized["has_userinfo_trick"],
        "is_punycode": normalized["is_punycode"],
        "homograph_suspected": normalized["homograph_suspected"],
        "was_percent_encoded": normalized["was_percent_encoded"],
        "uses_https": normalized["scheme"] == "https",
        "has_at_symbol": "@" in normalized["original_url"],
        "has_hyphen_in_host": "-" in host,
        "digit_ratio_in_host": sum(c.isdigit() for c in host) / len(host) if host else 0,
        "host_entropy": round(shannon_entropy(host), 2),
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "is_known_shortener": host in SHORTENER_DOMAINS,
        "sensitive_keyword_hits": [kw for kw in SENSITIVE_KEYWORDS if kw in (path + query).lower()],
        "brand_flags": brand_similarity_flags(host),
        "excessive_subdomains": subdomain_count >= 3,
        "long_url": len(url) > 75,
    }
    return features


def score(features: dict) -> dict:
    """
    Converts features into a weighted risk score (0-100) and verdict.
    Weights are intentionally transparent and tunable — this is the
    part worth experimenting with and writing up in your README.
    """
    points = 0
    reasons = []

    def add(cond, weight, reason):
        nonlocal points
        if cond:
            points += weight
            reasons.append(f"+{weight}: {reason}")

    add(features["is_ip_host"], 25, "host is a raw IP address instead of a domain name")
    add(features["has_userinfo_trick"], 25, "URL uses '@' to disguise the real destination host")
    add(features["homograph_suspected"], 30, "punycode host decodes to non-ASCII lookalike characters (homograph attack)")
    add(features["was_percent_encoded"], 10, "URL was percent/hex encoded")
    add(not features["uses_https"], 8, "no HTTPS")
    add(features["suspicious_tld"], 12, "uses a TLD commonly abused for phishing")
    add(features["is_known_shortener"], 15, "URL shortener hides the real destination")
    add(features["excessive_subdomains"], 15, "excessive subdomains (common cloaking technique)")
    add(features["long_url"], 5, "unusually long URL")
    add(features["host_entropy"] > 4.0, 10, "high entropy / random-looking domain name")
    add(len(features["sensitive_keyword_hits"]) > 0, 10,
        f"sensitive keywords in path/query: {features['sensitive_keyword_hits']}")
    add(len(features["brand_flags"]) > 0, 25,
        "brand impersonation suspected: " + "; ".join(features["brand_flags"]))

    points = min(points, 100)

    if points >= 60:
        verdict = "PHISHING (high confidence)"
    elif points >= 30:
        verdict = "SUSPICIOUS (review manually)"
    else:
        verdict = "LIKELY SAFE"

    return {"score": points, "verdict": verdict, "reasons": reasons}
