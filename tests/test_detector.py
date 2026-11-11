"""
Basic unit tests. Run with:  pytest tests/
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from deobfuscate import normalize, is_ip_address, percent_decode
from features import extract_features, score


def test_percent_decode_simple():
    assert percent_decode("%68%74%74%70") == "http"


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("google.com") is False


def test_userinfo_trick_detected():
    result = normalize("http://paypal.com@evil.net/login")
    assert result["has_userinfo_trick"] is True
    assert result["host"] == "evil.net"


def test_ip_host_flagged_high_risk():
    normalized = normalize("http://192.168.1.5/login")
    feats = extract_features(normalized)
    result = score(feats)
    assert result["score"] >= 25
    assert "IP" in " ".join(result["reasons"]) or any("IP" in r for r in result["reasons"])


def test_clean_url_scores_low():
    normalized = normalize("https://www.wikipedia.org/wiki/Phishing")
    feats = extract_features(normalized)
    result = score(feats)
    assert result["score"] < 20
    assert result["verdict"] == "LIKELY SAFE"


def test_brand_typosquat_detected():
    normalized = normalize("http://paypa1-secure.com/login")
    feats = extract_features(normalized)
    assert len(feats["brand_flags"]) > 0


def test_shortener_flagged():
    normalized = normalize("http://bit.ly/3xample")
    feats = extract_features(normalized)
    assert feats["is_known_shortener"] is True
