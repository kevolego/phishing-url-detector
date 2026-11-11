"""
deobfuscate.py
---------------
Normalizes a URL before feature extraction so obfuscation tricks don't
let a phishing URL slip past the detector undetected.

Handles:
  - Percent / hex encoding            (%68%74%74%70 -> http)
  - Punycode / IDN homograph domains  (xn--pple-43d.com -> (a)pple.com)
  - Userinfo ("@") tricks             (http://real.com@evil.com -> evil.com is the real host)
  - Excess whitespace / control chars
  - Mixed-case scheme/host normalization
"""

import re
import socket
from urllib.parse import urlsplit, unquote, urlunsplit

try:
    import idna
    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False


def percent_decode(url: str, max_passes: int = 3) -> str:
    """Repeatedly percent-decode in case of double/triple encoding."""
    decoded = url
    for _ in range(max_passes):
        new_decoded = unquote(decoded)
        if new_decoded == decoded:
            break
        decoded = new_decoded
    return decoded


def strip_control_chars(url: str) -> str:
    """Remove zero-width spaces, tabs, newlines that can confuse parsers."""
    return re.sub(r"[\u200B-\u200F\u202A-\u202E\t\r\n]", "", url).strip()


def extract_real_host_from_userinfo(url: str) -> dict:
    """
    Detects the classic `http://trusted-looking.com@evil.com/path` trick.
    Returns info about whether a userinfo '@' was used to disguise the host.
    """
    parts = urlsplit(url)
    netloc = parts.netloc
    result = {"has_userinfo_trick": False, "displayed_before_at": None, "real_host": parts.hostname}

    if "@" in netloc:
        before_at, _, after_at = netloc.rpartition("@")
        result["has_userinfo_trick"] = True
        result["displayed_before_at"] = before_at
        # the REAL host is whatever comes after the last @ (before any port)
        real_host = after_at.split(":")[0]
        result["real_host"] = real_host

    return result


def decode_punycode_host(host: str) -> str:
    """
    Converts punycode (xn--...) back to Unicode so homograph tricks
    (Cyrillic 'а' vs Latin 'a', etc.) are visible to the scorer.
    """
    if not host:
        return host
    try:
        if HAS_IDNA:
            return idna.decode(host)
        else:
            return host.encode().decode("idna")
    except Exception:
        return host  # not punycode, or decode failed; leave as-is


def is_ip_address(host: str) -> bool:
    """True if the host is a raw IPv4/IPv6 address instead of a domain name."""
    if not host:
        return False
    try:
        socket.inet_aton(host)
        return True
    except (OSError, socket.error):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (OSError, socket.error):
        return False


def normalize(raw_url: str) -> dict:
    """
    Main entry point. Takes a raw, possibly-obfuscated URL string and
    returns a dict with the cleaned URL plus flags describing what
    obfuscation (if any) was detected. Downstream feature extraction
    should use this dict instead of the raw string.
    """
    original = raw_url
    url = strip_control_chars(raw_url)
    url = percent_decode(url)

    # Add a scheme if missing so urlsplit parses the host correctly
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url

    userinfo_info = extract_real_host_from_userinfo(url)
    parts = urlsplit(url)
    host = userinfo_info["real_host"] or parts.hostname or ""

    decoded_host = decode_punycode_host(host)
    is_punycode = host.startswith("xn--") or ".xn--" in host
    homograph_suspected = is_punycode and decoded_host != host and any(
        ord(ch) > 127 for ch in decoded_host
    )

    return {
        "original_url": original,
        "normalized_url": urlunsplit(parts),
        "host": host.lower(),
        "decoded_host": decoded_host,
        "is_punycode": is_punycode,
        "homograph_suspected": homograph_suspected,
        "has_userinfo_trick": userinfo_info["has_userinfo_trick"],
        "displayed_before_at": userinfo_info["displayed_before_at"],
        "is_ip_host": is_ip_address(host),
        "was_percent_encoded": original != unquote(original),
        "path": parts.path,
        "query": parts.query,
        "scheme": parts.scheme,
    }


if __name__ == "__main__":
    # quick manual sanity checks
    samples = [
        "http://paypal.com@192.168.1.5/login",
        "https://xn--pple-43d.com/verify",
        "http://%77%77%77.evil.com/",
        "https://accounts.google.com.verify-login.security-check.ru/",
    ]
    for s in samples:
        print(s, "->")
        for k, v in normalize(s).items():
            print(f"   {k}: {v}")
        print()
