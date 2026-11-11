# 🔎 Phishing URL Detector

![tests](https://github.com/kevolego/phishing-url-detector/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A heuristic, **explainable** phishing URL detector that deobfuscates a URL
before scoring it — so the tricks real phishing kits use don't slip past
a naive "does it contain the word paypal" check.

**[Try the live browser version →](https://kevolego.github.io/phishing-url-detector/)**
*(runs entirely client-side — nothing is sent anywhere)*

Project #13 of a 100-project cybersecurity portfolio.

---

## Why this project exists

Most beginner phishing-URL checkers just regex a raw string looking for a
brand name. That misses the obfuscation tricks real phishing pages
actually use. This tool normalizes the URL *first* — unmasking hidden
hosts, decoding punycode, stripping encoding — then scores it, and
explains **exactly why** it flagged (or didn't flag) a link.

## Obfuscation techniques handled

| Technique | Example | Detection |
|---|---|---|
| Raw IP instead of domain | `http://192.168.1.5/login` | `is_ip_host` |
| Userinfo `@` trick | `http://paypal.com@evil.net` | real host resolved to `evil.net` |
| Punycode / homograph attack | `xn--pple-43d.com` → `аpple.com` (Cyrillic а) | `homograph_suspected` |
| Percent/hex encoding | `%68%74%74%70` → `http` | `was_percent_encoded` |
| URL shorteners | `bit.ly/xyz` | `is_known_shortener` |
| Excessive subdomains | `paypal.com.verify.login.evil.net` | `excessive_subdomains` |
| Typosquatting | `paypa1-secure.com` | fuzzy brand match |
| Suspicious TLDs | `.xyz`, `.tk`, `.top` | `suspicious_tld` |
| High-entropy random domains | `x7fk29d.com` | Shannon entropy |

## How scoring works

Each risk factor adds weighted points toward a 0–100 score — fully
transparent, not a black box. Every point is logged with a plain-English
reason.

- **0–29** → Likely safe
- **30–59** → Suspicious, review manually
- **60–100** → Phishing, high confidence

Weights live in `src/features.py` → `score()`. A natural next step: train
a real ML classifier (logistic regression / random forest) on these same
features using a labeled dataset like
[PhishTank](https://phishtank.org/) or [OpenPhish](https://openphish.com/),
and compare it against this heuristic baseline.

## Two ways to use it

### 1. Browser version (no install, works for anyone)
Open `web/index.html` directly, or use the **[hosted version](https://kevolego.github.io/phishing-url-detector/)**.
Paste a link, get a verdict. Nothing leaves the browser — ideal for
sharing with non-technical people who just want to check a suspicious link.

### 2. Python CLI (for scripting / batch checks)

```bash
git clone https://github.com/kevolego/phishing-url-detector.git
cd phishing-url-detector
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Check a single URL:
```bash
python3 src/detector.py "http://paypal.com@evil.net/login"
```

Check a batch of URLs from a file:
```bash
python3 src/detector.py --file data/sample_urls.txt
```

Save results as JSON:
```bash
python3 src/detector.py --file data/sample_urls.txt --json results.json
```

## Project structure

```
phishing-url-detector/
├── .github/workflows/tests.yml   # CI: runs pytest on every push
├── src/
│   ├── deobfuscate.py            # normalizes/decodes the URL
│   ├── features.py                # extracts risk features + scores
│   └── detector.py                # CLI entry point
├── web/
│   └── index.html                 # browser-only version (same logic, in JS)
├── tests/
│   └── test_detector.py
├── data/
│   ├── sample_urls.txt            # example URLs to test against
│   └── stress_test_urls.txt       # realistic phishing-kit style test batch
├── requirements.txt
└── README.md
```

> **Note:** `web/index.html` is a JavaScript port of the same detection
> logic in `src/`. If you tune a weight or add a check in `features.py`,
> update the JS version too — they're kept in sync by hand, not shared code.

## Running tests

```bash
export PYTHONPATH=src        # Windows: set PYTHONPATH=src
pytest tests/ -v
```

Tests run automatically on every push via GitHub Actions (see badge above).

## Example output

```
======================================================================
URL:        http://paypal.com@192.168.1.5/login
Host:       192.168.1.5
Score:      68/100
Verdict:    PHISHING (high confidence)
Reasons:
   +25: host is a raw IP address instead of a domain name
   +25: URL uses '@' to disguise the real destination host
   +8: no HTTPS
   +10: sensitive keywords in path/query: ['login']
======================================================================
```

## Known limitations

- Rule-based scoring can, in principle, be tuned around by an attacker
  who knows the weights — worth discussing in an interview as a design
  tradeoff, not hiding.
- Brand list and suspicious-TLD list are small and hand-curated; extend
  `BRAND_TARGETS` / `SUSPICIOUS_TLDS` in `features.py` as needed.
- No live reputation data (WHOIS age, SSL cert issuer, hosting ASN) —
  a natural "v2" feature.
- Static analysis only — no network requests are made, so it's safe to
  check a suspicious link without visiting it.

## Disclaimer

Built for educational and defensive purposes only.

## License

MIT — see [LICENSE](LICENSE).
