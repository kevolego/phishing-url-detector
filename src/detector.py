#!/usr/bin/env python3
"""
detector.py
-----------
Command-line phishing URL detector.

Usage:
    python src/detector.py "http://paypal.com@evil.net/login"
    python src/detector.py --file urls.txt
    python src/detector.py --file urls.txt --json results.json
"""

import argparse
import json
import sys

from deobfuscate import normalize
from features import extract_features, score


def analyze_url(raw_url: str) -> dict:
    normalized = normalize(raw_url)
    feats = extract_features(normalized)
    result = score(feats)
    return {
        "url": raw_url,
        "normalized_host": normalized["host"],
        "decoded_host": normalized["decoded_host"],
        "score": result["score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
    }


def print_report(result: dict):
    print("=" * 70)
    print(f"URL:        {result['url']}")
    if result["normalized_host"] != result["decoded_host"]:
        print(f"Host:       {result['normalized_host']}  (decodes to: {result['decoded_host']})")
    else:
        print(f"Host:       {result['normalized_host']}")
    print(f"Score:      {result['score']}/100")
    print(f"Verdict:    {result['verdict']}")
    if result["reasons"]:
        print("Reasons:")
        for r in result["reasons"]:
            print(f"   {r}")
    else:
        print("Reasons:    no red flags detected")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Heuristic phishing URL detector with deobfuscation.")
    parser.add_argument("url", nargs="?", help="A single URL to check")
    parser.add_argument("--file", help="Path to a text file with one URL per line")
    parser.add_argument("--json", help="Write results as JSON to this path")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            urls.extend(line.strip() for line in f if line.strip())

    results = []
    for u in urls:
        r = analyze_url(u)
        results.append(r)
        print_report(r)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved {len(results)} result(s) to {args.json}")


if __name__ == "__main__":
    main()
