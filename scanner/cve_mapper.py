#!/usr/bin/env python3

import json
import os
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "cve_db.json")


def load_db(path: str = DB_PATH) -> list[dict]:
    with open(path, "r") as f:
        return json.load(f)


def map_cve(banner: str, db_path: str = DB_PATH) -> list[dict]:
    if not banner:
        return []

    banner_lower = banner.lower()

    try:
        db = load_db(db_path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading CVE database: {e}")
        return []

    matches = []
    for entry in db:
        for keyword in entry.get("affected_software", []):
            if keyword.lower() in banner_lower:
                matches.append({
                    "cve_id": entry["cve_id"],
                    "description": entry["description"],
                    "cvss_score": entry["cvss_score"],
                    "severity": entry["severity"],
                    "affected_software": entry["affected_software"],
                })
                break

    return matches


if __name__ == "__main__":
    import sys

    banner = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""
    if not banner:
        print("Usage: python cve_mapper.py <banner string>")
        sys.exit(1)

    results = map_cve(banner)
    if results:
        print(f"Found {len(results)} CVE match(es) for banner: {banner!r}\n")
        for cve in results:
            print(f"  {cve['cve_id']}  [{cve['severity']}]  CVSS: {cve['cvss_score']}")
            print(f"  {cve['description']}")
            print(f"  Affected: {', '.join(cve['affected_software'])}\n")
    else:
        print(f"No CVEs matched banner: {banner!r}")
