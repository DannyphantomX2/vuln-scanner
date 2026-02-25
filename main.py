#!/usr/bin/env python3

import argparse
import os
import sys

from scanner import run_scan, parse_ports
from banner import grab_banner
from cve_mapper import map_cve
from report import generate_report


def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner with banner grabbing and CVE mapping")
    parser.add_argument("--target", required=True, help="IP address or CIDR range")
    parser.add_argument("--ports", default="1-1024", help="Port range (e.g. 1-1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--verbose", action="store_true", help="Print closed/error ports")
    return parser.parse_args()


def print_summary(results: list[dict]):
    col_port    = 7
    col_service = 12
    col_banner  = 52
    col_cves    = 6

    header = (
        f"{'PORT':<{col_port}}"
        f"{'SERVICE':<{col_service}}"
        f"{'BANNER PREVIEW':<{col_banner}}"
        f"{'CVEs':>{col_cves}}"
    )
    divider = "-" * len(header)

    print(f"\n{divider}")
    print(header)
    print(divider)

    for r in sorted(results, key=lambda x: x["port"]):
        port    = f"{r['port']}/tcp"
        service = r["service"][:col_service - 1]
        preview = (r["banner"] or "")[:50]
        cve_count = len(r["cves"])

        print(
            f"{port:<{col_port}}"
            f"{service:<{col_service}}"
            f"{preview:<{col_banner}}"
            f"{cve_count:>{col_cves}}"
        )

    print(divider)


def main():
    args = parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Target : {args.target}")
    print(f"Ports  : {args.ports} ({len(ports)} ports)")
    print(f"Threads: {args.threads}")

    open_ports = run_scan(args.target, ports, args.threads, args.verbose)

    scan_results = []

    print("\nGrabbing banners and mapping CVEs ...")
    for entry in open_ports:
        host    = entry["host"]
        port    = entry["port"]
        service = entry["service"]

        banner = grab_banner(host, port)
        cves   = map_cve(banner) if banner else []

        if args.verbose:
            cve_ids = ", ".join(c["cve_id"] for c in cves) if cves else "none"
            print(f"  {host}:{port}  banner={'yes' if banner else 'none'}  cves={cve_ids}")

        scan_results.append({
            "host":    host,
            "port":    port,
            "service": service,
            "banner":  banner,
            "cves":    cves,
        })

    print_summary(scan_results)

    total_cves = sum(len(r["cves"]) for r in scan_results)
    print(f"Open ports   : {len(scan_results)}")
    print(f"Total CVEs   : {total_cves}")

    report_file = generate_report(args.target, scan_results)
    print(f"Report saved: {os.path.basename(report_file)}")

    return scan_results


if __name__ == "__main__":
    scan_results = main()
