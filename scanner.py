#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, port: int, timeout: float = 1.0, verbose: bool = False) -> Optional[dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            service = get_service_name(port)
            entry = {"port": port, "state": "open", "service": service}
            print(f"  {port}/tcp  open  {service}")
            return entry
        else:
            if verbose:
                print(f"  {port}/tcp  closed")
            return None
    except socket.error as e:
        if verbose:
            print(f"  {port}/tcp  error  {e}")
        return None
    finally:
        sock.close()


def parse_ports(port_arg: str) -> list[int]:
    parts = port_arg.strip().split("-")
    if len(parts) == 2:
        start, end = int(parts[0]), int(parts[1])
        return list(range(start, end + 1))
    elif len(parts) == 1:
        return [int(parts[0])]
    else:
        raise ValueError(f"Invalid port range: {port_arg}")


def get_hosts(target: str) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    except ValueError:
        return [target]


def scan_host(host: str, ports: list[int], threads: int, verbose: bool) -> list[dict]:
    print(f"\nScanning {host} ...")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, 1.0, verbose): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    results.sort(key=lambda x: x["port"])
    return results


def run_scan(target: str, ports: list[int], threads: int, verbose: bool) -> list[dict]:
    hosts = get_hosts(target)
    all_results = []
    for host in hosts:
        host_results = scan_host(host, ports, threads, verbose)
        for entry in host_results:
            entry["host"] = host
        all_results.extend(host_results)
    return all_results


def main():
    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("--target", required=True, help="IP address or CIDR range to scan")
    parser.add_argument("--ports", default="1-1024", help="Port range (e.g. 1-1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--verbose", action="store_true", help="Print closed/error ports too")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Target : {args.target}")
    print(f"Ports  : {args.ports} ({len(ports)} ports)")
    print(f"Threads: {args.threads}")

    results = run_scan(args.target, ports, args.threads, args.verbose)

    print(f"\nScan complete. {len(results)} open port(s) found.")
    return results


if __name__ == "__main__":
    main()
