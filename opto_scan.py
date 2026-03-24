#!/usr/bin/env python3
"""
opto_wait_scan.py

Examples:
    python opto_wait_scan.py 192.168.1.0/24
    python opto_wait_scan.py 192.168.1.255
    python opto_wait_scan.py 169.254.0.0/16 --wait 60
    python opto_wait_scan.py 192.168.1.0/24 --all

What it does:
- Sends the Opto discovery packet to the subnet broadcast
- Repeats discovery while waiting
- Repeatedly pings hosts to populate ARP
- Polls the ARP table for up to N seconds
- Prints devices as they appear

Works on Linux and Windows.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import time
from typing import Iterable, List, Set, Tuple

DISCOVERY_PORTS = (2002, 2001)
DISCOVERY_PAYLOAD = b"\x00\x00\x04\x50\x00\x00\xff\xff\xf0\x30\x00\x20\x01\x30\x00\x00"

DEFAULT_MAC_PREFIXES = [
    "00:a0:3d",
    "6c:bf:b5",
    "b8:27:eb",
]


def parse_target(value: str) -> Tuple[ipaddress.IPv4Network, str]:
    """
    Accept either:
      - subnet CIDR, e.g. 192.168.1.0/24
      - single IPv4 host, e.g. 192.168.1.42 (treated as /24)
      - broadcast address, e.g. 192.168.1.255 (treated as /24)
    Returns:
      (network, broadcast_ip)
    """
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("Only IPv4 is supported")
            return net, str(net.broadcast_address)

        ip = ipaddress.ip_address(value)
        if not isinstance(ip, ipaddress.IPv4Address):
            raise ValueError("Only IPv4 is supported")

        # If user gives x.y.z.255, treat it as broadcast for x.y.z.0/24
        if str(ip).endswith(".255"):
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return net, str(ip)

        # Otherwise treat single host as its /24
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return net, str(net.broadcast_address)

    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def discover_targets(broadcast_ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for port in DISCOVERY_PORTS:
            sock.sendto(DISCOVERY_PAYLOAD, (broadcast_ip, port))
    finally:
        sock.close()


def build_ping_command(ip: str) -> List[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "800", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def ping_host(ip: str) -> None:
    try:
        subprocess.run(
            build_ping_command(ip),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass


def ping_subset(hosts: Iterable[ipaddress.IPv4Address], workers: int = 64) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda h: ping_host(str(h)), hosts))


def read_arp_table() -> List[Tuple[str, str]]:
    system = platform.system().lower()
    commands = [["arp", "-a"]] if system == "windows" else [["ip", "neigh"], ["arp", "-n"]]

    output = ""
    for cmd in commands:
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")
            if output.strip():
                break
        except Exception:
            continue

    if not output.strip():
        return []

    entries: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    unix_re = re.compile(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
    win_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")

    for ip, mac in unix_re.findall(output):
        mac = mac.lower()
        if (ip, mac) not in seen:
            seen.add((ip, mac))
            entries.append((ip, mac))

    for ip, mac in win_re.findall(output):
        mac = mac.lower().replace("-", ":")
        if (ip, mac) not in seen:
            seen.add((ip, mac))
            entries.append((ip, mac))

    return entries


def mac_matches(mac: str, prefixes: List[str]) -> bool:
    mac = mac.lower()
    return any(mac.startswith(p.lower()) for p in prefixes)


def generate_hostname(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) != 6:
        return "opto-unknown"
    return f"opto-{parts[-3]}-{parts[-2]}-{parts[-1]}"


def is_reasonable_host(ip: str, network: ipaddress.IPv4Network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr in network and addr != network.network_address and addr != network.broadcast_address
    except ValueError:
        return False


def choose_ping_hosts(network: ipaddress.IPv4Network) -> List[ipaddress.IPv4Address]:
    """
    Avoid trying to ping every address in huge ranges every cycle.
    """
    hosts = list(network.hosts())

    # Small subnet: ping all
    if network.num_addresses <= 512:
        return hosts

    # /16 or larger: sample common likely ranges first
    sampled = []
    for host in hosts:
        last_octet = int(str(host).split(".")[-1])
        if last_octet in (1, 2, 10, 20, 50, 100, 101, 150, 200, 250):
            sampled.append(host)

    return sampled if sampled else hosts[:512]


def scan_for_targets(
    network: ipaddress.IPv4Network,
    broadcast_ip: str,
    wait_seconds: int,
    resends: int,
    interval: float,
    mac_prefixes: List[str],
    show_all: bool,
) -> int:
    print(f"[+] Network:   {network}")
    print(f"[+] Broadcast: {broadcast_ip}")
    print(f"[+] Waiting up to {wait_seconds} seconds")
    print()

    known: Set[Tuple[str, str]] = set()
    ping_hosts_list = choose_ping_hosts(network)
    start = time.time()
    next_discovery = 0.0
    next_ping = 0.0
    sent_count = 0

    while True:
        elapsed = time.time() - start
        if elapsed >= wait_seconds:
            break

        now = time.time()

        if sent_count < resends and now >= next_discovery:
            print(f"[+] Sending discovery packet ({sent_count + 1}/{resends})")
            discover_targets(broadcast_ip)
            sent_count += 1
            next_discovery = now + max(3.0, wait_seconds / max(resends, 1))

        if now >= next_ping:
            ping_subset(ping_hosts_list)
            next_ping = now + 5.0

        arp_entries = read_arp_table()
        for ip, mac in arp_entries:
            if not is_reasonable_host(ip, network):
                continue
            if not show_all and not mac_matches(mac, mac_prefixes):
                continue

            key = (ip, mac)
            if key not in known:
                known.add(key)
                print(f"[FOUND] {ip:15}  {mac:17}  {generate_hostname(mac)}")

        time.sleep(interval)

    print()
    if not known:
        print("[-] No matching targets found.")
        return 1

    print(f"[+] Found {len(known)} target(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait-and-scan for Opto targets.")
    parser.add_argument(
        "target",
        help="IPv4 subnet, host IP, or broadcast IP (examples: 192.168.1.0/24, 192.168.1.42, 192.168.1.255)",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=60,
        help="How long to keep scanning after sending discovery (default: 60)",
    )
    parser.add_argument(
        "--resends",
        type=int,
        default=3,
        help="How many times to resend the discovery packet during the wait window (default: 3)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="ARP polling interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--prefix",
        action="append",
        default=[],
        help="Additional MAC prefix to match, e.g. --prefix aa:bb:cc",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show all discovered ARP hosts in the subnet, not just known MAC prefixes",
    )

    args = parser.parse_args()
    network, broadcast_ip = parse_target(args.target)
    mac_prefixes = DEFAULT_MAC_PREFIXES + args.prefix

    return scan_for_targets(
        network=network,
        broadcast_ip=broadcast_ip,
        wait_seconds=args.wait,
        resends=args.resends,
        interval=args.interval,
        mac_prefixes=mac_prefixes,
        show_all=args.all,
    )


if __name__ == "__main__":
    sys.exit(main())
"""
eaxample:
$ ./opto_scan.py 192.168.1.69 --wait 60
[+] Network:   192.168.1.0/24
[+] Broadcast: 192.168.1.255
[+] Waiting up to 60 seconds

[+] Sending discovery packet (1/3)
[+] Sending discovery packet (2/3)
[+] Sending discovery packet (3/3)

[-] No matching targets found.
"""

