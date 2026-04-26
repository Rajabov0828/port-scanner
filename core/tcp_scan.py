"""
TCP Port Scanner.

Modes:
  - SYN scan  (stealth, requires root / CAP_NET_RAW) — uses Scapy
  - Connect   (fallback, no root needed)             — uses socket

Both modes are multi-threaded.
"""

from __future__ import annotations
import socket
import struct
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from core.services import get_service, HIGH_RISK_PORTS
from core.banner import grab_banner, BannerResult


@dataclass
class PortResult:
    port:     int
    state:    str         # open / closed / filtered
    service:  str = ""
    banner:   BannerResult = field(default_factory=BannerResult)
    latency:  float = 0.0  # ms
    risk:     bool = False


def tcp_connect_scan(
    host:       str,
    ports:      list[int],
    timeout:    float = 1.0,
    threads:    int   = 100,
    grab:       bool  = True,
    progress_cb: Callable[[int], None] | None = None,
) -> list[PortResult]:
    """
    Full TCP connect scan.
    Works without root. Slightly noisier than SYN.
    """
    results: list[PortResult] = []

    def _scan_port(port: int) -> PortResult:
        t0 = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            lat  = (time.perf_counter() - t0) * 1000
            sock.close()

            if code == 0:
                svc    = get_service(port)
                banner = grab_banner(host, port) if grab else BannerResult()
                return PortResult(
                    port    = port,
                    state   = "open",
                    service = svc,
                    banner  = banner,
                    latency = round(lat, 2),
                    risk    = port in HIGH_RISK_PORTS,
                )
            else:
                return PortResult(port=port, state="closed", latency=round(lat, 2))

        except socket.timeout:
            return PortResult(port=port, state="filtered")
        except OSError:
            return PortResult(port=port, state="filtered")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_scan_port, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if progress_cb:
                progress_cb(1)

    return sorted(results, key=lambda r: r.port)


def tcp_syn_scan(
    host:        str,
    ports:       list[int],
    timeout:     float = 1.0,
    threads:     int   = 150,
    grab:        bool  = True,
    progress_cb: Callable[[int], None] | None = None,
) -> list[PortResult]:
    """
    TCP SYN (half-open) scan via Scapy.
    Requires root/CAP_NET_RAW. Falls back to connect scan if unavailable.
    """
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0           # suppress Scapy output
    except ImportError:
        # Scapy not installed — fall back
        return tcp_connect_scan(host, ports, timeout, threads, grab, progress_cb)

    results: list[PortResult] = []

    def _syn_probe(port: int) -> PortResult:
        t0 = time.perf_counter()
        try:
            pkt = IP(dst=host) / TCP(dport=port, flags="S", sport=random.randint(1024, 65535))
            resp = sr1(pkt, timeout=timeout, verbose=0)
            lat  = (time.perf_counter() - t0) * 1000

            if resp is None:
                return PortResult(port=port, state="filtered", latency=round(lat, 2))

            if resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                flags = tcp_layer.flags

                # SYN-ACK (0x12) → open
                if flags == 0x12:
                    # Send RST to avoid half-open connection pile-up
                    rst = IP(dst=host) / TCP(
                        dport=port, sport=pkt[TCP].sport,
                        flags="R", seq=pkt[TCP].seq + 1
                    )
                    from scapy.all import send
                    send(rst, verbose=0)

                    svc    = get_service(port)
                    banner = grab_banner(host, port) if grab else BannerResult()
                    return PortResult(
                        port    = port,
                        state   = "open",
                        service = svc,
                        banner  = banner,
                        latency = round(lat, 2),
                        risk    = port in HIGH_RISK_PORTS,
                    )

                # RST (0x14) → closed
                if flags == 0x14:
                    return PortResult(port=port, state="closed", latency=round(lat, 2))

            return PortResult(port=port, state="filtered", latency=round(lat, 2))

        except Exception:
            return PortResult(port=port, state="filtered")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_syn_probe, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if progress_cb:
                progress_cb(1)

    return sorted(results, key=lambda r: r.port)


# ─── Port Range Helpers ───────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 137, 138,
    139, 143, 161, 179, 389, 443, 445, 464, 465, 500, 512, 513, 514,
    515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1080, 1099,
    1194, 1433, 1434, 1521, 1701, 1723, 2049, 2375, 2376, 2377,
    2379, 2380, 3000, 3268, 3269, 3306, 3389, 4001, 4444, 4500,
    4848, 5000, 5432, 5672, 5900, 5901, 5984, 6000, 6379, 6443,
    6672, 7001, 7002, 8080, 8161, 8443, 8500, 8888, 9000, 9090,
    9092, 9100, 9200, 9300, 10250, 11211, 15672, 27017, 27018,
    28017,
]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1433, 1521, 1723, 2049, 2375, 3306, 3389, 4444, 5432,
    5900, 5984, 6379, 7001, 8080, 8443, 8888, 9200, 11211,
    27017, 27018,
]


def parse_port_range(spec: str) -> list[int]:
    """
    Parse port specification string.
    Examples:
      "80"          → [80]
      "80,443"      → [80, 443]
      "1-1024"      → [1..1024]
      "top100"      → TOP_100_PORTS
      "top1000"     → TOP_1000_PORTS
      "22,80,1-100" → combined
    """
    spec = spec.strip().lower()

    if spec == "top100":
        return sorted(TOP_100_PORTS)
    if spec == "top1000":
        return sorted(set(TOP_1000_PORTS))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))

    return sorted(p for p in ports if 1 <= p <= 65535)
