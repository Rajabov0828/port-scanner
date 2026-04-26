"""
UDP Port Scanner.

UDP scanning is inherently unreliable:
  - No response     → open|filtered  (can't distinguish)
  - ICMP port unreach → closed
  - Response data   → open

Requires root/CAP_NET_RAW for best results.
Common UDP services are probed with protocol-specific payloads.
"""

from __future__ import annotations
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from core.services import get_service


@dataclass
class UDPPortResult:
    port:    int
    state:   str    # open / closed / open|filtered
    service: str = ""
    latency: float = 0.0
    data:    bytes = b""


# ─── Protocol-specific UDP probes ────────────────────────────────────────────

def _dns_probe() -> bytes:
    """DNS query for version.bind (CHAOS class)."""
    return (
        b"\x00\x01"   # Transaction ID
        b"\x00\x00"   # Flags: standard query
        b"\x00\x01"   # QDCOUNT = 1
        b"\x00\x00"   # ANCOUNT = 0
        b"\x00\x00"   # NSCOUNT = 0
        b"\x00\x00"   # ARCOUNT = 0
        b"\x07version\x04bind\x00"  # QNAME
        b"\x00\x10"   # QTYPE = TXT
        b"\x00\x03"   # QCLASS = CHAOS
    )

def _ntp_probe() -> bytes:
    """NTP client request."""
    return b"\x1b" + b"\x00" * 47

def _snmp_probe() -> bytes:
    """SNMP v1 GetRequest for sysDescr."""
    return (
        b"\x30\x26"             # SEQUENCE
        b"\x02\x01\x00"         # INTEGER version=0 (SNMPv1)
        b"\x04\x06public"       # OCTET STRING community=public
        b"\xa0\x19"             # GetRequest PDU
        b"\x02\x04\x00\x00\x00\x01"  # request-id=1
        b"\x02\x01\x00"         # error-status=0
        b"\x02\x01\x00"         # error-index=0
        b"\x30\x0b\x30\x09"     # VarBindList
        b"\x06\x05\x2b\x06\x01\x02\x01"  # OID 1.3.6.1.2.1
        b"\x05\x00"             # NULL
    )

def _sip_probe() -> bytes:
    return b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK\r\n\r\n"

def _mdns_probe() -> bytes:
    """mDNS query."""
    return (
        b"\x00\x00"   # ID=0
        b"\x00\x00"   # Flags
        b"\x00\x01"   # QDCOUNT=1
        b"\x00\x00\x00\x00\x00\x00"
        b"\x05_http\x04_tcp\x05local\x00"  # Query
        b"\x00\x0c"   # PTR type
        b"\x00\x01"   # IN class
    )

# port → probe bytes
UDP_PROBES: dict[int, bytes] = {
    53:   _dns_probe(),
    67:   b"\x01\x01\x06\x00" + b"\x00" * 236,  # DHCP Discover
    69:   b"\x00\x01test.txt\x00netascii\x00",   # TFTP RRQ
    123:  _ntp_probe(),
    161:  _snmp_probe(),
    500:  b"\x00" * 20 + b"\x01" + b"\x00" * 3, # IKE
    1194: b"\x38" + b"\x00" * 10,               # OpenVPN
    1900: (                                       # SSDP
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST:239.255.255.250:1900\r\n"
        b"MAN:\"ssdp:discover\"\r\n"
        b"MX:1\r\nST:ssdp:all\r\n\r\n"
    ),
    5353: _mdns_probe(),
    5060: _sip_probe(),
}

GENERIC_UDP_PROBE = b"\x00"

COMMON_UDP_PORTS = [
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162,
    389, 500, 514, 520, 623, 1194, 1434, 1900,
    4500, 5353, 5060, 5355,
]


def udp_scan(
    host:        str,
    ports:       list[int] | None = None,
    timeout:     float = 2.0,
    threads:     int   = 50,
    progress_cb: Callable[[int], None] | None = None,
) -> list[UDPPortResult]:
    """
    Scan UDP ports on host.
    Returns list of UDPPortResult sorted by port.
    """
    if ports is None:
        ports = COMMON_UDP_PORTS

    results: list[UDPPortResult] = []

    def _scan_udp(port: int) -> UDPPortResult:
        probe = UDP_PROBES.get(port, GENERIC_UDP_PROBE)
        t0 = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(probe, (host, port))

            try:
                data, _ = sock.recvfrom(4096)
                lat = (time.perf_counter() - t0) * 1000
                sock.close()
                return UDPPortResult(
                    port    = port,
                    state   = "open",
                    service = get_service(port),
                    latency = round(lat, 2),
                    data    = data[:64],
                )
            except socket.timeout:
                lat = (time.perf_counter() - t0) * 1000
                sock.close()
                # No response → open|filtered (can't tell without root+ICMP)
                return UDPPortResult(
                    port    = port,
                    state   = "open|filtered",
                    service = get_service(port),
                    latency = round(lat, 2),
                )

        except OSError as e:
            # ICMP Port Unreachable → closed
            if "Connection refused" in str(e) or e.errno == 111:
                return UDPPortResult(port=port, state="closed")
            return UDPPortResult(port=port, state="open|filtered", service=get_service(port))
        finally:
            if progress_cb:
                progress_cb(1)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_scan_udp, p) for p in ports]
        results = [f.result() for f in as_completed(futures)]

    return sorted(results, key=lambda r: r.port)
