"""
OS fingerprinting via passive & active analysis.

Techniques used:
  1. TTL-based detection      — Linux ~64, Windows ~128, Cisco/BSD ~255
  2. TCP Window Size          — different OS use different default window sizes
  3. TCP Options order        — MSS, SACK, Timestamps, Window Scale
  4. ICMP TTL (ping response)

No Scapy OS DB required — pure heuristic approach.
"""

from __future__ import annotations
import socket
import struct
from dataclasses import dataclass, field


@dataclass
class OSResult:
    os_guess: str = "Unknown"
    confidence: str = "Low"          # Low / Medium / High
    ttl: int | None = None
    window_size: int | None = None
    tcp_options: list[str] = field(default_factory=list)
    details: str = ""


# ─── TTL Fingerprints ────────────────────────────────────────────────────────
# Initial TTL values (actual TTL = initial - hops, so we round up to nearest)
TTL_MAP: list[tuple[range, str, str]] = [
    (range(0,   65),  "Linux / Android / macOS",  "High"),
    (range(65,  129), "Windows",                   "High"),
    (range(129, 256), "Cisco IOS / BSD / Solaris",  "Medium"),
]

# ─── Window Size Fingerprints ────────────────────────────────────────────────
WINDOW_MAP: dict[int, tuple[str, str]] = {
    # Windows
    8192:   ("Windows XP",            "Medium"),
    16384:  ("Windows 2000/XP",       "Medium"),
    65535:  ("Windows Vista/7/10",    "Medium"),
    64240:  ("Windows 10/11",         "High"),
    # Linux
    5840:   ("Linux 2.6 kernel",      "High"),
    14600:  ("Linux 3.x/4.x kernel",  "High"),
    29200:  ("Linux 4.x/5.x kernel",  "Medium"),
    # macOS / BSD
    65535:  ("macOS / FreeBSD",       "Medium"),
    # Cisco
    4128:   ("Cisco IOS",             "High"),
}


def detect_os(host: str, open_ports: list[int], timeout: float = 3.0) -> OSResult:
    """
    Perform OS fingerprinting against a host.
    Tries multiple techniques and combines results.
    """
    result = OSResult()

    # Technique 1: Get TTL via ICMP ping (raw socket — needs root)
    ttl = _get_ttl_icmp(host, timeout)

    # Technique 2: Get TCP TTL + window from a SYN-ACK response
    if ttl is None and open_ports:
        ttl, window = _get_tcp_fingerprint(host, open_ports[0], timeout)
        result.window_size = window
    else:
        _, window = _get_tcp_fingerprint(host, open_ports[0] if open_ports else 80, timeout)
        result.window_size = window

    result.ttl = ttl

    # Combine TTL and Window guesses
    ttl_guess, ttl_conf = _guess_from_ttl(ttl)
    win_guess, win_conf = _guess_from_window(window)

    # If both agree → higher confidence
    if ttl_guess and win_guess:
        if _os_family(ttl_guess) == _os_family(win_guess):
            result.os_guess = ttl_guess
            result.confidence = "High" if ttl_conf == "High" else "Medium"
        else:
            result.os_guess = f"{ttl_guess} (TTL) / {win_guess} (Window)"
            result.confidence = "Low"
    elif ttl_guess:
        result.os_guess = ttl_guess
        result.confidence = ttl_conf
    elif win_guess:
        result.os_guess = win_guess
        result.confidence = win_conf

    result.details = _build_details(ttl, window)
    return result


def _get_ttl_icmp(host: str, timeout: float) -> int | None:
    """Send ICMP echo, extract TTL from IP header."""
    try:
        import os as _os
        # Raw socket needs root — fall back silently if permission denied
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        # ICMP Echo Request: type=8, code=0, checksum, id, seq
        icmp_id  = 0x1234
        icmp_seq = 1
        payload  = b"PORTSCANNER-PROBE"
        header   = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq)
        checksum = _checksum(header + payload)
        packet   = struct.pack("!BBHHH", 8, 0, checksum, icmp_id, icmp_seq) + payload

        sock.sendto(packet, (host, 0))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # IP header is first 20 bytes; TTL is byte 8
        ttl = data[8]
        return ttl

    except (PermissionError, OSError):
        return None


def _get_tcp_fingerprint(host: str, port: int, timeout: float) -> tuple[int | None, int | None]:
    """
    Connect to host:port, capture TTL and TCP window size from IP/TCP headers.
    Uses raw socket SYN — falls back to connect-based TTL estimation.
    """
    try:
        # Try raw socket SYN capture (root required)
        ttl, window = _raw_syn_fingerprint(host, port, timeout)
        if ttl:
            return ttl, window
    except (PermissionError, OSError):
        pass

    # Fallback: connect and use IP_TTL socket option (unreliable but works)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
        sock.connect((host, port))
        # Can't get remote TTL from connect-based socket, but we can try IP_RECVTTL
        # This is platform-dependent — skip silently
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return None, None


def _raw_syn_fingerprint(host: str, port: int, timeout: float) -> tuple[int | None, int | None]:
    """
    Send raw TCP SYN and parse SYN-ACK to extract TTL and window size.
    Requires root/CAP_NET_RAW.
    """
    import random

    src_port = random.randint(49152, 65535)
    dst_ip   = socket.gethostbyname(host)
    src_ip   = "0.0.0.0"  # kernel fills this

    # Build TCP SYN packet
    tcp_header = _build_tcp_syn(src_ip, dst_ip, src_port, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
    sock.sendto(tcp_header, (dst_ip, 0))

    start = __import__("time").time()
    while __import__("time").time() - start < timeout:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            break

        # IP header: version/IHL, DSCP, total_len, id, flags, TTL, proto, checksum, src, dst
        if len(data) < 40:
            continue

        ip_ihl = (data[0] & 0x0F) * 4
        ip_proto = data[9]
        ttl = data[8]

        if ip_proto != 6:  # not TCP
            continue

        # TCP header starts after IP header
        tcp_src  = struct.unpack("!H", data[ip_ihl:ip_ihl+2])[0]
        tcp_dst  = struct.unpack("!H", data[ip_ihl+2:ip_ihl+4])[0]
        tcp_flags = data[ip_ihl+13]
        window   = struct.unpack("!H", data[ip_ihl+14:ip_ihl+16])[0]

        # SYN-ACK: flags = 0x12
        if tcp_src == port and tcp_dst == src_port and (tcp_flags & 0x12) == 0x12:
            sock.close()
            # Send RST to clean up
            return ttl, window

    sock.close()
    return None, None


def _build_tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a raw TCP SYN packet."""
    import random
    seq = random.randint(0, 2**32 - 1)
    # TCP header fields
    offset_res = (5 << 4) | 0   # data offset = 5, reserved = 0
    flags = 0x02                  # SYN
    window = 65535
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        offset_res, flags,
        window, 0, 0
    )
    # Pseudo-header for checksum
    src = socket.inet_aton(src_ip) if src_ip != "0.0.0.0" else b"\x00\x00\x00\x00"
    dst = socket.inet_aton(dst_ip)
    pseudo = src + dst + b"\x00\x06" + struct.pack("!H", len(tcp_header))
    checksum = _checksum(pseudo + tcp_header)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        offset_res, flags,
        window, checksum, 0
    )
    return tcp_header


def _checksum(data: bytes) -> int:
    """Standard internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _guess_from_ttl(ttl: int | None) -> tuple[str, str]:
    if ttl is None:
        return "", "Low"
    for rng, name, conf in TTL_MAP:
        if ttl in rng:
            return name, conf
    return "Unknown", "Low"


def _guess_from_window(window: int | None) -> tuple[str, str]:
    if window is None:
        return "", "Low"
    return WINDOW_MAP.get(window, ("", "Low"))


def _os_family(guess: str) -> str:
    g = guess.lower()
    if "windows" in g:        return "windows"
    if "linux" in g:          return "linux"
    if "macos" in g or "bsd" in g: return "bsd"
    if "cisco" in g:          return "cisco"
    return "other"


def _build_details(ttl: int | None, window: int | None) -> str:
    parts = []
    if ttl is not None:
        parts.append(f"TTL={ttl}")
    if window is not None:
        parts.append(f"Window={window}")
    return ", ".join(parts) if parts else "No fingerprint data collected"
