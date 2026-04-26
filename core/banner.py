"""
Banner grabbing — connects to open ports and extracts service banners.
Supports HTTP, FTP, SMTP, SSH, generic TCP.
"""

import socket
import ssl
import re
from dataclasses import dataclass, field


@dataclass
class BannerResult:
    raw: str = ""
    cleaned: str = ""
    protocol_hint: str = ""
    version: str = ""
    extra: dict = field(default_factory=dict)


# HTTP probe — sent to web ports
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

# Generic probe for ports that respond on connect
GENERIC_PROBE = b"\r\n"

# Ports that need specific probes
PROBES: dict[int, bytes] = {
    80:   HTTP_PROBE,
    443:  HTTP_PROBE,
    8080: HTTP_PROBE,
    8443: HTTP_PROBE,
    8888: HTTP_PROBE,
    3000: HTTP_PROBE,
    5000: HTTP_PROBE,
    21:   GENERIC_PROBE,   # FTP sends banner on connect
    22:   GENERIC_PROBE,   # SSH sends banner on connect
    25:   GENERIC_PROBE,   # SMTP sends banner on connect
    110:  GENERIC_PROBE,   # POP3
    143:  GENERIC_PROBE,   # IMAP
}

# SSL/TLS ports
SSL_PORTS: set[int] = {443, 465, 587, 636, 993, 995, 8443, 3269}


def grab_banner(host: str, port: int, timeout: float = 3.0) -> BannerResult:
    """
    Attempt to grab a service banner from host:port.
    Returns BannerResult with raw banner and parsed fields.
    """
    result = BannerResult()
    probe = PROBES.get(port, GENERIC_PROBE)
    use_ssl = port in SSL_PORTS

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = sock

        conn.connect((host, port))

        # Some services (FTP, SSH, SMTP) send banner immediately
        # Try reading first before sending probe
        conn.settimeout(1.5)
        try:
            initial = conn.recv(1024)
            if initial:
                result.raw = initial.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        # Send probe if we have one and haven't got banner yet
        if not result.raw and probe:
            conn.settimeout(timeout)
            conn.send(probe)
            conn.settimeout(2.0)
            try:
                data = conn.recv(4096)
                result.raw = data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass

        conn.close()

    except (socket.timeout, ConnectionRefusedError, OSError):
        return result

    if result.raw:
        result.cleaned = _clean_banner(result.raw)
        result.protocol_hint = _detect_protocol(result.raw, port)
        result.version = _extract_version(result.raw, result.protocol_hint)

    return result


def _clean_banner(raw: str) -> str:
    """Remove non-printable characters and limit length."""
    cleaned = re.sub(r"[^\x20-\x7E\n\r\t]", "", raw)
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    return " | ".join(lines[:3])[:300]


def _detect_protocol(banner: str, port: int) -> str:
    """Guess protocol from banner content."""
    b = banner.upper()
    if "SSH-" in b:               return "SSH"
    if "HTTP/" in b:              return "HTTP"
    if "220 " in b and "FTP" in b: return "FTP"
    if "220 " in b and "SMTP" in b: return "SMTP"
    if "+OK" in b:                return "POP3"
    if "* OK" in b:               return "IMAP"
    if "MYSQL" in b or "\x4a\x00\x00\x00" in banner: return "MySQL"
    if "REDIS" in b or "+PONG" in b: return "Redis"
    if "MONGODB" in b:            return "MongoDB"
    if "220" in b:                return "FTP/SMTP"
    return "TCP"


def _extract_version(banner: str, protocol: str) -> str:
    """Try to extract version string from banner."""
    # SSH: SSH-2.0-OpenSSH_8.4
    m = re.search(r"SSH-([\d.]+)-(\S+)", banner)
    if m:
        return f"SSH-{m.group(1)} {m.group(2)}"

    # HTTP Server header
    m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # FTP/SMTP: 220 server version
    m = re.search(r"^220\s+(.+)", banner, re.MULTILINE)
    if m:
        return m.group(1).strip()[:80]

    # Generic version pattern: word/digit.digit
    m = re.search(r"([A-Za-z]+)[\s/]v?([\d]+\.[\d]+[\.\d]*)", banner)
    if m:
        return f"{m.group(1)} {m.group(2)}"

    return ""
