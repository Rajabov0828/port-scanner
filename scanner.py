#!/usr/bin/env python3
"""
port-scanner — Professional TCP/UDP Port Scanner
Author : Jurabek Rajabov
GitHub : https://github.com/Rajabov0828
License: MIT

Usage examples:
  sudo python scanner.py 192.168.1.1
  sudo python scanner.py example.com -p top100 --syn
  sudo python scanner.py 10.0.0.1 -p 1-1024 --udp --output reports/
  python scanner.py 192.168.1.1 -p 22,80,443 --no-banner
"""

from __future__ import annotations
import argparse
import sys
import socket
import time
import os

from core.tcp_scan import tcp_connect_scan, tcp_syn_scan, parse_port_range
from core.udp_scan import udp_scan, COMMON_UDP_PORTS
from core.os_detect import detect_os
from reports.terminal import print_report, ScanSummary
from reports.exporters import save_json, save_txt, save_html, save_xml


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Port Scanner — Professional Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.1
  sudo python scanner.py 192.168.1.1 --syn
  python scanner.py example.com -p top100 --udp
  python scanner.py 10.0.0.0/24 -p 22,80,443 --output ./reports
  python scanner.py 192.168.1.1 -p 1-65535 --threads 500 --timeout 0.5
        """,
    )

    # Target
    p.add_argument("target", help="Target IP, hostname, or CIDR range")

    # Port range
    p.add_argument(
        "-p", "--ports",
        default="top100",
        metavar="PORTS",
        help="Port range: '80', '1-1024', '22,80,443', 'top100', 'top1000' (default: top100)",
    )

    # Scan mode
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--syn",     action="store_true", help="TCP SYN scan (requires root)")
    mode.add_argument("--connect", action="store_true", help="TCP connect scan (default)")

    # Options
    p.add_argument("--udp",      action="store_true", help="Also run UDP scan on common ports")
    p.add_argument("--os",       action="store_true", help="Enable OS fingerprinting")
    p.add_argument("--no-banner",action="store_true", help="Skip banner grabbing (faster)")
    p.add_argument("--threads",  type=int, default=150, metavar="N",  help="Thread count (default: 150)")
    p.add_argument("--timeout",  type=float, default=1.0, metavar="S", help="Per-port timeout in seconds (default: 1.0)")

    # Output
    p.add_argument("--output", "-o", metavar="DIR", help="Save reports to directory (json+txt+html+xml)")
    p.add_argument("--json",   metavar="FILE", help="Save JSON report to file")
    p.add_argument("--html",   metavar="FILE", help="Save HTML report to file")
    p.add_argument("--txt",    metavar="FILE", help="Save TXT report to file")
    p.add_argument("--xml",    metavar="FILE", help="Save XML report to file (Nmap-compatible)")
    p.add_argument("--quiet",  "-q", action="store_true", help="Suppress terminal output")

    return p


# ─── Progress bar ─────────────────────────────────────────────────────────────

class Progress:
    """Minimal progress counter — works with or without Rich."""
    def __init__(self, total: int, label: str = "Scanning"):
        self.total   = total
        self.done    = 0
        self.label   = label
        self._rich   = None
        self._task   = None
        self._init_rich()

    def _init_rich(self):
        try:
            from rich.progress import Progress as RichProgress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
            self._rp = RichProgress(
                SpinnerColumn(),
                TextColumn("[bold green]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TimeElapsedColumn(),
            )
            self._rp.start()
            self._task = self._rp.add_task(self.label, total=self.total)
        except ImportError:
            self._rp = None

    def update(self, n: int = 1):
        self.done += n
        if self._rp:
            self._rp.update(self._task, advance=n)
        else:
            pct = int(self.done / self.total * 100)
            print(f"\r{self.label}: {pct}% ({self.done}/{self.total})", end="", flush=True)

    def stop(self):
        if self._rp:
            self._rp.stop()
        else:
            print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def resolve_host(target: str) -> tuple[str, str]:
    """Return (hostname, ip). If target is an IP, hostname == ip."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = target
        return hostname, ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve target: {target}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # ── Resolve target ────────────────────────────────────────────────────────
    hostname, ip = resolve_host(args.target)
    ports        = parse_port_range(args.ports)
    grab         = not args.no_banner
    use_syn      = args.syn

    if use_syn and os.geteuid() != 0:
        print("[WARN] SYN scan requires root. Falling back to connect scan.")
        use_syn = False

    scan_mode = "syn" if use_syn else "connect"

    print(f"\n  Target   : {hostname} ({ip})")
    print(f"  Ports    : {args.ports} ({len(ports)} ports)")
    print(f"  Mode     : {scan_mode.upper()}")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  Banner   : {'no' if not grab else 'yes'}")
    print()

    # ── TCP Scan ──────────────────────────────────────────────────────────────
    progress = Progress(total=len(ports), label="TCP scan")
    t_start  = time.perf_counter()

    if use_syn:
        tcp_results = tcp_syn_scan(
            ip, ports, args.timeout, args.threads, grab,
            progress_cb=progress.update,
        )
    else:
        tcp_results = tcp_connect_scan(
            ip, ports, args.timeout, args.threads, grab,
            progress_cb=progress.update,
        )

    progress.stop()

    # ── UDP Scan ──────────────────────────────────────────────────────────────
    udp_results = []
    if args.udp:
        udp_progress = Progress(total=len(COMMON_UDP_PORTS), label="UDP scan")
        udp_results = udp_scan(
            ip, timeout=args.timeout, threads=50,
            progress_cb=udp_progress.update,
        )
        udp_progress.stop()

    # ── OS Detection ──────────────────────────────────────────────────────────
    os_result = None
    if args.os or True:  # Always attempt OS detection
        open_ports = [r.port for r in tcp_results if r.state == "open"]
        if open_ports:
            os_result = detect_os(ip, open_ports, timeout=args.timeout)

    scan_time = time.perf_counter() - t_start

    # ── Build summary ─────────────────────────────────────────────────────────
    summary = ScanSummary(
        host        = hostname,
        ip          = ip,
        scan_time   = round(scan_time, 2),
        tcp_results = tcp_results,
        udp_results = udp_results,
        os_result   = os_result,
        scan_mode   = scan_mode,
    )

    # ── Terminal report ───────────────────────────────────────────────────────
    if not args.quiet:
        print_report(summary)

    # ── File reports ──────────────────────────────────────────────────────────
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        base = os.path.join(args.output, f"scan_{ip.replace('.', '_')}")
        save_json(summary, base + ".json")
        save_txt (summary, base + ".txt")
        save_html(summary, base + ".html")
        save_xml (summary, base + ".xml")
        print(f"\n  Reports saved to: {args.output}/")

    if args.json: save_json(summary, args.json)
    if args.txt:  save_txt (summary, args.txt)
    if args.html: save_html(summary, args.html)
    if args.xml:  save_xml (summary, args.xml)


if __name__ == "__main__":
    main()
