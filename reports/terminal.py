"""
Terminal report — colored, formatted output using Rich.
Falls back to plain output if Rich is not installed.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.tcp_scan import PortResult
    from core.udp_scan import UDPPortResult
    from core.os_detect import OSResult


@dataclass
class ScanSummary:
    host:       str
    ip:         str
    scan_time:  float
    tcp_results: list = field(default_factory=list)
    udp_results: list = field(default_factory=list)
    os_result:  object | None = None
    scan_mode:  str = "connect"


def print_report(summary: ScanSummary) -> None:
    try:
        _rich_report(summary)
    except ImportError:
        _plain_report(summary)


def _rich_report(summary: ScanSummary) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    console = Console()

    # ── Header ──────────────────────────────────────────────────────────────
    open_tcp = [r for r in summary.tcp_results if r.state == "open"]
    open_udp = [r for r in summary.udp_results if r.state == "open"]
    risk_ports = [r for r in open_tcp if r.risk]

    header = Text()
    header.append("\n  PORT SCANNER v1.0", style="bold green")
    header.append("  —  Professional Edition\n", style="dim")
    console.print(header)

    # ── Target info ─────────────────────────────────────────────────────────
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column("Key",   style="dim cyan",  width=18)
    info_table.add_column("Value", style="white")
    info_table.add_row("Target",     summary.host)
    info_table.add_row("IP",         summary.ip)
    info_table.add_row("Scan mode",  summary.scan_mode.upper())
    info_table.add_row("Scan time",  f"{summary.scan_time:.2f}s")
    info_table.add_row("Open TCP",   f"[bold green]{len(open_tcp)}[/] ports")
    info_table.add_row("Open UDP",   f"[bold yellow]{len(open_udp)}[/] ports")
    if risk_ports:
        info_table.add_row("High risk",  f"[bold red]{len(risk_ports)}[/] ports")
    console.print(Panel(info_table, title="[bold]Scan Target[/]", border_style="green", padding=(0,1)))

    # ── OS Detection ────────────────────────────────────────────────────────
    if summary.os_result and summary.os_result.os_guess != "Unknown":
        os = summary.os_result
        conf_color = {"High": "green", "Medium": "yellow", "Low": "red"}.get(os.confidence, "white")
        os_text = (
            f"[bold]{os.os_guess}[/]  "
            f"[{conf_color}]({os.confidence} confidence)[/{conf_color}]"
        )
        if os.details:
            os_text += f"  [dim]{os.details}[/dim]"
        console.print(Panel(os_text, title="[bold]OS Detection[/]", border_style="cyan", padding=(0,1)))

    # ── TCP Results ─────────────────────────────────────────────────────────
    if summary.tcp_results:
        tcp_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            padding=(0, 1),
        )
        tcp_table.add_column("PORT",    width=8,  style="bold")
        tcp_table.add_column("STATE",   width=10)
        tcp_table.add_column("SERVICE", width=20)
        tcp_table.add_column("LATENCY", width=10, style="dim")
        tcp_table.add_column("BANNER / VERSION", style="dim")

        for r in sorted(summary.tcp_results, key=lambda x: x.port):
            if r.state == "open":
                state_str = "[bold green]OPEN[/]"
                port_str  = f"[bold green]{r.port}[/]"
            elif r.state == "filtered":
                state_str = "[yellow]FILTERED[/]"
                port_str  = str(r.port)
            else:
                continue  # skip closed ports in output

            risk_flag = " [red]⚠[/]" if r.risk else ""
            svc_str   = f"{r.service}{risk_flag}"

            banner_str = ""
            if r.banner and r.banner.version:
                banner_str = r.banner.version[:60]
            elif r.banner and r.banner.cleaned:
                banner_str = r.banner.cleaned[:60]

            tcp_table.add_row(
                port_str,
                state_str,
                svc_str,
                f"{r.latency:.1f}ms" if r.latency else "",
                banner_str,
            )

        console.print(Panel(tcp_table, title="[bold]TCP Scan Results[/]", border_style="green"))

    # ── UDP Results ─────────────────────────────────────────────────────────
    open_udp_results = [r for r in summary.udp_results if r.state in ("open", "open|filtered")]
    if open_udp_results:
        udp_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold yellow",
            border_style="dim",
            padding=(0, 1),
        )
        udp_table.add_column("PORT",    width=8,  style="bold")
        udp_table.add_column("STATE",   width=14)
        udp_table.add_column("SERVICE", width=20)
        udp_table.add_column("LATENCY", width=10, style="dim")

        for r in sorted(open_udp_results, key=lambda x: x.port):
            state_color = "green" if r.state == "open" else "yellow"
            udp_table.add_row(
                f"[bold yellow]{r.port}[/]",
                f"[{state_color}]{r.state.upper()}[/{state_color}]",
                r.service,
                f"{r.latency:.1f}ms" if r.latency else "",
            )

        console.print(Panel(udp_table, title="[bold]UDP Scan Results[/]", border_style="yellow"))

    # ── Risk Summary ────────────────────────────────────────────────────────
    if risk_ports:
        risk_lines = []
        for r in risk_ports:
            version = r.banner.version if r.banner else ""
            line = f"  [bold red]:{r.port}[/] — {r.service}"
            if version:
                line += f"  [dim]({version})[/dim]"
            risk_lines.append(line)

        console.print(Panel(
            "\n".join(risk_lines),
            title="[bold red]⚠ High-Risk Open Ports[/]",
            border_style="red",
        ))

    console.print(f"\n[dim]Scan complete. Use --output to save reports.[/dim]\n")


def _plain_report(summary: ScanSummary) -> None:
    """Fallback if Rich is not installed."""
    open_tcp = [r for r in summary.tcp_results if r.state == "open"]
    print(f"\n=== PORT SCANNER RESULTS ===")
    print(f"Target : {summary.host} ({summary.ip})")
    print(f"Mode   : {summary.scan_mode}")
    print(f"Time   : {summary.scan_time:.2f}s")
    print(f"Open   : {len(open_tcp)} TCP ports\n")

    if summary.os_result:
        print(f"OS     : {summary.os_result.os_guess} ({summary.os_result.confidence})")
        print()

    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<18} {'LATENCY':<10} BANNER")
    print("-" * 70)
    for r in sorted(summary.tcp_results, key=lambda x: x.port):
        if r.state not in ("open", "filtered"):
            continue
        banner = r.banner.version or r.banner.cleaned[:40] if r.banner else ""
        print(f"{r.port:<8} {r.state:<10} {r.service:<18} {r.latency:.1f}ms      {banner}")
    print()
