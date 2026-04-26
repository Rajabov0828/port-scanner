"""
Report generators: JSON, TXT, HTML, XML.
All take a ScanSummary and a file path, write the report.
"""

from __future__ import annotations
import json
import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reports.terminal import ScanSummary


# ─── JSON ─────────────────────────────────────────────────────────────────────

def save_json(summary, path: str) -> None:
    data = _summary_to_dict(summary)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[JSON] Saved → {path}")


def _summary_to_dict(summary) -> dict:
    os_data = None
    if summary.os_result:
        o = summary.os_result
        os_data = {
            "os_guess":   o.os_guess,
            "confidence": o.confidence,
            "ttl":        o.ttl,
            "window":     o.window_size,
            "details":    o.details,
        }

    tcp_ports = []
    for r in summary.tcp_results:
        banner = {}
        if r.banner:
            banner = {
                "raw":       r.banner.raw[:200] if r.banner.raw else "",
                "version":   r.banner.version,
                "protocol":  r.banner.protocol_hint,
            }
        tcp_ports.append({
            "port":    r.port,
            "state":   r.state,
            "service": r.service,
            "latency": r.latency,
            "risk":    r.risk,
            "banner":  banner,
        })

    udp_ports = []
    for r in summary.udp_results:
        udp_ports.append({
            "port":    r.port,
            "state":   r.state,
            "service": r.service,
            "latency": r.latency,
        })

    return {
        "meta": {
            "tool":      "port-scanner v1.0",
            "author":    "Jurabek Rajabov",
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_time": summary.scan_time,
            "scan_mode": summary.scan_mode,
        },
        "target": {
            "host": summary.host,
            "ip":   summary.ip,
        },
        "os":         os_data,
        "tcp_ports":  tcp_ports,
        "udp_ports":  udp_ports,
        "stats": {
            "open_tcp":      sum(1 for r in summary.tcp_results if r.state == "open"),
            "filtered_tcp":  sum(1 for r in summary.tcp_results if r.state == "filtered"),
            "closed_tcp":    sum(1 for r in summary.tcp_results if r.state == "closed"),
            "open_udp":      sum(1 for r in summary.udp_results if r.state == "open"),
            "risk_ports":    sum(1 for r in summary.tcp_results if r.risk and r.state == "open"),
        },
    }


# ─── TXT ─────────────────────────────────────────────────────────────────────

def save_txt(summary, path: str) -> None:
    lines = []
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_tcp = [r for r in summary.tcp_results if r.state == "open"]
    risk_tcp = [r for r in open_tcp if r.risk]

    lines += [
        "=" * 60,
        "  PORT SCANNER v1.0  —  Scan Report",
        "=" * 60,
        f"  Timestamp  : {ts}",
        f"  Target     : {summary.host}",
        f"  IP         : {summary.ip}",
        f"  Scan mode  : {summary.scan_mode.upper()}",
        f"  Scan time  : {summary.scan_time:.2f}s",
        f"  Open TCP   : {len(open_tcp)} ports",
        f"  Risk ports : {len(risk_tcp)} ports",
        "=" * 60, "",
    ]

    if summary.os_result and summary.os_result.os_guess != "Unknown":
        o = summary.os_result
        lines += [
            "OS DETECTION",
            "-" * 40,
            f"  OS Guess   : {o.os_guess}",
            f"  Confidence : {o.confidence}",
            f"  Details    : {o.details}",
            "",
        ]

    if summary.tcp_results:
        lines += ["TCP SCAN RESULTS", "-" * 40]
        lines.append(f"  {'PORT':<8} {'STATE':<12} {'SERVICE':<20} {'LAT':<10} BANNER")
        lines.append("  " + "-" * 56)
        for r in sorted(summary.tcp_results, key=lambda x: x.port):
            if r.state not in ("open", "filtered"):
                continue
            risk_flag = " [RISK]" if r.risk else ""
            banner = ""
            if r.banner:
                banner = (r.banner.version or r.banner.cleaned)[:50]
            lines.append(
                f"  {r.port:<8} {r.state:<12} {r.service + risk_flag:<20} "
                f"{str(round(r.latency,1))+'ms':<10} {banner}"
            )
        lines.append("")

    if summary.udp_results:
        open_udp = [r for r in summary.udp_results if r.state in ("open", "open|filtered")]
        if open_udp:
            lines += ["UDP SCAN RESULTS", "-" * 40]
            lines.append(f"  {'PORT':<8} {'STATE':<16} {'SERVICE':<20} LAT")
            lines.append("  " + "-" * 48)
            for r in sorted(open_udp, key=lambda x: x.port):
                lines.append(
                    f"  {r.port:<8} {r.state:<16} {r.service:<20} "
                    f"{str(round(r.latency,1))+'ms':<10}"
                )
            lines.append("")

    if risk_tcp:
        lines += ["HIGH-RISK OPEN PORTS", "-" * 40]
        for r in risk_tcp:
            version = (r.banner.version or "") if r.banner else ""
            lines.append(f"  :{r.port} — {r.service}  {version}")
        lines.append("")

    lines += ["=" * 60, "  End of Report", "=" * 60]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[TXT] Saved → {path}")


# ─── HTML ─────────────────────────────────────────────────────────────────────

def save_html(summary, path: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_tcp = [r for r in summary.tcp_results if r.state == "open"]
    risk_tcp = [r for r in open_tcp if r.risk]
    d = _summary_to_dict(summary)

    tcp_rows = ""
    for r in sorted(summary.tcp_results, key=lambda x: x.port):
        if r.state not in ("open", "filtered"):
            continue
        state_cls = "open" if r.state == "open" else "filtered"
        risk_cls  = "risk" if r.risk else ""
        banner = ""
        if r.banner:
            banner = r.banner.version or r.banner.cleaned[:80]
        tcp_rows += f"""
        <tr class="{state_cls} {risk_cls}">
          <td class="port">{r.port}</td>
          <td><span class="badge {state_cls}">{r.state.upper()}</span></td>
          <td>{r.service}{"<span class='risk-flag'>⚠</span>" if r.risk else ""}</td>
          <td class="mono dim">{r.latency:.1f}ms</td>
          <td class="mono dim">{_esc(banner)}</td>
        </tr>"""

    udp_rows = ""
    for r in sorted(summary.udp_results, key=lambda x: x.port):
        if r.state not in ("open", "open|filtered"):
            continue
        udp_rows += f"""
        <tr>
          <td class="port">{r.port}</td>
          <td><span class="badge filtered">{r.state.upper()}</span></td>
          <td>{r.service}</td>
          <td class="mono dim">{r.latency:.1f}ms</td>
        </tr>"""

    os_html = ""
    if summary.os_result and summary.os_result.os_guess != "Unknown":
        o = summary.os_result
        conf_cls = o.confidence.lower()
        os_html = f"""
      <div class="card os-card">
        <h2>OS Detection</h2>
        <div class="os-result">
          <span class="os-name">{o.os_guess}</span>
          <span class="confidence {conf_cls}">{o.confidence} confidence</span>
        </div>
        <div class="os-details mono dim">{o.details}</div>
      </div>"""

    risk_html = ""
    if risk_tcp:
        risk_items = "".join(
            f"<li><code>:{r.port}</code> — <strong>{r.service}</strong>"
            f"{' — ' + r.banner.version if r.banner and r.banner.version else ''}</li>"
            for r in risk_tcp
        )
        risk_html = f"""
      <div class="card risk-card">
        <h2>⚠ High-Risk Open Ports</h2>
        <ul>{risk_items}</ul>
      </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan Report — {summary.host}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --dim: #8b949e;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
    --blue: #58a6ff; --purple: #bc8cff;
    --font: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font);
         font-size: 13px; line-height: 1.6; padding: 2rem; }}
  h1 {{ font-size: 1.4rem; color: var(--green); margin-bottom: 0.3rem; }}
  h2 {{ font-size: 0.9rem; color: var(--blue); text-transform: uppercase;
        letter-spacing: .1em; margin-bottom: 1rem; }}
  .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 1.5rem; }}
  .subtitle {{ color: var(--dim); font-size: 0.8rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
           gap: 1rem; margin-bottom: 1.5rem; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border);
           border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .lbl {{ color: var(--dim); font-size: 0.75rem; margin-top: 4px; }}
  .num.green {{ color: var(--green); }}
  .num.yellow {{ color: var(--yellow); }}
  .num.red {{ color: var(--red); }}
  .card {{ background: var(--bg2); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .risk-card {{ border-color: var(--red); }}
  .os-card {{ border-color: var(--purple); }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border);
        color: var(--blue); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid var(--bg3); vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg3); }}
  .port {{ color: var(--blue); font-weight: 700; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }}
  .badge.open {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge.filtered {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .risk-flag {{ color: var(--red); margin-left: 6px; }}
  .risk td:first-child {{ border-left: 3px solid var(--red); }}
  .mono {{ font-family: var(--font); }}
  .dim {{ color: var(--dim); }}
  .os-result {{ display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }}
  .os-name {{ font-size: 1rem; font-weight: 600; color: var(--purple); }}
  .confidence {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
  .confidence.high   {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .confidence.medium {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .confidence.low    {{ background: rgba(248,81,73,0.15);  color: var(--red); }}
  .risk-card ul {{ list-style: none; padding: 0; }}
  .risk-card li {{ padding: 6px 0; border-bottom: 1px solid var(--bg3); color: var(--dim); }}
  .risk-card li:last-child {{ border-bottom: none; }}
  .risk-card code {{ color: var(--red); }}
  code {{ background: var(--bg3); padding: 1px 6px; border-radius: 3px; }}
  .footer {{ color: var(--dim); font-size: 0.75rem; margin-top: 2rem;
             border-top: 1px solid var(--border); padding-top: 1rem; }}
</style>
</head>
<body>
  <div class="header">
    <h1>PORT SCANNER v1.0</h1>
    <div class="subtitle">
      Target: <strong>{summary.host}</strong> ({summary.ip}) &nbsp;|&nbsp;
      Mode: {summary.scan_mode.upper()} &nbsp;|&nbsp;
      {ts}
    </div>
  </div>

  <div class="grid">
    <div class="stat"><div class="num green">{len(open_tcp)}</div><div class="lbl">Open TCP</div></div>
    <div class="stat"><div class="num yellow">{sum(1 for r in summary.tcp_results if r.state=='filtered')}</div><div class="lbl">Filtered TCP</div></div>
    <div class="stat"><div class="num yellow">{sum(1 for r in summary.udp_results if r.state in ('open','open|filtered'))}</div><div class="lbl">Open UDP</div></div>
    <div class="stat"><div class="num red">{len(risk_tcp)}</div><div class="lbl">Risk Ports</div></div>
    <div class="stat"><div class="num">{summary.scan_time:.1f}s</div><div class="lbl">Scan Time</div></div>
  </div>

  {os_html}
  {risk_html}

  <div class="card">
    <h2>TCP Scan Results</h2>
    <table>
      <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Latency</th><th>Banner / Version</th></tr></thead>
      <tbody>{tcp_rows}</tbody>
    </table>
  </div>

  {"<div class='card'><h2>UDP Scan Results</h2><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Latency</th></tr></thead><tbody>" + udp_rows + "</tbody></table></div>" if udp_rows else ""}

  <div class="footer">
    Generated by port-scanner v1.0 &nbsp;|&nbsp; Author: Jurabek Rajabov &nbsp;|&nbsp;
    <em>For authorized security testing only</em>
  </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[HTML] Saved → {path}")


# ─── XML (Nmap-compatible format) ─────────────────────────────────────────────

def save_xml(summary, path: str) -> None:
    ts = int(datetime.datetime.now().timestamp())
    ts_str = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")

    port_tags = ""
    for r in sorted(summary.tcp_results, key=lambda x: x.port):
        if r.state == "closed":
            continue
        version = ""
        product = ""
        if r.banner:
            version = _esc(r.banner.version)
            product = _esc(r.banner.protocol_hint)

        port_tags += f"""
      <port protocol="tcp" portid="{r.port}">
        <state state="{r.state}" reason="syn-ack"/>
        <service name="{r.service.lower()}" product="{product}" version="{version}"/>
      </port>"""

    for r in sorted(summary.udp_results, key=lambda x: x.port):
        if r.state == "closed":
            continue
        port_tags += f"""
      <port protocol="udp" portid="{r.port}">
        <state state="{r.state}" reason="udp-response"/>
        <service name="{r.service.lower()}"/>
      </port>"""

    os_tag = ""
    if summary.os_result and summary.os_result.os_guess != "Unknown":
        o = summary.os_result
        accuracy = {"High": "90", "Medium": "70", "Low": "50"}.get(o.confidence, "50")
        os_tag = f"""
      <os>
        <osmatch name="{_esc(o.os_guess)}" accuracy="{accuracy}">
          <osclass type="general purpose"/>
        </osmatch>
      </os>"""

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="port-scanner" args="port-scanner" start="{ts}"
         startstr="{ts_str}" version="1.0" xmloutputversion="1.05">
  <host starttime="{ts}" endtime="{ts}">
    <status state="up" reason="echo-reply"/>
    <address addr="{summary.ip}" addrtype="ipv4"/>
    <hostnames>
      <hostname name="{summary.host}" type="user"/>
    </hostnames>
    <ports>{port_tags}
    </ports>
    {os_tag}
  </host>
  <runstats>
    <finished time="{ts}" elapsed="{summary.scan_time:.2f}" summary="scan done"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"[XML] Saved → {path}")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Escape XML/HTML special characters."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )
