# 🔍 Port Scanner

Professional TCP/UDP port scanner written in Python. Supports SYN stealth scan, banner grabbing, OS fingerprinting, and 6 output formats.

> **Educational purposes only. Always get permission before scanning any system.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **TCP SYN Scan** | Stealth half-open scan via Scapy (requires root) |
| **TCP Connect Scan** | Fallback mode, no root required |
| **UDP Scan** | Common UDP ports with protocol-specific probes |
| **Banner Grabbing** | HTTP, SSH, FTP, SMTP, Redis, MySQL and more |
| **OS Fingerprinting** | TTL + TCP Window Size heuristics |
| **Multi-threading** | Up to 500+ threads, configurable |
| **6 Output Formats** | Terminal (Rich), JSON, TXT, HTML, XML (Nmap-compat) |

---

## 📁 Structure

```
port-scanner/
├── scanner.py          # Main CLI entry point
├── core/
│   ├── tcp_scan.py     # TCP SYN + Connect scan
│   ├── udp_scan.py     # UDP scan with protocol probes
│   ├── banner.py       # Banner grabbing
│   ├── os_detect.py    # OS fingerprinting
│   └── services.py     # Port → service name map (1000+ ports)
├── reports/
│   ├── terminal.py     # Rich colored terminal output
│   └── exporters.py    # JSON, TXT, HTML, XML exporters
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

```bash
git clone https://github.com/Rajabov0828/port-scanner
cd port-scanner
pip install -r requirements.txt
```

---

## 🎯 Usage

```bash
# Basic scan (top 100 ports, no root needed)
python scanner.py 192.168.1.1

# SYN stealth scan (requires root)
sudo python scanner.py 192.168.1.1 --syn

# Full scan with UDP + save all reports
sudo python scanner.py 192.168.1.1 -p top1000 --udp --output ./reports

# Specific ports
python scanner.py example.com -p 22,80,443,3306,6379

# Fast scan (high threads, low timeout)
python scanner.py 192.168.1.1 -p 1-1024 --threads 300 --timeout 0.3

# Save individual formats
python scanner.py 192.168.1.1 --json scan.json --html scan.html
```

---

## 📊 Output Example

```
  TARGET   : example.com (93.184.216.34)
  ┌─────────────────────────────────────┐
  │  OS: Linux / Android  (High)        │
  │  TTL=64, Window=29200               │
  └─────────────────────────────────────┘

  PORT     STATE      SERVICE          LATENCY   BANNER / VERSION
  ─────────────────────────────────────────────────────────────────
  22       OPEN       SSH              12.4ms    OpenSSH_8.9
  80       OPEN       HTTP             18.2ms    nginx/1.24.0
  443      OPEN       HTTPS            19.1ms    nginx/1.24.0
  8080     FILTERED   HTTP-Alt         -
```

---

## 🛡️ Port Range Syntax

| Syntax | Meaning |
|--------|---------|
| `80` | Single port |
| `22,80,443` | Multiple ports |
| `1-1024` | Range |
| `top100` | Top 100 common ports |
| `top1000` | Top 1000 common ports |
| `1-65535` | All ports |

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**.  
Scanning systems without explicit permission is illegal in most countries.  
The author is not responsible for any misuse.

---

## 👤 Author

**Jurabek Rajabov** — Cybersecurity Learner  
GitHub: [@Rajabov0828](https://github.com/Rajabov0828)

---

## 📜 License

MIT License
