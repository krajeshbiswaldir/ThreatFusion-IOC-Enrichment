# 🔥 ThreatFusion — IOC Enrichment Tool

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ThreatFusion** is a professional, command-line IOC (Indicator of Compromise) enrichment tool built for SOC analysts, threat intelligence engineers, and DFIR teams. It automatically detects IOC types, enriches them via multiple threat intelligence APIs, and generates executive-ready reports in CSV, Excel, HTML, and PDF formats.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Auto-Detection** | Automatically identifies IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 |
| **Multi-Source Enrichment** | VirusTotal, AbuseIPDB, AlienVault OTX, WHOIS, GeoIP, Shodan |
| **Risk Scoring Engine** | Weighted algorithm combining VT (50%), AbuseIPDB (30%), OTX (20%) |
| **Parallel Processing** | ThreadPoolExecutor with configurable workers |
| **Rate Limiting** | Built-in API throttling and exponential backoff for 429 errors |
| **4 Output Formats** | CSV, Excel (conditional formatting), HTML (interactive dashboard), PDF |
| **Production Quality** | Retry logic, SSL handling, timeout management, session reuse |

---

## 🚀 Quick Start

## Install dependencies
```bash
pip install requests pandas openpyxl reportlab jinja2 pycountry python-whois shodan tqdm
### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/ThreatFusion-IOC-Enrichment.git
cd ThreatFusion-IOC-Enrichment
