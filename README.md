# 🛡️ PortScanner — Advanced Port Scanner Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-red?style=flat-square&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Purpose](https://img.shields.io/badge/Purpose-Educational%20Only-yellow?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-3.0-cyan?style=flat-square)]()

> A professional-grade, multi-threaded TCP port scanner with a modern dark-themed cybersecurity dashboard — built entirely in Python and Streamlit.

---

## ✨ Feature Overview

### 🔍 Core Scanning Engine
| Feature | Details |
|---|---|
| Multi-threaded scanning | Up to 300 concurrent threads using `ThreadPoolExecutor` |
| Quick Scan | 46 pre-selected critical and common ports |
| Full Range Scan | Ports 1–65535 with configurable threading |
| Custom Range | User-defined start/end port range |
| Configurable timeout | Per-port connection timeout (0.2–3.0s) |
| Banner Grabbing | Service version detection via raw socket probing |
| Service Detection | 43+ known service mappings + `getservbyport` fallback |

### 🧠 Intelligence Engine
| Feature | Details |
|---|---|
| Risk Classification | 4 levels: Critical / High / Medium / Low |
| CVE References | 29+ CVE hints for common vulnerable services |
| Vulnerability Hints | Detailed remediation recommendations per port |
| OS Fingerprinting | Heuristic OS detection from open port patterns |
| IP Geolocation | Country, city, ISP, org, timezone via ip-api.com |

### 🎨 Dashboard UI
| Feature | Details |
|---|---|
| Modern Dark Theme | Clean deep-space background with cyan accent colors |
| Professional Typography | Inter font family for modern, readable interface |
| Form-based Configuration | Streamlined scan setup with validation |
| Live Terminal Log | Real-time scanning progress with color-coded output |
| Risk-coded Port Badges | Color-coded badges by vulnerability severity |
| Real-time Progress Bar | Gradient progress indicator during scans |
| 4-tab Results Panel | Live Output / Port Details / Vulnerability Report / History |
| OS Detection Display | Heuristic OS identification with visual badges |
| Vulnerability Alerts | Critical security alerts for high-risk findings |

### 📦 Export & History
| Feature | Details |
|---|---|
| CSV Export | Port, service, risk, CVE, banner, description, recommendation |
| TXT Report | Full formatted security report with geo and vuln sections |
| Scan History | JSON-persisted local history of past 20 scans |
| History Table | Timestamped history with target, IP, open ports, risk count |

---

## 🗂️ Project Structure

```
port-scanner/
│
├── app.py              # Main Streamlit dashboard — UI, layout, scan execution
├── scanner.py          # TCP scanning engine — threading, banner grabbing, resolution
├── intel.py            # Intelligence engine — risk DB, OS fingerprinting, geolocation
├── history.py          # Scan history persistence (JSON)
├── export_utils.py     # CSV and TXT report generation
├── requirements.txt    # Python dependencies
├── scan_history.json   # Auto-created scan history (gitignore this)
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip

### Local Installation

```bash
# 1. Clone the repository
git clone https://github.com/devanshibirla20/port-scanner.git
cd port-scanner

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app
streamlit run app.py
```

App opens at `http://localhost:8501`

## ⚙️ Configuration Reference

| Setting | Default | Range | Notes |
|---|---|---|---|
| Scan Mode | Quick Scan | 3 options | Quick=46 ports, Full=65535, Custom |
| Threads | 150 | 10–300 | Higher = faster, may trigger IDS |
| Timeout | 0.75s | 0.2–3.0s | Lower = faster, more false negatives |
| Banner Grabbing | On | Toggle | Adds ~1–2s per open port |
| Geolocation | On | Toggle | Uses ip-api.com (free, no key) |
| History Tracking | On | Toggle | Saves to local JSON |

---

## 🔐 Risk Level System

| Level | Color | Examples | Action |
|---|---|---|---|
| 🔴 Critical | Red | RDP, SMB, Redis, MongoDB, FTP, Telnet | Immediate action required |
| 🟠 High | Orange | SMTP, POP3, IMAP, Jupyter, LDAP | Address within 24h |
| 🟡 Medium | Amber | HTTP, DNS, HTTP-Alt | Review and harden |
| 🟢 Low | Green | SSH, HTTPS, IMAPS | Monitor and maintain |

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Web Framework | Streamlit ≥ 1.35 |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Networking | `socket` (stdlib) |
| Geolocation | ip-api.com (free REST API) |
| Data Processing | pandas |
| Export | csv, io (stdlib) |
| Persistence | json (stdlib) |
| Fonts | Inter (Google Fonts) |

---

## ⚠️ Legal Disclaimer

> **This tool is for EDUCATIONAL PURPOSES ONLY.**
>
> You must only scan hosts and networks that you **own** or have **explicit written permission** to test. Unauthorized port scanning is illegal in many jurisdictions and may violate:
> - The Computer Fraud and Abuse Act (CFAA) — United States
> - The Computer Misuse Act — United Kingdom
> - Section 66B of the IT Act — India
> - Similar cybercrime laws worldwide
>
> The author and contributors assume **no liability** for any misuse of this tool.
> By using this software, you agree to use it only for lawful purposes.

---

## 🤝 Contributing

Pull requests welcome! Please open an issue first to discuss major changes.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---
<img width="1907" height="872" alt="Screenshot 2026-04-19 163155" src="https://github.com/user-attachments/assets/1af9d6ac-a99c-43dd-8960-ab12d7ee0e3c" />

---

<img width="1912" height="871" alt="Screenshot 2026-04-19 163232" src="https://github.com/user-attachments/assets/14362bbb-8584-42da-a4f1-58e57d84a64b" />

---
<img width="1919" height="872" alt="Screenshot 2026-04-19 163252" src="https://github.com/user-attachments/assets/70e494f5-df36-49cc-a336-2beea63a1b74" />


---

*🛡️ PortScanner Pro — Built as a learning project in Cybersecurity · Python + Streamlit*
