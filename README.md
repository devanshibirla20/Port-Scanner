# 🛡️ PortScanner — Advanced Port Scanner Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-red?style=flat-square&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Purpose](https://img.shields.io/badge/Purpose-Educational%20Only-yellow?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-3.0-cyan?style=flat-square)]()

> A professional-grade, multi-threaded TCP port scanner with a modern dark-themed cybersecurity dashboard — built entirely in Python and Streamlit.

---

🌐 🔴 Live Demo

👉 Try it here:
🔗 https://port-scanner-hz9xxesxazaanhmaydorxc.streamlit.app/

---

✨ Feature Overview
🔍 Core Scanning Engine
Multi-threaded scanning (up to 300 threads)
Quick scan (common ports)
Full scan (1–65535)
Custom port range
Configurable timeout
Banner grabbing (service detection)
🧠 Intelligence Engine
Risk classification (Critical / High / Medium / Low)
CVE hints & vulnerability suggestions
OS fingerprinting (heuristic)
IP geolocation (country, ISP, org)
🎨 Dashboard UI
Clean dark cybersecurity theme
Live terminal output
Real-time progress tracking
Risk-based color badges
Tab-based interface
OS detection display
Vulnerability alerts
📦 Export & History
CSV export
Full TXT security report
Scan history tracking
Structured result tables
🗂️ Project Structure
port-scanner/
│
├── app.py
├── scanner.py
├── intel.py
├── history.py
├── export_utils.py
├── requirements.txt
└── README.md
🚀 Getting Started
git clone https://github.com/devanshibirla20/port-scanner.git
cd port-scanner

python -m venv venv
venv\Scripts\activate   # (Windows)

pip install -r requirements.txt
streamlit run app.py
⚙️ Configuration
Setting	Range	Description
Threads	10–300	Speed vs load
Timeout	0.2–3s	Accuracy vs speed
Scan Mode	3 types	Quick / Full / Custom
🔐 Risk Levels
Level	Meaning
🔴 Critical	Immediate risk
🟠 High	Needs fixing
🟡 Medium	Review
🟢 Low	Safe
🛠️ Tech Stack
Python
Streamlit
Socket Programming
ThreadPoolExecutor
Pandas

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---
<img width="1907" height="872" alt="Screenshot 2026-04-19 163155" src="https://github.com/user-attachments/assets/1af9d6ac-a99c-43dd-8960-ab12d7ee0e3c" />

---

<img width="1912" height="871" alt="Screenshot 2026-04-19 163232" src="https://github.com/user-attachments/assets/14362bbb-8584-42da-a4f1-58e57d84a64b" />

---
<img width="1919" height="872" alt="Screenshot 2026-04-19 163252" src="https://github.com/user-attachments/assets/70e494f5-df36-49cc-a336-2beea63a1b74" />


---
⚠️ Disclaimer

This tool is for educational purposes only.
Do not scan systems without permission.


*🛡️ PortScanner Pro — Built as a learning project in Cybersecurity · Python + Streamlit*
