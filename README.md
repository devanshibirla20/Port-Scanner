# 🛡️ Modern Port Scanner

> A beautiful, production-ready TCP Port Scanner built with **Python** and **Streamlit** — designed for cybersecurity learners and portfolio showcasing.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-red?style=flat-square&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Educational](https://img.shields.io/badge/Purpose-Educational%20Only-yellow?style=flat-square)

---

## 📌 Description

**Modern Port Scanner** is a full-featured web application that performs **TCP connect scans** on any target host. Built as a cybersecurity portfolio project, it demonstrates Python networking skills, multi-threading, and professional UI design — all packaged in a sleek dark-terminal interface.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🎯 Target Input | IP address or hostname with live DNS resolution |
| ⚡ Quick Scan | Pre-configured list of 26 most critical ports |
| 🔢 Custom Range | Scan any port range from 1 to 65535 |
| 🧵 Multi-threaded | Up to 300 concurrent threads for fast scanning |
| 📡 Live Progress | Real-time progress bar + live terminal log |
| 🟢 Open Port Badges | Instant visual feedback as ports are discovered |
| 📋 Summary Table | Sorted results with service names and timestamps |
| 📥 Export | Download results as `.csv` or formatted `.txt` report |
| 🎨 Dark UI | Modern dark-terminal aesthetic with JetBrains Mono font |
| ⚠️ Disclaimer | Prominent educational-only warning banner |

---

## 🚀 How to Run

### Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourname/modern-port-scanner.git
cd modern-port-scanner

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app
streamlit run app.py
```

App opens at `http://localhost:8501` in your browser.

### Deploy Free on Streamlit Cloud

1. Push this repository to **GitHub** (public or private).
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **"New app"** → select your repo → set main file to `app.py`.
4. Click **Deploy** — your app gets a free public URL in ~60 seconds.

---

## 🖼️ Screenshots

> Add screenshots to a `/screenshots` folder and reference them here.

| View | Description |
|---|---|
| `screenshots/hero.png` | Hero banner and configuration panel |
| `screenshots/scanning.png` | Live scan in progress with terminal log |
| `screenshots/results.png` | Final results table with open ports |
| `screenshots/download.png` | CSV and TXT download buttons |

---

## 🛠️ Technologies Used

- **Python 3.10+** — Core language
- **Streamlit** — Web application framework
- **socket** — TCP connect scanning (stdlib)
- **concurrent.futures** — Multi-threaded port scanning (stdlib)
- **pandas** — Results table display and CSV export
- **JetBrains Mono** — Terminal-style typography (Google Fonts)

---

## 📁 Project Structure

```
modern-port-scanner/
├── app.py            ← Main Streamlit application
├── requirements.txt  ← Python dependencies
└── README.md         ← This file
```

---

## ⚙️ Configuration Reference

| Setting | Default | Range | Notes |
|---|---|---|---|
| Start Port | 1 | 1–65534 | Disabled in Quick Scan mode |
| End Port | 1024 | 2–65535 | Disabled in Quick Scan mode |
| Threads | 100 | 10–300 | Higher = faster but noisier |
| Timeout | 0.8 s | 0.2–3.0 s | Lower = faster but more false-negatives |

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes ONLY.**
>
> Only scan IP addresses and hosts that **you own** or have **explicit written permission** to test.
> Unauthorized port scanning may violate local, national, or international laws including the
> Computer Fraud and Abuse Act (CFAA) and similar legislation in other countries.
>
> The author and contributors accept **no liability** for any misuse of this software.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue first to discuss changes.

---

*Built as a learning project in Cybersecurity · Python + Streamlit*
