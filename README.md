# 🛡️ PortScanner Pro — Advanced Cybersecurity Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-red?style=flat-square&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Purpose](https://img.shields.io/badge/Purpose-Educational%20Only-yellow?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-3.0-cyan?style=flat-square)]()

> 🚀 A professional-grade, multi-threaded TCP port scanner with a modern cybersecurity dashboard — built using Python & Streamlit.

---

## 🌐 Live Demo

👉 **Try it here:**  
🔗 https://port-scanner-hz9xxesxazaanhmaydorxc.streamlit.app/

---

## ✨ Key Features

### 🔍 Core Scanning Engine
- ⚡ Multi-threaded scanning (up to 300 threads)
- 🚀 Quick Scan (common ports)
- 📡 Full Scan (1–65535)
- 🎯 Custom Port Range
- ⏱ Configurable timeout
- 🔎 Banner grabbing (service detection)

---

### 🧠 Intelligence Engine
- 🔴 Risk classification (Critical / High / Medium / Low)
- 📚 CVE hints & vulnerability suggestions
- 🖥 OS fingerprinting (heuristic-based)
- 🌍 IP geolocation (country, ISP, organization)

---

### 🎨 Dashboard UI
- 🌑 Modern dark cybersecurity theme
- 💻 Live terminal-style output
- 📊 Real-time progress tracking
- 🎯 Risk-based color badges
- 📑 Tab-based interface
- 🧾 Vulnerability alerts & OS detection

---

### 📦 Export & History
- 📥 CSV export (structured data)
- 📄 Full TXT security report
- 🕑 Scan history tracking
- 📊 Organized result tables

---

## 🗂️ Project Structure

```
port-scanner/
│
├── app.py
├── scanner.py
├── intel.py
├── history.py
├── export_utils.py
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

```bash
git clone https://github.com/devanshibirla20/port-scanner.git
cd port-scanner

python -m venv venv
venv\Scripts\activate   # Windows

pip install -r requirements.txt
streamlit run app.py
```

📍 App runs on: `http://localhost:8501`

---

## ⚙️ Configuration

| Setting     | Range       | Description              |
|------------|------------|--------------------------|
| Threads     | 10–300     | Speed vs system load     |
| Timeout     | 0.2–3 sec  | Accuracy vs speed        |
| Scan Mode   | 3 types    | Quick / Full / Custom    |

---

## 🔐 Risk Levels

| Level        | Meaning              |
|-------------|---------------------|
| 🔴 Critical | Immediate threat     |
| 🟠 High     | Needs fixing        |
| 🟡 Medium   | Review recommended  |
| 🟢 Low      | Safe / monitored    |

---

## 🛠️ Tech Stack

- 🐍 Python  
- ⚡ Streamlit  
- 🌐 Socket Programming  
- 🧵 ThreadPoolExecutor  
- 📊 Pandas  

---

## 📸 Screenshots

![UI Screenshot 1](https://github.com/user-attachments/assets/1af9d6ac-a99c-43dd-8960-ab12d7ee0e3c)

![UI Screenshot 2](https://github.com/user-attachments/assets/14362bbb-8584-42da-a4f1-58e57d84a64b)

<img width="1919" height="872" alt="Screenshot 2026-04-19 163252" src="https://github.com/user-attachments/assets/7e2772ed-5449-419a-9b1a-efac7b0147d1" />


---

## ⚠️ Disclaimer

> This tool is strictly for **educational purposes only**.

- ❌ Do NOT scan systems without permission  
- ⚖️ Unauthorized scanning may violate cyber laws  

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👩‍💻 Author

**Devanshi Birla**  
🛡️ Cybersecurity Enthusiast  

---

⭐ If you like this project, consider giving it a star!
