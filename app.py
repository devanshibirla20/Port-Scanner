"""
app.py — Port Scanner Dashboard
Author : Devanshi Birla
Version: 3.0
Stack  : Python · Streamlit · ThreadPoolExecutor
"""

import time
from datetime import datetime

import streamlit as st

from scanner import resolve_host, run_scan, QUICK_PORTS
from intel import get_risk, get_risk_color, detect_os, get_geo
from history import add_scan, get_history, clear_history
from export_utils import build_csv, build_txt

st.set_page_config(
    page_title="PortScanner Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

THEME_CSS = """
<style>
:root {
    --bg0: #0b1624;
    --bg1: #121f33;
    --bg2: #17263c;
    --surface: #162438;
    --surface-2: #192d43;
    --border: rgba(255,255,255,0.08);
    --text: #e7eef8;
    --muted: #8fa4bd;
    --accent: #60d5ff;
    --accent-soft: rgba(96,213,255,0.14);
    --success: #7ad8a0;
    --warning: #f2be6b;
    --danger: #f26f6b;
    --radius: 18px;
    --shadow: 0 20px 60px rgba(0,0,0,0.18);
}
html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg0) !important;
    color: var(--text);
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { background: #111c2d !important; }
section[data-testid="stSidebarContent"] { padding-top: 1rem; }

::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 999px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

.hero {
    background: linear-gradient(180deg, #132038 0%, #0d1826 100%);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 24px;
    padding: 2rem 2.25rem;
    margin-bottom: 1.25rem;
    box-shadow: var(--shadow);
}
.hero-title {
    font-family: Inter, system-ui, sans-serif;
    font-size: 2.4rem;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.03em;
}
.hero-title span { color: var(--accent); }
.hero-sub {
    margin: 0.9rem 0 1.25rem;
    color: var(--muted);
    font-size: 0.95rem;
    line-height: 1.6;
    max-width: 720px;
}
.hero-stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.75rem;
    margin-top: 1rem;
}
.hero-stat {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 16px;
    padding: 1rem;
}
.hero-stat b {
    display: block;
    color: var(--text);
    font-size: 1.15rem;
    margin-bottom: 0.25rem;
}
.hero-stat span {
    color: var(--muted);
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.disclaimer {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 1rem 1.2rem;
    color: var(--warning);
    font-size: 0.86rem;
    margin-bottom: 1.5rem;
}

.panel {
    background: #121f30;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 20px;
    padding: 1.5rem;
    box-shadow: 0 15px 35px rgba(0,0,0,0.12);
}
.panel-title {
    font-size: 0.78rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 1.1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.panel-title::before {
    content: '';
    width: 8px;
    height: 8px;
    border-radius: 999px;
    background: var(--accent);
}

.stat-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.85rem;
    margin-bottom: 1.2rem;
}
.stat-box {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 1rem 0.9rem;
    text-align: center;
}
.stat-n {
    font-size: 1.6rem;
    font-weight: 700;
    margin: 0;
    color: var(--text);
}
.stat-n.g { color: var(--success); }
.stat-n.r { color: var(--danger); }
.stat-n.a { color: var(--warning); }
.stat-l {
    color: var(--muted);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-size: 0.72rem;
    margin-top: 0.35rem;
}

.terminal {
    background: #101d30;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
    font-size: 0.8rem;
    line-height: 1.8;
    max-height: 280px;
    overflow-y: auto;
    color: #d6e3ff;
}
.terminal span { display: block; }

.badge-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    min-height: 38px;
}
.port-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.45rem 0.9rem;
    border-radius: 999px;
    font-size: 0.75rem;
    background: rgba(96,213,255,0.12);
    border: 1px solid rgba(96,213,255,0.18);
    color: var(--accent);
}
.badge-crit { background: rgba(242,111,107,0.12); border-color: rgba(242,111,107,0.24); color: var(--danger); }
.badge-high { background: rgba(242,190,107,0.12); border-color: rgba(242,190,107,0.22); color: var(--warning); }
.badge-med { background: rgba(122,216,160,0.12); border-color: rgba(122,216,160,0.22); color: var(--success); }
.badge-low { background: rgba(96,213,255,0.12); border-color: rgba(96,213,255,0.24); color: var(--accent); }

.geo-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 1rem;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.85rem;
}
.geo-row { font-size: 0.82rem; color: var(--text); }
.geo-label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.72rem; }
.geo-value { color: var(--text); }

.vuln-alert {
    background: rgba(242,111,107,0.1);
    border: 1px solid rgba(242,111,107,0.25);
    border-radius: 18px;
    padding: 1rem 1.05rem;
    color: var(--danger);
    margin: 0.85rem 0;
    font-size: 0.92rem;
}

.scan-table, .hist-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.84rem;
}
.scan-table th, .hist-table th {
    text-align: left;
    padding: 0.85rem 1rem;
    color: var(--muted);
    font-weight: 600;
    letter-spacing: 0.12em;
    font-size: 0.72rem;
    border-bottom: 1px solid rgba(255,255,255,0.08);
}
.scan-table td, .hist-table td {
    padding: 0.9rem 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.08);
    color: var(--text);
    vertical-align: top;
}
.scan-table tr:hover td, .hist-table tr:hover td { background: rgba(255,255,255,0.03); }

.risk-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.35rem 0.7rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    background: rgba(255,255,255,0.05);
    color: var(--text);
    border: 1px solid rgba(255,255,255,0.08);
}

.os-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 999px;
    padding: 0.65rem 1rem;
    color: var(--text);
    font-size: 0.82rem;
}

.stButton > button {
    background: linear-gradient(180deg, #0f4a72 0%, #0c3b5a 100%) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 14px !important;
    font-size: 0.9rem !important;
    padding: 0.95rem 1rem !important;
    box-shadow: 0 10px 30px rgba(0,0,0,0.18) !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 14px 36px rgba(0,0,0,0.22) !important;
}

.stTextInput input, .stNumberInput input, .stSelectbox select {
    background: #122338 !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    color: var(--text) !important;
    border-radius: 14px !important;
    font-size: 0.9rem !important;
    padding: 0.85rem !important;
}
.stTextInput input:focus, .stNumberInput input:focus, .stSelectbox select:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(96,213,255,0.12) !important;
    outline: none !important;
}
label {
    color: var(--muted) !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.04em !important;
}

.stProgress > div > div > div {
    background: linear-gradient(90deg, #2c7fad, #60d5ff) !important;
    border-radius: 999px !important;
    box-shadow: none !important;
}
[data-testid="stProgressBar"] > div {
    background: rgba(255,255,255,0.08) !important;
    border-radius: 999px !important;
}

.stTabs [data-baseweb="tab-list"] { gap: 6px; background: transparent !important; padding-bottom: 0.25rem; }
.stTabs [data-baseweb="tab"] {
    background: rgba(255,255,255,0.03) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 14px 14px 0 0 !important;
    color: var(--muted) !important;
    font-size: 0.82rem !important;
}
.stTabs [aria-selected="true"] {
    background: rgba(96,213,255,0.16) !important;
    border-color: rgba(96,213,255,0.22) !important;
    color: var(--accent) !important;
}

.stCheckbox > label { color: var(--text) !important; font-size: 0.88rem !important; }
.stSlider [data-baseweb="slider"] div { background: var(--accent) !important; }

.stDownloadButton > button {
    background: rgba(122,216,160,0.12) !important;
    border: 1px solid rgba(122,216,160,0.24) !important;
    color: var(--success) !important;
    border-radius: 14px !important;
    font-size: 0.82rem !important;
    padding: 0.8rem 0.95rem !important;
}
.stDownloadButton > button:hover { background: rgba(122,216,160,0.18) !important; }

[data-testid="stAlert"] { border-radius: 16px !important; font-size: 0.9rem !important; }

.footer {
    text-align: center;
    margin-top: 2.5rem;
    padding-top: 1.2rem;
    border-top: 1px solid rgba(255,255,255,0.08);
    color: var(--muted);
    font-size: 0.78rem;
}
.footer span { color: var(--accent); }

.scan-pulse {
    display: inline-block;
    width: 8px;
    height: 8px;
    background: var(--accent);
    border-radius: 999px;
    margin-right: 0.65rem;
}
[data-baseweb="select"] { background: #122338 !important; border-color: rgba(255,255,255,0.1) !important; }
</style>
"""


st.markdown(THEME_CSS, unsafe_allow_html=True)

defaults = {
    "scan_results":  [],
    "last_target":   "",
    "last_ip":       "",
    "last_duration": 0.0,
    "last_geo":      {},
    "last_os":       ("Unknown", "None"),
    "scan_done":     False,
    "log_lines":     [],
    "badges_html":   "",
    "n_scanned":     0,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


def risk_class(level: str) -> str:
    return {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low"}.get(level, "low")


def render_badge(port: int, service: str, level: str) -> str:
    cls = risk_class(level)
    icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(level, "⚪")
    vuln = " ⚠" if level in ("Critical", "High") else ""
    return f"<span class='port-badge badge-{cls}'>{icon} {port}/{service}{vuln}</span>"


def render_risk_pill(level: str) -> str:
    color = get_risk_color(level)
    bg    = color.replace(")", ", 0.12)").replace("rgb", "rgba") if "rgb" in color else f"{color}22"
    return (
        f"<span class='risk-pill' style='"
        f"color:{color};background:{color}1a;"
        f"border:1px solid {color}55;'>{level}</span>"
    )


def render_stat_grid(n_open: int, n_crit: int, n_high: int, duration: float) -> str:
    return f"""
    <div class='stat-grid'>
      <div class='stat-box'>
        <span class='stat-n g'>{n_open}</span>
        <div class='stat-l'>Open Ports</div>
      </div>
      <div class='stat-box'>
        <span class='stat-n r'>{n_crit}</span>
        <div class='stat-l'>Critical</div>
      </div>
      <div class='stat-box'>
        <span class='stat-n a'>{n_high}</span>
        <div class='stat-l'>High Risk</div>
      </div>
      <div class='stat-box'>
        <span class='stat-n'>{duration}</span>
        <div class='stat-l'>Seconds</div>
      </div>
    </div>"""


def render_geo(geo: dict) -> str:
    if geo.get("status") != "success":
        msg = geo.get("message", "Unavailable")
        return f"<div class='geo-card' style='grid-template-columns:1fr;'><div class='geo-row'><div class='geo-label'>Status</div><div class='geo-value' style='color:#3a5278;'>{msg}</div></div></div>"
    items = [
        ("Country",  f"{geo.get('country','N/A')} ({geo.get('countryCode','')})"),
        ("Region",   geo.get("regionName", "N/A")),
        ("City",     geo.get("city", "N/A")),
        ("ISP",      geo.get("isp", "N/A")),
        ("Org",      geo.get("org", "N/A")),
        ("Timezone", geo.get("timezone", "N/A")),
    ]
    rows = "".join(
        f"<div class='geo-row'><div class='geo-label'>{k}</div><div class='geo-value'>{v}</div></div>"
        for k, v in items
    )
    return f"<div class='geo-card'>{rows}</div>"


def render_results_table(results: list[dict]) -> str:
    if not results:
        return "<p style='font-family:\"Share Tech Mono\",monospace;font-size:0.75rem;color:#3a5278;'>No open ports detected.</p>"

    rows = ""
    for r in results:
        risk = get_risk(r["port"])
        pill = render_risk_pill(risk["level"])
        banner = r.get("banner", "") or "<span style='color:#1a2d47;'>—</span>"
        banner_td = f"<span style='color:#4a6fa5;font-size:0.68rem;'>{banner[:60]}</span>"
        cve = f"<span style='color:#3a5278;font-size:0.65rem;'>{risk['cve_hint'][:50]}</span>"
        rows += f"""
        <tr>
          <td><b style='color:#00f5ff;'>{r['port']}</b></td>
          <td>{r['service']}</td>
          <td>{pill}</td>
          <td>{banner_td}</td>
          <td>{cve}</td>
        </tr>"""

    return f"""
    <table class='scan-table'>
      <thead><tr>
        <th>Port</th><th>Service</th><th>Risk</th><th>Banner</th><th>CVE Reference</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def render_vuln_details(results: list[dict]) -> str:
    critical = [r for r in results if get_risk(r["port"])["level"] == "Critical"]
    high     = [r for r in results if get_risk(r["port"])["level"] == "High"]
    target   = critical + high
    if not target:
        return "<p style='font-family:\"Share Tech Mono\",monospace;font-size:0.75rem;color:#06d6a0;'>✓ No critical or high-risk ports detected.</p>"

    html = ""
    for r in target:
        risk  = get_risk(r["port"])
        color = get_risk_color(risk["level"])
        html += f"""
        <div style='margin-bottom:1rem;padding:0.9rem 1rem;background:rgba(255,45,85,0.04);
                    border:1px solid {color}33;border-left:3px solid {color};border-radius:0 10px 10px 0;'>
          <div style='font-family:"Share Tech Mono",monospace;font-size:0.75rem;color:{color};
                      font-weight:600;margin-bottom:0.4rem;'>
            ⚠ PORT {r['port']} / {r['service']} — {risk['level'].upper()}
          </div>
          <div style='font-family:"Share Tech Mono",monospace;font-size:0.7rem;color:#4a6fa5;margin-bottom:3px;'>
            CVE: {risk['cve_hint']}
          </div>
          <div style='font-family:"Exo 2",sans-serif;font-size:0.78rem;color:#8aa0c0;margin-bottom:5px;'>
            {risk['description']}
          </div>
          <div style='font-family:"Exo 2",sans-serif;font-size:0.76rem;color:#06d6a0;'>
            ✓ Fix: {risk['recommendation']}
          </div>
        </div>"""
    return html


def render_history_table(records: list[dict]) -> str:
    if not records:
        return "<p style='font-family:\"Share Tech Mono\",monospace;font-size:0.74rem;color:#3a5278;'>No scan history yet.</p>"
    rows = "".join(
        f"<tr>"
        f"<td>{r['timestamp']}</td>"
        f"<td style='color:#00f5ff;'>{r['target']}</td>"
        f"<td>{r['ip']}</td>"
        f"<td style='color:#06d6a0;'>{r['open_ports']}</td>"
        f"<td style='color:{'#ff2d55' if r['high_risk'] > 0 else '#06d6a0'};'>{r['high_risk']}</td>"
        f"<td>{r['duration']}s</td>"
        f"</tr>"
        for r in records
    )
    return f"""
    <table class='hist-table'>
      <thead><tr>
        <th>Timestamp</th><th>Target</th><th>IP</th>
        <th>Open</th><th>High Risk</th><th>Duration</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


st.markdown("""
<div class='hero'>
  <div class='hero-title'>🛡️ PORT<span>SCANNER</span></div>
  <div class='hero-sub'>Advanced TCP Port Scanner · Risk Intelligence · Service Detection · Geolocation</div>
  <div class='hero-stats'>
    <div class='hero-stat'><b>43+</b>Known Services</div>
    <div class='hero-stat'><b>29+</b>CVE References</div>
    <div class='hero-stat'><b>65535</b>Max Port Range</div>
    <div class='hero-stat'><b>300</b>Max Threads</div>
  </div>
</div>
<div class='disclaimer'>
  ⚠ EDUCATIONAL USE ONLY — Only scan hosts you own or have explicit written permission to test.
  Unauthorized scanning may violate the CFAA and equivalent laws. The author assumes no liability.
</div>
""", unsafe_allow_html=True)

col_left, col_right = st.columns([1, 1.9], gap="large")

with col_left:
    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    st.markdown("<div class='panel-title'>Scan Configuration</div>", unsafe_allow_html=True)

    with st.form("scan_config_form"):
        target = st.text_input(
            "Target IP / Hostname",
            placeholder="e.g. 192.168.1.1  or  scanme.nmap.org",
            help="Enter an IP address or resolvable hostname.",
        )

        scan_mode = st.selectbox(
            "Scan Mode",
            ["⚡ Quick Scan (Common Ports)", "📡 Full Range (1–65535)", "🎯 Custom Range"],
            help="Quick scan covers 46 critical ports. Full scan takes longer.",
        )

        start_port, end_port = 1, 1024
        if scan_mode == "🎯 Custom Range":
            c1, c2 = st.columns(2)
            with c1:
                start_port = st.number_input("Start Port", 1, 65534, 1)
            with c2:
                end_port   = st.number_input("End Port",   2, 65535, 1024)

        threads = st.slider(
            "Concurrent Threads", 10, 300, 150, 10,
            help="More threads = faster but noisier. 100-150 is optimal.",
        )
        timeout = st.slider(
            "Timeout per Port (s)", 0.2, 3.0, 0.75, 0.05,
            help="Lower = faster but may miss slow hosts.",
        )

        st.markdown("---")
        grab_banners = st.checkbox(
            "🔍 Banner Grabbing",
            value=True,
            help="Attempt to read service banners (version info). Slightly slower.",
        )
        do_geo = st.checkbox(
            "🌍 IP Geolocation",
            value=True,
            help="Fetch country, ISP, and org info via ip-api.com.",
        )
        track_history = st.checkbox(
            "📋 Save to History",
            value=True,
            help="Save scan summary to local history log.",
        )

        st.markdown("<br>", unsafe_allow_html=True)
        scan_btn = st.form_submit_button("🔍  INITIATE SCAN", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    if st.session_state.scan_done:
        results  = st.session_state.scan_results
        n_crit   = sum(1 for r in results if get_risk(r["port"])["level"] == "Critical")
        n_high   = sum(1 for r in results if get_risk(r["port"])["level"] == "High")
        n_open   = len(results)
        duration = st.session_state.last_duration
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(render_stat_grid(n_open, n_crit, n_high, duration), unsafe_allow_html=True)

        open_p_list = [r["port"] for r in results]
        os_name, confidence = detect_os(open_p_list)
        st.markdown(
            f"<div class='os-badge'>🖥 {os_name} &nbsp;<span style='color:#3a5278;font-size:0.65rem;'>[{confidence} confidence]</span></div>",
            unsafe_allow_html=True,
        )

with col_right:
    tab_live, tab_details, tab_vuln, tab_history = st.tabs([
        "📡  Live Output",
        "📋  Port Details",
        "🔥  Vulnerability Report",
        "🕑  Scan History",
    ])

    with tab_live:
        prog_bar   = st.progress(0)
        status_el  = st.empty()

        st.markdown("<div class='panel-title' style='margin-top:0.8rem;'>Open Ports Found</div>", unsafe_allow_html=True)
        badge_el   = st.empty()

        st.markdown("<div class='panel-title' style='margin-top:0.8rem;'>Terminal Log</div>", unsafe_allow_html=True)
        log_el     = st.empty()

        geo_title  = st.empty()
        geo_el     = st.empty()

        status_el.markdown(
            "<span style='font-family:\"Share Tech Mono\",monospace;font-size:0.76rem;color:#3a5278;'>"
            "// Waiting for scan to start…</span>",
            unsafe_allow_html=True,
        )
        badge_el.markdown(
            "<div class='badge-wrap'><span style='font-family:\"Share Tech Mono\",monospace;"
            "font-size:0.72rem;color:#1a2d47;'>// No open ports discovered yet…</span></div>",
            unsafe_allow_html=True,
        )
        log_el.markdown(
            "<div class='terminal'><span class='t-info'>// System ready. Awaiting target.</span></div>",
            unsafe_allow_html=True,
        )

        if st.session_state.scan_done:
            results = st.session_state.scan_results
            prog_bar.progress(1.0)
            status_el.markdown(
                f"<span style='font-family:\"Share Tech Mono\",monospace;font-size:0.76rem;color:#06d6a0;'>"
                f"✔ Scan complete — {st.session_state.last_duration}s</span>",
                unsafe_allow_html=True,
            )
            badge_el.markdown(
                f"<div class='badge-wrap'>{st.session_state.badges_html}</div>",
                unsafe_allow_html=True,
            )
            log_el.markdown(
                "<div class='terminal'>" + "<br>".join(st.session_state.log_lines[:80]) + "</div>",
                unsafe_allow_html=True,
            )
            geo_title.markdown("<div class='panel-title' style='margin-top:0.8rem;'>IP Geolocation</div>", unsafe_allow_html=True)
            geo_el.markdown(render_geo(st.session_state.last_geo), unsafe_allow_html=True)

    with tab_details:
        if st.session_state.scan_done and st.session_state.scan_results:
            st.markdown(render_results_table(st.session_state.scan_results), unsafe_allow_html=True)
        else:
            st.markdown(
                "<p style='font-family:\"Share Tech Mono\",monospace;font-size:0.75rem;color:#3a5278;'>"
                "// Run a scan to see port details here.</p>",
                unsafe_allow_html=True,
            )

    with tab_vuln:
        if st.session_state.scan_done and st.session_state.scan_results:
            results  = st.session_state.scan_results
            n_crit   = sum(1 for r in results if get_risk(r["port"])["level"] == "Critical")
            n_high   = sum(1 for r in results if get_risk(r["port"])["level"] == "High")
            if n_crit:
                st.markdown(
                    f"<div class='vuln-alert'>🚨 CRITICAL ALERT — {n_crit} critically vulnerable port(s) detected! "
                    f"Immediate action required.</div>",
                    unsafe_allow_html=True,
                )
            st.markdown(render_vuln_details(results), unsafe_allow_html=True)

            if results:
                geo  = st.session_state.last_geo
                ip   = st.session_state.last_ip
                tgt  = st.session_state.last_target
                dur  = st.session_state.last_duration
                os_g = st.session_state.last_os[0]

                csv_bytes = build_csv(results, tgt, ip, dur, get_risk)
                txt_bytes = build_txt(results, tgt, ip, dur, os_g, geo, get_risk)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")

                st.markdown("<br>", unsafe_allow_html=True)
                dc1, dc2 = st.columns(2)
                with dc1:
                    st.download_button("📥 Export CSV", csv_bytes,
                                       f"scan_{ip}_{ts}.csv", "text/csv",
                                       use_container_width=True)
                with dc2:
                    st.download_button("📄 Export Full Report", txt_bytes,
                                       f"scan_{ip}_{ts}.txt", "text/plain",
                                       use_container_width=True)
        else:
            st.markdown(
                "<p style='font-family:\"Share Tech Mono\",monospace;font-size:0.75rem;color:#3a5278;'>"
                "// Vulnerability report will appear here after scanning.</p>",
                unsafe_allow_html=True,
            )

    with tab_history:
        history = get_history()
        st.markdown(render_history_table(history), unsafe_allow_html=True)
        if history:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🗑 Clear History", use_container_width=False):
                clear_history()
                st.rerun()


if scan_btn:

    if not target.strip():
        st.error("❌ Please enter a target IP or hostname.")
        st.stop()

    if scan_mode == "🎯 Custom Range" and start_port >= end_port:
        st.error("❌ Start port must be less than end port.")
        st.stop()

    with col_right:
        with tab_live:
            status_el.markdown(
                "<span style='font-family:\"Share Tech Mono\",monospace;font-size:0.76rem;color:#00f5ff;'>"
                "<span class='scan-pulse'></span>Resolving host…</span>",
                unsafe_allow_html=True,
            )

    ip = resolve_host(target)
    if not ip:
        st.error(f"❌ Cannot resolve **{target}**. Check the address and network connectivity.")
        st.stop()

    if scan_mode == "⚡ Quick Scan (Common Ports)":
        ports = QUICK_PORTS
        mode_label = "Quick Scan"
    elif scan_mode == "📡 Full Range (1–65535)":
        ports = list(range(1, 65536))
        mode_label = "Full Range (1–65535)"
    else:
        ports = list(range(int(start_port), int(end_port) + 1))
        mode_label = f"Custom Range ({start_port}–{end_port})"

    total_ports = len(ports)

    st.session_state.log_lines    = []
    st.session_state.badges_html  = ""
    st.session_state.scan_results = []
    st.session_state.scan_done    = False

    start_line = (
        f"<span class='t-info'>// SCAN INITIATED — Target: {ip} | "
        f"Mode: {mode_label} | Ports: {total_ports} | Threads: {threads}</span>"
    )
    st.session_state.log_lines.append(start_line)

    done_count = [0]

    def on_progress(result: dict):
        port    = result["port"]
        is_open = result["is_open"]
        done_count[0] += 1

        prog_bar.progress(done_count[0] / total_ports)
        status_el.markdown(
            f"<span style='font-family:\"Share Tech Mono\",monospace;font-size:0.75rem;color:#3a5278;'>"
            f"<span class='scan-pulse'></span>Scanning port "
            f"<b style='color:#ccd9f0;'>{port}</b> "
            f"— {done_count[0]}/{total_ports}</span>",
            unsafe_allow_html=True,
        )

        if is_open:
            risk = get_risk(port)
            svc  = result["service"]
            lvl  = risk["level"]
            banner = result.get("banner", "")
            banner_note = f" ┤ {banner[:60]}" if banner else ""

            log_cls = {"Critical": "t-crit", "High": "t-high", "Medium": "t-med"}.get(lvl, "t-open")
            vuln_tag = " ⚠ VULNERABLE" if lvl in ("Critical", "High") else ""
            st.session_state.log_lines.insert(1,
                f"<span class='{log_cls}'>✔  PORT {port:<6} OPEN   "
                f"{svc:<18} [{lvl}]{vuln_tag}{banner_note}</span>"
            )

            st.session_state.badges_html += render_badge(port, svc, lvl)
        else:
            st.session_state.log_lines.insert(
                min(2, len(st.session_state.log_lines)),
                f"<span class='t-closed'>·   port {port:<6} closed</span>"
            )

        log_el.markdown(
            "<div class='terminal'>"
            + "<br>".join(st.session_state.log_lines[:80])
            + "</div>",
            unsafe_allow_html=True,
        )
        badge_el.markdown(
            f"<div class='badge-wrap'>{st.session_state.badges_html}</div>"
            if st.session_state.badges_html else
            "<div class='badge-wrap'><span style='font-family:\"Share Tech Mono\",monospace;"
            "font-size:0.72rem;color:#1a2d47;'>// Scanning…</span></div>",
            unsafe_allow_html=True,
        )

    open_ports, duration = run_scan(
        ip=ip,
        ports=ports,
        threads=threads,
        timeout=timeout,
        grab_banners=grab_banners,
        on_progress=on_progress,
    )

    prog_bar.progress(1.0)

    n_open = len(open_ports)
    n_crit = sum(1 for r in open_ports if get_risk(r["port"])["level"] == "Critical")
    n_high = sum(1 for r in open_ports if get_risk(r["port"])["level"] == "High")

    # Final log entry
    st.session_state.log_lines.insert(1,
        f"<span class='t-info'>// SCAN COMPLETE — {n_open} open ports | "
        f"{n_crit} critical | {n_high} high | {duration}s elapsed</span>"
    )
    log_el.markdown(
        "<div class='terminal'>" + "<br>".join(st.session_state.log_lines[:80]) + "</div>",
        unsafe_allow_html=True,
    )

    status_el.markdown(
        f"<span style='font-family:\"Share Tech Mono\",monospace;font-size:0.76rem;color:#06d6a0;'>"
        f"✔ Scan complete — {duration}s elapsed — {n_open} open ports found</span>",
        unsafe_allow_html=True,
    )

    geo: dict = {}
    if do_geo:
        with st.spinner("Fetching geolocation…"):
            geo = get_geo(ip)
        geo_title.markdown("<div class='panel-title' style='margin-top:0.8rem;'>IP Geolocation</div>", unsafe_allow_html=True)
        geo_el.markdown(render_geo(geo), unsafe_allow_html=True)

    st.session_state.scan_results  = open_ports
    st.session_state.last_target   = target.strip()
    st.session_state.last_ip       = ip
    st.session_state.last_duration = duration
    st.session_state.last_geo      = geo
    st.session_state.last_os       = detect_os([r["port"] for r in open_ports])
    st.session_state.scan_done     = True

    if track_history:
        add_scan(
            target=target.strip(), ip=ip,
            total_ports=total_ports, open_count=n_open,
            high_risk=n_crit + n_high, duration=duration,
        )

    if n_crit:
        with col_right:
            st.markdown(
                f"<div class='vuln-alert'>🚨 {n_crit} CRITICAL port(s) detected! "
                f"Switch to the Vulnerability Report tab for remediation steps.</div>",
                unsafe_allow_html=True,
            )

    st.rerun()

st.markdown("""
<div class='footer'>
  🛡️ &nbsp; PORTRSCANNER v3.0 &nbsp;·&nbsp;
  <span>Devanshi Birla</span> &nbsp;·&nbsp;
  Built as a learning project in Cybersecurity &nbsp;·&nbsp;
  Python + Streamlit &nbsp;·&nbsp; Educational Use Only
</div>
""", unsafe_allow_html=True)

