"""
export_utils.py
Handles exporting scan results to CSV and TXT formats
"""

import io
from datetime import datetime

def build_csv(results, target, ip, duration, get_risk):
    output = io.StringIO()

    output.write("Target,IP,Duration(s)\n")
    output.write(f"{target},{ip},{duration}\n\n")

    output.write("Port,Service,Risk,Banner,CVE\n")

    for r in results:
        risk = get_risk(r["port"])
        banner = r.get("banner", "").replace(",", " ")
        cve = risk.get("cve_hint", "").replace(",", " ")

        output.write(
            f"{r['port']},{r['service']},{risk['level']},{banner},{cve}\n"
        )

    return output.getvalue().encode("utf-8")

def build_txt(results, target, ip, duration, os_name, geo, get_risk):
    output = io.StringIO()

    output.write("=" * 60 + "\n")
    output.write("        CYBERSCAN PRO — FULL REPORT\n")
    output.write("=" * 60 + "\n\n")

    output.write(f"Target      : {target}\n")
    output.write(f"IP Address  : {ip}\n")
    output.write(f"Scan Time   : {duration} seconds\n")
    output.write(f"OS Guess    : {os_name}\n")
    output.write(f"Timestamp   : {datetime.now()}\n\n")

    if geo and geo.get("status") == "success":
        output.write("🌍 GEOLOCATION\n")
        output.write("-" * 40 + "\n")
        output.write(f"Country : {geo.get('country')}\n")
        output.write(f"Region  : {geo.get('regionName')}\n")
        output.write(f"City    : {geo.get('city')}\n")
        output.write(f"ISP     : {geo.get('isp')}\n")
        output.write(f"Org     : {geo.get('org')}\n")
        output.write(f"Timezone: {geo.get('timezone')}\n\n")

    output.write("📡 OPEN PORTS\n")
    output.write("-" * 40 + "\n")

    if not results:
        output.write("No open ports found.\n")
    else:
        for r in results:
            risk = get_risk(r["port"])

            output.write(f"\nPORT {r['port']} ({r['service']})\n")
            output.write(f"Risk Level : {risk['level']}\n")
            output.write(f"CVE        : {risk['cve_hint']}\n")
            output.write(f"Description: {risk['description']}\n")
            output.write(f"Fix        : {risk['recommendation']}\n")

            if r.get("banner"):
                output.write(f"Banner     : {r['banner']}\n")

    output.write("\n" + "=" * 60 + "\n")
    output.write("⚠ Educational Use Only\n")

    return output.getvalue().encode("utf-8")

