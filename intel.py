"""
intel.py — Cybersecurity Intelligence Engine
Handles: risk classification, OS fingerprinting, vuln hints, geolocation
"""

import re
import urllib.request
import json
from typing import TypedDict


class RiskEntry(TypedDict):
    level: str          
    cve_hint: str       
    description: str   
    recommendation: str 


RISK_DB: dict[int, RiskEntry] = {
    21: {
        "level": "Critical",
        "cve_hint": "CVE-1999-0497 / Anonymous FTP",
        "description": "FTP transmits credentials in plaintext. Anonymous login often enabled.",
        "recommendation": "Replace with SFTP (port 22). Disable anonymous access.",
    },
    22: {
        "level": "Low",
        "cve_hint": "CVE-2023-38408 (OpenSSH)",
        "description": "SSH is generally secure but brute-force attacks are common.",
        "recommendation": "Disable password auth, use key-based auth. Rate-limit with fail2ban.",
    },
    23: {
        "level": "Critical",
        "cve_hint": "No encryption — all traffic in cleartext",
        "description": "Telnet sends all data including passwords as plaintext over the network.",
        "recommendation": "Immediately replace with SSH. Disable Telnet on all devices.",
    },
    25: {
        "level": "High",
        "cve_hint": "Open relay / CVE-2020-7247",
        "description": "SMTP open relay enables spam campaigns and phishing infrastructure.",
        "recommendation": "Require authentication. Implement SPF, DKIM, DMARC.",
    },
    53: {
        "level": "Medium",
        "cve_hint": "DNS amplification / Zone transfer",
        "description": "Open DNS resolvers can be abused for DDoS amplification attacks.",
        "recommendation": "Restrict zone transfers. Disable recursion for external IPs.",
    },
    80: {
        "level": "Medium",
        "cve_hint": "HTTP — no encryption",
        "description": "Unencrypted HTTP allows MITM attacks and credential interception.",
        "recommendation": "Force redirect to HTTPS (443). Implement HSTS.",
    },
    110: {
        "level": "High",
        "cve_hint": "POP3 plaintext credentials",
        "description": "POP3 transmits email credentials without encryption.",
        "recommendation": "Use POP3S on port 995 with TLS enforced.",
    },
    135: {
        "level": "Critical",
        "cve_hint": "MS03-026 / DCOM RPC exploit",
        "description": "MS-RPC endpoint mapper is a classic Windows exploit vector.",
        "recommendation": "Block at firewall. Apply all Windows security patches.",
    },
    139: {
        "level": "Critical",
        "cve_hint": "MS08-067 / NetBIOS attacks",
        "description": "NetBIOS-SSN enables SMB enumeration, relay attacks, and credential theft.",
        "recommendation": "Disable NetBIOS over TCP/IP. Block at firewall perimeter.",
    },
    143: {
        "level": "Medium",
        "cve_hint": "IMAP credential exposure",
        "description": "IMAP can leak credentials if STARTTLS is not enforced.",
        "recommendation": "Use IMAPS on port 993. Enforce TLS for all connections.",
    },
    389: {
        "level": "High",
        "cve_hint": "LDAP injection / null bind",
        "description": "LDAP allows directory enumeration and null-bind attacks.",
        "recommendation": "Require authentication. Use LDAPS (636). Restrict access.",
    },
    443: {
        "level": "Low",
        "cve_hint": "Verify TLS version and cipher suite",
        "description": "HTTPS is standard but weak TLS versions (1.0/1.1) pose risks.",
        "recommendation": "Enforce TLS 1.2+. Disable weak ciphers. Check cert expiry.",
    },
    445: {
        "level": "Critical",
        "cve_hint": "MS17-010 EternalBlue / WannaCry / NotPetya",
        "description": "SMB port 445 was exploited by WannaCry ransomware globally.",
        "recommendation": "Block externally. Patch immediately. Disable SMBv1.",
    },
    1080: {
        "level": "Critical",
        "cve_hint": "Open SOCKS proxy",
        "description": "Open SOCKS proxy anonymizes attacker traffic through your host.",
        "recommendation": "Disable if not needed. Restrict to trusted IPs only.",
    },
    1433: {
        "level": "Critical",
        "cve_hint": "CVE-2020-0618 MSSQL / SA brute-force",
        "description": "MSSQL exposed externally is a prime target for data exfiltration.",
        "recommendation": "Never expose databases externally. Use VPN/bastion host.",
    },
    1521: {
        "level": "Critical",
        "cve_hint": "Oracle TNS listener attacks",
        "description": "Oracle DB listener allows remote code execution if misconfigured.",
        "recommendation": "Bind to localhost only. Use connection pooling behind a proxy.",
    },
    2375: {
        "level": "Critical",
        "cve_hint": "Docker API unauthenticated RCE",
        "description": "Unauthenticated Docker API allows full host takeover and container escape.",
        "recommendation": "Never expose Docker socket. Use TLS mutual auth (port 2376).",
    },
    3306: {
        "level": "Critical",
        "cve_hint": "MySQL direct exposure / CVE-2012-2122",
        "description": "MySQL externally exposed enables brute-force and data theft.",
        "recommendation": "Bind to 127.0.0.1. Never expose databases to the internet.",
    },
    3389: {
        "level": "Critical",
        "cve_hint": "CVE-2019-0708 BlueKeep / DejaBlue",
        "description": "RDP is one of the most attacked services — ransomware entry point.",
        "recommendation": "Use VPN + NLA. Change default port. Enable Network Level Auth.",
    },
    5432: {
        "level": "Critical",
        "cve_hint": "PostgreSQL direct exposure",
        "description": "PostgreSQL externally exposed enables data exfiltration and attacks.",
        "recommendation": "Bind to localhost. Use connection pooler like pgBouncer.",
    },
    5900: {
        "level": "Critical",
        "cve_hint": "VNC no-auth / CVE-2022-47952",
        "description": "VNC is frequently deployed without authentication, granting GUI access.",
        "recommendation": "Use VPN. Set strong password. Use VNC over SSH tunnel.",
    },
    5984: {
        "level": "Critical",
        "cve_hint": "CouchDB CVE-2017-12635 RCE",
        "description": "CouchDB admin party mode allows unauthenticated admin access.",
        "recommendation": "Disable admin party. Bind to localhost. Require authentication.",
    },
    6379: {
        "level": "Critical",
        "cve_hint": "Redis unauthenticated — ransomware target",
        "description": "Redis has no authentication by default. Used in cryptojacking attacks.",
        "recommendation": "Set requirepass in redis.conf. Bind to 127.0.0.1. Use firewall.",
    },
    8080: {
        "level": "Medium",
        "cve_hint": "Development server exposed",
        "description": "Dev servers expose debug panels, stack traces and sensitive config.",
        "recommendation": "Never run dev servers in production. Use proper WSGI/reverse proxy.",
    },
    8888: {
        "level": "High",
        "cve_hint": "Jupyter unauthenticated code execution",
        "description": "Jupyter Notebook allows arbitrary Python execution on the host.",
        "recommendation": "Run behind auth reverse proxy. Never expose publicly.",
    },
    9200: {
        "level": "Critical",
        "cve_hint": "Elasticsearch no-auth data exposure",
        "description": "Billions of records leaked from public Elasticsearch instances.",
        "recommendation": "Enable X-Pack security. Bind to localhost. Use firewall.",
    },
    11211: {
        "level": "Critical",
        "cve_hint": "Memcached DDoS amplification / no auth",
        "description": "Memcached has no auth and is used in record-breaking DDoS attacks.",
        "recommendation": "Bind to 127.0.0.1. Block UDP port 11211 at firewall.",
    },
    27017: {
        "level": "Critical",
        "cve_hint": "MongoDB no-auth — mass data theft",
        "description": "Thousands of MongoDB instances lost data to automated attacks.",
        "recommendation": "Enable auth in mongod.conf. Bind to 127.0.0.1. Use firewall.",
    },
}


def get_risk(port: int) -> RiskEntry:
    """Get risk info for a port, with sensible defaults for unlisted ports."""
    if port in RISK_DB:
        return RISK_DB[port]
    return {
        "level": "Low",
        "cve_hint": "No known critical CVE",
        "description": "Non-standard port with no common vulnerability mapping.",
        "recommendation": "Verify this service is intentionally exposed.",
    }


def get_risk_color(level: str) -> str:
    """Return CSS color for a risk level."""
    return {
        "Critical": "#ff2d55",
        "High": "#ff6b35",
        "Medium": "#ffd166",
        "Low": "#06d6a0",
    }.get(level, "#aaaaaa")


OS_SIGNATURES: list[tuple[set[int], str, str]] = [
    ({135, 139, 445, 3389}, "Windows (Active Directory/RDP)", "High"),
    ({135, 445, 3389}, "Windows Server", "High"),
    ({135, 139, 445}, "Windows (SMB-enabled)", "High"),
    ({22, 80, 443, 3306}, "Linux LAMP Stack", "Medium"),
    ({22, 80, 443, 5432}, "Linux (PostgreSQL/nginx)", "Medium"),
    ({22, 80, 443, 6379}, "Linux (Redis/nginx)", "Medium"),
    ({22, 27017}, "Linux (MongoDB Server)", "Medium"),
    ({22, 9200}, "Linux (Elasticsearch Node)", "Medium"),
    ({22, 2375}, "Linux (Docker Host — EXPOSED!)", "High"),
    ({22, 6443}, "Linux (Kubernetes Node)", "High"),
    ({22, 3306, 80}, "Linux LAMP", "Medium"),
    ({22, 5432}, "Linux (PostgreSQL)", "Low"),
    ({22, 25, 110, 143}, "Linux Mail Server (MTA)", "Medium"),
    ({21, 22, 80, 443}, "Linux Web/FTP Server", "Low"),
    ({22,}, "Linux/Unix (SSH only)", "Low"),
    ({23,}, "Network Device (Router/Switch)", "Medium"),
    ({21,}, "FTP Server", "Low"),
    ({1521,}, "Oracle Database Server", "Medium"),
    ({1433,}, "Windows SQL Server", "Medium"),
]


def detect_os(open_ports: list[int]) -> tuple[str, str]:
    """
    Heuristic OS detection from open port set.
    Returns (os_guess, confidence).
    """
    port_set = set(open_ports)
    best_match = ("Unknown", "None")
    best_overlap = 0

    for sig_ports, os_name, confidence in OS_SIGNATURES:
        overlap = len(sig_ports & port_set)
        if overlap == len(sig_ports) and overlap > best_overlap:
            best_overlap = overlap
            best_match = (os_name, confidence)

    return best_match

def get_geo(ip: str) -> dict:
    """
    Fetch geolocation data for an IP using ip-api.com.
    Returns dict with country, city, ISP, org, timezone, etc.
    Returns empty dict on failure or for private IPs.
    """
    private_prefixes = ("192.168.", "10.", "172.", "127.", "::1", "localhost")
    if any(ip.startswith(p) for p in private_prefixes):
        return {"status": "private", "message": "Private/LAN IP — no geolocation available"}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,timezone,lat,lon,query"
        req = urllib.request.Request(url, headers={"User-Agent": "PortScanner/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data
    except Exception:
        return {"status": "fail", "message": "Geolocation unavailable"}
