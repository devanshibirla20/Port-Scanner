"""
scanner.py — High-performance TCP port scanning engine
Handles: concurrent scanning, banner grabbing, service/version detection
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable


SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 53: "DNS", 67: "DHCP", 68: "DHCP-Client", 69: "TFTP",
    79: "Finger", 80: "HTTP", 88: "Kerberos", 102: "MS-EXCH-ROUTING",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE/IPsec", 514: "Syslog", 515: "LPD",
    520: "RIP", 587: "SMTP-Sub", 593: "HTTP-RPC", 631: "IPP", 636: "LDAPS",
    873: "rsync", 902: "VMware", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-Brw",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 2483: "Oracle-DB", 3000: "Dev/Grafana",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4369: "Erlang-EPMd",
    4443: "Alt-HTTPS", 4444: "Metasploit", 5000: "UPnP/Flask",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s-API", 7077: "Spark", 7474: "Neo4j",
    8000: "HTTP-Dev", 8080: "HTTP-Alt", 8081: "HTTP-Alt2",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "SonarQube/PHP-FPM",
    9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "ES-Transport", 10250: "Kubelet",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27017: "MongoDB",
    27018: "MongoDB-Shard", 50070: "Hadoop-HDFS",
}

QUICK_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
    465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 2049,
    2375, 3000, 3306, 3389, 3690, 4369, 5000, 5432, 5672, 5900,
    5984, 6379, 6443, 8080, 8443, 8888, 9000, 9092, 9200, 11211,
    15672, 27017,
]


def get_service(port: int) -> str:
    """Return service name for a port number."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return "Unknown"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab a service banner from an open port.
    Sends a generic HTTP-style probe; falls back to raw read.
    Returns empty string on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Try HTTP probe first
            if port in (80, 8080, 8000, 8888, 8443, 443, 3000, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                s.sendall(b"\r\n")

            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:120]
    except Exception:
        pass
    return ""


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict:
    """
    Scan a single TCP port.
    Returns a result dict with is_open, banner, service, etc.
    """
    result = {"port": port, "is_open": False, "service": get_service(port), "banner": ""}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            connected = s.connect_ex((ip, port)) == 0
            result["is_open"] = connected
    except Exception:
        pass

    if result["is_open"] and grab:
        result["banner"] = grab_banner(ip, port, timeout=min(timeout * 2, 3.0))

    return result


def run_scan(
    ip: str,
    ports: list[int],
    threads: int,
    timeout: float,
    grab_banners: bool,
    on_progress: Callable[[dict], None],
) -> tuple[list[dict], float]:
    """
    Run concurrent port scan.
    Calls on_progress(result_dict) for every completed port (open or closed).
    Returns (list_of_open_results, total_duration_seconds).
    """
    open_ports: list[dict] = []
    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, p, timeout, grab_banners): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["is_open"]:
                open_ports.append(result)
            on_progress(result)

    duration = round(time.perf_counter() - start, 2)
    return sorted(open_ports, key=lambda x: x["port"]), duration


def resolve_host(host: str) -> str | None:
    """Resolve hostname to IP. Returns None on failure."""
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror:
        return None
