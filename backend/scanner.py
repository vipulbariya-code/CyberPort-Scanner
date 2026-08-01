"""
scanner.py
----------
Core scanning engine for CyberPort Scanner.

Implements a multi-threaded TCP connect scan using Python's built-in
`socket` module — the same fundamental technique taught in any network
security course. No exploitation, banner-grabbing exploitation, or
attack payloads are included: this module only checks whether a TCP
handshake completes on a given port, which is the standard, benign
building block of network diagnostics tools (e.g. `nmap -sT`).

IMPORTANT — RESPONSIBLE USE
This tool must only be pointed at systems the operator owns or has
explicit written authorization to test. Scanning systems without
permission may be illegal in your jurisdiction (e.g. under the U.S.
Computer Fraud and Abuse Act or similar laws elsewhere).
"""

import socket
import threading
import time
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

# Common service names for well-known ports — purely informational,
# used only to label results in the UI (mirrors /etc/services).
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP-Submission", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS",
    3128: "Squid-Proxy", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6667: "IRC", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


class ValidationError(Exception):
    """Raised when user-supplied scan parameters fail validation."""
    pass


def get_service_name(port: int) -> str:
    return COMMON_SERVICES.get(port, "Unknown")


def validate_target(target: str) -> str:
    """
    Validate a target string as either a valid IPv4 address or a
    syntactically valid hostname. Returns the cleaned target.
    """
    target = (target or "").strip()
    if not target:
        raise ValidationError("Target address is required.")

    # Try IPv4 first
    try:
        ipaddress.IPv4Address(target)
        return target
    except ValueError:
        pass

    # Fallback: hostname validation (RFC 1123-ish, permissive)
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    if hostname_pattern.match(target):
        return target

    raise ValidationError(
        "Target must be a valid IPv4 address or hostname (e.g. 192.168.1.1 or example.com)."
    )


def validate_port_range(start_port, end_port, max_range=1024):
    """Validate and normalize a start/end port pair."""
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except (TypeError, ValueError):
        raise ValidationError("Ports must be whole numbers.")

    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        raise ValidationError("Ports must be between 1 and 65535.")

    if start_port > end_port:
        raise ValidationError("Start port must be less than or equal to end port.")

    if (end_port - start_port + 1) > max_range:
        raise ValidationError(
            f"Port range too large. Please scan at most {max_range} ports at a time."
        )

    return start_port, end_port


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address; raises ValidationError on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValidationError(f"Could not resolve host '{target}'. Check the address and try again.")


class PortScanner:
    """
    Multi-threaded TCP connect-scan engine.

    Usage:
        scanner = PortScanner(target_ip, start_port, end_port)
        for update in scanner.run(progress_callback=...):
            ...
    """

    def __init__(self, target_ip: str, start_port: int, end_port: int,
                 timeout: float = 0.6, max_threads: int = 100):
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_threads = max_threads
        self._lock = threading.Lock()
        self._scanned = 0
        self._open_ports = []
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _scan_port(self, port: int):
        """Attempt a TCP handshake on a single port. Returns True if open."""
        if self._cancelled:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target_ip, port))
            return result == 0
        except socket.error:
            return False
        finally:
            sock.close()

    def run(self, progress_callback=None):
        """
        Executes the scan synchronously, calling progress_callback(scanned, total, open_count)
        periodically. Returns a dict summary when complete.
        """
        ports = list(range(self.start_port, self.end_port + 1))
        total = len(ports)
        start_time = time.time()
        open_ports = []
        scanned = 0

        with ThreadPoolExecutor(max_workers=min(self.max_threads, total)) as executor:
            future_to_port = {executor.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(future_to_port):
                if self._cancelled:
                    break
                port = future_to_port[future]
                is_open = future.result()
                scanned += 1
                if is_open:
                    open_ports.append({
                        "port": port,
                        "service": get_service_name(port),
                        "state": "open",
                    })
                if progress_callback:
                    progress_callback(scanned, total, len(open_ports))

        open_ports.sort(key=lambda x: x["port"])
        duration = round(time.time() - start_time, 2)

        return {
            "target_ip": self.target_ip,
            "start_port": self.start_port,
            "end_port": self.end_port,
            "total_scanned": scanned,
            "open_ports": open_ports,
            "closed_count": scanned - len(open_ports),
            "duration_seconds": duration,
        }
