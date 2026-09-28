"""
ports_data.py
-------------
Educational port reference database and information lookup for CyberPort Scanner.

Provides verified, educational technical descriptions for well-known and
frequently encountered network ports according to IANA and RFC standards.
Contains no unsupported vulnerability claims.
"""

COMMON_PORTS_DATABASE = {
    20: {
        "protocol": "TCP",
        "service": "FTP-DATA",
        "description": "File Transfer Protocol (FTP) data transfer channel used for streaming file contents between client and server."
    },
    21: {
        "protocol": "TCP",
        "service": "FTP",
        "description": "File Transfer Protocol (FTP) control channel used for establishing sessions, user authentication, and command exchange."
    },
    22: {
        "protocol": "TCP",
        "service": "SSH",
        "description": "Secure Shell (SSH) protocol providing encrypted remote terminal sessions, secure command execution, and SFTP file transfer."
    },
    23: {
        "protocol": "TCP",
        "service": "Telnet",
        "description": "Legacy unencrypted virtual terminal protocol used historically for remote text-based command-line communications."
    },
    25: {
        "protocol": "TCP",
        "service": "SMTP",
        "description": "Simple Mail Transfer Protocol (SMTP) used for routing and transmitting outgoing email messages between mail servers."
    },
    53: {
        "protocol": "TCP/UDP",
        "service": "DNS",
        "description": "Domain Name System (DNS) translates human-friendly hostnames into numerical IP addresses necessary for network routing."
    },
    67: {
        "protocol": "UDP",
        "service": "DHCP",
        "description": "Dynamic Host Configuration Protocol (DHCP) server port used to automatically assign IP addresses and network configurations to hosts."
    },
    68: {
        "protocol": "UDP",
        "service": "DHCP",
        "description": "Dynamic Host Configuration Protocol (DHCP) client port used by network devices to receive configuration leases."
    },
    69: {
        "protocol": "UDP",
        "service": "TFTP",
        "description": "Trivial File Transfer Protocol (TFTP), a simplified UDP file transfer mechanism commonly used for network booting and firmware updates."
    },
    80: {
        "protocol": "TCP",
        "service": "HTTP",
        "description": "Hypertext Transfer Protocol (HTTP) serves standard unencrypted web pages, assets, and REST API communications."
    },
    110: {
        "protocol": "TCP",
        "service": "POP3",
        "description": "Post Office Protocol version 3 (POP3) used by email clients to retrieve stored messages from a remote mail server."
    },
    111: {
        "protocol": "TCP/UDP",
        "service": "RPCBind",
        "description": "Remote Procedure Call (RPC) portmapper coordinating service port mappings on Unix/Linux systems."
    },
    119: {
        "protocol": "TCP",
        "service": "NNTP",
        "description": "Network News Transfer Protocol (NNTP) used for reading and distributing Usenet newsgroup discussion threads."
    },
    123: {
        "protocol": "UDP",
        "service": "NTP",
        "description": "Network Time Protocol (NTP) synchronizes computer clocks across distributed networks with high precision."
    },
    135: {
        "protocol": "TCP",
        "service": "MSRPC",
        "description": "Microsoft RPC Endpoint Mapper, resolving RPC interfaces to dynamic listening endpoints on Windows platforms."
    },
    137: {
        "protocol": "UDP",
        "service": "NetBIOS-NS",
        "description": "NetBIOS Name Service used for local name resolution in legacy Windows workgroups and LANs."
    },
    138: {
        "protocol": "UDP",
        "service": "NetBIOS-DGM",
        "description": "NetBIOS Datagram Service providing connectionless message transfer across local subnet systems."
    },
    139: {
        "protocol": "TCP",
        "service": "NetBIOS-SSN",
        "description": "NetBIOS Session Service facilitating printer and file sharing over NetBIOS frames."
    },
    143: {
        "protocol": "TCP",
        "service": "IMAP",
        "description": "Internet Message Access Protocol (IMAP) allows email clients to view, organize, and synchronize mailboxes on a remote server."
    },
    161: {
        "protocol": "UDP",
        "service": "SNMP",
        "description": "Simple Network Management Protocol (SNMP) used by network management systems to monitor hardware health and performance."
    },
    162: {
        "protocol": "UDP",
        "service": "SNMP-Trap",
        "description": "SNMP Trap port used by network devices to send asynchronous event alerts and alarms to management consoles."
    },
    179: {
        "protocol": "TCP",
        "service": "BGP",
        "description": "Border Gateway Protocol (BGP) managing routing decisions between Autonomous Systems (AS) across the global Internet backbone."
    },
    194: {
        "protocol": "TCP",
        "service": "IRC",
        "description": "Internet Relay Chat (IRC) protocol providing real-time text conferencing across multi-channel client/server networks."
    },
    389: {
        "protocol": "TCP",
        "service": "LDAP",
        "description": "Lightweight Directory Access Protocol (LDAP) used for querying central organizational directories and user accounts."
    },
    443: {
        "protocol": "TCP",
        "service": "HTTPS",
        "description": "Hypertext Transfer Protocol Secure (HTTPS) encrypts web traffic using TLS/SSL to protect data integrity and confidentiality."
    },
    445: {
        "protocol": "TCP",
        "service": "SMB",
        "description": "Server Message Block (SMB) running natively over TCP/IP for Windows network file sharing, printer sharing, and IPC."
    },
    465: {
        "protocol": "TCP",
        "service": "SMTPS",
        "description": "Simple Mail Transfer Protocol over implicit TLS (SMTPS) for encrypted email transmission."
    },
    514: {
        "protocol": "UDP/TCP",
        "service": "Syslog",
        "description": "System Logging Protocol (Syslog) used for transmitting diagnostic and security log messages to central logging daemons."
    },
    515: {
        "protocol": "TCP",
        "service": "LPD",
        "description": "Line Printer Daemon (LPD) protocol used for legacy TCP/IP network print spooling and queue management."
    },
    587: {
        "protocol": "TCP",
        "service": "SMTP-Submission",
        "description": "Standard email submission port used by mail client agents (MUAs) to submit outbound email with TLS and authentication."
    },
    631: {
        "protocol": "TCP",
        "service": "IPP",
        "description": "Internet Printing Protocol (IPP) used by modern printing subsystems (such as CUPS) for network print management."
    },
    636: {
        "protocol": "TCP",
        "service": "LDAPS",
        "description": "Lightweight Directory Access Protocol over TLS/SSL (LDAPS) providing encrypted directory access."
    },
    993: {
        "protocol": "TCP",
        "service": "IMAPS",
        "description": "Internet Message Access Protocol over TLS (IMAPS) for secure encrypted mailbox synchronization."
    },
    995: {
        "protocol": "TCP",
        "service": "POP3S",
        "description": "Post Office Protocol version 3 over TLS (POP3S) for secure encrypted email retrieval."
    },
    1080: {
        "protocol": "TCP",
        "service": "SOCKS",
        "description": "SOCKS Proxy protocol routing network packets between client and destination servers through an intermediary proxy."
    },
    1433: {
        "protocol": "TCP",
        "service": "MSSQL",
        "description": "Microsoft SQL Server database engine default listening port for database client connections."
    },
    1521: {
        "protocol": "TCP",
        "service": "Oracle-DB",
        "description": "Oracle Database listener default port handling client connection requests to Oracle database instances."
    },
    1723: {
        "protocol": "TCP",
        "service": "PPTP",
        "description": "Point-to-Point Tunneling Protocol (PPTP) legacy control channel used for virtual private network (VPN) connections."
    },
    2049: {
        "protocol": "TCP/UDP",
        "service": "NFS",
        "description": "Network File System (NFS) protocol enabling client systems to mount and access shared directories over local networks."
    },
    3128: {
        "protocol": "TCP",
        "service": "Squid-Proxy",
        "description": "Squid Web Proxy Cache default port for HTTP proxying, caching, and traffic forwarding."
    },
    3306: {
        "protocol": "TCP",
        "service": "MySQL",
        "description": "MySQL and MariaDB relational database management systems default client connection port."
    },
    3389: {
        "protocol": "TCP/UDP",
        "service": "RDP",
        "description": "Remote Desktop Protocol (RDP) developed by Microsoft for interactive graphical remote desktop connections."
    },
    5060: {
        "protocol": "TCP/UDP",
        "service": "SIP",
        "description": "Session Initiation Protocol (SIP) signaling protocol used for controlling voice and video communications over IP (VoIP)."
    },
    5432: {
        "protocol": "TCP",
        "service": "PostgreSQL",
        "description": "PostgreSQL relational database management system default listening port for client connections."
    },
    5900: {
        "protocol": "TCP",
        "service": "VNC",
        "description": "Virtual Network Computing (VNC) display server port (:0) for graphical desktop remote control using RFB protocol."
    },
    5984: {
        "protocol": "TCP",
        "service": "CouchDB",
        "description": "Apache CouchDB document-oriented NoSQL database RESTful HTTP interface."
    },
    6379: {
        "protocol": "TCP",
        "service": "Redis",
        "description": "Redis in-memory data store, cache, and message broker default connection port."
    },
    6667: {
        "protocol": "TCP",
        "service": "IRC",
        "description": "Standard unencrypted Internet Relay Chat (IRC) port used by IRC clients to connect to chat networks."
    },
    8000: {
        "protocol": "TCP",
        "service": "HTTP-Alt",
        "description": "Common alternative HTTP port frequently used for local web development servers and RESTful microservices."
    },
    8008: {
        "protocol": "TCP",
        "service": "HTTP-Alt",
        "description": "Alternative HTTP port commonly used for local web administration consoles and lightweight servers."
    },
    8080: {
        "protocol": "TCP",
        "service": "HTTP-Proxy",
        "description": "Widely used alternative HTTP port, application server port (e.g. Tomcat), and web caching proxy port."
    },
    8443: {
        "protocol": "TCP",
        "service": "HTTPS-Alt",
        "description": "Common alternative HTTPS port used for secure secondary web interfaces, admin dashboards, and APIs."
    },
    8888: {
        "protocol": "TCP",
        "service": "HTTP-Alt",
        "description": "Alternative HTTP port frequently utilized by web application dashboards, proxies, and Jupyter notebooks."
    },
    9200: {
        "protocol": "TCP",
        "service": "Elasticsearch",
        "description": "Elasticsearch distributed search and analytics engine RESTful HTTP communication port."
    },
    27017: {
        "protocol": "TCP",
        "service": "MongoDB",
        "description": "MongoDB document-oriented NoSQL database default listening port for client connections."
    },
}


def get_port_info(port: int) -> dict:
    """
    Look up educational information for a given network port number (1-65535).
    Raises ValueError if port is out of valid range.
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("Port must be an integer between 1 and 65535.")

    if port in COMMON_PORTS_DATABASE:
        info = COMMON_PORTS_DATABASE[port]
        return {
            "port": port,
            "protocol": info["protocol"],
            "service": info["service"],
            "description": info["description"],
        }

    # Range-based educational categorization for non-indexed ports
    if 1 <= port <= 1023:
        category = "Well-Known Port (System Port)"
        desc = (
            f"Port {port} falls within the IANA Well-Known Ports range (1–1023), "
            "which is reserved for fundamental operating system services and standardized network protocols."
        )
    elif 1024 <= port <= 49151:
        category = "Registered Port (User Port)"
        desc = (
            f"Port {port} falls within the IANA Registered Ports range (1024–49151), "
            "which is assigned by IANA for specific vendor applications, services, and developer tooling upon registration."
        )
    else:
        category = "Dynamic / Private Port (Ephemeral Port)"
        desc = (
            f"Port {port} falls within the IANA Dynamic/Private Ports range (49152–65535), "
            "typically used by operating systems for outbound temporary connections (ephemeral ports) or custom private applications."
        )

    return {
        "port": port,
        "protocol": "TCP",
        "service": "Custom/Unassigned",
        "category": category,
        "description": desc,
    }
