"""
Port → Service name mapping.
Top 1000 ports + common security-relevant ports.
"""

SERVICES: dict[int, str] = {
    # Web
    80:    "HTTP",
    443:   "HTTPS",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    3000:  "HTTP-Dev",
    5000:  "HTTP-Dev",

    # Remote Access
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    5901:  "VNC-1",
    5902:  "VNC-2",

    # Mail
    25:    "SMTP",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    110:   "POP3",
    995:   "POP3S",
    143:   "IMAP",
    993:   "IMAPS",

    # DNS & Network
    53:    "DNS",
    67:    "DHCP-Server",
    68:    "DHCP-Client",
    69:    "TFTP",
    123:   "NTP",
    161:   "SNMP",
    162:   "SNMP-Trap",

    # File Transfer
    20:    "FTP-Data",
    21:    "FTP",
    69:    "TFTP",
    115:   "SFTP",
    548:   "AFP",
    2049:  "NFS",

    # Databases
    1433:  "MSSQL",
    1434:  "MSSQL-UDP",
    1521:  "Oracle",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    5984:  "CouchDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB-HTTP",

    # Message Queues & Cache
    5672:  "RabbitMQ-AMQP",
    15672: "RabbitMQ-UI",
    6380:  "Redis-Alt",
    11211: "Memcached",
    9092:  "Kafka",
    2181:  "ZooKeeper",

    # Windows / AD
    135:   "MSRPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    389:   "LDAP",
    445:   "SMB",
    464:   "Kerberos-Change",
    636:   "LDAPS",
    3268:  "LDAP-GlobalCat",
    3269:  "LDAPS-GlobalCat",
    88:    "Kerberos",

    # VPN & Tunneling
    500:   "IKE/IPSec",
    1194:  "OpenVPN",
    1701:  "L2TP",
    1723:  "PPTP",
    4500:  "IPSec-NAT",

    # Monitoring & DevOps
    2375:  "Docker",
    2376:  "Docker-TLS",
    2377:  "Docker-Swarm",
    4243:  "Docker-Alt",
    8500:  "Consul",
    8600:  "Consul-DNS",
    4001:  "etcd",
    2379:  "etcd-Client",
    2380:  "etcd-Peer",
    9090:  "Prometheus",
    3100:  "Loki",
    3001:  "Grafana-Alt",
    9100:  "Node-Exporter",
    6443:  "Kubernetes-API",
    10250: "Kubelet",

    # Misc
    111:   "RPCBind",
    512:   "rexec",
    513:   "rlogin",
    514:   "Syslog/rsh",
    515:   "LPD-Print",
    631:   "IPP-Print",
    873:   "rsync",
    902:   "VMware",
    1080:  "SOCKS",
    1099:  "Java-RMI",
    4444:  "Metasploit",
    4848:  "GlassFish",
    5555:  "ADB-Android",
    6000:  "X11",
    7001:  "WebLogic",
    7002:  "WebLogic-SSL",
    8009:  "AJP",
    8161:  "ActiveMQ",
    9000:  "SonarQube",
    9090:  "WebSM",
    9999:  "Icecast",
}


def get_service(port: int) -> str:
    """Return service name for port, or 'Unknown'."""
    return SERVICES.get(port, "Unknown")


# Ports with high security relevance — shown with extra warning in terminal
HIGH_RISK_PORTS: set[int] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 512, 513, 514, 1080, 1099,
    1433, 1521, 2049, 2375, 3306, 3389, 4444, 5432, 5900,
    6379, 7001, 8080, 8443, 9200, 11211, 27017,
}
