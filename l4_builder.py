"""
l4_builder.py  —  Layer 4 Intelligence Engine
===============================================
Centralises ALL Layer-4 knowledge:
  • TCP / UDP / ICMP / IGMP / GRE / ESP / AH / SCTP / DCCP / OSPF
  • Port registry   (IANA + well-known + registered + dynamic ranges)
  • TCP flag semantics + handshake state machine
  • UDP service detection (by port pair)
  • ICMP extended type/code lookup (delegates to l3_builder table)
  • GRE inner-payload resolution
  • IPsec ESP/AH field-level detail
  • Auto-mapping: l3.next_layer → L4 handler class
  • process_l4() integration function called by main.py
"""

from __future__ import annotations
import struct
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PORT REGISTRY
#  Covers: IANA well-known (0-1023), registered (1024-49151),
#          plus common dynamic/ephemeral patterns
# ══════════════════════════════════════════════════════════════════════════════

PORT_REGISTRY: dict[int, dict] = {

    # ── Well-known (0–1023) ───────────────────────────────────────────────────
    7:    dict(name="Echo",          proto=["tcp","udp"], category="Diagnostic",
               status="Active",   usage="Echo back any received data"),
    19:   dict(name="CHARGEN",       proto=["tcp","udp"], category="Diagnostic",
               status="Deprecated",usage="Character generator (RFC 864)"),
    20:   dict(name="FTP-Data",      proto=["tcp"],       category="File Transfer",
               status="Active",   usage="FTP data channel"),
    21:   dict(name="FTP-Control",   proto=["tcp"],       category="File Transfer",
               status="Active",   usage="FTP command channel"),
    22:   dict(name="SSH",           proto=["tcp"],       category="Remote Access",
               status="Active",   usage="Secure Shell remote login + SFTP"),
    23:   dict(name="Telnet",        proto=["tcp"],       category="Remote Access",
               status="Deprecated",usage="Cleartext remote terminal (insecure)"),
    25:   dict(name="SMTP",          proto=["tcp"],       category="Email",
               status="Active",   usage="Mail transfer between servers"),
    37:   dict(name="Time",          proto=["tcp","udp"], category="Time",
               status="Deprecated",usage="Legacy time protocol (RFC 868)"),
    43:   dict(name="WHOIS",         proto=["tcp"],       category="Directory",
               status="Active",   usage="Domain/IP registration lookup"),
    53:   dict(name="DNS",           proto=["tcp","udp"], category="Name Resolution",
               status="Active",   usage="Domain name to IP resolution"),
    67:   dict(name="DHCP-Server",   proto=["udp"],       category="Address Assignment",
               status="Active",   usage="DHCP server listens on this port"),
    68:   dict(name="DHCP-Client",   proto=["udp"],       category="Address Assignment",
               status="Active",   usage="DHCP client listens on this port"),
    69:   dict(name="TFTP",          proto=["udp"],       category="File Transfer",
               status="Active",   usage="Trivial FTP — no auth, used by PXE boot"),
    70:   dict(name="Gopher",        proto=["tcp"],       category="Web",
               status="Deprecated",usage="Pre-web document retrieval"),
    79:   dict(name="Finger",        proto=["tcp"],       category="Directory",
               status="Deprecated",usage="User info lookup (privacy risk)"),
    80:   dict(name="HTTP",          proto=["tcp","udp"], category="Web",
               status="Active",   usage="Hypertext Transfer Protocol"),
    88:   dict(name="Kerberos",      proto=["tcp","udp"], category="Authentication",
               status="Active",   usage="MIT Kerberos authentication"),
    102:  dict(name="ISO-TSAP",      proto=["tcp"],       category="OSI",
               status="Active",   usage="ISO Transport Service Access Point"),
    110:  dict(name="POP3",          proto=["tcp"],       category="Email",
               status="Active",   usage="Post Office Protocol 3 — mail retrieval"),
    111:  dict(name="RPC",           proto=["tcp","udp"], category="RPC",
               status="Active",   usage="ONC RPC portmapper"),
    119:  dict(name="NNTP",          proto=["tcp"],       category="News",
               status="Active",   usage="Network News Transfer Protocol"),
    123:  dict(name="NTP",           proto=["udp"],       category="Time",
               status="Active",   usage="Network Time Protocol"),
    135:  dict(name="MS-RPC",        proto=["tcp","udp"], category="Windows",
               status="Active",   usage="Microsoft RPC endpoint mapper"),
    137:  dict(name="NetBIOS-NS",    proto=["udp"],       category="Windows",
               status="Active",   usage="NetBIOS Name Service"),
    138:  dict(name="NetBIOS-DGM",   proto=["udp"],       category="Windows",
               status="Active",   usage="NetBIOS Datagram Service"),
    139:  dict(name="NetBIOS-SSN",   proto=["tcp"],       category="Windows",
               status="Active",   usage="NetBIOS Session Service"),
    143:  dict(name="IMAP",          proto=["tcp"],       category="Email",
               status="Active",   usage="Internet Message Access Protocol"),
    161:  dict(name="SNMP",          proto=["udp"],       category="Management",
               status="Active",   usage="Get/Set device MIB variables"),
    162:  dict(name="SNMP-Trap",     proto=["udp"],       category="Management",
               status="Active",   usage="SNMP asynchronous trap notifications"),
    179:  dict(name="BGP",           proto=["tcp"],       category="Routing",
               status="Active",   usage="Border Gateway Protocol"),
    194:  dict(name="IRC",           proto=["tcp"],       category="Messaging",
               status="Active",   usage="Internet Relay Chat"),
    389:  dict(name="LDAP",          proto=["tcp","udp"], category="Directory",
               status="Active",   usage="Lightweight Directory Access Protocol"),
    443:  dict(name="HTTPS",         proto=["tcp","udp"], category="Web",
               status="Active",   usage="HTTP over TLS/SSL — HTTP/3 uses UDP/QUIC"),
    445:  dict(name="SMB",           proto=["tcp"],       category="File Sharing",
               status="Active",   usage="SMB/CIFS file sharing (Windows)"),
    465:  dict(name="SMTPS",         proto=["tcp"],       category="Email",
               status="Active",   usage="SMTP over TLS (implicit TLS)"),
    500:  dict(name="IKE/ISAKMP",    proto=["udp"],       category="Security",
               status="Active",   usage="IPsec key exchange (IKEv1/v2)"),
    514:  dict(name="Syslog",        proto=["udp"],       category="Logging",
               status="Active",   usage="System log messages"),
    515:  dict(name="LPD",           proto=["tcp"],       category="Printing",
               status="Active",   usage="Line Printer Daemon"),
    520:  dict(name="RIP",           proto=["udp"],       category="Routing",
               status="Active",   usage="Routing Information Protocol v1/v2"),
    521:  dict(name="RIPng",         proto=["udp"],       category="Routing",
               status="Active",   usage="RIP next generation (IPv6)"),
    554:  dict(name="RTSP",          proto=["tcp","udp"], category="Streaming",
               status="Active",   usage="Real-Time Streaming Protocol"),
    587:  dict(name="SMTP-Submission",proto=["tcp"],      category="Email",
               status="Active",   usage="Mail submission with auth (RFC 6409)"),
    593:  dict(name="MS-RPC-HTTP",   proto=["tcp"],       category="Windows",
               status="Active",   usage="Microsoft RPC over HTTP"),
    623:  dict(name="IPMI",          proto=["udp"],       category="Management",
               status="Active",   usage="IPMI/BMC remote management"),
    636:  dict(name="LDAPS",         proto=["tcp"],       category="Directory",
               status="Active",   usage="LDAP over TLS/SSL"),
    646:  dict(name="LDP",           proto=["tcp","udp"], category="MPLS",
               status="Active",   usage="MPLS Label Distribution Protocol"),
    694:  dict(name="Heartbeat",     proto=["udp"],       category="Clustering",
               status="Active",   usage="Linux-HA heartbeat"),
    860:  dict(name="iSCSI",         proto=["tcp"],       category="Storage",
               status="Active",   usage="iSCSI block storage over TCP"),
    873:  dict(name="rsync",         proto=["tcp"],       category="File Transfer",
               status="Active",   usage="rsync daemon file synchronisation"),
    902:  dict(name="VMware-ESX",    proto=["tcp","udp"], category="Virtualisation",
               status="Vendor-specific",usage="VMware ESXi management"),
    # ── Registered (1024–49151) ───────────────────────────────────────────────
    993:  dict(name="IMAPS",         proto=["tcp"],       category="Email",
               status="Active",   usage="IMAP over TLS/SSL"),
    995:  dict(name="POP3S",         proto=["tcp"],       category="Email",
               status="Active",   usage="POP3 over TLS/SSL"),
    1080: dict(name="SOCKS",         proto=["tcp"],       category="Proxy",
               status="Active",   usage="SOCKS proxy protocol"),
    1194: dict(name="OpenVPN",       proto=["tcp","udp"], category="VPN",
               status="Active",   usage="OpenVPN tunnel"),
    1433: dict(name="MSSQL",         proto=["tcp","udp"], category="Database",
               status="Active",   usage="Microsoft SQL Server"),
    1521: dict(name="Oracle-DB",     proto=["tcp"],       category="Database",
               status="Active",   usage="Oracle Database Listener"),
    1701: dict(name="L2TP",          proto=["udp"],       category="VPN",
               status="Active",   usage="Layer 2 Tunneling Protocol"),
    1723: dict(name="PPTP",          proto=["tcp"],       category="VPN",
               status="Deprecated",usage="Point-to-Point Tunneling Protocol"),
    1812: dict(name="RADIUS-Auth",   proto=["udp"],       category="Authentication",
               status="Active",   usage="RADIUS authentication"),
    1813: dict(name="RADIUS-Acct",   proto=["udp"],       category="Authentication",
               status="Active",   usage="RADIUS accounting"),
    1883: dict(name="MQTT",          proto=["tcp"],       category="IoT",
               status="Active",   usage="Message Queuing Telemetry Transport"),
    2049: dict(name="NFS",           proto=["tcp","udp"], category="File Sharing",
               status="Active",   usage="Network File System"),
    2181: dict(name="ZooKeeper",     proto=["tcp"],       category="Distributed",
               status="Active",   usage="Apache ZooKeeper coordination"),
    2375: dict(name="Docker",        proto=["tcp"],       category="Container",
               status="Active",   usage="Docker daemon API (insecure)"),
    2376: dict(name="Docker-TLS",    proto=["tcp"],       category="Container",
               status="Active",   usage="Docker daemon API (TLS)"),
    3306: dict(name="MySQL",         proto=["tcp","udp"], category="Database",
               status="Active",   usage="MySQL/MariaDB"),
    3389: dict(name="RDP",           proto=["tcp","udp"], category="Remote Access",
               status="Active",   usage="Remote Desktop Protocol"),
    4500: dict(name="IKE-NAT-T",     proto=["udp"],       category="Security",
               status="Active",   usage="IPsec IKE NAT traversal"),
    4789: dict(name="VXLAN",         proto=["udp"],       category="Overlay",
               status="Active",   usage="Virtual Extensible LAN"),
    5000: dict(name="Docker-Registry",proto=["tcp"],      category="Container",
               status="Active",   usage="Docker image registry"),
    5060: dict(name="SIP",           proto=["tcp","udp"], category="VoIP",
               status="Active",   usage="SIP call signalling"),
    5061: dict(name="SIP-TLS",       proto=["tcp"],       category="VoIP",
               status="Active",   usage="SIP over TLS"),
    5355: dict(name="LLMNR",         proto=["tcp","udp"], category="Name Resolution",
               status="Active",   usage="Link-Local Multicast Name Resolution"),
    5432: dict(name="PostgreSQL",    proto=["tcp"],       category="Database",
               status="Active",   usage="PostgreSQL database server"),
    5672: dict(name="AMQP",          proto=["tcp"],       category="Messaging",
               status="Active",   usage="Advanced Message Queuing Protocol"),
    5900: dict(name="VNC",           proto=["tcp"],       category="Remote Access",
               status="Active",   usage="Virtual Network Computing"),
    6379: dict(name="Redis",         proto=["tcp"],       category="Database",
               status="Active",   usage="Redis in-memory data store"),
    6514: dict(name="Syslog-TLS",    proto=["tcp"],       category="Logging",
               status="Active",   usage="Syslog over TLS (RFC 5425)"),
    6653: dict(name="OpenFlow",      proto=["tcp"],       category="SDN",
               status="Active",   usage="OpenFlow SDN controller"),
    7946: dict(name="Docker-Swarm",  proto=["tcp","udp"], category="Container",
               status="Active",   usage="Docker Swarm node communication"),
    8080: dict(name="HTTP-Alt",      proto=["tcp"],       category="Web",
               status="Active",   usage="Alternate HTTP / proxy"),
    8443: dict(name="HTTPS-Alt",     proto=["tcp"],       category="Web",
               status="Active",   usage="Alternate HTTPS"),
    8883: dict(name="MQTT-TLS",      proto=["tcp"],       category="IoT",
               status="Active",   usage="MQTT over TLS"),
    9090: dict(name="Prometheus",    proto=["tcp"],       category="Monitoring",
               status="Active",   usage="Prometheus metrics endpoint"),
    9092: dict(name="Kafka",         proto=["tcp"],       category="Messaging",
               status="Active",   usage="Apache Kafka broker"),
    9200: dict(name="Elasticsearch", proto=["tcp"],       category="Search",
               status="Active",   usage="Elasticsearch REST API"),
    10250:dict(name="Kubernetes-Kubelet",proto=["tcp"],   category="Container",
               status="Active",   usage="Kubernetes node agent API"),
    27017:dict(name="MongoDB",       proto=["tcp"],       category="Database",
               status="Active",   usage="MongoDB document database"),
    50000:dict(name="SAP",           proto=["tcp"],       category="ERP",
               status="Active",   usage="SAP application server"),
    51820:dict(name="WireGuard",     proto=["udp"],       category="VPN",
               status="Active",   usage="WireGuard VPN tunnel"),
}

# ── Ephemeral / dynamic port ranges ──────────────────────────────────────────
EPHEMERAL_RANGES = [
    (32768, 60999, "Linux default ephemeral"),
    (49152, 65535, "IANA recommended ephemeral (RFC 6335)"),
    (1024,  5000,  "BSD/Windows legacy ephemeral"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — TCP FLAG SEMANTICS
# ══════════════════════════════════════════════════════════════════════════════

TCP_FLAG_BITS: dict[str, int] = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
    "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
    "ECE": 0x40, "CWR": 0x80,
}

TCP_FLAG_DETAIL: dict[str, dict] = {
    "SYN": dict(usage="Open connection — initiate 3-way handshake",
                direction="client→server (step1) or server→client (step2)"),
    "ACK": dict(usage="Acknowledge received data — always set after handshake",
                direction="both"),
    "FIN": dict(usage="Graceful close — no more data to send",
                direction="initiating side → peer"),
    "RST": dict(usage="Abrupt connection reset — discard all state",
                direction="either — usually error response"),
    "PSH": dict(usage="Push data to application immediately (do not buffer)",
                direction="either — set on last segment of application write"),
    "URG": dict(usage="Urgent pointer field is significant — out-of-band data",
                direction="either — rarely used in modern TCP"),
    "ECE": dict(usage="ECN-Echo — peer received CE-marked packet (congestion signalled)",
                direction="receiver→sender during congestion"),
    "CWR": dict(usage="Congestion Window Reduced — sender already reduced cwnd",
                direction="sender→receiver acknowledging ECE"),
}

TCP_HANDSHAKE_STATES: dict[str, dict] = {
    "CLOSED":      dict(flags=None,   description="No connection"),
    "LISTEN":      dict(flags=None,   description="Server waiting for SYN"),
    "SYN_SENT":    dict(flags="SYN",  description="Client sent SYN, waiting SYN-ACK"),
    "SYN_RCVD":    dict(flags="SYN+ACK", description="Server sent SYN-ACK, waiting ACK"),
    "ESTABLISHED": dict(flags="ACK",  description="Connection open — data flows"),
    "FIN_WAIT_1":  dict(flags="FIN+ACK", description="Active closer sent FIN"),
    "FIN_WAIT_2":  dict(flags="ACK",  description="Active closer got ACK for FIN"),
    "CLOSE_WAIT":  dict(flags="ACK",  description="Passive closer got FIN, app must close"),
    "LAST_ACK":    dict(flags="FIN+ACK", description="Passive closer sent FIN"),
    "TIME_WAIT":   dict(flags="ACK",  description="2×MSL wait before CLOSED"),
    "CLOSING":     dict(flags="FIN+ACK", description="Simultaneous close"),
}


def decode_tcp_flags(flag_byte: int) -> list[str]:
    """Return list of active flag names for a TCP flags byte."""
    return [name for name, bit in TCP_FLAG_BITS.items() if flag_byte & bit]


def tcp_flag_summary(flag_byte: int) -> str:
    """Human-readable TCP flag string e.g. 'SYN+ACK'."""
    names = decode_tcp_flags(flag_byte)
    return "+".join(names) if names else "NONE"


def classify_tcp_segment(flag_byte: int, payload_len: int) -> dict:
    """
    Classify a TCP segment by its flags and payload.
    Returns dict(classification, description, handshake_step).
    """
    flags = decode_tcp_flags(flag_byte)
    fset  = set(flags)

    if fset == {"SYN"}:
        return dict(classification="SYN",
                    description="Connection request — 3-way handshake step 1",
                    handshake_step=1)
    if fset == {"SYN", "ACK"}:
        return dict(classification="SYN-ACK",
                    description="Connection grant — 3-way handshake step 2",
                    handshake_step=2)
    if fset == {"ACK"} and payload_len == 0:
        return dict(classification="ACK",
                    description="Pure acknowledgment — no data",
                    handshake_step=3)
    if "PSH" in fset and "ACK" in fset and payload_len > 0:
        return dict(classification="PSH+ACK",
                    description=f"Data segment ({payload_len}B) — push to application",
                    handshake_step=4)
    if "FIN" in fset and "ACK" in fset:
        return dict(classification="FIN+ACK",
                    description="Graceful close initiation",
                    handshake_step=5)
    if fset == {"RST"} or fset == {"RST", "ACK"}:
        return dict(classification="RST",
                    description="Abrupt connection reset",
                    handshake_step=6)
    return dict(classification="+".join(sorted(flags)),
                description="TCP segment",
                handshake_step=None)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — UDP SERVICE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

UDP_SERVICE_MAP: dict[tuple, dict] = {
    (53,  53):   dict(name="DNS Query/Response",  direction="client→server or server→client"),
    (67,  68):   dict(name="DHCP Server→Client",  direction="server→client"),
    (68,  67):   dict(name="DHCP Client→Server",  direction="client→server"),
    (123, 123):  dict(name="NTP",                 direction="client↔server"),
    (161, 162):  dict(name="SNMP Get/Set",        direction="manager→agent"),
    (162, 162):  dict(name="SNMP Trap",           direction="agent→manager"),
    (514, 514):  dict(name="Syslog",              direction="device→collector"),
    (520, 520):  dict(name="RIP v1/v2",           direction="router↔router"),
    (521, 521):  dict(name="RIPng",               direction="router↔router"),
    (69,  69):   dict(name="TFTP",                direction="client↔server"),
    (5060,5060): dict(name="SIP",                 direction="UA↔UA or UA↔Proxy"),
    (1194,1194): dict(name="OpenVPN",             direction="peer↔peer"),
    (4789,4789): dict(name="VXLAN Tunnel",        direction="VTEP↔VTEP"),
    (51820,51820):dict(name="WireGuard",          direction="peer↔peer"),
    (4500,4500): dict(name="IKE NAT-T",           direction="IPsec peer↔peer"),
    (500, 500):  dict(name="IKE/ISAKMP",          direction="IPsec peer↔peer"),
}


def detect_udp_service(src_port: int, dst_port: int) -> dict:
    """Detect UDP service from port pair (tries both orderings)."""
    svc = UDP_SERVICE_MAP.get((src_port, dst_port))
    if svc:
        return svc
    svc = UDP_SERVICE_MAP.get((dst_port, src_port))
    if svc:
        return svc
    # fallback: check individual port names
    src_info = PORT_REGISTRY.get(src_port)
    dst_info = PORT_REGISTRY.get(dst_port)
    if dst_info and "udp" in dst_info.get("proto", []):
        return dict(name=dst_info["name"], direction=f"→ port {dst_port}")
    if src_info and "udp" in src_info.get("proto", []):
        return dict(name=src_info["name"], direction=f"← port {src_port}")
    return dict(name="Unknown UDP service", direction="unknown")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — GRE FIELD DETAIL
# ══════════════════════════════════════════════════════════════════════════════

GRE_VERSIONS: dict[int, str] = {
    0: "GRE (RFC 2784 / RFC 2890) — standard",
    1: "Enhanced GRE (PPTP) — RFC 2637",
}

def decode_gre_header(data: bytes) -> dict:
    """
    Decode a GRE header (minimum 4 bytes).
    Returns dict with flags, version, protocol, optional fields.
    """
    if len(data) < 4:
        return dict(valid=False, reason="Too short for GRE")

    word0    = struct.unpack("!H", data[0:2])[0]
    proto    = struct.unpack("!H", data[2:4])[0]

    cksum_present = bool(word0 & 0x8000)
    key_present   = bool(word0 & 0x2000)
    seq_present   = bool(word0 & 0x1000)
    version       = word0 & 0x7

    offset = 4
    checksum = None
    key      = None
    seq      = None

    if cksum_present:
        checksum = struct.unpack("!H", data[offset:offset+2])[0]
        offset  += 4  # checksum(2) + reserved(2)
    if key_present and offset + 4 <= len(data):
        key    = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4
    if seq_present and offset + 4 <= len(data):
        seq    = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4

    return dict(
        valid         = True,
        version       = version,
        version_name  = GRE_VERSIONS.get(version, f"Unknown v{version}"),
        proto         = proto,
        proto_name    = f"0x{proto:04X}",
        cksum_present = cksum_present,
        checksum      = checksum,
        key_present   = key_present,
        key           = key,
        seq_present   = seq_present,
        seq           = seq,
        header_len    = offset,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — IPSEC ESP / AH DETAIL
# ══════════════════════════════════════════════════════════════════════════════

ESP_FIELD_DETAIL: dict = {
    "SPI":      "4B Security Parameters Index — identifies SA on receiver",
    "Seq":      "4B anti-replay counter — increments per packet",
    "IV":       "variable initialisation vector (AES-CBC=16B, AES-GCM=8B)",
    "Payload":  "encrypted data (variable)",
    "Pad":      "0-255B padding to block boundary",
    "Pad-len":  "1B number of pad bytes",
    "Next-Hdr": "1B inner protocol (4=IPv4 41=IPv6 17=UDP 6=TCP)",
    "ICV":      "8-16B integrity check value (authentication tag)",
}

AH_FIELD_DETAIL: dict = {
    "Next-Hdr":    "1B inner protocol number",
    "Payload-Len": "1B  (ICV length in 4B words − 2)",
    "Reserved":    "2B  must be zero",
    "SPI":         "4B Security Parameters Index",
    "Seq":         "4B anti-replay counter",
    "ICV":         "variable integrity check (HMAC-SHA1=12B HMAC-SHA256=16B)",
}

# Common ESP transform sets
ESP_TRANSFORMS: dict[str, dict] = {
    "AES-128-CBC + HMAC-SHA1-96": dict(enc_key=128, auth_key=160,
                                        iv_len=16, icv_len=12, status="Active"),
    "AES-256-CBC + HMAC-SHA256-128":dict(enc_key=256, auth_key=256,
                                          iv_len=16, icv_len=16, status="Active"),
    "AES-128-GCM-16":              dict(enc_key=128, auth_key=None,
                                        iv_len=8, icv_len=16, status="Active",
                                        note="AEAD — no separate auth algo"),
    "AES-256-GCM-16":              dict(enc_key=256, auth_key=None,
                                        iv_len=8, icv_len=16, status="Active",
                                        note="AEAD — preferred in IKEv2"),
    "3DES-CBC + HMAC-SHA1-96":     dict(enc_key=168, auth_key=160,
                                        iv_len=8, icv_len=12, status="Deprecated"),
    "NULL + HMAC-SHA1-96":         dict(enc_key=None, auth_key=160,
                                        iv_len=0, icv_len=12, status="Active",
                                        note="Integrity only — no encryption"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — PROTOCOL-LEVEL FIELD DETAIL (concise)
# ══════════════════════════════════════════════════════════════════════════════

L4_FIELD_DETAIL: dict[str, dict] = {
    "tcp": {
        "Src Port":    "2B source port (ephemeral for clients)",
        "Dst Port":    "2B destination port (service identifier)",
        "Seq":         "4B position of first data byte in this segment",
        "Ack":         "4B next byte expected from peer (ACK flag must be set)",
        "Data Offset": "4b header length ÷4 (min=5 for 20B no-option header)",
        "Flags":       "9b: NS CWR ECE URG ACK PSH RST SYN FIN",
        "Window":      "2B receive buffer space (flow control)",
        "Checksum":    "2B RFC793 pseudo-header + segment",
        "Urgent":      "2B valid only when URG flag set",
    },
    "udp": {
        "Src Port":  "2B source port",
        "Dst Port":  "2B destination port",
        "Length":    "2B header(8B) + data length",
        "Checksum":  "2B RFC768 pseudo-header + datagram (0xFFFF if zero)",
    },
    "icmp": {
        "Type":     "1B message type (8=request 0=reply 3=unreachable 11=TTL-exceeded)",
        "Code":     "1B sub-code qualifying the type",
        "Checksum": "2B over entire ICMP message",
        "Rest":     "4B type-specific (ID+Seq for echo, unused for errors)",
        "Data":     "variable: for errors = IP header + 8B of triggering packet",
    },
    "igmp": {
        "Type":         "1B 0x11=Query 0x16=Report(v2) 0x22=Report(v3) 0x17=Leave",
        "Max Resp":     "1B max response time in tenths of second",
        "Checksum":     "2B over IGMP message",
        "Group Addr":   "4B multicast group address",
    },
    "gre": {
        "Flags+Ver":  "2B: C=cksum K=key S=seq bits + version(3b)",
        "Protocol":   "2B inner EtherType (0x0800=IPv4 0x86DD=IPv6 0x6558=TEB)",
        "Checksum":   "opt 4B (2B cksum + 2B reserved) when C=1",
        "Key":        "opt 4B tunnel key when K=1",
        "Seq":        "opt 4B sequence number when S=1",
    },
    "esp": ESP_FIELD_DETAIL,
    "ah":  AH_FIELD_DETAIL,
    "ospf": {
        "Version":   "1B  2=OSPFv2 (IPv4) 3=OSPFv3 (IPv6)",
        "Type":      "1B  1=Hello 2=DBD 3=LSReq 4=LSU 5=LSAck",
        "Length":    "2B  total packet length",
        "Router-ID": "4B  sender's router identifier",
        "Area-ID":   "4B  ospf area (0.0.0.0=backbone)",
        "Checksum":  "2B  over entire OSPF packet",
        "Auth-Type": "2B  0=none 1=simple-password 2=MD5",
    },
    "sctp": {
        "Src Port":   "2B",
        "Dst Port":   "2B",
        "Verif-Tag":  "4B  peer's assigned tag",
        "Checksum":   "4B  CRC-32c over full packet",
        "Chunks":     "variable  Type(1B)+Flags(1B)+Length(2B)+Value",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — PORT RANGE CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def classify_port(port: int) -> dict:
    """
    Classify a port number.
    Returns dict(range_name, registered_name, is_ephemeral, category).
    """
    known = PORT_REGISTRY.get(port)
    name  = known["name"] if known else None
    cat   = known["category"] if known else None

    if 0 <= port <= 1023:
        return dict(range_name="Well-known (0-1023)", registered_name=name,
                    category=cat, is_ephemeral=False)
    if 1024 <= port <= 49151:
        return dict(range_name="Registered (1024-49151)", registered_name=name,
                    category=cat, is_ephemeral=False)
    return dict(range_name="Dynamic/Ephemeral (49152-65535)", registered_name=name,
                category=cat, is_ephemeral=True)


def port_info(port: int) -> str:
    """One-line port description."""
    known = PORT_REGISTRY.get(port)
    if known:
        return f"{port}/{'/'.join(known['proto'])} — {known['name']} [{known['usage']}]"
    cls = classify_port(port)
    return f"{port} — {cls['range_name']}"


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — AUTO-MAPPING ENGINE  (l3_data.next_layer → L4 handler)
# ══════════════════════════════════════════════════════════════════════════════

# Protocols that ARE L4 (can be directly dispatched)
L4_HANDLERS: set = {
    "tcp", "udp", "icmp", "icmpv6", "igmp",
    "gre", "esp", "ah", "sctp", "dccp",
    "ospf", "eigrp", "vrrp", "pim",
    "rsvp", "l2tp", "isis",
}

# Protocols that have no further L4 (terminate here)
L4_TERMINATES: set = {
    "arp", "rarp", "stp", "lldp", "pagp", "lacp",
    "dtp", "pfc", "pause", "vlan_only",
}

# Recursive / tunnelled protocols that need inner L4 analysis
L4_RECURSIVE: set = {
    "gre",    # inner proto field
    "esp",    # decrypted inner packet
    "ah",     # inner proto = next header
    "l2tp",   # inner PPP → inner IP → inner L4
}


def resolve_l4_handler(next_layer: str | None) -> dict:
    """
    Given l3_data.next_layer, return L4 dispatch info.
    """
    if next_layer is None:
        return dict(handler=None, has_payload=False, recursive=False,
                    reason="No L4 implied by this L3 protocol")
    nl = next_layer.lower()
    if nl in L4_TERMINATES:
        return dict(handler=None, has_payload=False, recursive=False,
                    reason=f"{nl} terminates — no Layer 4")
    if nl in L4_HANDLERS:
        return dict(handler=nl, has_payload=True,
                    recursive=nl in L4_RECURSIVE,
                    reason=f"Standard L4 protocol: {nl}")
    return dict(handler="raw", has_payload=True, recursive=False,
                reason=f"Unknown L4: {nl} — treated as RAW payload")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — process_l4()  (called by main.py)
# ══════════════════════════════════════════════════════════════════════════════

def process_l4(
    l3_data:    dict,
    src_port:   int   | None = None,
    dst_port:   int   | None = None,
    flags:      int   | None = None,
    seq_num:    int   | None = None,
    ack_num:    int   | None = None,
    icmp_type:  int   | None = None,
    icmp_code:  int   | None = None,
    raw_segment:bytes | None = None,
    extra:      dict  | None = None,
) -> dict:
    """
    Central L4 intelligence dispatcher.

    Parameters
    ----------
    l3_data     : dict returned by process_l3() — provides next_layer hint
    src_port    : source port (TCP/UDP)
    dst_port    : destination port (TCP/UDP)
    flags       : TCP flags byte
    seq_num     : TCP sequence number
    ack_num     : TCP acknowledgement number
    icmp_type   : ICMP type
    icmp_code   : ICMP code
    raw_segment : raw L4 bytes (optional — for decode)
    extra       : any extra context

    Returns
    -------
    dict with keys:
        handler, l4_class, service_info, field_detail,
        tcp_classification, port_info, gre_detail,
        has_payload, recursive, summary
    """
    extra   = extra or {}
    nl      = l3_data.get("next_layer")
    handler = resolve_l4_handler(nl)
    l4_cls  = handler.get("handler", "raw")

    # ── Port classification ───────────────────────────────────────────────────
    src_port_info = classify_port(src_port) if src_port is not None else {}
    dst_port_info = classify_port(dst_port) if dst_port is not None else {}

    # ── Service detection ─────────────────────────────────────────────────────
    service_info  = {}
    if l4_cls == "tcp" and dst_port is not None:
        known = PORT_REGISTRY.get(dst_port)
        if known:
            service_info = known
    elif l4_cls == "udp" and src_port is not None and dst_port is not None:
        service_info = detect_udp_service(src_port, dst_port)

    # ── TCP segment classification ────────────────────────────────────────────
    tcp_class = {}
    if l4_cls == "tcp" and flags is not None:
        payload_len = len(raw_segment) - 20 if raw_segment else 0
        tcp_class   = classify_tcp_segment(flags, payload_len)

    # ── Field detail ──────────────────────────────────────────────────────────
    field_detail = L4_FIELD_DETAIL.get(l4_cls, {})

    # ── GRE decode ────────────────────────────────────────────────────────────
    gre_detail = {}
    if l4_cls == "gre" and raw_segment:
        gre_detail = decode_gre_header(raw_segment)

    # ── ICMP lookup ───────────────────────────────────────────────────────────
    icmp_detail = {}
    if l4_cls == "icmp" and icmp_type is not None:
        # Import from l3_builder at runtime to avoid circular dependency
        try:
            from l3_builder import get_icmp_type_info
            icmp_detail = get_icmp_type_info(icmp_type)
            if icmp_code is not None:
                code_name = icmp_detail.get("codes", {}).get(icmp_code, f"Code {icmp_code}")
                icmp_detail["resolved_code"] = code_name
        except ImportError:
            icmp_detail = dict(type=icmp_type, code=icmp_code)

    # ── Summary string ────────────────────────────────────────────────────────
    if l4_cls == "tcp":
        flag_str = tcp_flag_summary(flags) if flags is not None else "?"
        sp = port_info(src_port) if src_port is not None else "?"
        dp = port_info(dst_port) if dst_port is not None else "?"
        summary = f"TCP  {sp} → {dp}  flags={flag_str}"

    elif l4_cls == "udp":
        sp = port_info(src_port) if src_port is not None else "?"
        dp = port_info(dst_port) if dst_port is not None else "?"
        svc = service_info.get("name", "")
        summary = f"UDP  {sp} → {dp}  {svc}"

    elif l4_cls == "icmp":
        t_name = icmp_detail.get("name", f"Type {icmp_type}")
        c_name = icmp_detail.get("resolved_code", f"Code {icmp_code}")
        summary = f"ICMP  {t_name} / {c_name}"

    elif l4_cls == "gre":
        inner = gre_detail.get("proto_name", "?")
        summary = f"GRE  inner={inner}"

    elif l4_cls == "esp":
        summary = "ESP  (encrypted payload — no L4 visible)"

    elif l4_cls == "ah":
        summary = "AH  (authenticated — inner proto in Next-Hdr field)"

    else:
        summary = f"L4={l4_cls or 'none'}"

    return dict(
        handler          = handler,
        l4_class         = l4_cls,
        src_port         = src_port,
        dst_port         = dst_port,
        src_port_info    = src_port_info,
        dst_port_info    = dst_port_info,
        service_info     = service_info,
        tcp_classification = tcp_class,
        field_detail     = field_detail,
        gre_detail       = gre_detail,
        icmp_detail      = icmp_detail,
        flags            = flags,
        flag_str         = tcp_flag_summary(flags) if flags is not None else None,
        seq_num          = seq_num,
        ack_num          = ack_num,
        has_payload      = handler.get("has_payload", False),
        recursive        = handler.get("recursive", False),
        summary          = summary,
        l3_context       = l3_data,
        extra            = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — CONVENIENCE WRAPPERS
# ══════════════════════════════════════════════════════════════════════════════

def process_l4_tcp(l3_data: dict, src_port: int, dst_port: int,
                   flags: int, seq: int, ack: int,
                   raw: bytes | None = None) -> dict:
    return process_l4(l3_data, src_port=src_port, dst_port=dst_port,
                      flags=flags, seq_num=seq, ack_num=ack, raw_segment=raw)


def process_l4_udp(l3_data: dict, src_port: int, dst_port: int,
                   raw: bytes | None = None) -> dict:
    return process_l4(l3_data, src_port=src_port, dst_port=dst_port, raw_segment=raw)


def process_l4_icmp(l3_data: dict, icmp_type: int, icmp_code: int,
                    raw: bytes | None = None) -> dict:
    return process_l4(l3_data, icmp_type=icmp_type, icmp_code=icmp_code, raw_segment=raw)


def process_l4_gre(l3_data: dict, raw: bytes) -> dict:
    return process_l4(l3_data, raw_segment=raw)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — LISTING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def list_ports(
    proto:    str | None = None,
    category: str | None = None,
    status:   str | None = None,
) -> list[tuple[int, str, str]]:
    """
    Return list of (port, name, usage) optionally filtered.
    proto    : 'tcp' | 'udp'
    category : e.g. 'Database' | 'Web' | 'VPN'
    status   : 'Active' | 'Deprecated'
    """
    result = []
    for port, info in PORT_REGISTRY.items():
        if proto and proto not in info.get("proto", []):
            continue
        if category and info.get("category") != category:
            continue
        if status and info.get("status") != status:
            continue
        result.append((port, info["name"], info["usage"]))
    return sorted(result, key=lambda x: x[0])


def get_esp_transforms() -> dict:
    return ESP_TRANSFORMS


def get_tcp_states() -> dict:
    return TCP_HANDSHAKE_STATES


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — NON-IP L4 PROTOCOL HANDLERS
#  Covers: XNS SPP/PEP/Echo/Error/RIP, Novell SPX/NCP/SAP/RIP,
#          AppleTalk ATP/NBP/RTMP/AEP/ZIP/ADSP,
#          Banyan VINES IPC/SPP, DECnet NSP, DEC LAT sessions, IBM SNA RU
# ══════════════════════════════════════════════════════════════════════════════

NON_IP_L4_REGISTRY: dict[str, dict] = {

    # ── XNS L4 protocols ──────────────────────────────────────────────────────
    "spp": dict(
        name="XNS SPP (Sequenced Packet Protocol)",
        transport="reliable ordered byte stream  (≈ TCP)",
        header_bytes=12,
        fields={
            "Connection ID (src)":  "2B source connection ID",
            "Connection ID (dst)":  "2B destination connection ID",
            "Sequence Number":      "2B",
            "Acknowledge Number":   "2B",
            "Allocation Number":    "2B (window: next seq peer may send)",
            "Datastream Type":      "1B sub-stream: 0=normal 1=end-of-msg 254=attention 255=probe",
            "Flags":                "1B: Send-ACK(1) Attention(2) EOM(4) Sys-Pkt(128)",
        },
        connections="3-way: Connect(SPP)/SPPACK/data → Disconnect/SPPACK",
        sockets="established via IDP; SPP socket numbers > 3000",
        applications="Courier RPC  ·  Filing  ·  Clearinghouse directory  ·  Printing",
    ),
    "pep": dict(
        name="XNS PEP (Packet Exchange Protocol)",
        transport="unreliable request/response  (≈ UDP)",
        header_bytes=4,
        fields={
            "ID":      "4B transaction ID — response copies request ID",
            "Client":  "4B client-type",
            "Data":    "variable request/response payload",
        },
        applications="Clearinghouse lookup  ·  Echo  ·  Routing queries",
    ),
    "xns_echo": dict(
        name="XNS Echo Protocol",
        transport="single request/response pair",
        header_bytes=2,
        fields={"Type":"2B  1=Request  2=Reply","Data":"variable — copied from request to reply"},
        applications="Network reachability testing (like ICMP echo)",
    ),
    "xns_error": dict(
        name="XNS Error Protocol",
        transport="one-way error notification",
        header_bytes=4,
        fields={"Error Type":"2B  0=Unspecified 1=Bad-Checksum 2=No-Socket 3=Pkt-Too-Large",
                "Error Param":"2B  max-packet-size for type 3",
                "Original":"first 42B of offending IDP packet"},
        applications="Network error reporting (like ICMP unreachable)",
    ),
    "xns_rip": dict(
        name="XNS RIP (Routing Information Protocol)",
        transport="periodic broadcast + request/response",
        header_bytes=2,
        fields={"Packet Type":"2B  1=Request 2=Response",
                "Entries":"variable: Network(4B)+Hop-Count(2B)",
                "Infinity":"hop count 16 = unreachable"},
        applications="XNS network routing table maintenance",
    ),

    # ── Novell IPX L4 protocols ────────────────────────────────────────────────
    "spx": dict(
        name="Novell SPX (Sequenced Packet Exchange)",
        transport="reliable ordered connection-oriented (≈ TCP)",
        header_bytes=12,
        fields={
            "Connection Control":   "1B flags EOM(4) Attention(5) ACK-req(6) Sys-pkt(7)",
            "Datastream Type":      "1B 0=normal 1=end-of-msg 254=attention 255=probe",
            "Src Connection ID":    "2B",
            "Dst Connection ID":    "2B",
            "Sequence Number":      "2B",
            "Acknowledge Number":   "2B",
            "Allocation Number":    "2B (window)",
        },
        connections="Connect-Req/Connect-Ack/data → Disconnect",
        applications="NetWare print  ·  remote access  ·  legacy NetWare apps",
    ),
    "ncp": dict(
        name="Novell NCP (NetWare Core Protocol)",
        transport="request/response over IPX (IPX type 17)",
        header_bytes=7,
        fields={
            "Request Type":    "2B  0x1111=Create-Service-Conn 0x2222=Service-Req 0x3333=Service-Reply 0x5555=Destroy 0x9999=Broadcast",
            "Sequence Number": "1B  0-255 wrapping",
            "Connection Low":  "1B low byte of connection number (1-250)",
            "Task Number":     "1B",
            "Connection High": "1B high byte",
            "Function Code":   "1B  21=Read 22=Write 66=CloseFile 72=OpenFile 0x17=NDS calls",
            "Sub-Function":    "variable depends on Function Code",
            "Data":            "variable  function-specific payload",
        },
        applications="NetWare file system  ·  NDS/eDirectory  ·  print queues  ·  bindery",
    ),
    "sap_ipx": dict(
        name="Novell SAP (Service Advertisement Protocol)",
        transport="periodic broadcast + nearest-server query (IPX type 4, socket 0x0452)",
        header_bytes=2,
        fields={
            "Query Type":    "2B  1=General-Svc-Query 2=General-Svc-Resp 3=Nearest-Query 4=Nearest-Resp",
            "Server Type":   "2B  0x0004=FileServer 0x0007=PrintServer 0x0278=NDS 0x0640+=app-specific",
            "Server Name":   "48B null-padded server name string",
            "Network":       "4B server network",
            "Node":          "6B server node MAC",
            "Socket":        "2B service socket number",
            "Hops":          "2B hop count (16=down/unreachable)",
        },
        applications="Advertising and discovering NetWare servers and services",
        note="SAP broadcasts every 60s — replaced by SLP in NetWare 5+ environments",
    ),
    "netbios_ipx": dict(
        name="NetBIOS over IPX (type-20 propagation)",
        transport="broadcast propagation through routers (IPX type 20)",
        header_bytes=0,
        fields={"Data":"NetBIOS datagram — Name_Claimed/Name_Query/Datagram/Broadcast",
                "Note":"IPX type-20 broadcasts are forwarded up to 8 hops — router must enable"},
        applications="Windows networking on NetWare  ·  legacy file/printer sharing",
    ),

    # ── AppleTalk L4 protocols ─────────────────────────────────────────────────
    "atp": dict(
        name="AppleTalk ATP (Transaction Protocol)",
        transport="reliable request/response with exactly-once semantics",
        header_bytes=8,
        fields={
            "Control":        "1B: TReq=0x40 TResp=0x80 TRel=0xC0 | XO(5) EOM(4) STS(3)",
            "Bitmap/SeqNo":   "1B: in TReq=response bitmap; in TResp=response seq 0-7",
            "Transaction ID": "2B unique transaction identifier",
            "User Bytes":     "4B caller-defined (ASP uses for func/bitmap)",
            "Data":           "variable — max 578B per response packet",
        },
        connections="TReq → [up to 8 TResp] → TRel  (XO = exactly-once semantics)",
        applications="AFP (AppleTalk Filing Protocol)  ·  PAP (Printer Access Protocol)  ·  ASP",
    ),
    "nbp": dict(
        name="AppleTalk NBP (Name Binding Protocol)",
        transport="DDP broadcast/multicast request → unicast reply",
        header_bytes=2,
        fields={
            "Function":    "4b BrRq(1) LkUp(2) LkUp-Reply(3) FwdReq(4) NuLkUp(5) NuLkUp-Reply(6) Confirm(7)",
            "Tuple Count": "4b number of NBP tuples in packet",
            "CBId":        "1B callback ID (correlates request to reply)",
            "Tuples":      "variable: Network(2B)+Node(1B)+Socket(1B)+Enum(1B)+Name(var)",
            "Name format": "Object:Type@Zone — e.g. LaserWriter:LaserWriter@Engineering",
        },
        applications="Service discovery on AppleTalk (≈ mDNS/DNS-SD on modern Apple)",
    ),
    "rtmp": dict(
        name="AppleTalk RTMP (Routing Table Maintenance Protocol)",
        transport="periodic broadcast (every 10s) + request/response",
        header_bytes=4,
        fields={"Sender Net":"2B","ID Len":"1B=8","Sender ID":"1B",
                "Routing Tuples":"variable StartNet(2B)+Distance(1B)+EndNet(2B) per route"},
        note="Distance measured in router hops — max 15 (16=unreachable)",
        applications="AppleTalk inter-zone routing table distribution",
    ),
    "aep": dict(
        name="AppleTalk AEP (Echo Protocol)",
        transport="single DDP echo request/reply",
        header_bytes=1,
        fields={"Function":"1B  1=Echo-Request  2=Echo-Reply","Data":"variable — copied to reply"},
        applications="AppleTalk reachability testing (≈ ICMP ping)",
    ),
    "zip": dict(
        name="AppleTalk ZIP (Zone Information Protocol)",
        transport="request/response + ATP-based zone list retrieval",
        header_bytes=2,
        fields={"Function":"1B 1=GetZoneList 2=GetLocalZones 3=GetMyZone 5=Query 6=Reply 7=TakeMyZone 8=Notify",
                "Zone Count":"1B (in multi-zone responses)",
                "Zone Names":"variable Pascal strings"},
        applications="AppleTalk zone name management — Chooser zone list",
    ),
    "adsp": dict(
        name="AppleTalk ADSP (Data Stream Protocol)",
        transport="reliable full-duplex byte stream  (≈ TCP)",
        header_bytes=13,
        fields={"Connection ID":"2B","First Byte Seq":"4B","Next Recv Seq":"4B",
                "Recv Window":"2B","Descriptor":"1B flags: EOM ACKREQ CLOSE RESET",
                "Data":"variable"},
        applications="Apple Remote Access  ·  AOCE  ·  legacy Mac peer networking",
    ),

    # ── Banyan VINES L4 protocols ──────────────────────────────────────────────
    "vines_ipc": dict(
        name="Banyan VINES IPC (Interprocess Communication)",
        transport="reliable message delivery (connection-oriented)",
        header_bytes=16,
        fields={"Src Port":"2B","Dst Port":"2B","Packet Type":"1B 0=Data 1=Error 2=Discard 3=Probe 4=Ack",
                "Control":"1B flags","Local Conn":"2B","Remote Conn":"2B",
                "Seq Number":"4B","Ack Number":"4B"},
        applications="VINES file service  ·  print  ·  StreetTalk queries  ·  messaging",
    ),
    "vines_spp": dict(
        name="Banyan VINES SPP (Sequenced Packet Protocol)",
        transport="reliable stream connection (≈ TCP, simpler than IPC)",
        header_bytes=8,
        fields={"Src Port":"2B","Dst Port":"2B","Seq":"2B","Ack":"2B"},
        applications="VINES terminal services  ·  simple file transfer",
    ),
    "vines_arp": dict(
        name="Banyan VINES ARP",
        transport="VIP broadcast/unicast — no connection setup",
        header_bytes=8,
        fields={"Type":"2B  1=Request 2=Response 3=Assignment","Network":"4B","Subnetwork":"2B"},
        applications="VINES internet address resolution",
    ),
    "vines_rtp": dict(
        name="Banyan VINES RTP (Routing Table Protocol)",
        transport="periodic broadcast + request/response",
        header_bytes=4,
        fields={"Packet Type":"2B  1=Request 2=Update 3=Response 4=Redirect",
                "Control":"2B","Entries":"variable network/metric tuples"},
        applications="VINES routing table maintenance",
    ),
    "vines_icp": dict(
        name="Banyan VINES ICP (Internet Control Protocol)",
        transport="one-way error/cost notification",
        header_bytes=4,
        fields={"Packet Type":"2B  0=Exception 1=Metric-Notification",
                "Exception Code":"2B","Original":"first bytes of offending VIP packet"},
        applications="VINES error reporting + path cost notifications",
    ),

    # ── DECnet NSP ────────────────────────────────────────────────────────────
    "nsp": dict(
        name="DECnet NSP (Network Services Protocol)",
        transport="reliable full-duplex logical link  (≈ TCP)",
        header_bytes="variable 3-9B",
        fields={
            "Msg Flags":  "1B: Data/Other-Data/Interrupt/Connect-Init/Connect-Confirm/Disconnect-Init/Disconnect-Confirm/Ack",
            "Dst Addr":   "2B destination logical link address",
            "Src Addr":   "2B source logical link address",
            "Ack Num":    "2B (LS bit=1 + 15b seq) in data/other segments",
            "Seq Num":    "2B sequence number",
            "Reason":     "2B reason code in connect/disconnect messages",
            "Data":       "variable user payload in data segments",
        },
        msg_types={
            0x00: "Data Segment",        0x10: "Other Data (expedited)",
            0x20: "Connect Initiate",    0x28: "Connect Confirm",
            0x30: "Disconnect Initiate", 0x38: "Disconnect Confirm",
            0x04: "Data ACK",            0x14: "Other Data ACK",
            0x08: "No-Resource ACK",     0x01: "Interrupt",
        },
        applications="CTERM (virtual terminal)  ·  DAP/FAL (file access)  ·  NML (management)  ·  Mail-11",
    ),

    # ── DEC LAT Session Slots ─────────────────────────────────────────────────
    "lat_session": dict(
        name="DEC LAT Session Slots",
        transport="multiplexed virtual circuits within LAT messages",
        header_bytes=3,
        fields={"Slot Type":  "1B: 0=Data 1=Attention 3=Start 9=Disconnect A=Reject",
                "Byte Count": "1B number of data bytes in this slot",
                "Min Attention":"1B minimum credits",
                "Data":       "variable terminal data (keystrokes, screen output)"},
        connections="Start→Start-Response → Data slots ↔ Disconnect",
        note="Up to 255 terminal sessions multiplexed in one LAT virtual circuit",
        applications="DECserver 100/200/300/500/700  ·  VAX console  ·  serial line mux",
    ),

    # ── IBM SNA RU Layer ──────────────────────────────────────────────────────
    "sna_ru": dict(
        name="IBM SNA RU (Request/Response Unit)",
        transport="hierarchical session over SNA path control",
        header_bytes=3,
        fields={"RH Byte 0":"Request/Response(1b)+Category(2b)+FI(1b)+SDI(1b)+BCI(1b)+ECI(1b)+DR1I(1b)",
                "RH Byte 1":"DR2I+ERI+QRI+PI+BBU+BIS+EIS bits",
                "RH Byte 2":"RLWI+QUI+PDI+CEBI bits + sense byte indicator",
                "RU":       "variable — contains VTAM/CICS/3270 data stream"},
        request_types={"FMD":"Function Management Data — normal application data",
                       "NC": "Network Control — path control operations",
                       "DFC":"Data Flow Control — pacing, chaining, brackets",
                       "SC": "Session Control — BIND/UNBIND/SDT/CLEAR"},
        applications="3270 terminal emulation  ·  CICS transactions  ·  JES print  ·  DB2",
    ),
}


def get_non_ip_l4_info(l4_class: str) -> dict:
    """Return non-IP L4 protocol registry entry."""
    return NON_IP_L4_REGISTRY.get(l4_class, {})


def process_l4_non_ip(l3_data: dict, extra: dict | None = None) -> dict:
    """
    L4 dispatcher for non-IP protocol stacks (XNS, IPX, DDP, VINES, DECnet, LAT, SNA).
    Uses l3_data.next_layer to select the L4 handler.
    """
    extra   = extra or {}
    nl      = l3_data.get("next_layer", "")
    entry   = NON_IP_L4_REGISTRY.get(nl, {})

    if not entry:
        return dict(l4_class="raw", summary=f"Non-IP L4: {nl} — raw payload",
                    field_detail={}, has_payload=True, l3_context=l3_data)

    return dict(
        l4_class     = nl,
        l4_name      = entry.get("name", nl),
        transport    = entry.get("transport", ""),
        header_bytes = entry.get("header_bytes", 0),
        field_detail = entry.get("fields", {}),
        applications = entry.get("applications", ""),
        connections  = entry.get("connections", ""),
        note         = entry.get("note", ""),
        has_payload  = True,
        summary      = f"{entry.get('name', nl)}  [{entry.get('transport','')}]",
        l3_context   = l3_data,
        extra        = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — STORAGE NETWORK L4 INTERACTIVE BUILDERS
#  All ask_* functions prompt user for every field with caution notes.
# ══════════════════════════════════════════════════════════════════════════════

STORAGE_L4_REGISTRY: dict[str, dict] = {

    # ── FCoE ──────────────────────────────────────────────────────────────────
    "fcoe_fcp": dict(
        name="FCoE FCP (Fibre Channel Protocol — SCSI over FC)",
        transport="FC frames over lossless Ethernet (PFC CoS 3 required)",
        header_bytes=24,
        fields={
            "R_CTL":     "1B  0x00=FCP_DATA 0x06=FCP_XFER_RDY 0x07=FCP_RSP",
            "D_ID":      "3B  Destination N_Port ID (e.g. 0x01 0x00 0x00)",
            "S_ID":      "3B  Source N_Port ID",
            "TYPE":      "1B  0x08=FCP",
            "F_CTL":     "3B  ExchangeSeq(bit23)+SeqInitiator+LastSeq",
            "SEQ_ID":    "1B  0=first sequence",
            "SEQ_CNT":   "2B  frame count within sequence",
            "OX_ID":     "2B  Originator Exchange ID",
            "RX_ID":     "2B  Responder Exchange ID (0xFFFF if initiator)",
            "FCP_LUN":   "8B  SCSI LUN (usually 0x0000000000000000 for LUN 0)",
            "FCP_Cntl":  "1B  FCP_CMD=0x02 FCP_DATA_DIR: bit1=write bit2=read",
            "FCP_DL":    "4B  data length (byte count of SCSI data phase)",
            "SCSI CDB":  "16B  Command Descriptor Block: Op+LUN+LBA+Length",
            "CDB Opcode":"1B  0x00=Test-Unit-Ready 0x03=RequestSense 0x12=Inquiry 0x1A=ModeSense6 0x25=ReadCapacity 0x28=Read10 0x2A=Write10 0x55=ModeSense10 0x88=Read16 0x8A=Write16 0xA0=ReportLUNs",
            "CAUTION":   "OX_ID must be unique per exchange — reuse causes exchange collision and I/O abort",
        },
        applications="SAN block I/O — disk read/write over FCoE fabric",
        caution="Requires PFC on CoS 3 and DCBX negotiation — without lossless = FC frames dropped = I/O errors",
    ),
    "fcoe_els": dict(
        name="FCoE ELS (Extended Link Service — FLOGI/PLOGI/LOGO)",
        transport="FC link service over lossless Ethernet",
        header_bytes=4,
        fields={
            "ELS Command": "1B  0x04=FLOGI 0x03=PLOGI 0x05=LOGO 0x52=FDISC 0x09=ADISC 0x23=RNID",
            "Reserved":    "3B",
            "FLOGI Payload":"36B N_Port Name(8B)+Fabric Name(8B)+Class3 Service Params(16B)",
            "PLOGI N_Port Name":"8B WWN of requesting N_Port",
            "PLOGI Node Name":  "8B WWN of node containing the N_Port",
            "Class3 Params":    "16B receive data size + concurrent sequences",
            "CAUTION":     "FLOGI must succeed before PLOGI — ELS ordering is strict",
        },
        applications="FCoE fabric login sequence — required before any FCP I/O",
    ),
    "fcoe_bls": dict(
        name="FCoE BLS (Basic Link Service — ABTS/BA_ACC/BA_RJT)",
        transport="FC abort/reset over lossless Ethernet",
        header_bytes=4,
        fields={
            "R_CTL":    "1B  0x81=BA_NOP 0x82=ABTS 0x84=BA_ACC 0x85=BA_RJT",
            "SEQ_ID":   "1B  sequence ID being aborted",
            "SEQ_CNT":  "2B  last frame count of aborted sequence",
            "OX_ID":    "2B  exchange to abort",
            "RX_ID":    "2B  responder exchange ID",
            "CAUTION":  "ABTS waits for BA_ACC before retry — timeout without response = port reset",
        },
        applications="FCoE error recovery — abort failing I/O exchanges",
    ),

    # ── FIP ───────────────────────────────────────────────────────────────────
    "fip_discovery": dict(
        name="FIP Discovery (FCF Solicitation/Advertisement)",
        transport="FCoE fabric discovery over Ethernet multicast",
        header_bytes=4,
        fields={
            "Op":         "2B  0x0001=Solicitation 0x0002=Advertisement",
            "Subcode":    "1B",
            "Desc ListLen":"2B  in 32-bit words",
            "Priority":   "1B  FCF priority (lower=better) 0=highest",
            "FC-Map":     "3B  0x0E:FC:00 default Ethernet-to-FC mapping prefix",
            "Switch Name":"8B  FCF WWN",
            "Fabric Name":"8B  fabric WWN",
            "FCF MAC":    "6B  FCF MAC address",
            "Max FCoE Size":"2B  maximum FCoE frame size (default 2158)",
            "FKA_ADV_Period":"4B  ms keepalive interval (default 8000ms)",
            "CAUTION":    "FC-Map must match on all FCoE nodes — mismatch = ENode cannot join fabric",
        },
        applications="FCoE initialisation — ENode discovers FCF before FLOGI",
    ),
    "fip_vlan": dict(
        name="FIP VLAN Discovery",
        transport="FIP VLAN request/notification",
        header_bytes=4,
        fields={
            "Op":      "2B  0x0004=VLAN",
            "Subcode": "1B  0x01=VLAN-Request 0x02=VLAN-Notification",
            "VLAN ID": "2B  VLAN carrying FCoE traffic (1-4094)",
            "CAUTION": "ENode must switch to discovered VLAN before sending FIP solicitation",
        },
        applications='FCoE VLAN discovery — FIP VLAN notification for FCoE fabric VLAN assignment',
    ),

    "aoe_ata": dict(
        name="AoE ATA Command",
        transport="ATA disk command over Ethernet — no IP/TCP",
        header_bytes=12,
        fields={
            "ATA Error/Feature":"1B  ATA feature register (command) or error register (response)",
            "ATA SectorCount":  "1B  number of 512B sectors",
            "ATA CmdStatus":    "1B  ATA command: 0x20=Read 0x30=Write 0xEC=Identify 0xB0=SMART 0xEF=SetFeatures",
            "ATA LBA0":         "1B  LBA bits 7:0",
            "ATA LBA1":         "1B  LBA bits 15:8",
            "ATA LBA2":         "1B  LBA bits 23:16",
            "ATA Device":       "1B  bits 3:0=LBA bits 27:24, bit4=DRV, bit6=LBA-mode=1, bit7=1",
            "ATA LBA3":         "1B  LBA bits 31:24 (48-bit LBA)",
            "ATA LBA4":         "1B  LBA bits 39:32",
            "ATA LBA5":         "1B  LBA bits 47:40",
            "ATA Data":         "variable  512B per sector",
            "CAUTION":          "ATA device register bit6 must=1 for LBA mode — CHS mode deprecated",
        },
        applications="AoE disk read/write/identify on Ethernet-attached storage",
    ),
    "aoe_config": dict(
        name="AoE Config Query",
        transport="AoE target capability query",
        header_bytes=8,
        fields={
            "Buffer Count": "2B  number of outstanding ATA requests target can accept",
            "Firmware Vers":"2B",
            "Sector Count": "1B  max sectors per ATA command",
            "AoE CCCmd":    "1B  0=Read 1=Test 2=Prefix-Test 3=Set 4=ForcedSet",
            "Config Length":"2B  length of config string",
            "Config String":"variable  target config data (e.g. storage device info)",
            "CAUTION":      "Buffer Count limits pipeline depth — exceed it = lost frames and retransmit",
        },
        applications='AoE storage configuration — AoE device capability query/response',
    ),

    "roce_verb": dict(
        name="RoCE v1 RDMA Verb (Send/Write/Read)",
        transport="RDMA over lossless Ethernet — zero copy",
        header_bytes=12,
        fields={
            "OpCode":   "1B  0=RC-Send-First 4=RC-Send-Only 6=RC-Write-First 10=RC-Write-Only 12=RC-Read-Request",
            "SE":       "1b  Solicited Event — receiver posts completion",
            "M":        "1b  MigReq — migration state",
            "Pad":      "2b  payload padding bytes count",
            "TVer":     "4b  transport version=0",
            "P_Key":    "2B  partition key (default 0xFFFF=default partition)",
            "Dest QP":  "3B  Destination Queue Pair number",
            "A":        "1b  Acknowledge Request bit",
            "PSN":      "3B  Packet Sequence Number (increments per packet)",
            "RETH VirtAddr":"8B  (Write/Read) virtual address on remote node",
            "RETH R_Key":"4B  (Write/Read) remote key authorising access to that VA",
            "RETH DMA_Len":"4B  (Write/Read) total bytes to transfer",
            "Payload":  "variable  RDMA payload (must be 4B aligned)",
            "ICRC":     "4B  Invariant CRC over all invariant fields",
            "CAUTION":  "P_Key mismatch drops frame silently — verify partition config on both QPs",
        },
        applications="HPC MPI · NVMe-oF targets · GPU-direct RDMA · Lustre/GPFS parallel I/O",
        caution="Requires PFC + ECN (DCQCN) on lossless fabric — packet loss = QP error and I/O hang",
    ),
    "roce_ack": dict(
        name="RoCE v1 ACK/NAK",
        transport="RoCE reliable connected acknowledgement",
        header_bytes=12,
        fields={
            "OpCode":   "1B  0x10=RC-ACK 0x11=RC-Atomic-ACK",
            "Dest QP":  "3B",
            "PSN":      "3B",
            "AETH Syndrome": "1B  0x00=ACK others=NAK(code in bits 6:5)",
            "AETH MSN": "3B  Message Sequence Number acknowledged",
            "ICRC":     "4B",
            "CAUTION":  "NAK code 0x60=RNR-NAK (retry-later) — implement RNR retry timer or sender stalls",
        },
        applications='RoCE v1 reliable connection ACK/NAK — acknowledgement for RC and UC transport',
    ),

    "iscsi_scsi": dict(
        name="iSCSI SCSI Command/Response PDU",
        transport="iSCSI over direct Ethernet (no TCP)",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x01=Command 0x21=Response",
            "Flags":     "1B  F=Final W=Write R=Read Attr(3b)=0x0=Untagged",
            "CDB Len":   "1B  always 16B for standard CDB",
            "DataSegLen":"3B  data segment byte count",
            "LUN":       "8B  iSCSI LUN (8B format): first 2B=bus+target encoding",
            "ITT":       "4B  Initiator Task Tag — unique per outstanding command",
            "Expected DL":"4B  total data bytes expected (read=transfer size, write=same)",
            "CmdSN":     "4B  command sequence number (ordering)",
            "ExpStatSN": "4B  next expected StatusSN from target",
            "CDB":       "16B  SCSI Command Descriptor Block",
            "SCSI_Op":   "1B  0x00=TUR 0x03=RequestSense 0x12=Inquiry 0x25=ReadCap 0x28=Read10 0x2A=Write10 0x88=Read16 0x8A=Write16",
            "LBA":       "4-8B  starting logical block address (in CDB)",
            "Transfer Length":"2-4B  number of blocks (in CDB)",
            "CAUTION":   "ITT must be unique across all outstanding commands — duplicate ITT = target abort",
        },
        applications="iSCSI block storage I/O over direct Ethernet fabric",
    ),
    "iscsi_data": dict(
        name="iSCSI Data PDU (Data-In/Data-Out)",
        transport="iSCSI data transfer phase",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x04=Data-Out(write) 0x25=Data-In(read)",
            "Flags":     "1B  F=Final A=Acknowledge S=Status(Data-In only)",
            "DataSegLen":"3B  data bytes in this PDU",
            "LUN":       "8B",
            "ITT":       "4B  matches Command ITT",
            "TTT":       "4B  Target Transfer Tag (from R2T — 0xFFFFFFFF for unsolicited)",
            "StatSN":    "4B  status sequence (Data-In only)",
            "ExpCmdSN":  "4B",
            "DataSN":    "4B  data sequence number within task (starts at 0)",
            "BufferOffset":"4B  byte offset into total data buffer",
            "Data":      "variable  actual SCSI data (read or write)",
            "CAUTION":   "BufferOffset + DataSegLen must not exceed ExpectedDataTransferLength",
        },
        applications='iSCSI block storage data transfer — Data-In (target→initiator) and Data-Out',
    ),
    "iscsi_nop": dict(
        name="iSCSI NOP (keepalive)",
        transport="iSCSI session keepalive",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x00=NOP-Out 0x3F=NOP-In",
            "ITT":       "4B  0xFFFFFFFF for unsolicited NOP-In",
            "TTT":       "4B  0xFFFFFFFF for NOP-Out ping",
            "CmdSN":     "4B",
            "ExpStatSN": "4B",
            "Data":      "optional  ping data (echoed back)",
            "CAUTION":   "NOP-Out with ITT≠0xFFFFFFFF expects NOP-In response — no response = session timeout",
        },
        applications='iSCSI NOP keepalive — connection health check and latency measurement',
    ),

    "nvme_cmd": dict(
        name="NVMe Command Capsule (SQE — Submission Queue Entry)",
        transport="NVMe-oF L2 command submission",
        header_bytes=64,
        fields={
            "Opcode":    "1B  0x00=Flush 0x01=Write 0x02=Read 0x04=WriteUncorrectable 0x05=Compare 0x08=WriteZeroes 0x09=DSM 0x0C=Verify 0x0D=ResvRegister 0x7C=Format 0x7E=SecuritySend 0x7F=SecurityRecv",
            "FUSE":      "2b  Fused operation: 00=Normal 01=FirstFuse 10=SecondFuse",
            "PSDT":      "2b  PRP or SGL select: 00=PRP 01=SGL-Seg 10=SGL-Last",
            "CID":       "2B  Command Identifier — unique per SQ",
            "NSID":      "4B  Namespace ID (1-based; 0xFFFFFFFF=all namespaces)",
            "MPTR":      "8B  Metadata Pointer",
            "PRP1":      "8B  Physical Region Page entry 1 (data buffer host address)",
            "PRP2":      "8B  Physical Region Page entry 2 (or SGL segment pointer)",
            "CDW10":     "4B  command-specific DWord 10 (e.g. LBA[31:0] for Read/Write)",
            "CDW11":     "4B  command-specific DWord 11 (e.g. LBA[63:32])",
            "CDW12":     "4B  NLB(15:0)+PRINFO(3b)+FUA(1b)+LR(1b) for Read/Write",
            "CDW13":     "4B",
            "CDW14":     "4B",
            "CDW15":     "4B",
            "CAUTION":   "CID must be unique within the SQ — duplicate CID = command abort by controller",
        },
        applications="NVMe SSD I/O over Ethernet fabric — sub-10µs latency",
        caution="NSID 0 is reserved — use 1-based IDs; 0xFFFFFFFF only for admin namespace commands",
    ),
    "nvme_resp": dict(
        name="NVMe Completion Capsule (CQE — Completion Queue Entry)",
        transport="NVMe-oF L2 command completion",
        header_bytes=16,
        fields={
            "DW0":       "4B  command-specific result",
            "DW1":       "4B  reserved",
            "SQ_Head":   "2B  SQ Head Pointer — freed SQ slots",
            "SQ_ID":     "2B  identifies which SQ this completion is for",
            "CID":       "2B  matches Command Identifier from SQE",
            "P":         "1b  Phase Tag — alternates 0/1 per CQ wrap",
            "SC":        "8b  Status Code: 0=Success 1=InvalidCmdOpcode 2=InvalidField",
            "SCT":       "3b  Status Code Type: 0=Generic 1=CmdSpecific 2=MediaError",
            "CAUTION":   "Phase Tag mismatch means stale CQE — always check P bit matches expected phase",
        },
        applications='NVMe-oF completion capsule — command response with status and result value',
    ),
    "nvme_data": dict(
        name="NVMe H2C/C2H Data PDU",
        transport="NVMe-oF L2 data transfer",
        header_bytes=8,
        fields={
            "PDU Type":  "1B  0x02=H2C-Data(write) 0x03=C2H-Data(read)",
            "Flags":     "1B  HDGSTF+DDGSTF+LAST_PDU",
            "HDR Len":   "1B  header DWords",
            "PLEN":      "4B  total PDU length",
            "CCCID":     "4B  Command Capsule CID this data belongs to",
            "DATAO":     "4B  data offset within total transfer",
            "Data":      "variable  actual NVMe data (4B aligned)",
            "CAUTION":   "DATAO must be 4B aligned — misaligned offsets = PDU error and CQE failure",
        },
        applications='NVMe-oF data capsule — host-to-controller and controller-to-host data transfer',
    ),

    "cfm_ccm": dict(
        name="CFM CCM (Continuity Check Message)",
        transport="IEEE 802.1ag L2 OAM — periodic heartbeat",
        header_bytes=75,
        fields={
            "MD Level":  "3b  Maintenance Domain level 0-7 (0=lowest/customer 7=highest/operator)",
            "Version":   "5b  must be 0",
            "Opcode":    "1B  0x01=CCM",
            "Flags":     "1B  RDI(bit7)=Remote-Defect-Indicator  Period(bits 2:0): 1=3.3ms 2=10ms 4=1s 5=10s",
            "TLV Offset":"1B  0x46=70 (offset to first TLV from Flags byte)",
            "Seq Number":"4B  monotonically increasing — gap indicates frame loss",
            "MEPID":     "2B  1-8191  unique MEP ID within the MA",
            "MAID":      "48B  Maintenance Association ID: MDNameFormat(1B)+MDNameLen(1B)+MDName+MANameFormat(1B)+MANameLen(1B)+MAName",
            "Tx Timestamp":"8B  optional — for one-way delay measurement",
            "Port Status":"optional TLV  type=2 len=1 value: 1=Blocked 2=Up",
            "Intf Status":"optional TLV  type=4 len=1 value: 1=Up 2=Down 3=Testing",
            "End TLV":   "1B=0x00  mandatory last TLV",
            "CAUTION":   "All MEPs in MA must use same CCM interval — mismatch causes false RDI alarm",
        },
        applications="Ethernet OAM continuity monitoring — carrier fault detection",
    ),
    "cfm_lb": dict(
        name="CFM LBM/LBR (Loopback Message/Reply)",
        transport="IEEE 802.1ag L2 loopback — ≈ L2 ping",
        header_bytes=4,
        fields={
            "MD Level":      "3b",
            "Version":       "5b=0",
            "Opcode":        "1B  0x03=LBM  0x02=LBR",
            "Flags":         "1B=0",
            "TLV Offset":    "1B=0x04",
            "Transaction ID":"4B  echoed in LBR — identifies request",
            "Data TLV":      "optional  type=3 len=N data pattern (echoed)",
            "End TLV":       "1B=0x00",
            "CAUTION":       "LBM Dst must be unicast MEP MAC — broadcast LBM = all MEPs reply (multicast flood)",
        },
        applications="CFM loopback — verify L2 path between MEPs without IP",
    ),
    "cfm_lt": dict(
        name="CFM LTM/LTR (Linktrace Message/Reply)",
        transport="IEEE 802.1ag L2 traceroute",
        header_bytes=4,
        fields={
            "MD Level":     "3b",
            "Version":      "5b=0",
            "Opcode":       "1B  0x05=LTM  0x04=LTR",
            "Flags":        "1B  LTM: UseFDBonly(bit7)",
            "TLV Offset":   "1B",
            "Transaction ID":"4B",
            "TTL":          "1B  LTM only — hop limit (decremented per MIP/MEP)",
            "Orig MAC":     "6B  LTM sender MAC",
            "Target MAC":   "6B  LTM target MEP MAC",
            "Relay Action": "1B  LTR only: 1=RlyHit 2=RlyFDB 3=RlyMPDB",
            "CAUTION":      "LTM TTL too low = partial trace; LTM must be sent to LTM multicast 01:80:C2:00:00:3X",
        },
        applications="CFM path trace — identify intermediate MIPs between MEPs",
    ),
    "cfm_dm": dict(
        name="CFM/Y.1731 Delay Measurement (DMM/DMR/1DM/LMM/LMR)",
        transport="IEEE 802.1ag / ITU-T Y.1731 performance measurement",
        header_bytes=4,
        fields={
            "MD Level":      "3b",
            "Version":       "5b=0",
            "Opcode":        "1B  47=DMM 46=DMR 49=1DM 43=LMM 42=LMR",
            "Flags":         "1B=0",
            "TLV Offset":    "1B",
            "Seq Number":    "4B  (DMM/SLM) frame counter",
            "TxTimeStampf":  "8B  Tx PTP timestamp of this frame (seconds(6B)+nanoseconds(4B))",
            "RxTimeStampf":  "8B  Rx timestamp when peer received previous DMM",
            "TxTimeStampb":  "8B  (DMR) Tx timestamp of this DMR",
            "RxTimeStampb":  "8B  (DMR) Rx timestamp when this node received DMM",
            "TxFCf":         "4B  (LMM) transmitted frame counter far-end",
            "RxFCf":         "4B  (LMM) received frame counter far-end",
            "TxFCb":         "4B  (LMR) transmitted frame counter near-end",
            "CAUTION":       "Hardware timestamping required for accuracy — software TS error > 100µs typical",
        },
        applications="Y.1731 SLA measurement — frame delay (FD), mean FD, FDV (jitter), frame loss ratio",
    ),
    "cfm_ais": dict(
        name="Y.1731 AIS/LCK (Alarm Indication / Lock Signal)",
        transport="ITU-T Y.1731 defect propagation signal",
        header_bytes=4,
        fields={
            "MD Level":  "3b  client layer MD level (higher than server layer)",
            "Version":   "5b=0",
            "Opcode":    "1B  0x21=AIS  0x23=LCK",
            "Flags":     "1B  Period(3b): 4=1s 5=1min  Level(3b): client MD level",
            "TLV Offset":"1B=0x04",
            "End TLV":   "1B=0x00",
            "CAUTION":   "AIS must be sent at client layer level — wrong level = ignored by client MEPs",
        },
        applications="Server-layer fault propagation — suppress client-layer RDI alarms during known outage",
    ),
    "cfm_sl": dict(
        name="Y.1731 SLM/SLR (Synthetic Loss Measurement)",
        transport="ITU-T Y.1731 statistical frame loss measurement",
        header_bytes=4,
        fields={
            "Opcode":    "1B  0x37=SLM  0x38=SLR",
            "Flags":     "1B",
            "Seq Number":"4B",
            "Source MEP ID":"2B",
            "RxFCl":     "4B  received frame count local",
            "TxFCf":     "4B  transmitted frame count far end",
            "RxFCf":     "4B  received frame count far end",
            "CAUTION":   "SLM/SLR interval must match — mismatched periods = incorrect loss ratio calculation",
        },
        applications="Carrier-grade frame loss ratio measurement for SLA reporting",
    ),

    # ── Switch Protocol L4 builders ───────────────────────────────────────────
    "eapol_eap": dict(
        name="EAPOL EAP-Packet (802.1X authentication exchange)",
        transport="EAP over LAN — IEEE 802.1X port NAC",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B  0x02=802.1X-2004  0x03=802.1X-2010",
            "EAPOL Type":    "1B  0x00=EAP-Packet",
            "EAPOL Length":  "2B  EAP data length",
            "EAP Code":      "1B  0x01=Request 0x02=Response 0x03=Success 0x04=Failure",
            "EAP ID":        "1B  request/response correlation ID",
            "EAP Length":    "2B  total EAP message length including Code+ID+Length",
            "EAP Type":      "1B  1=Identity 4=MD5-Challenge 13=EAP-TLS 25=PEAP 43=EAP-FAST 52=EAP-GPSK",
            "EAP Type Data": "variable  method-specific: TLS hello / PEAP tunnel / challenge bytes",
            "CAUTION":       "EAP-ID must match between Request and Response — ID mismatch = auth failure",
        },
        applications="802.1X wired/wireless port authentication — RADIUS EAP tunnel via Access-Request",
    ),
    "eapol_key": dict(
        name="EAPOL-Key (WPA/WPA2 4-way handshake key material)",
        transport="WPA key derivation exchange",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B",
            "EAPOL Type":    "1B  0x03=EAPOL-Key",
            "EAPOL Length":  "2B",
            "Key Descriptor":"1B  0x02=RSN/WPA2 0x01=WPA1",
            "Key Info":      "2B  KeyType(1b)+Install(1b)+ACK(1b)+MIC(1b)+Secure(1b)+Error(1b)+Request(1b)+Encrypted-KeyData(1b)+SMK(1b)",
            "Key Length":    "2B  PTK/GTK length in bytes",
            "Replay Counter":"8B  monotonic — prevents replay of old 4-way messages",
            "Nonce":         "32B  ANonce (AP random) or SNonce (STA random)",
            "EAPOL-Key IV":  "16B  (WPA1 only) key encryption IV",
            "Key RSC":       "8B  RSN receive sequence counter",
            "Key MIC":       "16B  HMAC-SHA1 or AES-CMAC over entire EAPOL frame",
            "Key Data Len":  "2B",
            "Key Data":      "variable  RSN IE or GTK wrapped with KEK",
            "CAUTION":       "Replay Counter must strictly increase — reuse or decrease = 4-way handshake failure",
        },
        applications="WPA2/WPA3 4-way handshake — derives PTK from ANonce+SNonce+PMK",
    ),
    "eapol_ctrl": dict(
        name="EAPOL-Start / EAPOL-Logoff",
        transport="802.1X supplicant control messages",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B",
            "EAPOL Type":    "1B  0x01=EAPOL-Start  0x02=EAPOL-Logoff",
            "EAPOL Length":  "2B  0x0000 (no data)",
            "CAUTION":       "EAPOL-Logoff sent unprotected — rogue logoff possible without MFP (802.11w)",
        },
        applications='EAPOL-Start/Logoff — IEEE 802.1X session initiation and termination control',
    ),
    "lldp_tlv": dict(
        name="LLDP TLV (Type-Length-Value)",
        transport="LLDP TLV chain in LLDPDU",
        header_bytes=2,
        fields={
            "TLV Type":    "7b  0=End 1=ChassisID 2=PortID 3=TTL 4=PortDesc 5=SysName 6=SysDesc 7=SysCap 8=MgmtAddr 127=OrgSpec",
            "TLV Length":  "9b  value field length in bytes",
            "SubType":     "1B  (ChassisID/PortID) 4=MAC 5=NetworkAddr 7=Local",
            "Value":       "variable  TLV-specific content",
            "ChassisID":   "e.g. 6B MAC address if SubType=4",
            "PortID":      "e.g. interface name string if SubType=5",
            "TTL Value":   "2B  seconds until neighbour info expires (0=remove entry)",
            "SysCap":      "2B  Capabilities: bit0=Other bit2=Bridge bit4=Router bit6=Telephone bit8=DOCSIS bit10=StationOnly",
            "Enabled Cap": "2B  subset of SysCap that is enabled",
            "MgmtAddrLen": "1B",
            "MgmtAddrSubType":"1B  1=IPv4 2=IPv6",
            "MgmtAddr":    "4B IPv4 or 16B IPv6",
            "CAUTION":     "TTL=0 immediately removes entry from peer LLDP table — use 0 only for graceful removal",
        },
        applications="LLDP neighbour discovery — topology mapping, PoE negotiation, LLDP-MED",
    ),
    "lldp_orgspec": dict(
        name="LLDP Org-Specific TLV",
        transport="LLDP TLV Type=127 — vendor/standard extensions",
        header_bytes=2,
        fields={
            "TLV Type":  "7b=127",
            "TLV Length":"9b",
            "OUI":       "3B  00:80:C2=IEEE802.1  00:12:0F=IEEE802.3  00:12:BB=TIA-MED",
            "SubType":   "1B  OUI-specific: 802.1/SubType=1=PortVLANID 2=PortProtoVLANID 3=VLANName 4=ProtocolID; 802.3/SubType=1=MacPhy 2=PowerMDI 3=LinkAgg 4=MaxFS",
            "Value":     "variable  SubType-specific",
            "802.3at PoE":"SubType=2 MDIPowerSupport(1B)+MDIPowerPair(1B)+PowerClass(1B)+TypeSource(1B)+Priority(1B)+PDRequested(2B)+PSEAllocated(2B)",
            "CAUTION":   "OUI must match exactly — wrong OUI = TLV ignored by peer; 802.3bt requires 802.3 SubType=2 extended format",
        },
        applications="PoE power negotiation (802.3at/bt) · VLAN info · port protocol · LLDP-MED capabilities",
    ),
    "mrp_attr": dict(
        name="MRP Attribute (MVRP/MMRP attribute declaration)",
        transport="MRP attribute event — VLAN or multicast registration",
        header_bytes=4,
        fields={
            "Protocol ID":    "2B  0x0000=MRP",
            "Attribute Type": "1B  MVRP:0x01=VLAN  MMRP:0x01=ServiceReq 0x02=MAC-VID",
            "Attribute Length":"1B  bytes per attribute value",
            "MRP Event":      "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv (leave)",
            "Number of Values":"1B  packed events per byte",
            "VLAN ID":        "12b  (MVRP) VLAN being registered 1-4094",
            "MAC Address":    "6B  (MMRP) multicast MAC being registered",
            "VID":            "12b  (MMRP MAC-VID) VLAN context",
            "End Mark":       "2B  0x0000",
            "CAUTION":        "Lv event removes registration — accidental Lv = VLAN traffic lost on trunk",
        },
        applications="Dynamic VLAN/multicast registration between 802.1Q switches without manual config",
    ),
    "mrp_pdu": dict(
        name="MRP Ring PDU (IEC 62439-2)",
        transport="MRP ring redundancy control",
        header_bytes=10,
        fields={
            "Version":    "2B  0x0001",
            "Type":       "2B  0x0001=Common 0x0002=Test 0x0003=TopologyChange 0x0004=LinkDown 0x0005=LinkUp",
            "Length":     "2B  data length",
            "Priority":   "2B  MRM priority lower=preferred (0x8000=default)",
            "SA":         "6B  source MAC of MRM",
            "Port Role":  "2B  0x0001=Primary 0x0002=Secondary",
            "Ring State": "2B  0x0000=Open(broken) 0x0001=Closed(healthy)",
            "Interval":   "2B  test frame interval ms (default 10ms)",
            "Transition": "2B  topology change counter",
            "Timestamp":  "4B  millisecond timestamp",
            "CAUTION":    "Two MRMs on same ring = topology oscillation and packet storms — ensure only one MRM",
        },
        applications="Industrial ring redundancy — PROFINET MRP < 200ms failover",
    ),
    "prp_payload": dict(
        name="PRP Redundancy Control Trailer",
        transport="PRP trailer appended to standard Ethernet frame",
        header_bytes=6,
        fields={
            "Sequence Number":"2B  same value on both LAN-A and LAN-B copies",
            "LAN-ID":         "4b  0xA=LAN-A  0xB=LAN-B  (upper nibble of byte)",
            "LSDU Size":      "12b  original frame payload length (LSDU)",
            "PRP Suffix":     "2B  0x88FB — marks frame as PRP-tagged for Supervision",
            "CAUTION":        "Supervision frames (EtherType 0x88FB) must be sent on both LANs — missing on one LAN = incorrect VDAN state",
        },
        applications="Zero-switchover redundancy — IEC 61850 protection relays, process bus, ring-free dual-LAN",
    ),
    "ptp_msg": dict(
        name="PTP Message (IEEE 1588-2008/2019)",
        transport="IEEE 1588 precision time protocol over L2",
        header_bytes=34,
        fields={
            "messageType":     "4b  0=Sync 1=Delay_Req 2=Pdelay_Req 3=Pdelay_Resp 8=Follow_Up 9=Delay_Resp 11=Announce",
            "versionPTP":      "4b  must be 2",
            "messageLength":   "2B  total PDU bytes",
            "domainNumber":    "1B  clock domain 0-127 (0=default)",
            "minorVersionPTP": "1B  0 for 2008, 1 for 2019",
            "flagField":       "2B  twoStepFlag+unicastFlag+alternateMasterFlag+PTP_TIMESCALE+timeTraceable+frequencyTraceable",
            "correctionField": "8B  sub-nanosecond correction in 2^-16 ns units (usually 0)",
            "messageTypeSpecific":"4B",
            "sourcePortIdentity":"10B  clockIdentity(8B=EUI-64)+portNumber(2B)",
            "sequenceId":      "2B  per-messageType counter (wraps 0-65535)",
            "controlField":    "1B  deprecated: 0=Sync 1=Delay_Req 2=Follow_Up 3=Delay_Resp 4=Management 5=others",
            "logMessageInterval":"1B  log2 of interval (-3=0.125s 0=1s 1=2s 7=128s)",
            "originTimestamp": "10B  seconds(6B)+nanoseconds(4B) — Sync/Announce/Delay_Req",
            "utcOffset":       "2B  (Announce) current UTC-TAI offset in seconds",
            "grandmasterPriority1":"1B  (Announce) BMCA priority1 (lower=preferred) default 128",
            "grandmasterPriority2":"1B  (Announce) BMCA priority2 default 128",
            "grandmasterClockQuality":"4B  (Announce) clockClass+clockAccuracy+offsetScaledLogVariance",
            "CAUTION":         "Sync+Follow_Up sequenceId must match — mismatch causes slave to discard Follow_Up and miss sync",
        },
        applications="Sub-µs clock sync: financial trading · telecom (G.8275.2) · industrial (IEC 61588) · AES67 audio",
    ),
    "trill_inner": dict(
        name="TRILL Inner Ethernet Frame",
        transport="Original Ethernet frame inside TRILL encapsulation",
        header_bytes=6,
        fields={
            "Hop Count":   "6b  decremented per RBridge — frame dropped at 0",
            "Egress RB":   "16b  egress RBridge nickname (must be reachable in IS-IS topology)",
            "Ingress RB":  "16b  ingress RBridge nickname (this RBridge's nickname)",
            "Inner Dst":   "6B  original destination MAC (preserved inside TRILL)",
            "Inner Src":   "6B  original source MAC",
            "Inner EtherType":"2B  original EtherType of the encapsulated frame",
            "Payload":     "variable  original frame payload",
            "CAUTION":     "Egress RB nickname 0xFFFF = unknown unicast flood — IS-IS must converge before forwarding",
        },
        applications="TRILL multi-path L2 fabric — data centre Ethernet without STP blocking",
    ),
    "isis_pdu": dict(
        name="IS-IS PDU (for TRILL control plane)",
        transport="IS-IS link-state routing directly over Ethernet",
        header_bytes=3,
        fields={
            "NLPID":       "1B  0x83=IS-IS",
            "Header Length":"1B  fixed header portion length",
            "IS Version":  "1B  must be 1",
            "PDU Type":    "1B  15=L1-Hello 16=L2-Hello 17=P2P-Hello 18=L1-LSP 20=L2-LSP 24=L1-CSNP 25=L2-CSNP",
            "Version":     "1B  must be 1",
            "MaxAreaAddr": "1B  0=3 areas max",
            "System ID":   "6B  RBridge system ID (usually derived from MAC)",
            "TLVs":        "variable  1=AreaAddr 2=ISReach 6=ISNeighbors 22=ExtISReach 135=ExtIPReach 137=Hostname 141=MT-ISReach 228=NicknamePri 229=Nickname 232=VLANsEnabled",
            "Auth TLV":    "optional  TLV type=10 SubType=3 HMAC-SHA256 authentication",
            "CAUTION":     "IS-IS authentication must be configured — unauthenticated IS-IS = rogue RBridge injection",
        },
        applications="TRILL control plane — RBridge hello/LSP exchange for nickname and topology distribution",
    ),
    "avb_stream": dict(
        name="AVB Stream Reservation (FQTSS — 802.1Qav)",
        transport="Credit-based shaper stream descriptor",
        header_bytes=8,
        fields={
            "StreamID":      "8B  Talker MAC(6B)+UniqueID(2B) — globally identifies stream",
            "Priority":      "3b  802.1Q priority class (5=A 4=B for AVB)",
            "MaxIntervalFrames":"2B  max frames per class measurement interval",
            "MaxFrameSize":  "2B  max SDU size including all headers in bytes",
            "CAUTION":       "StreamID must be globally unique — duplicate = stream rejection; UniqueID assigned by talker application",
        },
        applications="AVB/TSN audio/video stream reservation — coordinate shaper across switches",
    ),
    "tsn_gcl": dict(
        name="TSN Gate Control List Entry (IEEE 802.1Qbv)",
        transport="Time-Aware Shaper gate schedule",
        header_bytes=10,
        fields={
            "GateState":    "1B  8-bit field, each bit=gate open/close for queues 0-7 (1=open 0=closed)",
            "TimeInterval": "4B  duration of this GCL entry in nanoseconds",
            "BaseTime":     "10B  PTP-synchronised start time: seconds(6B)+nanoseconds(4B)",
            "CycleTime":    "8B  Numerator(4B)/Denominator(4B) Hz fraction",
            "CycleTimeExt": "4B  extension time to complete current frame at end of cycle",
            "ConfigChange": "1B  applies new GCL atomically — only set when not mid-cycle",
            "CAUTION":      "All switches must be PTP-synchronised to nanosecond accuracy — clock drift = guard band violations and dropped frames",
        },
        applications="Deterministic latency: industrial robot motion · in-vehicle Ethernet (802.1Qbv) · pro AV",
    ),
    "msrp_attr": dict(
        name="MSRP Attribute (Talker-Advertise / Listener)",
        transport="Multiple Stream Registration Protocol attribute",
        header_bytes=4,
        fields={
            "Attr Type":      "1B  0x01=Talker-Advertise 0x02=Talker-Failed 0x03=Listener 0x04=Domain",
            "MRP Event":      "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv",
            "StreamID":       "8B  MAC(6B)+UniqueID(2B)",
            "DataFrameParams":"4B  DestAddr(6B)+VLAN+Prio+RankInterval",
            "Accumulated Latency":"4B  µs  end-to-end latency accumulation",
            "FailureInfo":    "1B+6B (Talker-Failed only) BridgeID+FailureCode",
            "CAUTION":        "Listener must register before data flows — talker-only without listener = bandwidth reserved but unused (wasteful)",
        },
        applications="AVB/TSN stream bandwidth reservation — coordinate talker and listener path",
    ),
    "ecp_vdp": dict(
        name="ECP VDP (VSI Discovery Protocol — IEEE 802.1Qbg)",
        transport="Edge Control Protocol — hypervisor VM port assignment",
        header_bytes=4,
        fields={
            "Subtype":     "2B  0x0001=VDP",
            "Sequence":    "2B  monotonic ACK correlation",
            "Op":          "4b  0=Request 1=ACK",
            "Response":    "4b  0=Success 1=InvalidFormat 2=Busy 3=ResourcesExhausted",
            "VSI Type":    "4B  VSI type identifier (UUID-based)",
            "VSI Type Ver":"1B  VSI type version",
            "VSI ID Format":"1B  1=IPv4 2=IPv6 3=local 4=UUID",
            "VSI ID":      "16B  UUID identifying this VSI instance",
            "Filter Info": "variable  VLAN/Group filter for this VSI",
            "CAUTION":     "VSI ID must be unique per VM instance — duplicate UUID = incorrect port assignment",
        },
        applications="Hypervisor VEPA mode — 802.1BR virtual port assignment for VM NICs",
    ),
    "nsh_payload": dict(
        name="NSH Service Chain Payload",
        transport="Network Service Header — SFC chaining",
        header_bytes=8,
        fields={
            "Ver":          "2b  must be 0",
            "O":            "1b  OAM — frame is OAM not data",
            "TTL":          "6b  decremented per service function — drop at 0",
            "Length":       "6b  header length in 4-byte words",
            "MD-Type":      "4b  1=Fixed-Length(4×32b) 2=Variable-Length(TLVs)",
            "NextProto":    "4b  1=IPv4 2=IPv6 3=Ethernet 4=NSH 5=MPLS",
            "SPI":          "24b  Service Path Identifier — identifies the service chain",
            "SI":           "8b  Service Index — decremented per function hop",
            "Context Headers":"16B (MD-Type=1) 4×32b mandatory context fields",
            "CAUTION":      "TTL must be ≥ number of service functions — TTL=0 at any hop = silent drop with no error",
        },
        applications="SFC: Firewall→IDS→LB→NAT ordered function chaining without topology change",
    ),
    "macsec_payload": dict(
        name="MACSec Encrypted Payload",
        transport="IEEE 802.1AE per-hop Ethernet encryption",
        header_bytes=8,
        fields={
            "TCI":     "1B  V(1b)=0 + ES(1b) + SC(1b) + SCB(1b) + E(1b)=encryption + C(1b)=changed + Ver(2b)=0",
            "AN":      "2b  Association Number 0-3 (identifies active SAK key)",
            "SL":      "6b  Short Length 0=full frame 1-60=short frame actual length",
            "PN":      "4B  Packet Number — must be strictly increasing per SA (replay window check)",
            "SCI":     "8B  Secure Channel ID = Src-MAC(6B)+Port(2B) — only if SC bit=1",
            "Payload": "variable  GCM-AES encrypted original Ethernet payload",
            "ICV":     "16B  GCM-AES authentication tag (integrity check value)",
            "CAUTION": "PN rollover at 0xFFFFFFFF terminates SA — must rekey via MKA (EAPOL-Key) before 0xC0000000 to avoid SA expiry during traffic",
        },
        applications="Data centre inter-switch link encryption · WAN MACsec · 802.1X MACsec session",
    ),
    "hyperscsi_pdu": dict(
        name="HyperSCSI PDU (deprecated)",
        transport="HyperSCSI SCSI command over Ethernet — obsolete",
        header_bytes=4,
        fields={
            "Version":   "1B  0",
            "Type":      "1B  0=Command 1=Data 2=Response 3=Sense",
            "Sequence":  "2B",
            "Initiator": "1B",
            "CDB Len":   "1B",
            "CDB":       "variable  SCSI Command Descriptor Block",
            "Data":      "variable  payload",
            "CAUTION":   "Deprecated — no security, no auth; use iSCSI (TCP port 3260) or FCoE instead",
        },
        applications='HyperSCSI SCSI over Ethernet — deprecated storage protocol (use iSCSI/FCoE)',
    ),
    "iser_pdu": dict(
        name="iSER PDU (iSCSI Extensions for RDMA)",
        transport="iSCSI over RDMA — zero-copy block I/O",
        header_bytes=28,
        fields={
            "Flags":      "1B  W(bit7)=Write-STag-Valid  R(bit6)=Read-STag-Valid",
            "Reserved":   "1B",
            "Write STag": "4B  RDMA Steering Tag for target-to-initiator Write",
            "Write TO":   "8B  Tagged Offset for iSER write",
            "Read STag":  "4B  RDMA Steering Tag for Read",
            "Read TO":    "8B  Tagged Offset for Read",
            "iSCSI BHS":  "48B  standard iSCSI Basic Header Segment (same as iSCSI/TCP)",
            "CAUTION":    "Both STag and TO must be registered via RDMA BIND before use — unregistered STag = remote access violation and QP error",
        },
        applications="High-performance iSCSI — eliminates kernel copy overhead via RDMA zero-copy path",
    ),
    "fcoe_ip": dict(
        name="IP over Fibre Channel (FC-BB-5)",
        transport="IP datagrams encapsulated in FC frames",
        header_bytes=4,
        fields={
            "TYPE":    "1B  0x20=IP-over-FC",
            "IP HDR":  "20B  standard IPv4 header",
            "Payload": "variable  IP payload",
            "CAUTION": "Rarely used — FCoE normally carries FCP SCSI, not raw IP",
        },
        applications='IP over Fibre Channel — IPv4/IPv6 inside FC frames over FCoE (FC-BB-5)',
    ),
    "fip_linkserv": dict(
        name="FIP Link Service (FLOGI/FDISC/LOGO over FIP)",
        transport="FCoE fabric login carried over FIP",
        header_bytes=4,
        fields={
            "Op":         "2B  0x0002=Link-Service",
            "Subcode":    "1B  0x01=FLOGI 0x02=FDISC 0x03=LOGO 0x04=FLOGI-LS_ACC 0x05=FLOGI-LS_RJT",
            "Desc ListLen":"2B",
            "Local MAC":  "6B  ENode MAC address",
            "FC-MAP":     "3B  0x0E:FC:00 default",
            "Switch Name":"8B  FCF WWN (in LS_ACC)",
            "N_Port ID":  "3B  assigned by FCF (in LS_ACC)",
            "CAUTION":    "FLOGI must be sent to FCF-MAC not broadcast — use FIP advertisement MAC",
        },
        applications="FCoE fabric login — derives FPMA (Fabric Provided MAC Address)",
    ),
    "fip_ctrl": dict(
        name="FIP Control (Keep-Alive / Clear-Virtual-Links)",
        transport="FIP session maintenance",
        header_bytes=4,
        fields={
            "Op":       "2B  0x0003=Control",
            "Subcode":  "1B  0x01=Keep-Alive 0x02=Clear-Virtual-Links",
            "Desc Len": "2B",
            "Local MAC":"6B  ENode MAC",
            "CAUTION":  "FKA_ADV_Period default 8s — no keep-alive within 3×period = FCF drops virtual link",
        },
        applications='FCoE FIP control — FC fabric keep-alive and virtual link maintenance for FCoE endpoints',
    ),
    "aoe_macmask": dict(
        name="AoE MAC Mask List (access control)",
        transport="AoE target MAC address ACL",
        header_bytes=8,
        fields={
            "CMD":      "1B  0x02=MAC-Mask-List",
            "MCmd":     "1B  0=Read 1=Edit-ACL",
            "MCount":   "2B  number of directives",
            "Directives":"variable  4B each: Reserved(1B)+Cmd(1B)+MAC(6B) Cmd: 0=NoDirective 1=Add 2=Delete 255=DeleteAll",
            "CAUTION":  "Empty ACL = all MACs allowed — explicitly add allowed MACs before deploying to production",
        },
        applications='AoE MAC mask — access control list configuration for AoE storage device ports',
    ),
    "iscsi_r2t": dict(
        name="iSCSI R2T (Ready to Transfer — write flow control)",
        transport="iSCSI target-driven write pacing",
        header_bytes=48,
        fields={
            "Opcode":       "1B  0x31=R2T",
            "Flags":        "1B  F=Final",
            "DataSegLen":   "3B  0 (no data segment in R2T)",
            "LUN":          "8B",
            "ITT":          "4B  matches initiator command ITT",
            "TTT":          "4B  Target Transfer Tag — must be echoed in Data-Out",
            "StatSN":       "4B  target status sequence number",
            "ExpCmdSN":     "4B",
            "BufferOffset": "4B  byte offset into write buffer for this R2T",
            "DesiredDataLen":"4B  bytes target wants in this Data-Out burst",
            "CAUTION":      "Initiator must not send more than DesiredDataLen bytes — overflow = target abort",
        },
        applications="iSCSI write flow control — target paces write data in bursts",
    ),
    "oui_ext_payload": dict(
        name="OUI-Extended Payload (IEEE 802 0x88B7)",
        transport="Vendor/org-specific payload under registered OUI",
        header_bytes=5,
        fields={
            "OUI":           "3B  IEEE-registered Organisation Unique Identifier",
            "Ext EtherType": "2B  sub-protocol (vendor-defined)",
            "Payload":       "variable  organisation-specific frame content",
            "CAUTION":       "OUI must be your registered IEEE OUI — using another org's OUI violates IEEE 802 policy",
        },
        applications='IEEE 802 OUI Extended payload — organisation-specific protocol data per IEEE 802 §9',
    ),
    "mih_pdu": dict(
        name="MIH PDU (IEEE 802.21 Media Independent Handover)",
        transport="Vertical handover signalling",
        header_bytes=6,
        fields={
            "Version":     "4b  must be 1",
            "AID":         "12b  Action ID — identifies MIH service and operation",
            "OPCode":      "4b  0=Indication 1=Request 2=Response 3=Push",
            "TransactionID":"12b  correlation ID",
            "PayloadLen":  "16b  payload byte count",
            "Payload":     "variable  MIH events/commands/information elements",
            "CAUTION":     "MIH requires pre-configured MIIS server address — missing server = handover decision failure",
        },
        applications="IEEE 802.21 — seamless vertical handover between 802.3/802.11/3GPP/WiMAX",
    ),
    # ── Legacy passthrough handlers (raw/simple) ──────────────────────────────
    "raw_idp":   dict(name="XNS Raw IDP Datagram",        transport="raw passthrough", header_bytes=0, fields={"Data":"variable XNS raw payload"}),
    "raw_ipx":   dict(name="Novell IPX Raw Datagram",     transport="raw passthrough", header_bytes=0, fields={"Data":"variable IPX raw payload"}),
    "netbios":   dict(name="NetBIOS over IPX (type-20)",  transport="broadcast propagation", header_bytes=0, fields={"Data":"NetBIOS datagram payload"}),
    "snmp":      dict(name="SNMP over DDP (AppleTalk)",   transport="SNMP management", header_bytes=0, fields={"Data":"SNMPv1/v2c PDU"}),
    "aurp":      dict(name="AURP (AppleTalk Update Routing)", transport="WAN routing", header_bytes=4, fields={"ConnectionID":"2B","Sequence":"2B","Data":"variable AURP tuples"}),
    "pup_error": dict(name="Xerox PUP Error", transport="error notification", header_bytes=4,
        fields={"Error Code":"2B  error type code","Error Param":"2B  error-specific parameter","Original":"variable  first 22B of offending PUP datagram"},
        applications="PUP Error — Xerox PARC Universal Packet delivery error reporting (1970s historical)"),
    "pup_echo":  dict(name="Xerox PUP Echo/Echo Reply",   transport="reachability test", header_bytes=2, fields={"Type":"2B 130=Request 131=Reply","Data":"variable echoed data"}),
    # ── Additional L4 handlers for new EtherTypes ─────────────────────────────
    "pbb_payload": dict(
        name="PBB Customer Frame (MAC-in-MAC payload)",
        transport="Provider Backbone Bridging inner customer frame",
        header_bytes=14,
        fields={"Inner Dst MAC":"6B customer destination MAC",
                "Inner Src MAC":"6B customer source MAC",
                "Inner EtherType":"2B customer protocol (0x0800=IPv4 etc.)",
                "Customer Payload":"variable original customer Ethernet payload",
                "CAUTION":"I-SID collision causes cross-customer frame delivery — unique I-SID per service mandatory"},
        applications='IEEE 802.1ah PBB — inner customer Ethernet frame inside MAC-in-MAC provider backbone',
    ),
    "avtp_aaf": dict(
        name="AVTP AAF (Audio — IEEE 1722)",
        transport="AVTP Audio Format — professional PCM/AES3",
        header_bytes=24,
        fields={"Format":"1B 0x02=INT16 0x03=INT24 0x04=INT32 0x05=FLOAT32 0x09=AES3",
                "NSR":"4b nominal sample rate 0x03=44.1kHz 0x04=48kHz 0x05=88.2kHz 0x06=96kHz 0x07=192kHz",
                "Channels":"10b number of audio channels 1-1024",
                "Bit Depth":"8b 0=Padded 16=16b 24=24b 32=32b",
                "Evt":"4b 0=normal 1=mute 2=pullup 3=pulldown",
                "SP":"1b sparse timestamp — 1=not every frame has timestamp",
                "Payload":"variable interleaved PCM samples (channels × samples × bytes/sample)",
                "CAUTION":"Channels × BitDepth × SampleRate must fit in Ethernet MTU — use VLAN with QoS for priority"},
        applications="AES67/AVnu/Milan audio networking",
    ),
    "avtp_cvf": dict(
        name="AVTP CVF (Compressed Video — IEEE 1722)",
        transport="AVTP Compressed Video Format — H.264/MJPEG/JPEG2000",
        header_bytes=28,
        fields={"Format":"1B 0=MJpeg 1=H264 2=JPEG2000",
                "Format Subtype":"1B codec-specific",
                "PTD":"1b PTS discontinuity",
                "M":"1b RTP marker (last fragment of frame)",
                "Evt":"4b",
                "H264 Timestamp":"4B (H264) PTP timestamp of video frame",
                "NAL Header":"1B H264 NAL unit type (1=slice 5=IDR 7=SPS 8=PPS)",
                "Payload":"variable NAL unit or JPEG data",
                "CAUTION":"IDR frame (NAL type=5) must precede all P/B frames — missing IDR = decoder error on stream join"},
        applications="Professional video over Ethernet",
    ),
    "avtp_crf": dict(
        name="AVTP CRF (Clock Reference — IEEE 1722)",
        transport="AVTP media clock reference distribution",
        header_bytes=24,
        fields={"Type":"1B 0=User 1=AudioSample 2=VideoFrame 3=VideoLine 4=MachineCycle",
                "Pull":"3b clock multiplier/divisor",
                "Base Freq":"29b base frequency in Hz (e.g. 48000 for audio)",
                "CRF Data Count":"4B number of timestamps in payload",
                "CRF Timestamps":"variable 8B PTP timestamps × count",
                "CAUTION":"Base frequency must match across all listeners — mismatch causes clock drift and AV sync failure"},
        applications='IEEE 1722 CRF — Clock Reference Format stream for AVB/TSN media clock distribution',
    ),
    "avtp_iec61883": dict(
        name="AVTP IEC 61883 (FireWire A/V over AVTP)",
        transport="IEC 61883 audio/video over IEEE 1722",
        header_bytes=24,
        fields={"CIP Qi":"2b 0=IEC61883-1","CIP FN":"2b","CIP QPC":"3b","CIP SPH":"1b",
                "CIP DBC":"1B data block counter","CIP Fmt":"6b 0x10=61883-4(DV) 0x20=61883-6(audio) 0x22=61883-8(MIDI)",
                "CIP FDF":"3B format-dependent field","Payload":"variable A/V data blocks",
                "CAUTION":"DBC must be monotonically increasing — reset causes audio glitch on receiver"},
        applications='IEEE 1722 IEC 61883 — audio/video stream (DV/MPEG-2/PCM audio) over AVB networks',
    ),
    "avtp_ctrl": dict(
        name="AVTP Control Message (IEEE 1722)",
        transport="AVTP control and management",
        header_bytes=24,
        fields={"Control Data Length":"2B","Stream Data Length":"2B",
                "Control Data":"variable AVTP control payload",
                "CAUTION":"Control messages must not use reserved subtypes — reserved subtype = undefined behaviour"},
        applications='IEEE 1722 AVTP Control — non-timed control format for AVB/TSN device management',
    ),
    "bfd_control": dict(
        name="BFD Control Packet (RFC 5880)",
        transport="BFD session control — fast failure detection",
        header_bytes=24,
        fields={"Version":"3b=1","Diag":"5b diagnostic code",
                "Sta":"2b 0=AdminDown 1=Down 2=Init 3=Up",
                "P":"1b Poll","F":"1b Final","C":"1b CtrlPlaneIndependent","A":"1b Auth","D":"1b Demand","M":"1b=0",
                "Detect Mult":"1B timeout multiplier (e.g. 3)",
                "Length":"1B 24 minimum","My Discrim":"4B local discriminator (non-zero)",
                "Your Discrim":"4B peer discriminator (0 during Init)",
                "Desired Min TX Interval":"4B µs desired TX rate (e.g. 50000=50ms)",
                "Required Min RX Interval":"4B µs minimum RX rate",
                "Required Min Echo Interval":"4B µs echo interval (0=no echo)",
                "CAUTION":"Your Discriminator=0 only in Down state — sending 0 in Up state terminates session"},
        applications="Fast link failure detection < 50ms · ECMP/LAG failover · L2VPN path monitoring",
    ),
    "ncsi_cmd": dict(
        name="NC-SI Command/Response",
        transport="NIC sideband management",
        header_bytes=8,
        fields={"MC ID":"1B 0=primary management controller",
                "Hdr Rev":"1B must be 0x01",
                "IID":"1B instance ID for response correlation 0-15",
                "Type":"1B command type (see NC-SI spec)",
                "Channel":"1B NIC channel 0-3",
                "Payload Len":"2B payload byte count",
                "Payload":"variable command-specific data",
                "Checksum":"4B XOR over all previous bytes or 0x00000000",
                "CAUTION":"IID must be unique per outstanding request — reuse causes response routing to wrong request"},
        applications="BMC network passthrough · NIC firmware update · link status monitoring",
    ),
    "gre_inner_eth": dict(
        name="GRE Inner Ethernet Frame",
        transport="Ethernet-in-GRE L2VPN payload",
        header_bytes=14,
        fields={"Inner Dst MAC":"6B destination MAC inside tunnel",
                "Inner Src MAC":"6B source MAC inside tunnel",
                "Inner EtherType":"2B 0x0800=IPv4 etc.",
                "Inner Payload":"variable — original frame payload",
                "CAUTION":"ARP broadcasts inside GRE flood to all tunnel endpoints — use proxy ARP or limit broadcast domains"},
        applications='GRE transparent Ethernet bridging — inner L2 Ethernet frame tunnelled via GRE (RFC 1701)',
    ),
    "gre_inner_fr": dict(
        name="GRE Inner Frame Relay",
        transport="Frame Relay PVC in GRE",
        header_bytes=4,
        fields={"DLCI High":"6b bits 15-10 of DLCI","C/R":"1b","EA0":"1b=0",
                "DLCI Low":"4b bits 9-6","FECN":"1b","BECN":"1b","DE":"1b","EA1":"1b=1",
                "Information":"variable frame relay payload",
                "FCS":"2B CRC-16-CCITT",
                "CAUTION":"DLCI 0 is reserved for LMI signalling — data frames must use DLCI 16-991"},
        applications='GRE Frame Relay encapsulation — Frame Relay frames tunnelled over GRE/IP (RFC 1701)',
    ),
    "gre_ctrl_msg": dict(
        name="GRE Control Message (RFC 8157)",
        transport="GRE tunnel OAM",
        header_bytes=4,
        fields={"Control Type":"2B 0x0001=Keepalive-Req 0x0002=Keepalive-Reply 0x0003=Error 0x0004=BFD-Discrim",
                "Transaction ID":"2B request/response correlation",
                "Error Code":"2B (Error type) — error reason",
                "BFD Discrim":"4B (BFD-Discrim type) — local discriminator",
                "CAUTION":"Keepalive-Req expects Keepalive-Reply within hold timer — missing reply = tunnel teardown"},
        applications='GRE control message — PPTP-compatible keepalive and GRE tunnel management signalling',
    ),
    "vjcomp_pdu": dict(
        name="Van Jacobson Compressed TCP/IP",
        transport="VJ header compression for serial/PPP links",
        header_bytes=1,
        fields={"Type":"1B 0x45=Uncompressed 0x70-0x7F=Compressed",
                "Connection ID":"1B (compressed) — index into compression state table",
                "Delta Flags":"1B change mask indicating which header fields changed",
                "Urgent Ptr":"optional 2B (if changed)","Ack":"optional 2B/4B (if changed)",
                "Seq Num":"optional 4B (if changed)","IP ID Delta":"optional 2B",
                "Checksum":"2B","Data":"variable — TCP payload",
                "CAUTION":"Compression state must be flushed (uncompressed) after any packet loss — desync causes all subsequent packets to fail"},
        applications='Van Jacobson TCP/IP header compression — reduces serial WAN bandwidth usage per RFC 1144',
    ),
    "ppp_lcp": dict(
        name="PPP LCP (Link Control Protocol)",
        transport="PPP link establishment and configuration",
        header_bytes=4,
        fields={"Code":"1B 1=Configure-Req 2=Configure-Ack 3=Configure-Nak 4=Configure-Reject 5=Terminate-Req 6=Terminate-Ack 7=Code-Reject 8=Protocol-Reject 9=Echo-Req 10=Echo-Reply 11=Discard-Req",
                "ID":"1B request/reply correlation",
                "Length":"2B total LCP message length",
                "Options":"variable TLV options: 1=MRU(2B) 3=Auth-Protocol(2B+) 4=Quality-Protocol 5=Magic-Number(4B) 7=Protocol-Field-Compress 8=Addr-Ctrl-Compress",
                "MRU":"2B Maximum Receive Unit (default 1500)",
                "Magic Number":"4B random — detect looped-back links",
                "Auth Protocol":"2B 0xC023=PAP 0xC223=CHAP",
                "CAUTION":"Magic Number collision (both peers same random) indicates looped link — abort and regenerate"},
    ),
    "ppp_auth": dict(
        name="PPP PAP/CHAP Authentication",
        transport="PPP password or challenge authentication",
        header_bytes=4,
        fields={"Code":"1B PAP: 1=Auth-Req 2=Auth-Ack 3=Auth-Nak  CHAP: 1=Challenge 2=Response 3=Success 4=Failure",
                "ID":"1B","Length":"2B",
                "Peer-ID Length":"1B (PAP) username length",
                "Peer-ID":"variable (PAP) username in plaintext",
                "Passwd Length":"1B (PAP) password length",
                "Password":"variable (PAP) password in plaintext",
                "Value Size":"1B (CHAP) challenge/response length",
                "Value":"variable (CHAP) MD5/SHA hash of challenge+password",
                "Name":"variable peer identifier",
                "CAUTION":"PAP sends password in plaintext — use CHAP or EAP-TLS instead; CHAP uses MD5 which is broken for offline attacks"},
    ),
    "gsmp_msg": dict(
        name="GSMP Message",
        transport="General Switch Management Protocol command",
        header_bytes=8,
        fields={"Version":"4b=3","Message Type":"1B","Result":"1B 0=Success 1=Failure 2=Ignored",
                "Code":"1B failure reason","Port Session No":"1B",
                "Transaction ID":"4B",
                "Port":"4B target switch port",
                "Session Number":"4B per-adjacency session",
                "Payload":"variable type-specific data",
                "CAUTION":"No authentication — GSMP must be confined to management VLAN; never expose to untrusted hosts"},
        applications='GSMP switch management — ATM/Frame Relay to Ethernet switch fabric control (RFC 3292)',
    ),
    "mcap_msg": dict(
        name="MCAP Message",
        transport="Multicast channel allocation",
        header_bytes=8,
        fields={"Op":"1B 1=GetReq 2=GetResp 3=Setup 4=Delete",
                "Rpt Count":"1B repetition count",
                "Trans ID":"2B","Channel ID":"2B",
                "Timestamp":"8B 802.11 TSF time for channel start",
                "Duration":"2B channel duration in TUs (×1024µs)",
                "CAUTION":"Timestamp must be coordinated with 802.11 BSS TSF — wrong timestamp causes channel miss"},
        applications='MCAP — IEEE 802.11 Multicast Channel Allocation Protocol for wireless coexistence',
    ),
    "lowpan_iphc": dict(
        name="6LoWPAN IPHC Compressed IPv6",
        transport="IPv6 header compression for low-power wireless",
        header_bytes=2,
        fields={"TF":"2b traffic class compression","NH":"1b next header compression",
                "HLIM":"2b hop limit compression 0=inline 1=1 2=64 3=255",
                "CID":"1b context identifier extension","SAC":"1b source addr compression",
                "SAM":"2b source addr mode 0=inline 1=64b 2=16b 3=from context",
                "M":"1b multicast compression","DAC":"1b destination addr compression",
                "DAM":"2b destination addr mode","Payload":"variable compressed fields",
                "CAUTION":"SAM/DAM context must be provisioned on all nodes — missing context = decompression failure and packet drop"},
        applications='6LoWPAN IPHC — IPv6 header compression for 127-byte IEEE 802.15.4 IoT frames',
    ),
    "lowpan_mesh": dict(
        name="6LoWPAN Mesh Header",
        transport="6LoWPAN multi-hop mesh routing",
        header_bytes=4,
        fields={"V":"1b 1=16b source addr","F":"1b 1=16b dest addr",
                "HopsLeft":"4b remaining hops (0=drop)",
                "Orig Addr":"2B or 8B mesh originator address",
                "Final Addr":"2B or 8B mesh final destination",
                "CAUTION":"HopsLeft must be > diameter of mesh network — too-small value causes premature discard"},
        applications='6LoWPAN mesh addressing — multi-hop routing header for IEEE 802.15.4 mesh networks',
    ),
    "lowpan_frag": dict(
        name="6LoWPAN Fragmentation Header",
        transport="6LoWPAN IPv6 fragmentation",
        header_bytes=4,
        fields={"Type":"5b 0x18=first frag 0x1C=subsequent",
                "Datagram Size":"11b total reassembled datagram bytes",
                "Datagram Tag":"2B identifies fragment group (same across all fragments)",
                "Datagram Offset":"1B (subsequent frags only) byte offset ÷8",
                "Payload":"variable fragment data",
                "CAUTION":"Reassembly timer default 60s — fragment storm causes memory exhaustion in constrained devices"},
        applications='6LoWPAN fragmentation — large IPv6 packet fragmented across multiple 802.15.4 frames',
    ),
    "loopback_test": dict(
        name="Ethernet Loopback Test Pattern",
        transport="IEEE 802.3 loopback for cable qualification",
        header_bytes=4,
        fields={"Function":"2B 0x0001=Reply/Forward 0x0002=Reply-Only",
                "Reply Count":"2B remaining forward count before replying",
                "Test Data":"variable fill pattern for cable stress test (min 60B)",
                "CAUTION":"Loopback frames must not be forwarded to external ports — use dedicated VLAN or dedicated test port"},
    ),
    "frer_payload": dict(
        name="FRER Sequenced Frame Payload",
        transport="IEEE 802.1CB FRER inner payload",
        header_bytes=0,
        fields={"Inner EtherType":"2B original frame type","Payload":"variable original frame data",
                "CAUTION":"Sequence number window must be > max propagation delay difference between paths — narrow window = valid duplicate frames discarded"},
        applications='IEEE 802.1CB FRER — sequence-tagged frame for TSN stream replication and elimination',
    ),
    "ipv4_inner": dict(
        name="Inner IPv4 (inside Q-in-Q tunnel)",
        transport="IPv4 datagram inside Q-in-Q double-tagged frame",
        header_bytes=20,
        fields={"Version+IHL":"1B","DSCP+ECN":"1B","Total Length":"2B",
                "ID":"2B","Flags+FragOffset":"2B","TTL":"1B","Protocol":"1B",
                "Checksum":"2B","Src IP":"4B","Dst IP":"4B","Payload":"variable",
                "CAUTION":"Inner IP TTL still decremented per hop — ensure TTL sufficient for path through provider network"},
    ),
    "ipv6_inner": dict(
        name="Inner IPv6 (inside Q-in-Q tunnel)",
        transport="IPv6 datagram inside Q-in-Q",
        header_bytes=40,
        fields={"Version+TC+Flow":"4B","Payload Len":"2B","Next Header":"1B","Hop Limit":"1B",
                "Src IPv6":"16B","Dst IPv6":"16B","Payload":"variable"},
    ),
    # ── Switch protocol L4 handlers ───────────────────────────────────────────
    "mac_ctrl_pause": dict(
        name="IEEE 802.3x Pause Frame",
        transport="MAC-level symmetric flow control",
        header_bytes=4,
        fields={
            "Opcode":        "2B  0x0001",
            "Pause Quanta":  "2B  0-65535  pause duration × 512 bit-times at link speed  (e.g. 65535 = max pause)",
            "Reserved":      "42B  padding to minimum 64B frame size",
            "CAUTION":       "Pause is symmetric — pauses the ENTIRE link including control traffic; prefer PFC (per-priority) for mixed workloads",
        },
        applications="Flow control on full-duplex Ethernet links — prevent receiver buffer overflow",
    ),
    "mac_ctrl_pfc": dict(
        name="IEEE 802.1Qbb PFC (Priority-based Flow Control)",
        transport="Per-priority flow control for lossless Ethernet",
        header_bytes=20,
        fields={
            "Opcode":           "2B  0x0101",
            "Priority Enable":  "2B  bitmask P0(b0)-P7(b7) — 1=pause this priority class",
            "Quanta P0":        "2B  pause duration for priority 0 × 512 bit-times",
            "Quanta P1":        "2B  priority 1",
            "Quanta P2":        "2B  priority 2",
            "Quanta P3":        "2B  priority 3  (used by FCoE — must be non-zero for lossless SAN)",
            "Quanta P4":        "2B  priority 4",
            "Quanta P5":        "2B  priority 5",
            "Quanta P6":        "2B  priority 6",
            "Quanta P7":        "2B  priority 7  (network control — never pause this in practice)",
            "CAUTION":          "Never pause priority 7 (network control) — LACP/STP/BFD PDUs use high priority; pausing them causes topology reconvergence",
        },
        applications="Lossless Ethernet for FCoE(P3)/RoCE(P3-5)/NVMe-oF — prevents frame drop in storage networks",
    ),
    "mac_ctrl_epon": dict(
        name="EPON MPCP Gate / Report (0x8808 opcode 0x0002/0x0003)",
        transport="Ethernet PON multi-point control",
        header_bytes=8,
        fields={
            "Opcode":       "2B  0x0002=Gate  0x0003=Report",
            "Timestamp":    "4B  MPCP timestamp in 16ns units (OLT clock reference)",
            "Grant Start":  "4B  (Gate) start time for ONU transmission grant",
            "Grant Len":    "2B  (Gate) grant length × 16ns",
            "Grant Count":  "1B  (Gate) number of grants in this PDU (1-4)",
            "Sync Time":    "2B  (Gate) guard band / laser on-time in 16ns units",
            "Report Bitmap":"1B  (Report) bitmask of queue sets being reported",
            "Queue Length": "2B per queue  (Report) bytes pending in each queue",
            "CAUTION":      "MPCP timestamp rollover at 2^32 × 16ns ≈ 68s — OLT and ONU must handle rollover consistently or grants become misaligned",
        },
        applications='IEEE 802.3av MPCP — EPON Multi-Point Control Protocol for OLT-ONU registration and bandwidth',
    ),
    "lacp_actor_partner": dict(
        name="LACP Actor+Partner TLVs (IEEE 802.3ad)",
        transport="Link Aggregation Control Protocol PDU",
        header_bytes=110,
        fields={
            "Subtype":            "1B  0x01",
            "Version":            "1B  0x01",
            "Actor TLV Type":     "1B  0x01",
            "Actor TLV Length":   "1B  0x14",
            "Actor System Priority":"2B  lower=preferred  default 32768",
            "Actor System MAC":   "6B  actor (local) system MAC",
            "Actor Key":          "2B  aggregation key — must match across all ports in LAG",
            "Actor Port Priority":"2B  lower=active vs standby  default 32768",
            "Actor Port Number":  "2B  port identifier",
            "Actor State":        "1B  bits: LACP_Activity(0)+LACP_Timeout(1)+Aggregation(2)+Synchronization(3)+Collecting(4)+Distributing(5)+Defaulted(6)+Expired(7)",
            "Actor Reserved":     "3B  0x000000",
            "Partner TLV Type":   "1B  0x02",
            "Partner TLV Length": "1B  0x14",
            "Partner System Priority":"2B",
            "Partner System MAC": "6B",
            "Partner Key":        "2B",
            "Partner Port Priority":"2B",
            "Partner Port Number":"2B",
            "Partner State":      "1B  same bit layout as Actor State",
            "Partner Reserved":   "3B",
            "Collector TLV":      "1B=0x03  Len=0x10  MaxDelay(2B)+12B-padding",
            "Terminator TLV":     "2B  0x0000  + 50B padding to 128B",
            "CAUTION":            "Actor Key mismatch: ports with different admin keys cannot form LAG even with same MAC/speed — verify 'channel-group N mode active' uses same group N on both ends",
        },
        applications="IEEE 802.3ad / 802.1AX LAG — multi-vendor link aggregation up to 8 active ports",
    ),
    "lacp_marker": dict(
        name="LACP Marker PDU",
        transport="LACP marker for loopback and reorder detection",
        header_bytes=64,
        fields={
            "Subtype":         "1B  0x02",
            "Version":         "1B  0x01",
            "Marker TLV Type": "1B  0x01=MarkerInfo  0x02=MarkerResponse",
            "Marker TLV Len":  "1B  0x16",
            "Requester Port":  "2B  port ID of requestor",
            "Requester System":"6B  system MAC of requestor",
            "Requester Trans": "4B  transaction ID (echoed in Response)",
            "Reserved":        "2B",
            "Terminator TLV":  "2B  0x0000",
            "Padding":         "90B  to 128B total",
            "CAUTION":         "Marker is used to verify all frames from a port have been received before rebalancing — improper implementation causes out-of-order delivery during LAG rebalance",
        },
        applications='LACP Marker PDU — loopback path detection for LAG bundles per IEEE 802.3 Clause 43',
    ),
    "oam_pdu": dict(
        name="Ethernet OAM PDU (IEEE 802.3ah — EFM OAM)",
        transport="First/last mile Ethernet OAM",
        header_bytes=3,
        fields={
            "Subtype":      "1B  0x03",
            "Flags":        "2B  Link-Fault(b0)+Dying-Gasp(b1)+Critical-Event(b2)+Local-Evaluating(b6)+Local-Stable(b7)+Remote-Evaluating(b8)+Remote-Stable(b9)",
            "Code":         "1B  0x00=Info 0x01=EventNotif 0x02=UniqueEventNotif 0x03=LB-Control 0x04=VarRequest 0x05=VarResponse 0xFE=OrgSpecific",
            "TLV chain":    "variable  per-Code payload: Info=Local/Remote OAMPDU; EventNotif=error event TLVs; LB=Disable/Enable loopback",
            "Local Info TLV":"OAM_version(1B)+MaxPDU_size(2B)+Config(1B)+capabilities(2B)+OUI(3B)+Vendor(4B)",
            "Event TLV":    "Type=1=Symbol-Period 2=Frame-Period 3=Frame-Seconds  Timestamp(2B)+Window+Threshold+Errors+Total+RunningTotal+EventTotal",
            "CAUTION":      "Loopback-Enable (Code=0x03 Enable) puts remote OAM client into loopback — all frames forwarded back; accidentally left enabled causes complete link failure for normal traffic",
        },
        applications="DSL/fibre access OAM — link monitoring, loopback testing, event notification to NOC",
    ),
    "ossp_pdu": dict(
        name="OSSP PDU (Organisation Specific Slow Protocol)",
        transport="Vendor-specific extension to slow protocol",
        header_bytes=10,
        fields={
            "Subtype":   "1B  0x0A",
            "OUI":       "3B  organisation OUI (e.g. 0x00-12-0F=IEEE 0x00-00-0C=Cisco)",
            "ITU-T App": "2B  ITU-T application identifier (if OUI=ITU-T)",
            "Payload":   "variable  organisation-specific PDU content",
            "CAUTION":   "OSSP frames not recognised by peer are silently discarded — verify OUI registration before deployment",
        },
        applications='OSSP — Organisation Specific Slow Protocol vendor-defined extension for custom slow-proto PDUs',
    ),
    "cdp_tlv": dict(
        name="CDP TLV (Cisco Discovery Protocol)",
        transport="CDP Type-Length-Value chain",
        header_bytes=4,
        fields={
            "TLV Type":      "2B  see CDP TLV type list in l2_builder",
            "TLV Length":    "2B  total TLV bytes including Type+Length",
            "TLV Value":     "variable  type-specific content",
            "DeviceID":      "hostname string or chassis serial number",
            "Addresses":     "Count(4B) + per-address: Protocol-Type(1B)+Protocol-Length(1B)+Protocol+Address-Length(2B)+Address",
            "Capabilities":  "4B bitmask: 0x01=Router 0x02=TB-Bridge 0x04=SR-Bridge 0x08=Switch 0x10=Host 0x20=IGMP 0x40=Repeater 0x80=Phone 0x100=Remote",
            "PowerAvailable":"4B  milliwatts available (PoE request/offer)",
            "CAUTION":       "CDP contains full device inventory — disable on untrusted ports; enable CDP only on inter-device uplinks",
        },
        applications="Network topology discovery · NMS polling · PoE negotiation · VoIP phone VLAN assignment",
    ),
    "vtp_pdu": dict(
        name="VTP PDU (Cisco VLAN Trunk Protocol)",
        transport="VTP VLAN database synchronisation",
        header_bytes=36,
        fields={
            "VTP Version":     "1B  0x01/0x02/0x03",
            "Code":            "1B  0x01=Summary 0x02=Subset 0x03=Request 0x04=Join",
            "Followers":       "1B  (Summary) Subset-Advertisement count to follow",
            "Domain Length":   "1B  VTP domain name byte count",
            "VTP Domain":      "32B  null-padded  — MUST match to accept advertisements",
            "Config Revision": "4B  higher always wins — increment resets entire VLAN DB",
            "Updater Identity":"4B  IPv4 of last updater",
            "Update Timestamp":"12B  YYMMDDHHMMSS ASCII",
            "MD5 Digest":      "16B  HMAC-MD5(domain+password+payload)  empty if no auth",
            "VLAN Info":       "(Subset) per VLAN: InfoLen+Status+VLANtype+NameLen+ISL-VLAN+MTU+802.10+Name",
            "VTPv3 Features":  "MST(0x0002) VLAN(0x0001) Private(0x0003) domains separate",
            "CAUTION":         "Config Revision attack: a switch with higher revision and same domain name immediately overwrites ALL VLANs on entire VTP domain — use VTPv3 + password or VTP transparent mode",
        },
        applications="Enterprise VLAN provisioning — single point of VLAN config propagated to all switches in domain",
    ),
    "dtp_pdu": dict(
        name="DTP PDU (Cisco Dynamic Trunking Protocol)",
        transport="Cisco auto-trunk negotiation",
        header_bytes=1,
        fields={
            "DTP Version":   "1B  0x01",
            "Domain TLV":    "Type=0x01  Len=4+34B  trunk domain name  (must match for trunking)",
            "Status TLV":    "Type=0x02  Len=4+1B  0x81=Trunk/Desirable 0x83=Trunk/Auto 0x84=Access/On 0x85=Access/Off",
            "Type TLV":      "Type=0x03  Len=4+1B  0x01=ISL 0x02=802.1Q 0x03=Negotiate 0x04=None",
            "Neighbor TLV":  "Type=0x04  Len=4+6B  neighbor MAC address",
            "CAUTION":       "Send DTP Desirable frame to switch port → port forms trunk → VLAN hopping possible; disable: 'switchport mode access' + 'switchport nonegotiate' on ALL access ports",
        },
        applications="Switch uplink auto-configuration — legacy use only; disable on all access/untrusted ports",
    ),
    "stp_bpdu": dict(
        name="STP / PVST+ Configuration BPDU (802.1D / Cisco)",
        transport="Spanning Tree Protocol bridge PDU",
        header_bytes=35,
        fields={
            "Protocol ID":    "2B  0x0000",
            "Version":        "1B  0x00=STP/PVST+",
            "BPDU Type":      "1B  0x00=Configuration  0x80=TCN (Topology Change Notification)",
            "Flags":          "1B  TC(b0)+TCA(b7)  — TCA=Topology Change Acknowledgement",
            "Root BID":       "8B  Priority(2B)+MAC(6B)  — 4b priority + 12b SystemID-Ext(VLAN for PVST+) + 6B MAC",
            "Root Path Cost": "4B  cumulative cost: 100M=19 1G=4 10G=2 100G=1",
            "Bridge BID":     "8B  sending bridge ID (same format as Root BID)",
            "Port ID":        "2B  4b priority(0x80=default) + 12b port number",
            "Message Age":    "2B  1/256-second units  hops×1s from root",
            "Max Age":        "2B  1/256-second units  default 5120(=20s)",
            "Hello Time":     "2B  1/256-second units  default 512(=2s)",
            "Forward Delay":  "2B  1/256-second units  default 3840(=15s)",
            "PVST+ VLAN TLV": "Type=0x00+Len=0x02+VLAN-ID(2B)  — PVST+ proprietary extension",
            "CAUTION":        "Root bridge election: any switch with lower bridge ID becomes root — rogue switch with priority 0 takes root and re-routes all traffic; protect with BPDU Guard + Root Guard",
        },
        applications="Layer 2 loop prevention — all Cisco switches; PVST+ per-VLAN load balancing",
    ),
    "rstp_bpdu": dict(
        name="RSTP / Rapid-PVST+ BPDU (802.1w / Cisco)",
        transport="Rapid Spanning Tree Protocol PDU",
        header_bytes=36,
        fields={
            "Protocol ID":    "2B  0x0000",
            "Version":        "1B  0x02=RSTP  (Rapid-PVST+ also 0x02 with SNAP PID 0x010B)",
            "BPDU Type":      "1B  0x02=RST BPDU",
            "Flags":          "1B  TC(b0)+Proposal(b1)+PortRole(b2-b3)+Learning(b4)+Forwarding(b5)+Agreement(b6)+TCA(b7)",
            "Port Role":      "bits 2-3: 00=Unknown 01=Alternate/Backup 10=Root 11=Designated",
            "Root BID":       "8B",
            "Root Path Cost": "4B",
            "Bridge BID":     "8B",
            "Port ID":        "2B",
            "Message Age":    "2B",
            "Max Age":        "2B",
            "Hello Time":     "2B",
            "Forward Delay":  "2B",
            "Version1 Length":"1B  0x00  (no Version1 info)",
            "PVST+ VLAN TLV": "VLAN-ID(2B) for Rapid-PVST+",
            "CAUTION":        "RSTP Proposal/Agreement handshake: Proposal from Designated port triggers Agreement from Root port — broken if any port does not support RSTP (mixed RSTP/STP = fallback to 30s convergence)",
        },
        applications="Sub-second convergence L2 — standard in all modern networks; Rapid-PVST+ per-VLAN variant",
    ),
    "udld_pdu": dict(
        name="Cisco UDLD PDU",
        transport="Unidirectional Link Detection",
        header_bytes=4,
        fields={
            "Version":         "4b  0x01",
            "Opcode":          "4b  0x01=Probe 0x02=Echo 0x03=Flush",
            "Flags":           "1B  RT(b0)=Recommended-Timeout(7s)  RSY(b1)=Resync",
            "Checksum":        "2B  CRC over entire UDLD PDU",
            "TLV DeviceID":    "Type=0x0001  device+port identifier string",
            "TLV PortID":      "Type=0x0002  sending port interface name",
            "TLV EchoList":    "Type=0x0003  list of neighbor Device+Port IDs heard (echoed back in Echo PDU)",
            "TLV MsgInterval": "Type=0x0004  1B  probe interval 7s(normal) 1s(aggressive)",
            "TLV TimeoutInt":  "Type=0x0005  1B  detection timeout (3× interval by default)",
            "TLV DeviceName":  "Type=0x0006  hostname string",
            "TLV SeqNumber":   "Type=0x0007  4B  monotonic sequence counter",
            "CAUTION":         "UDLD Aggressive mode: port goes err-disabled if no Echo received within timeout — do not use on links with asymmetric delays or protection-switching paths (DWDM)",
        },
        applications="Fibre uplink protection — detect TX-only or RX-only failure on GigE/10G fibre links",
    ),
    "pagp_tlvs": dict(
        name="PAgP TLVs (Cisco Port Aggregation Protocol)",
        transport="Cisco EtherChannel negotiation",
        header_bytes=6,
        fields={
            "SNAP Header":   "5B  0xAAAA03+0x00000C+0x0104",
            "Version":       "1B  0x01",
            "Flags":         "1B  0x00=Info 0x40=Flush",
            "Group Capability":"4B  bitmask of grouping capabilities",
            "Group IfIndex": "4B  interface index for aggregation grouping",
            "Port Name":     "variable  interface name string",
            "Device ID":     "6B  device MAC address",
            "Learn Method":  "1B  0=Src-MAC 1=Any",
            "CAUTION":       "PAgP is Cisco-proprietary — use LACP (IEEE 802.3ad) for multi-vendor LAG; PAgP Auto+Auto = no channel formed (both passive)",
        },
        applications="Cisco EtherChannel formation — same function as LACP but Cisco-only",
    ),
}

# ── Merge all into NON_IP_L4_REGISTRY ─────────────────────────────────────────
NON_IP_L4_REGISTRY.update(STORAGE_L4_REGISTRY)


# ── Industrial / ITS / Building-Automation L4 Registry ────────────────────────
INDUSTRIAL_L4_REGISTRY: dict[str, dict] = {

    # ── WoL handlers ──────────────────────────────────────────────────────────
    "wol_magic": dict(
        name="Wake-on-LAN Magic Packet (no password)",
        transport="Wake-on-LAN (EtherType 0x0842 or UDP port 9 or 7)",
        header_bytes=102,
        fields={
            "Sync Stream":   "6B  0xFF×6 mandatory preamble that identifies magic packet",
            "Target MAC×16": "96B destination MAC address repeated exactly 16 times",
            "Frame total":   "102B minimum Ethernet payload (no password variant)",
            "Dst MAC":       "Broadcast FF:FF:FF:FF:FF:FF or directed subnet broadcast",
            "CAUTION":       "WoL only works when NIC WoL enabled in BIOS and AC power present; blocked by most routers — use subnet-directed broadcast or WoL proxy for cross-subnet",
        },
        applications="Remote power-on of workstations, servers, NAS devices",
    ),
    "wol_secure4": dict(
        name="Wake-on-LAN Magic Packet + 4B SecureOn Password",
        transport="Wake-on-LAN (EtherType 0x0842)",
        header_bytes=106,
        fields={
            "Sync Stream":   "6B  0xFF×6",
            "Target MAC×16": "96B  destination MAC × 16",
            "SecureOn Pwd":  "4B  password — must match NIC SecureOn configuration",
            "Frame total":   "106B payload",
            "CAUTION":       "SecureOn password stored in NIC EEPROM; password sent in cleartext over network",
        },
        applications="Secure remote power-on with NIC-level password protection",
    ),
    "wol_secure6": dict(
        name="Wake-on-LAN Magic Packet + 6B SecureOn Password",
        transport="Wake-on-LAN (EtherType 0x0842)",
        header_bytes=108,
        fields={
            "Sync Stream":   "6B  0xFF×6",
            "Target MAC×16": "96B  destination MAC × 16",
            "SecureOn Pwd":  "6B  6-byte password (often same as MAC address)",
            "Frame total":   "108B payload",
        },
        applications="Secure WoL — 6B password version (most common SecureOn format)",
    ),

    # ── 802.1Q VLAN inner dispatch handlers ───────────────────────────────────
    "ipv4_inner": dict(
        name="IPv4 payload inside 802.1Q VLAN tag",
        transport="IEEE 802.1Q tagged Ethernet",
        header_bytes=20,
        fields={
            "Inner EtherType": "2B  0x0800",
            "IPv4 Header":     "20B+ standard IPv4 header follows",
            "Note":            "Standard IPv4 processing after VLAN tag strip",
        },
        applications="VLAN-tagged IPv4 traffic — most common enterprise/datacenter frame type",
    ),
    "ipv6_inner": dict(
        name="IPv6 payload inside 802.1Q VLAN tag",
        transport="IEEE 802.1Q tagged Ethernet (IEEE 802.1Q + RFC 2460)",
        header_bytes=40,
        fields={
            "Inner EtherType": "2B  0x86DD (IPv6)",
            "Version":         "4b  must be 6",
            "Traffic Class":   "8b  DSCP(6b)+ECN(2b) — differentiated services",
            "Flow Label":      "20b  0=no flow; nonzero = QoS flow identifier",
            "Payload Length":  "2B  bytes after 40B fixed header (extensions + upper-layer)",
            "Next Header":     "1B  protocol: 58=ICMPv6 6=TCP 17=UDP 43=Routing 44=Fragment 51=AH 59=NoNextHdr",
            "Hop Limit":       "1B  TTL equivalent — decremented per hop; 0=discard",
            "Src Address":     "16B  128-bit source IPv6 address",
            "Dst Address":     "16B  128-bit destination IPv6 address",
        },
        applications="VLAN-tagged IPv6 traffic — most common in dual-stack enterprise/datacenter",
    ),
    "arp_inner": dict(
        name="ARP inside 802.1Q VLAN tag (RFC 826)",
        transport="IEEE 802.1Q tagged Ethernet",
        header_bytes=28,
        fields={
            "Inner EtherType":  "2B  0x0806 (ARP)",
            "HTYPE":            "2B  Hardware type: 1=Ethernet",
            "PTYPE":            "2B  Protocol type: 0x0800=IPv4",
            "HLEN":             "1B  Hardware address length: 6 (MAC)",
            "PLEN":             "1B  Protocol address length: 4 (IPv4)",
            "Operation":        "2B  1=ARP-Request  2=ARP-Reply  3=RARP-Request  4=RARP-Reply",
            "Sender HW Addr":   "6B  sender MAC address",
            "Sender Proto Addr":"4B  sender IPv4 address",
            "Target HW Addr":   "6B  target MAC (zeros in request — unknown)",
            "Target Proto Addr":"4B  target IPv4 address (the IP being resolved)",
            "VLAN Note":        "802.1Q tag is outer header; ARP inside operates within VLAN context",
        },
        applications="VLAN-tagged ARP — resolves IP-to-MAC within a VLAN segment",
    ),
    "mpls_inner": dict(
        name="MPLS inside 802.1Q VLAN tag (RFC 3032)",
        transport="IEEE 802.1Q tagged Ethernet",
        header_bytes=4,
        fields={
            "Inner EtherType": "2B  0x8847=MPLS-Unicast  0x8848=MPLS-Multicast",
            "Label":           "20b  label value 0-1048575; reserved: 0=IPv4-Explicit-Null 2=IPv6-Explicit-Null 3=Implicit-Null",
            "TC":              "3b  Traffic Class (formerly EXP): QoS/ECN bits",
            "S":               "1b  Bottom-of-Stack: 1=last label  0=more labels follow",
            "TTL":             "8b  Hop limit — decremented per LSR; 0=drop frame",
            "Additional Labels":"4B per label — stack continues until S=1",
            "VLAN Note":       "802.1Q tag stripped at ingress PE; MPLS label pushed for L3VPN/VPLS/pseudowire",
        },
        applications="Tagged MPLS — carrier VPLS, L3VPN over tagged trunk ports",
    ),
    "qinq_inner": dict(
        name="Q-in-Q double tag inner dispatch",
        transport="IEEE 802.1Q + IEEE 802.1ad stacked tags",
        header_bytes=8,
        fields={
            "Outer S-Tag":     "4B  0x88A8 + PCP+DEI+S-VID",
            "Inner C-Tag":     "4B  0x8100 + PCP+DEI+C-VID",
            "Inner EtherType": "2B  actual payload protocol",
        },
        applications="Metro Ethernet service tunnelling — isolates customer VLANs",
    ),
    "double_tag": dict(
        name="Double VLAN tagging (inner C-Tag)",
        transport="IEEE 802.1Q C-Tag inside Q-in-Q",
        header_bytes=4,
        fields={
            "Inner TPID": "2B  0x8100",
            "PCP":        "3b  inner CoS",
            "DEI":        "1b  drop eligible",
            "C-VID":      "12b customer VLAN ID",
        },
        applications="Customer VLAN within provider VLAN tunnel",
    ),

    # ── BACnet L4 handlers ────────────────────────────────────────────────────
    "bacnet_confirmed": dict(
        name="BACnet Confirmed-Request (PDU type 0)",
        transport="BACnet/Ethernet (ASHRAE 135 Annex H)",
        header_bytes=4,
        fields={
            "PDU Type":       "4b  0x00=Confirmed-Request",
            "SEG":            "1b  segmented message",
            "MOR":            "1b  more follows (segmented)",
            "SA":             "1b  segmented response accepted",
            "Max Segs":       "3b  max segments accepted",
            "Max APDU":       "4b  max APDU accepted: 0=50B 1=128B 2=206B 3=480B 4=1024B 5=1476B",
            "Invoke ID":      "1B  0-255 transaction identifier",
            "Sequence No":    "1B  (segmented only)",
            "Proposed Window":"1B  (segmented only)",
            "Service Choice": "1B  12=ReadProperty 15=WriteProperty 5=SubscribeCOV 14=ReadPropertyMultiple 16=WritePropertyMultiple",
            "Service Request":"variable  object-id + property-id + optional array-index + value",
            "Object ID":      "4B  type(10b)+instance(22b) e.g. 0x00400001=Analog-Input #1",
            "Property ID":    "variable  standard property enumeration",
            "CAUTION":        "InvokeID must be unique per outstanding transaction; timeout causes retransmit — configure BACnet timeout properly for WAN links",
        },
        applications="BACnet device interrogation, property read/write, alarm subscription",
    ),
    "bacnet_unconfirmed": dict(
        name="BACnet Unconfirmed-Request (PDU type 1)",
        transport="BACnet/Ethernet",
        header_bytes=2,
        fields={
            "PDU Type":       "4b  0x10=Unconfirmed-Request",
            "Reserved":       "4b  0",
            "Service Choice": "1B  8=WhoIs 0=IAm 7=WhoHas 1=IHave 2=UnconfirmedCOVNotification 5=TimeSynchronization",
            "Service Data":   "variable  WHO-IS: optional range(low+high instance) IAm: DeviceID+maxAPDU+segmentation+vendorID",
        },
        applications="WHO-IS/I-AM device discovery, COV notifications, time synchronisation",
    ),
    "bacnet_complex_ack": dict(
        name="BACnet Complex-ACK (PDU type 3)",
        transport="BACnet/Ethernet",
        header_bytes=3,
        fields={
            "PDU Type":       "4b  0x30=Complex-ACK",
            "SEG":            "1b  segmented",
            "MOR":            "1b  more follows",
            "Invoke ID":      "1B  matches original Confirmed-Request",
            "Service ACK":    "1B  echo of original service choice",
            "Service Data":   "variable  ReadProperty response: object-id+property-id+value",
        },
        applications="ReadProperty, ReadPropertyMultiple responses with data",
    ),
    "bacnet_simple_ack": dict(
        name="BACnet Simple-ACK (PDU type 2)",
        transport="BACnet/Ethernet",
        header_bytes=2,
        fields={
            "PDU Type":   "4b  0x20=Simple-ACK",
            "Reserved":   "4b  0",
            "Invoke ID":  "1B  transaction identifier",
            "Service ACK":"1B  15=WriteProperty 12=ReadProperty (echo of request)",
        },
        applications="Acknowledgement for WriteProperty and other write commands",
    ),
    "bacnet_error": dict(
        name="BACnet Error (PDU type 5)",
        transport="BACnet/Ethernet",
        header_bytes=3,
        fields={
            "PDU Type":    "4b  0x50=Error",
            "Reserved":    "4b  0",
            "Invoke ID":   "1B",
            "Service":     "1B  service that generated error",
            "Error Class": "variable  DEVICE/OBJECT/PROPERTY/RESOURCES/SECURITY/SERVICES/VT",
            "Error Code":  "variable  specific error code within class",
        },
        applications="Error response to Confirmed-Request services",
    ),
    "bacnet_segment": dict(
        name="BACnet Segment-ACK (PDU type 4)",
        transport="BACnet/Ethernet",
        header_bytes=4,
        fields={
            "PDU Type":      "4b  0x40",
            "NAK":           "1b  negative acknowledgement",
            "SRV":           "1b  server ACK",
            "Invoke ID":     "1B",
            "Sequence No":   "1B  segment being acknowledged",
            "Actual Window": "1B  actual window size granted",
        },
        applications="Flow control for segmented BACnet messages",
    ),
    "bacnet_reject": dict(
        name="BACnet Reject (PDU type 6)",
        transport="BACnet/Ethernet",
        header_bytes=3,
        fields={
            "PDU Type":    "4b  0x60",
            "Reserved":    "4b  0",
            "Invoke ID":   "1B",
            "Reject Reason":"1B  0=OTHER 1=BUFFER_OVERFLOW 2=INCONSISTENT_PARAMETERS 3=INVALID_PARAMETER_DATA 4=INVALID_TAG 5=MISSING_REQUIRED_PARAMETER 6=PARAMETER_OUT_OF_RANGE 7=TOO_MANY_ARGUMENTS 8=UNDEFINED_ENUMERATION 9=UNRECOGNIZED_SERVICE",
        },
        applications="Syntax/parameter rejection of Confirmed-Request",
    ),
    "bacnet_abort": dict(
        name="BACnet Abort (PDU type 7)",
        transport="BACnet/Ethernet",
        header_bytes=3,
        fields={
            "PDU Type":    "4b  0x70",
            "SRV":         "1b  1=server abort 0=client abort",
            "Invoke ID":   "1B",
            "Abort Reason":"1B  0=OTHER 1=BUFFER_OVERFLOW 2=INVALID_APDU 3=PREEMPTED 4=SEGMENTATION_NOT_SUPPORTED",
        },
        applications="Transaction abort — terminates ongoing exchange",
    ),

    # ── PROFINET L4 handlers ──────────────────────────────────────────────────
    "profinet_rt": dict(
        name="PROFINET RT Cyclic IO Data",
        transport="PROFINET RT (EtherType 0x8892)",
        header_bytes=4,
        fields={
            "Frame ID":       "2B  identifies RT class and data set",
            "Cycle Counter":  "2B  32kHz free-running synchronisation counter",
            "DataStatus":     "1B  b6=DataValid b5=ProviderState b3=Redundancy b2=PrimaryAR",
            "TransferStatus": "1B  0x00=OK",
            "IO Data":        "variable  process bytes as per GSD/GSDML slot configuration",
            "IOPS":           "1B per slot  provider status 0x80=GOOD 0x00=BAD",
            "IOCS":           "1B per slot  consumer status 0x80=GOOD 0x00=BAD",
        },
        applications="PLC I/O — cyclic exchange of sensor/actuator data at <1ms cycle time",
    ),
    "profinet_irt": dict(
        name="PROFINET IRT Isochronous Real-Time",
        transport="PROFINET IRT (EtherType 0x8892 Frame ID 0xC000-0xFBFF)",
        header_bytes=4,
        fields={
            "Frame ID":       "2B  0xC000-0xFBFF IRT class frame",
            "Cycle Counter":  "2B  hardware-timestamped cycle counter",
            "DataStatus":     "1B",
            "TransferStatus": "1B  0x00=OK",
            "IO Data":        "variable  synchronised process data",
            "CAUTION":        "IRT requires FPGA-based switching with hardware timestamping; SW switches NOT compatible; jitter must be <1µs",
        },
        applications="Servo drive synchronisation, motion control <0.25ms jitter",
    ),
    "profinet_dcp": dict(
        name="PROFINET DCP — Discovery and Configuration Protocol",
        transport="PROFINET DCP (EtherType 0x8892 Frame ID 0xFF00/0xFF01)",
        header_bytes=10,
        fields={
            "Frame ID":       "2B  0xFF00=DCP-MC-Request 0xFF01=DCP-UC-Response",
            "Service ID":     "1B  5=Identify 4=Set 3=Get 2=Hello",
            "Service Type":   "1B  0=Request 1=Response-Success 5=Response-Error",
            "Xid":            "4B  transaction ID for request/response matching",
            "Response Delay": "2B  ms delay before unicast response (prevent broadcast storm)",
            "Block Length":   "2B  length of option blocks following",
            "── DCP Blocks ──":"repeated: Option(1B)+SubOption(1B)+BlockLength(2B)+BlockData",
            "Option 0x01":    "IP address block: IPAddr(4B)+SubnetMask(4B)+Gateway(4B)",
            "Option 0x02":    "Device properties: NameOfStation / DeviceID / DeviceRole",
            "Option 0x05":    "DHCP: ParameterRequestList",
            "Option 0xFF":    "Control: 0x04=ResetToFactory 0x05=Response",
            "CAUTION":        "DCP Set with factory reset is unprotected by default — use PROFINET security profile to authenticate DCP set operations",
        },
        applications="Device discovery, IP assignment, device naming, factory reset",
    ),
    "profinet_alarm": dict(
        name="PROFINET Alarm PDU",
        transport="PROFINET (EtherType 0x8892 Frame ID 0xFC01/0xFE01)",
        header_bytes=8,
        fields={
            "Frame ID":       "2B  0xFC01=High 0xFE01=Low priority alarm",
            "AlarmType":      "2B  0x0001=Diagnosis 0x0002=Process 0x0004=Pull 0x0005=PlugWrong 0x0006=ControllerDiag",
            "API":            "4B  Application Process Identifier",
            "SlotNumber":     "2B  slot number",
            "SubSlotNumber":  "2B  sub-slot number",
            "ModIdent":       "4B  module identification",
            "SubModIdent":    "4B  sub-module identification",
            "AlarmSpecifier": "2B  SeqNum(11b)+AckSendReq(1b)+Diag(1b)+ARFSU(1b)+Maint(1b)+SubModState(1b)",
            "AlarmPayload":   "variable  diagnosis data or process alarm data",
        },
        applications="Diagnostic alarms, module pull/plug events, process alarms for HMI display",
    ),
    "profinet_frag": dict(
        name="PROFINET Fragmentation PDU",
        transport="PROFINET (EtherType 0x8892 Frame ID 0xFF40)",
        header_bytes=4,
        fields={
            "Frame ID":    "2B  0xFF40",
            "Frag Offset": "2B  byte offset into original PDU",
            "More Frags":  "1b  1=more fragments follow",
            "Data":        "variable  fragment data",
        },
        applications="Large PROFINET PDU fragmentation for non-jumbo networks",
    ),
    "profinet_rsvd": dict(
        name="PROFINET Reserved Frame (Frame ID 0xFC00-0xFCFF)",
        transport="PROFINET (EtherType 0x8892 — IEC 61158)",
        header_bytes=2,
        fields={
            "Frame ID":     "2B  0xFC00-0xFCFF — reserved range per IEC 61158-6-10",
            "Reserved":     "These Frame IDs are reserved by the PROFIBUS+PROFINET International organisation",
            "Action":       "Discard silently on receive — do not process or forward",
            "Range":        "0xFC00-0xFCFF = reserved  0xFD00-0xFEFF = Alarm frames  0xFF00=DCP-MC  0xFF01=DCP-UC",
        },
        applications="Reserved — undefined behaviour; discard on all IEC 61158-compliant devices",
    ),

    # ── EtherCAT L4 handlers ──────────────────────────────────────────────────
    "ethercat_datagram": dict(
        name="EtherCAT Datagram Chain",
        transport="EtherCAT (EtherType 0x88A4)",
        header_bytes=10,
        fields={
            "Cmd":    "1B  NOP=0x00 APRD=0x01 APWR=0x02 APRW=0x03 FPRD=0x04 FPWR=0x05 FPRW=0x06 BRD=0x07 BWR=0x08 BRW=0x09 LRD=0x0A LWR=0x0B LRW=0x0C ARMW=0x0D FRMW=0x0E",
            "IDX":    "1B  transaction index for TX/RX pairing (0x00-0xFF)",
            "ADP":    "2B  auto-increment position (APRD/APWR) or fixed address (FPRD/FPWR)",
            "ADO":    "2B  register/memory offset within slave",
            "Length": "11b datagram data byte count",
            "R":      "3b  reserved",
            "M":      "1b  1=more datagrams chained after this one",
            "IRQ":    "2B  interrupt flags from slaves",
            "Data":   "variable  process data (written by master, read/modified by slaves)",
            "WKC":    "2B  Working Counter — incremented by each slave that matches address",
            "APRD":   "Auto-increment Physical Read — reads from slave at position ADP+ADO",
            "FPRD":   "Fixed Physical Read — reads from slave with address ADP at offset ADO",
            "LRW":    "Logical Read-Write — slaves XOR-merge data at logical address",
            "CAUTION":"WKC mismatch means wrong slave count; check topology and addressing",
        },
        applications="Servo drive I/O, distributed clocks synchronisation, CoE/FoE/SoE mailbox gateway",
    ),
    "ethercat_nv": dict(
        name="EtherCAT Network Variables",
        transport="EtherCAT (type=4)",
        header_bytes=4,
        fields={
            "Type":    "3b  4=Network Variables",
            "Length":  "11b total payload",
            "NV Data": "variable  network variable payload",
        },
        applications="EtherCAT network variable broadcast between masters",
    ),
    "ethercat_mbx": dict(
        name="EtherCAT Mailbox Gateway",
        transport="EtherCAT (type=5)",
        header_bytes=6,
        fields={
            "Type":        "3b  5=Mailbox Gateway",
            "Length":      "11b",
            "MbxAddress":  "2B  mailbox target address",
            "MbxType":     "4b  0x03=CoE 0x04=FoE 0x05=SoE 0x0F=VoE",
            "MbxData":     "variable  CoE/FoE/SoE message content",
        },
        applications="CoE (CANopen over EtherCAT) SDO, FoE (File over EtherCAT) firmware update",
    ),

    # ── POWERLINK L4 handlers ─────────────────────────────────────────────────
    "powerlink_soc": dict(
        name="POWERLINK Start-of-Cycle",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=10,
        fields={
            "Message Type":    "1B  0x01",
            "Dst Node ID":     "1B  0xFF broadcast",
            "Src Node ID":     "1B  0x00 or MN address",
            "SoC Flags":       "1B  b4=MC(Multiplexed Cycle) b3=PS(Prescaled Slot)",
            "NetTime":         "8B  Absolute network time (optional) — UTC ns since epoch",
            "BeginSyncOffset": "4B  sync window start offset from SoC (ns)",
            "CAUTION":         "MN must transmit SoC within ±50ns of cycle start for tight sync; missing SoC triggers CN NMT_CS_PRE_OPERATIONAL_2",
        },
        applications="Cycle synchronisation — all CNs reset their local timers on SoC receipt",
    ),
    "powerlink_preq": dict(
        name="POWERLINK Poll Request",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=12,
        fields={
            "Message Type":  "1B  0x03",
            "Dst Node ID":   "1B  target CN address (0x01-0xEF)",
            "Src Node ID":   "1B  0x00 or MN address",
            "Flags":         "1B  b4=MS(Multiplexed Slot) b3=EA(Exception Acknowledge) b2=RD(Ready)",
            "PDO Version":   "1B  PDO mapping version",
            "Reserved":      "1B",
            "Size":          "2B  PDO data byte count",
            "PDO Data":      "variable  output process data for this CN",
        },
        applications="Cyclic output data from MN to individual CN",
    ),
    "powerlink_pres": dict(
        name="POWERLINK Poll Response",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=12,
        fields={
            "Message Type":  "1B  0x04",
            "Dst Node ID":   "1B  0xFF broadcast (PRes is multicast)",
            "Src Node ID":   "1B  responding CN address",
            "Flags":         "1B  b4=MS b3=EA(Exception ACK) b2=RD(Ready) b1=ER(Error)",
            "NMT Status":    "1B  CN NMT state",
            "PDO Version":   "1B",
            "Size":          "2B  PDO data byte count",
            "PDO Data":      "variable  input process data from CN",
        },
        applications="Cyclic input data from CN — broadcast so all nodes receive each CN's data",
    ),
    "powerlink_soa": dict(
        name="POWERLINK Start-of-Asynchronous",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=10,
        fields={
            "Message Type":   "1B  0x05",
            "Dst Node ID":    "1B  0xFF broadcast",
            "Src Node ID":    "1B  MN address",
            "SoA Flags":      "1B",
            "AnodeID":        "1B  node granted async slot (0=no grant 0xFF=MN async slot)",
            "ServiceID":      "1B  service type for granted node",
            "SyncControl":    "1B",
            "DestMACAddress": "6B  optional directed multicast for async NMT",
        },
        applications="Opens async window — grants one node permission to transmit acyclic data",
    ),
    "powerlink_asnd": dict(
        name="POWERLINK Async Send",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=6,
        fields={
            "Message Type":    "1B  0x06",
            "Dst Node ID":     "1B  target or 0xFF broadcast",
            "Src Node ID":     "1B  sender",
            "ServiceID":       "1B  0x00=KeepAlive 0x01=IdentResponse 0x02=StatusResponse 0x0D=NMT_Request 0x06=NMT_Command",
            "ServiceData":     "variable  NMT/SDO/IdentResp/StatusResp payload",
            "SDO Sequence Hdr":"4B  SendSeqNum(6b)+SendCon(2b)+RecvSeqNum(6b)+RecvCon(2b)",
            "SDO Command":     "1B  0x40=InitDownload 0x60=InitUpload 0x41=DownloadSegment 0x00=DownloadResponse",
        },
        applications="NMT state machine commands, SDO parameter access, device identification",
    ),
    "powerlink_amni": dict(
        name="POWERLINK Active MN Indication",
        transport="Ethernet POWERLINK (EtherType 0x88AB)",
        header_bytes=6,
        fields={
            "Message Type": "1B  0x07",
            "Dst Node ID":  "1B  0xFF broadcast",
            "Src Node ID":  "1B  active MN address",
            "Flags":        "1B",
            "Reserved":     "2B",
        },
        applications="Redundant MN announces it is taking over as active Managing Node",
    ),

    # ── IEC 61850 L4 handlers ─────────────────────────────────────────────────
    "goose_pdu": dict(
        name="IEC 61850-8-1 GOOSE PDU (ASN.1 BER)",
        transport="GOOSE (EtherType 0x88B8)",
        header_bytes=16,
        fields={
            "Tag":               "1B  0x61=GOOSE PDU context tag",
            "Length":            "variable BER length encoding",
            "goID [0]":          "VisibleString  unique GOOSE stream identifier",
            "datSet [1]":        "VisibleString  dataset reference IED/LN$GO$CBname",
            "stNum [4]":         "Uint32  state number — incremented on data change",
            "sqNum [5]":         "Uint32  sequence number — incremented each retransmission",
            "timeAllowedToLive [6]":"Uint32  ms — maximum inter-frame gap before considered lost",
            "t [2]":             "UtcTime 8B — event timestamp (IEEE 1588 PTP UTC)",
            "test [10]":         "Boolean  TRUE=do not act on this trip signal (test mode)",
            "confRev [11]":      "Uint32  config revision — discard if mismatch with IED config",
            "ndsCom [12]":       "Boolean  needs commissioning",
            "numDatSetEntries [13]":"Uint32  count of allData values",
            "allData [14]":      "SEQUENCE OF Data  trip/close/position/quality values as MMS types",
            "Retransmit timing": "T0→T1→T2→T3→Tmax (typical 1ms→4ms→8ms→2000ms→2000ms)",
            "CAUTION":           "test=TRUE blocks relay operation — must check in IED logic; confRev mismatch must discard ALL goose from that stream; no auth = add IEC 62351-6 HMAC in Reserved fields",
        },
        applications="Protection relay tripping, circuit breaker control, busbar differential protection",
    ),
    "gsse_pdu": dict(
        name="IEC 61850-8-1 GSSE PDU (deprecated)",
        transport="GOOSE (EtherType 0x88B8 APPID 0x4000-0x7FFF)",
        header_bytes=12,
        fields={
            "APPID":    "2B  0x4000-0x7FFF GSSE range",
            "Length":   "2B",
            "Reserved1":"2B",
            "Reserved2":"2B",
            "PDU":      "variable  ASN.1 BER GSSE PDU (deprecated in IEC 61850-8-1 Ed2)",
            "CAUTION":  "GSSE deprecated in IEC 61850 edition 2 — use GOOSE for all new installations",
        },
        applications="Legacy generic state event (replaced by GOOSE in Edition 2)",
    ),
    "gse_enter": dict(
        name="GSE Enter-Group Management",
        transport="GSE Management (EtherType 0x88B9)",
        header_bytes=12,
        fields={
            "Management Type": "1B  0x01=Enter-Group",
            "MaxTime":         "2B  max retransmission interval ms",
            "MinTime":         "2B  min retransmission interval ms",
            "DatSet":          "VisibleString  dataset reference to subscribe",
        },
        applications="Subscribe device to GOOSE/GSSE multicast group",
    ),
    "gse_leave": dict(
        name="GSE Leave-Group Management (IEC 61850-8-1)",
        transport="GSE Management (EtherType 0x88B9 — IEC 61850-8-1)",
        header_bytes=6,
        fields={
            "Management Type": "1B  0x02=Leave-Group — unsubscribe from GOOSE/GSSE multicast",
            "MaxTime":         "2B  was maximum retransmission time (ms) — may be 0 in Leave",
            "MinTime":         "2B  was minimum retransmission time (ms) — may be 0 in Leave",
            "DatSet":          "VisibleString  dataset reference to unsubscribe from",
            "Effect":          "Removes this IED from the multicast group for the specified dataset",
        },
        applications="Unsubscribe IED from GOOSE/GSSE multicast — sent when IED goes offline or reconfigured",
    ),
    "gse_getref": dict(
        name="GSE GetGoReference (IEC 61850-8-1)",
        transport="GSE Management (EtherType 0x88B9 — IEC 61850-8-1)",
        header_bytes=6,
        fields={
            "Management Type": "1B  0x03=GetGoReference",
            "MaxTime":         "2B  maximum retransmission time (ms)",
            "MinTime":         "2B  minimum retransmission time (ms)",
            "DatSet":          "VisibleString  GOOSE stream identifier to query",
            "Response":        "Returns the full goID reference path for the specified dataset",
        },
        applications="Query GOOSE stream reference path — used during IED commissioning",
    ),
    "gse_getdsr": dict(
        name="GSE GetGSSEDataSetReference (IEC 61850-8-1 — legacy)",
        transport="GSE Management (EtherType 0x88B9 — IEC 61850-8-1)",
        header_bytes=6,
        fields={
            "Management Type": "1B  0x04=GetGSSEDataSetReference",
            "MaxTime":         "2B  maximum retransmission time (ms)",
            "MinTime":         "2B  minimum retransmission time (ms)",
            "goID":            "VisibleString  GSSE stream identifier to query",
            "Note":            "GSSE (Generic Substation State Event) deprecated in IEC 61850 Edition 2 — use GOOSE",
        },
        applications="Query GSSE dataset reference — legacy IED interoperability only",
    ),
    "gse_getall": dict(
        name="GSE GetAllData (IEC 61850-8-1)",
        transport="GSE Management (EtherType 0x88B9 — IEC 61850-8-1)",
        header_bytes=5,
        fields={
            "Management Type": "1B  0x05=GetAllData",
            "MaxTime":         "2B  maximum retransmission period (ms)",
            "MinTime":         "2B  minimum retransmission period (ms)",
            "Response Data":   "variable  all current GOOSE/GSSE data values as MMS-encoded dataset",
            "Use Case":        "Initial sync after network join — retrieves current state without waiting for next event",
        },
        applications="Retrieve all current GOOSE/GSSE values on IED startup or reconnect",
    ),
    "sv_pdu": dict(
        name="IEC 61850-9-2 Sampled Values ASDU",
        transport="Sampled Values (EtherType 0x88BA)",
        header_bytes=16,
        fields={
            "Tag":         "1B  0x60=savPdu",
            "noASDU":      "Uint8  number of ASDUs in this PDU (1-255; typically 1 or 4)",
            "seqASDU":     "SEQUENCE OF ASDU — one per sample:",
            "svID":        "VisibleString  stream identifier e.g. IED1/MU0$SV$SMV1",
            "datSet":      "VisibleString  optional dataset reference",
            "smpCnt":      "Uint16  sample counter 0..smpRate-1 (wraps)",
            "confRev":     "Uint32  configuration revision",
            "smpSynch":    "Uint8  0=unsynced 1=local-clock 2=global-IEEE1588",
            "smpRate":     "Uint16  samples/second (4000 or 12800 typical)",
            "Dataset":     "variable  INT32+quality(4B) per channel per ASDU",
            "Channel":     "Each: instantaneous value(INT32 = 1mA or 10mV LSB) + quality(4B)",
            "Quality":     "4B: Validity(2b)+Overflow(1b)+OutOfRange(1b)+BadReference(1b)+Oscillatory(1b)+Failure(1b)+OldData(1b)+Inconsistent(1b)+Inaccurate(1b)+Source(1b)+Test(1b)+OperatorBlocked(1b)+Reserved(4b)+DeriveTime(1b)+MeasurementSource(1b)",
            "CAUTION":     "smpSynch≠2 may cause relay rejection; confRev mismatch discards all samples; 80-ASDU multi-PDU requires correct VLAN QoS markings",
        },
        applications="Merging unit data streams — current/voltage samples for differential protection",
    ),

    # ── SERCOS III L4 handlers ─────────────────────────────────────────────────
    "sercos3_hp": dict(
        name="SERCOS III Hot-Plug Telegram",
        transport="SERCOS III (EtherType 0x88CD)",
        header_bytes=8,
        fields={
            "Frame Type":  "1B  0x01",
            "Slave Addr":  "2B  inserting/removing slave address",
            "HP Step":     "1B  hot-plug phase 0-4",
            "HP Field":    "2B  HP status/control",
            "Data":        "variable  HP phase-dependent data",
        },
        applications="Hot-plug device insertion and removal without stopping ring operation",
    ),
    "sercos3_cp": dict(
        name="SERCOS III Cycle Packet",
        transport="SERCOS III (EtherType 0x88CD)",
        header_bytes=6,
        fields={
            "Frame Type":       "1B  0x11",
            "Slave Address":    "2B  0xFFFF=broadcast",
            "Telegram Length":  "2B  payload byte count",
            "Service Channel":  "2B  IDN parameter channel",
            "Data":             "variable  cyclic AT or MDT data for all slaves",
        },
        applications="Standard cyclic operation — carries all slave AT/MDT data",
    ),
    "sercos3_at": dict(
        name="SERCOS III Amplifier Telegram (AT)",
        transport="SERCOS III (EtherType 0x88CD)",
        header_bytes=8,
        fields={
            "Frame Type":      "1B  0x02",
            "Slave Address":   "2B  originating slave",
            "Telegram Length": "2B",
            "Service Channel": "2B  IDN service channel response",
            "Actual Position": "4B  INT32 actual position (feedback to master)",
            "Actual Velocity": "4B  INT32 actual velocity",
            "Status Word":     "2B  drive status bits",
            "Data":            "variable  additional configured feedback parameters",
        },
        applications="Servo drive feedback — actual position, velocity, torque, error status",
    ),
    "sercos3_mdt": dict(
        name="SERCOS III Master Data Telegram (MDT)",
        transport="SERCOS III (EtherType 0x88CD)",
        header_bytes=8,
        fields={
            "Frame Type":       "1B  0x12",
            "Slave Address":    "2B  target slave (0xFFFF=all)",
            "Telegram Length":  "2B",
            "Service Channel":  "2B  IDN service channel command",
            "Target Position":  "4B  INT32 setpoint position",
            "Target Velocity":  "4B  INT32 velocity feedforward",
            "Control Word":     "2B  drive control bits",
            "Data":             "variable  additional configured command parameters",
        },
        applications="Servo drive setpoints — target position, velocity, torque command from CNC",
    ),

    # ── WSMP/V2X L4 handlers ──────────────────────────────────────────────────
    "wsmp_bsm": dict(
        name="WSMP Basic Safety Message (SAE J2735)",
        transport="WSMP (EtherType 0x88DC PSID 0x20)",
        header_bytes=4,
        fields={
            "PSID":        "variable  0x20",
            "WSM Length":  "2B  payload byte count",
            "msgID":       "2B  0x0014=BasicSafetyMessage",
            "blob1":       "variable  Temporary(4B)+msgCnt(1B)+id(4B)+lat(4B)+long(4B)+elev(2B)+accuracy(4B)+speed(2B)+heading(2B)+accelSet4Way(7B)+brakes(2B)+size(3B)",
            "lat":         "4B  1/10 µdeg signed N>0 S<0 (±900000000)",
            "long":        "4B  1/10 µdeg signed E>0 W<0 (±1800000000)",
            "elev":        "2B  0.1m resolution 0xF001=Unknown",
            "speed":       "2B  0.02m/s resolution 8191=unavail",
            "heading":     "2B  0.0125deg 0-35999 (0=North CW)",
            "CAUTION":     "BSM transmitted 10/s at 23dBm DSRC 5.9GHz; IEEE 1609.2 security is optional per SAE J2945 but required for US NHTSA V2V mandate",
        },
        applications="Cooperative collision avoidance, intersection assistance, blind spot warning",
    ),
    "wsmp_spat": dict(
        name="WSMP Signal Phase and Timing (SAE J2735)",
        transport="WSMP (EtherType 0x88DC PSID 0x7E)",
        header_bytes=4,
        fields={
            "PSID":           "variable  0x7E",
            "WSM Length":     "2B",
            "msgID":          "2B  0x0013=SPAT",
            "intersectionID": "4B  regional+intersection identifier",
            "Status":         "2B  intersection status flags",
            "timeStamp":      "2B  optional minute-of-year",
            "movementList":   "variable  per-movement: phaseState+timing(minEndTime+maxEndTime) per signal phase",
            "CAUTION":        "SPAT must arrive within 150ms to be usable for signal phase prediction; IEEE 1609.2 signing adds ~15ms latency",
        },
        applications="Green-light speed advisory, red-light violation warning, automated stopping",
    ),
    "wsmp_map": dict(
        name="WSMP MAP Intersection Geometry (SAE J2735)",
        transport="WSMP (EtherType 0x88DC PSID 0x80)",
        header_bytes=4,
        fields={
            "PSID":          "variable  0x80",
            "WSM Length":    "2B",
            "msgID":         "2B  0x0012=MapData",
            "layerID":       "1B  optional layer number",
            "intersections": "variable  per intersection: refPoint+laneSet+approachList",
            "refPoint":      "lat+long+elev of reference point (stop bar or center)",
            "laneSet":       "lanes with width, nodes, attributes, allowed maneuvers",
        },
        applications="Intersection geometry for path prediction, lane-level SPAT matching",
    ),
    "wsmp_tim": dict(
        name="WSMP Traveller Information Message (SAE J2735)",
        transport="WSMP (EtherType 0x88DC PSID 0x8002)",
        header_bytes=4,
        fields={
            "PSID":        "variable  0x8002",
            "WSM Length":  "2B",
            "msgID":       "2B  0x001F=TravelerInformation",
            "packetID":    "9B  unique message identifier",
            "urlB":        "optional  URL for supplemental info",
            "dataFrames":  "variable  segments(ITIS codes)+anchor(lat+long)+content(speed/work-zone/weather)",
            "ITIS codes":  "standard incident/advisory codes — 0x0001=ACCIDENT 0x011A=WORKZONE",
        },
        applications="Road hazard warnings, work zone alerts, speed restrictions, weather advisories",
    ),
    "wsmp_cert": dict(
        name="WSMP IEEE 1609.2 Certificate/Security",
        transport="WSMP (EtherType 0x88DC PSID 0x8003)",
        header_bytes=4,
        fields={
            "PSID":            "variable  0x8003",
            "WSM Length":      "2B",
            "Protocol Version":"1B  3=IEEE 1609.2-2016",
            "Content Type":    "1B  0x80=signedData 0x84=certificate 0x85=certificateRequest",
            "HashAlgo":        "1B  0=SHA-256 1=SHA-384",
            "Signature":       "64B or 96B  ECDSA-P256 or ECDSA-P384 signature",
            "Certificate":     "variable  explicit or implicit certificate chain",
        },
        applications="V2X security credential exchange, certificate revocation list distribution",
    ),
    "wsmp_pdm": dict(
        name="WSMP Probe Data Management (SAE J2735)",
        transport="WSMP (EtherType 0x88DC PSID 0x8007)",
        header_bytes=4,
        fields={
            "PSID":        "variable  0x8007",
            "WSM Length":  "2B",
            "msgID":       "2B  0x0025=ProbeDataManagement",
            "sample":      "variable  speed+heading+lat+long+elevation+timestamp per waypoint",
        },
        applications="Vehicle trajectory probe data collection for traffic management",
    ),

    # ── GeoNetworking L4 handlers ─────────────────────────────────────────────
    "geonet_beacon": dict(
        name="GeoNetworking BEACON",
        transport="GeoNetworking (EtherType 0x8947 HT=1)",
        header_bytes=28,
        fields={
            "Basic Header":  "4B  Version+NH+Reserved+Lifetime+RHL",
            "Common Header": "8B  NH+HT=1+HST=0+TC+Flags+PL=0+MHL+Reserved",
            "Source PV":     "16B  GN-Address(8B)+TST(4B)+Lat(4B)+Long(4B)+Speed(2B)+Heading(2B)+Altitude(2B)+AccuracyFlags(1B)",
            "GN-Address":    "8B  M(1b)+ST(5b)+Reserved(10b)+Country(10b)+MACaddr(48b)",
            "Timestamp":     "4B  TAI ms since 2004-01-01 (GN timestamp)",
            "CAUTION":       "BEACON carries no data payload (PL=0); used for position table building only; do not route CAM over BEACON — use SHB or TSB",
        },
        applications="Neighbour position table building — received by all nearby ITS-G5 stations",
    ),
    "geonet_guc": dict(
        name="GeoNetworking GUC — Geo Unicast",
        transport="GeoNetworking (EtherType 0x8947 HT=2)",
        header_bytes=44,
        fields={
            "Basic Header":   "4B",
            "Common Header":  "8B  HT=2 (GUC)",
            "Source PV":      "16B  sender long position vector",
            "Destination":    "8B  destination GN-Address",
            "SN":             "2B  sequence number for duplicate detection",
            "Reserved":       "2B",
            "BTP Payload":    "variable  BTP-A/B + application data",
        },
        applications="Point-to-point ITS message delivery (eCall, pre-crash notification)",
    ),
    "geonet_gbc": dict(
        name="GeoNetworking GBC — Geo Broadcast",
        transport="GeoNetworking (EtherType 0x8947 HT=4)",
        header_bytes=48,
        fields={
            "Basic Header":   "4B",
            "Common Header":  "8B  HT=4 (GBC)",
            "Source PV":      "16B",
            "SN":             "2B  sequence number",
            "Reserved":       "2B",
            "GeoArea":        "20B  CenterLat+CenterLong+DistA+DistB+Angle+Reserved",
            "BTP Payload":    "variable  DENM/SPAT/MAP/TIM application data",
            "DistA/DistB":    "semi-axes of ellipse or rectangle in metres",
        },
        applications="DENM hazard alerts, SPAT/MAP, road works warnings in geographic area",
    ),
    "geonet_gac": dict(
        name="GeoNetworking GAC — Geo Area Anycast",
        transport="GeoNetworking (EtherType 0x8947 HT=3)",
        header_bytes=48,
        fields={
            "Basic Header":   "4B",
            "Common Header":  "8B  HT=3 (GAC)",
            "Source PV":      "16B",
            "SN":             "2B",
            "Reserved":       "2B",
            "GeoArea":        "20B  target area geometry",
            "BTP Payload":    "variable",
        },
        applications="Delivery to at least one node inside geographic area (anycast semantics)",
    ),
    "geonet_tsb": dict(
        name="GeoNetworking TSB — Topological Scoped Broadcast",
        transport="GeoNetworking (EtherType 0x8947 HT=5)",
        header_bytes=36,
        fields={
            "Basic Header":   "4B",
            "Common Header":  "8B  HT=5 (TSB) MHL limits hop scope",
            "SN":             "2B  sequence number",
            "Reserved":       "2B",
            "Source PV":      "16B",
            "BTP Payload":    "variable  CAM (Cooperative Awareness Message) typically",
            "MHL":            "1B in Common Header — max hops (1-255)",
        },
        applications="CAM (vehicle position/speed/heading) broadcast to neighbours within N hops",
    ),
    "geonet_ls": dict(
        name="GeoNetworking Location Service",
        transport="GeoNetworking (EtherType 0x8947 HT=6)",
        header_bytes=36,
        fields={
            "Basic Header":   "4B",
            "Common Header":  "8B  HT=6 (LS)",
            "SN":             "2B",
            "Reserved":       "2B",
            "Source PV":      "16B",
            "Request":        "8B  GN-Address of station being located",
            "LS Type":        "HST field: 0=LS-Request 1=LS-Reply",
        },
        applications="Resolve GN-Address to position when not in local neighbour table",
    ),
    "geonet_beacon": dict(  # intentional duplicate key update — use geonet_beacon_pdu key
        name="GeoNetworking BEACON (position update)",
        transport="GeoNetworking (EtherType 0x8947 HT=1)",
        header_bytes=28,
        fields={
            "Basic Header":  "4B",
            "Common Header": "8B  HT=1 PL=0",
            "Source PV":     "16B  long position vector",
        },
        applications="Periodic neighbour position table update — no payload",
    ),

    # ── Loopback (already referenced) ────────────────────────────────────────
    "loopback_test": dict(
        name="Ethernet Loopback Test (EtherType 0x9000)",
        transport="Configuration Testing Protocol — IEEE 802.3 Clause 57",
        header_bytes=4,
        fields={
            "Function":    "2B  1=Reply/Forward 2=Reply-Only",
            "Reply Count": "2B  number of replies expected",
            "Data":        "variable  loop-back test payload",
        },
        applications="Physical layer loop-back testing, cable verification, switch port diagnostics",
    ),

    # ── Thin L4 expansions ────────────────────────────────────────────────────
    "xns_echo": dict(
        name="XNS Echo Protocol (IDP type 2)",
        transport="XNS IDP (EtherType 0x0600)",
        header_bytes=4,
        fields={
            "Operation":   "2B  1=Echo Request 2=Echo Reply",
            "Sequence":    "2B  echo sequence number for request/reply matching",
            "Data":        "variable  echo payload (round-trip unmodified)",
            "CAUTION":     "XNS legacy — encountered only in very old Xerox or early Apple networks",
        },
        applications="XNS network reachability testing — analogous to ICMP echo",
    ),
    "netbios_ipx": dict(
        name="NetBIOS over IPX (Type-20 propagation)",
        transport="Novell IPX (EtherType 0x8137/0x0000 type 0x14)",
        header_bytes=4,
        fields={
            "Packet Type":    "1B  0x14=NetBIOS propagation (type-20)",
            "NBSS":           "variable  NetBIOS Session Service data",
            "Propagation":    "4B  cumulative routing bits for loop prevention (14 routers max)",
            "Routing Bitmap": "16B  bit per router to prevent infinite propagation",
            "CAUTION":        "IPX/NetBIOS type-20 propagation was a known security issue — disable on all modern networks; Novell deprecated NetBIOS over IPX in favour of NetBIOS over TCP/IP",
        },
        applications="Legacy Windows NT file/printer sharing discovery over IPX networks",
    ),
    "aep": dict(
        name="AppleTalk AEP — Echo Protocol (DDP type 4)",
        transport="AppleTalk DDP (EtherType 0x809B)",
        header_bytes=2,
        fields={
            "Function":   "1B  1=Echo Request 2=Echo Reply",
            "User Bytes": "variable  echo payload data (returned unmodified in reply)",
            "DDP Socket": "4=Echo socket (source and destination)",
            "CAUTION":    "AppleTalk deprecated — macOS 10.6 removed ATP/AEP support; only encountered on pre-2009 AppleTalk networks",
        },
        applications="AppleTalk node reachability testing — similar to ICMP ping for AppleTalk",
    ),
    "raw_idp": dict(
        name="XNS Raw IDP Datagram",
        transport="XNS IDP (EtherType 0x0600)",
        header_bytes=30,
        fields={
            "Checksum":    "2B  IDP checksum 0xFFFF=no checksum",
            "Length":      "2B  total IDP packet length including header",
            "Transport":   "1B  0=RIP 1=Echo 2=Error 4=PEX 5=SPP 12=NetBIOS",
            "Dest Net":    "4B  destination XNS network number",
            "Dest Host":   "6B  destination 48-bit host address",
            "Dest Socket": "2B  destination socket number",
            "Src Net":     "4B  source XNS network number",
            "Src Host":    "6B  source host address",
            "Src Socket":  "2B  source socket number",
            "Data":        "variable  IDP payload up to 546B",
            "CAUTION":     "XNS obsolete since mid-1990s; only in museum networks and some legacy Xerox equipment",
        },
        applications="XNS internetwork datagram delivery — predecessor to UDP/IP",
    ),
    "raw_ipx": dict(
        name="Novell IPX Raw Datagram",
        transport="Novell IPX (EtherType 0x8137 or 802.3 raw)",
        header_bytes=30,
        fields={
            "Checksum":    "2B  0xFFFF=no checksum (IPX never checksums in practice)",
            "Length":      "2B  total IPX packet length",
            "Hop Count":   "1B  router hops traversed (max 15; 16=unreachable)",
            "Packet Type": "1B  0=RIP 1=Echo 2=Error 4=PEX 5=SPX 17=NCP 20=NetBIOS-Propagation",
            "Dest Net":    "4B  destination IPX network number (0=local)",
            "Dest Node":   "6B  destination MAC address",
            "Dest Socket": "2B  0x0451=NCP 0x0452=SAP 0x0453=RIP 0x0455=NetBIOS 0x0456=Diagnostics",
            "Src Net":     "4B  source network",
            "Src Node":    "6B  source MAC",
            "Src Socket":  "2B  source socket",
            "Data":        "variable  IPX payload",
            "CAUTION":     "IPX RIP uses hop count not bandwidth — routes may be sub-optimal; SAP broadcasts every 60s flood the network at scale",
        },
        applications="Legacy Novell NetWare file/print services, NCP, SPX connections",
    ),
    "netbios": dict(
        name="NetBIOS over IPX Type-20 (name service)",
        transport="Novell IPX type 0x14",
        header_bytes=44,
        fields={
            "Packet Type":    "1B  0x14",
            "NetBIOS Type":   "1B  0x00=AddName 0x01=AddGroupName 0x02=DeleteName 0x08=Datagram 0x0A=Name Query",
            "Name":           "16B  NetBIOS name (padded to 16B with 0x20; byte 16=name type)",
            "Type Suffix":    "1B  00=Workstation 03=Messenger 20=FileServer 1C=DomainController",
            "Propagation":    "4B  IPX-type-20 routing bits",
            "Routing Bitmap": "16B  prevents infinite broadcast loops",
            "CAUTION":        "NetBIOS over IPX completely superseded by NetBIOS over TCP/IP (RFC 1001/1002); disable type-20 propagation on all routers",
        },
        applications="Legacy Windows NT/9x network browser and file share discovery over IPX",
    ),
    "snmp": dict(
        name="SNMP over AppleTalk DDP (socket 8)",
        transport="AppleTalk DDP (EtherType 0x809B DDP type 8 / socket 8)",
        header_bytes=6,
        fields={
            "SNMP Version":  "integer  0=v1 1=v2c 3=v3",
            "Community":     "OctetString  community string (cleartext password)",
            "PDU Type":      "1B  0=GetRequest 1=GetNextRequest 2=GetResponse 3=SetRequest 4=Trap 5=GetBulk 6=InformRequest 7=SNMPv2Trap",
            "Request ID":    "integer  request/response correlation",
            "Error Status":  "integer  0=noError 1=tooBig 2=noSuchName 3=badValue 4=readOnly 5=genErr",
            "Error Index":   "integer  identifies failing varbind",
            "VarBindList":   "SEQUENCE OF VarBind — OID + value pairs",
            "CAUTION":       "SNMPv1/v2c community string is cleartext — use SNMPv3 with auth+priv (AES-128+SHA-256) for all management; AppleTalk SNMP is extremely rare — normally SNMP over UDP/IP",
        },
        applications="Network management over legacy AppleTalk networks — extremely rare",
    ),
    "pup_echo": dict(
        name="Xerox PUP Echo Protocol",
        transport="Xerox PUP (EtherType 0x0200 type 12)",
        header_bytes=20,
        fields={
            "PUP Length":   "2B  total PUP byte count including header",
            "PUP Transport":"1B  hop count + checksum control",
            "PUP Type":     "1B  12=PUP Echo Request 13=PUP Echo Reply",
            "PUP ID":       "4B  transaction identifier (sequence + timestamp)",
            "Dest Port":    "10B  {network(4B)+host(6B)+socket(4B)} destination PUP address",
            "Src Port":     "10B  source PUP address",
            "Data":         "variable  echo payload",
            "CAUTION":      "PUP (PARC Universal Packet) is the 1970s Xerox PARC precursor to UDP/IP — only in museum networks",
        },
        applications="PUP network reachability test — historical Xerox PARC protocol",
    ),
}

NON_IP_L4_REGISTRY.update(INDUSTRIAL_L4_REGISTRY)

# ── TDLS / FBT L4 handlers (IEEE 802.11r/z EtherType 0x890D) ─────────────────
TDLS_L4_REGISTRY: dict[str, dict] = {

    "tdls_setup": dict(
        name="IEEE 802.11z TDLS — Tunneled Direct Link Setup",
        transport="TDLS (EtherType 0x890D Payload-Type=1)",
        header_bytes=3,
        fields={
            "Payload Type":    "1B  1=TDLS",
            "Category":        "1B  12=TDLS (IEEE 802.11 action category)",
            "Action Code":     "1B  0=Setup-Request 1=Setup-Response 2=Setup-Confirm 3=Teardown 4=Peer-Traffic-Indication 5=Channel-Switch-Request 6=Channel-Switch-Response 7=Peer-Traffic-Response",
            "Dialog Token":    "1B  request/response correlation (0=unsolicited)",
            "Status Code":     "2B  Setup-Resp/Confirm: 0=Success 25=Request-Declined 37=Failure",
            "Capability Info": "2B  IEEE 802.11 capability information",
            "Supported Rates": "variable  supported rate information element",
            "RSNIE":           "variable  RSN IE for PTK/GTK negotiation (AES-CCMP required)",
            "FTIE":            "variable  Fast Transition IE with MIC, ANonce, SNonce",
            "Link Identifier": "18B  BSSID(6B)+Initiator-STA(6B)+Responder-STA(6B)",
            "Timeout Interval":"5B  IE type(1B)+length(1B)+interval-type(1B)+value(4B)",
            "Teardown Reason": "2B  (Teardown only) 0=Unspecified 1=QoS 3=Inactivity 26=TDLS-Teardown",
            "CAUTION":         "TDLS bypasses AP for direct STA-to-STA path — AP must have TDLS-permitted policy; PTK derived via 4-way handshake using RSNIE; missing AP approval = association failure",
        },
        applications="802.11 direct STA-to-STA link for high-bandwidth local streaming, gaming, file transfer",
    ),

    "fbt_action": dict(
        name="IEEE 802.11r Fast BSS Transition Action",
        transport="FBT (EtherType 0x890D Payload-Type=2)",
        header_bytes=3,
        fields={
            "Payload Type":  "1B  2=Fast-BSS-Transition",
            "Category":      "1B  6=Fast-BSS-Transition (IEEE 802.11 action category)",
            "Action Code":   "1B  1=FT-Request 2=FT-Response 3=FT-Confirm 4=FT-Ack",
            "STA Address":   "6B  station MAC address",
            "Target AP":     "6B  target AP MAC address",
            "Status Code":   "2B  FT-Response: 0=Success 37=Failure 4=Rejected",
            "FT IE":         "variable  Fast Transition IE: MIC(16B)+ANonce(32B)+SNonce(32B)+R0KH-ID+R1KH-ID",
            "RSNIE":         "variable  RSN IE including PMK-R0 and PMK-R1 SA identifiers",
            "Timeout IE":    "variable  re-association deadline",
            "RIC":           "variable  Resource Information Container (QoS reservation)",
            "CAUTION":       "FBT requires 802.11r-capable AP and STA; pre-authentication via DS (over-DS) uses EtherType 0x890D; over-air FBT uses normal 802.11 management frames; R0KH/R1KH key hierarchy must be pre-configured across AP cluster",
        },
        applications="802.11r fast roaming — sub-50ms handoff for voice/video over Wi-Fi, enterprise mobility",
    ),
}

NON_IP_L4_REGISTRY.update(TDLS_L4_REGISTRY)

# ── Supplemental L4 Registry — fills all type_map gaps ────────────────────────
SUPPLEMENTAL_L4_REGISTRY: dict[str, dict] = {

    # ── PPPoE handlers — RFC 2516 ─────────────────────────────────────────────
    "pppoe_padi": dict(
        name="PPPoE PADI — Active Discovery Initiation (RFC 2516)",
        transport="PPPoE Discovery (EtherType 0x8863 CODE=0x09)",
        header_bytes=6,
        fields={
            "VER+TYPE":    "1B  0x11 (version=1, type=1 — always 0x11 per RFC 2516)",
            "CODE":        "1B  0x09 = PADI",
            "Session-ID":  "2B  0x0000 — MUST be zero in PADI",
            "Length":      "2B  total tag payload length",
            "Service-Name Tag":"4B+  Type=0x0101 + Length(2B) + ServiceName(variable); empty=any service",
            "Host-Uniq Tag":   "optional  Type=0x0103 + Length + 32B random nonce (for matching PADO to PADI)",
            "Relay-Session-ID":"optional  Type=0x0110 — for L2TP relay",
            "Dst MAC":     "Broadcast FF:FF:FF:FF:FF:FF — sent to all ACs on segment",
            "CAUTION":     "PADI is broadcast — one AC per session; if multiple ACs respond, client selects by AC-Name or service; replay attacks possible without Host-Uniq",
        },
        applications="Client initiates PPPoE session discovery — broadcast finds all PPPoE ACs",
    ),

    "pppoe_pado": dict(
        name="PPPoE PADO — Active Discovery Offer (RFC 2516)",
        transport="PPPoE Discovery (EtherType 0x8863 CODE=0x07)",
        header_bytes=6,
        fields={
            "VER+TYPE":    "1B  0x11",
            "CODE":        "1B  0x07 = PADO",
            "Session-ID":  "2B  0x0000 — still zero, no session yet",
            "Length":      "2B  tag payload length",
            "AC-Name Tag": "4B+  Type=0x0102 + Length + AccessConcentratorName (must not be empty)",
            "Service-Name Tag":"4B+  Type=0x0101 + Length + offered service name",
            "AC-Cookie Tag":   "optional  Type=0x0104 + Length + cookie (replay protection)",
            "Host-Uniq Tag":   "copy of Host-Uniq from PADI — correlates PADO to original PADI",
            "Dst MAC":     "Unicast to client MAC from PADI",
            "CAUTION":     "AC must include AC-Name; client should validate Host-Uniq to prevent spoofed PADOs from rogue ACs",
        },
        applications="AC responds to PADI with service offer — client selects AC and sends PADR",
    ),

    "pppoe_padr": dict(
        name="PPPoE PADR — Active Discovery Request (RFC 2516)",
        transport="PPPoE Discovery (EtherType 0x8863 CODE=0x19)",
        header_bytes=6,
        fields={
            "VER+TYPE":    "1B  0x11",
            "CODE":        "1B  0x19 = PADR",
            "Session-ID":  "2B  0x0000",
            "Length":      "2B",
            "Service-Name Tag":"4B+  specific service name from chosen PADO",
            "Host-Uniq Tag":   "optional  same nonce as original PADI",
            "AC-Cookie Tag":   "must echo AC-Cookie from PADO (if AC sent one)",
            "Dst MAC":     "Unicast to selected AC MAC address",
            "CAUTION":     "Must echo AC-Cookie if received in PADO — prevents session hijacking; if no cookie, session is unauthenticated at L2",
        },
        applications="Client unicasts to selected AC requesting dedicated PPP session",
    ),

    "pppoe_pads": dict(
        name="PPPoE PADS — Session Confirmation (RFC 2516)",
        transport="PPPoE Discovery (EtherType 0x8863 CODE=0x65)",
        header_bytes=6,
        fields={
            "VER+TYPE":    "1B  0x11",
            "CODE":        "1B  0x65 = PADS",
            "Session-ID":  "2B  non-zero — AC assigns unique session ID (1-65534)",
            "Length":      "2B",
            "Service-Name Tag":"4B+  confirms service name granted",
            "Host-Uniq Tag":   "echoed from PADR",
            "Error Tag":   "optional  Type=0x0201 if service not available — CODE becomes error indicator",
            "Session established": "After PADS, switch to 0x8864 with this Session-ID",
            "CAUTION":     "Session-ID must be unique per client MAC; Session-ID 0x0000 is reserved; AC must track active sessions",
        },
        applications="AC grants PPP session — client now sends PPP frames on 0x8864 with Session-ID",
    ),

    "pppoe_padt": dict(
        name="PPPoE PADT — Active Discovery Terminate (RFC 2516)",
        transport="PPPoE Discovery (EtherType 0x8863 CODE=0xA7)",
        header_bytes=6,
        fields={
            "VER+TYPE":    "1B  0x11",
            "CODE":        "1B  0xA7 = PADT",
            "Session-ID":  "2B  session being terminated (must match active session)",
            "Length":      "2B",
            "Generic-Error Tag":"optional  Type=0x0203 + error description string",
            "Dst MAC":     "Unicast to peer (client terminates → AC MAC; AC terminates → client MAC)",
            "CAUTION":     "Either end may send PADT; both must immediately stop sending session frames; no PADT acknowledgement — best-effort delivery",
        },
        applications="Terminate PPPoE session — sent on timeout, LCP terminate, or admin disconnect",
    ),

    "pppoe_session": dict(
        name="PPPoE Session Data (RFC 2516)",
        transport="PPPoE Session (EtherType 0x8864 CODE=0x00)",
        header_bytes=8,
        fields={
            "VER+TYPE":    "1B  0x11",
            "CODE":        "1B  0x00 = session data (always zero in session stage)",
            "Session-ID":  "2B  session handle from PADS (non-zero)",
            "Length":      "2B  PPP payload length (not including PPPoE 6B header)",
            "PPP Protocol":"2B  0x0021=IPv4 0x0057=IPv6 0x8021=IPCP 0x8057=IPv6CP 0xC021=LCP 0xC023=PAP 0xC223=CHAP",
            "PPP Data":    "variable  PPP protocol data",
            "CAUTION":     "Session-ID must match active session; PPP LCP must complete before IPCP; MRU negotiated in LCP — default 1492 (Ethernet 1500 minus 8B PPPoE header)",
        },
        applications="PPP frame exchange over established PPPoE session — carries IPv4/IPv6/LCP/NCP",
    ),

    # ── PPP sub-handlers ──────────────────────────────────────────────────────
    "ppp_ipv4": dict(
        name="IPv4 over PPP (RFC 1332)",
        transport="PPP (Protocol 0x0021)",
        header_bytes=20,
        fields={
            "PPP Protocol": "2B  0x0021",
            "IPv4 Header":  "20B+ standard IPv4 datagram",
            "Note":         "IPv4 over PPP — same as EtherType 0x0800 IPv4 but wrapped in PPP/PPPoE",
        },
        applications="Primary data carrying protocol for PPPoE broadband connections",
    ),

    "ppp_ipv6": dict(
        name="IPv6 over PPP (RFC 5072)",
        transport="PPP (Protocol 0x0057)",
        header_bytes=40,
        fields={
            "PPP Protocol":  "2B  0x0057 = IPv6",
            "Version":       "4b  must be 6",
            "Traffic Class": "8b  DSCP(6b)+ECN(2b)",
            "Flow Label":    "20b  0=no flow or QoS flow identifier",
            "Payload Length":"2B  bytes after 40B fixed header",
            "Next Header":   "1B  58=ICMPv6 6=TCP 17=UDP 43=Routing 44=Fragment",
            "Hop Limit":     "1B  TTL equivalent — decremented per hop",
            "Src Address":   "16B  source IPv6 address",
            "Dst Address":   "16B  destination IPv6 address",
            "IPv6CP":        "IPv6 Control Protocol (0x8057) must negotiate Interface-Identifier before data flows",
        },
        applications="IPv6 data over PPPoE broadband — requires IPv6CP negotiation first",
    ),

    "ppp_lcp": dict(
        name="PPP LCP — Link Control Protocol (RFC 1661)",
        transport="PPP (Protocol 0xC021)",
        header_bytes=4,
        fields={
            "Code":         "1B  1=Configure-Req 2=Configure-Ack 3=Configure-Nak 4=Configure-Reject 5=Terminate-Req 6=Terminate-Ack 7=Code-Reject 8=Protocol-Reject 9=Echo-Req 10=Echo-Reply 11=Discard-Req",
            "Identifier":   "1B  request/response correlation",
            "Length":       "2B  total LCP packet length",
            "Options":      "variable  Type(1B)+Length(1B)+Data: 1=MRU 3=Auth-Protocol 4=Quality-Protocol 5=Magic-Number 7=PFC 8=ACFC",
            "MRU Option":   "Type=1 Length=4 MRU(2B) — max receive unit (default 1500; PPPoE typically 1492)",
            "Auth Option":  "Type=3 Length=5 Protocol(2B)+Data: 0xC023=PAP 0xC223=CHAP+algorithm",
            "Magic-Number": "Type=5 Length=6 Magic(4B) — loopback detection",
            "CAUTION":      "LCP must complete before any NCP; MRU mismatch = fragmentation or drops; Magic-Number collision = loopback detected",
        },
        applications="Establish, configure, test, and terminate PPP links",
    ),

    "ppp_auth": dict(
        name="PPP Authentication (PAP/CHAP — RFC 1334/1994)",
        transport="PPP (Protocol 0xC023=PAP or 0xC223=CHAP)",
        header_bytes=4,
        fields={
            "Code":         "1B  PAP: 1=Authenticate-Req 2=Authenticate-Ack 3=Authenticate-Nak | CHAP: 1=Challenge 2=Response 3=Success 4=Failure",
            "Identifier":   "1B  request/response correlation",
            "Length":       "2B  total packet length",
            "PAP Peer-ID":  "1B length + Peer-ID string — sent in cleartext (PAP)",
            "PAP Password": "1B length + Password string — sent in cleartext (PAP)",
            "CHAP Value-Size":"1B  length of challenge/response value (16B for MD5)",
            "CHAP Value":   "16B  challenge (from AC) or MD5(id+secret+challenge) response",
            "CHAP Name":    "variable  authenticating peer name",
            "CAUTION":      "PAP sends credentials in cleartext — never use on untrusted links; CHAP uses MD5 which is weak — prefer EAP-TLS or MSCHAPv2 for modern deployments",
        },
        applications="PPPoE authentication — PAP for legacy, CHAP for basic security",
    ),

    "ppp_ncp": dict(
        name="PPP NCP — Network Control Protocol (RFC 1332/5072)",
        transport="PPP (Protocol 0x8021=IPCP or 0x8057=IPv6CP)",
        header_bytes=4,
        fields={
            "Code":         "1B  1=Configure-Req 2=Configure-Ack 3=Configure-Nak 4=Configure-Reject",
            "Identifier":   "1B  correlation",
            "Length":       "2B",
            "IPCP Options": "variable  Type(1B)+Length(1B)+Data: 3=IP-Address 129=Primary-DNS 131=Secondary-DNS",
            "IP-Address":   "Type=3 Length=6 IP(4B) — client requests or receives IP address",
            "DNS Options":  "Type=129/131 Length=6 DNS-IP(4B) — primary and secondary DNS servers",
            "IPv6CP Options":"Interface-Identifier Type=1 Length=10 Interface-ID(8B)",
            "CAUTION":      "IP-Address option 3 — client sends 0.0.0.0 requesting assignment; AC responds with assigned IP in Configure-Ack; DNS delivered via IPCP options 129/131",
        },
        applications="Negotiate IP address/DNS assignment over PPPoE broadband",
    ),

    "ppp_mpls": dict(
        name="MPLS over PPP (RFC 3032)",
        transport="PPP (Protocol 0x0281=unicast or 0x0283=multicast)",
        header_bytes=4,
        fields={
            "PPP Protocol": "2B  0x0281=MPLS-unicast  0x0283=MPLS-multicast",
            "Label":        "20b  MPLS label",
            "TC":           "3b  traffic class",
            "S":            "1b  bottom of stack",
            "TTL":          "8b  hop limit",
        },
        applications="MPLS label switching over PPPoE — carrier L3VPN over DSL/cable",
    ),

    "ppp_lqr": dict(
        name="PPP Link Quality Report (RFC 1989)",
        transport="PPP (Protocol 0xC025)",
        header_bytes=48,
        fields={
            "Magic-Number":    "4B  matches LCP-negotiated magic number",
            "LastOutLQRs":     "4B  count of LQRs sent on last link",
            "LastOutPackets":  "4B  last period total packets transmitted",
            "LastOutOctets":   "4B  last period total octets transmitted",
            "PeerInLQRs":      "4B  peer's received LQR count",
            "PeerInPackets":   "4B  peer's total received packets",
            "PeerInDiscards":  "4B  peer's received discards",
            "PeerInErrors":    "4B  peer's receive errors",
            "PeerInOctets":    "4B  peer's received octets",
            "PeerOutLQRs":     "4B  peer's transmitted LQR count",
            "PeerOutPackets":  "4B  peer's transmitted packets",
            "PeerOutOctets":   "4B  peer's transmitted octets",
        },
        applications="PPP link quality monitoring — triggers LCP renegotiation or link teardown on poor quality",
    ),

    # ── EAPOL handlers — IEEE 802.1X-2020 ────────────────────────────────────
    "eapol_asf": dict(
        name="EAPOL-Encapsulated-ASF-Alert (IEEE 802.1X §11.12)",
        transport="EAPOL (EtherType 0x888E Type=4)",
        header_bytes=4,
        fields={
            "EAPOL Type":  "1B  0x04",
            "Length":      "2B  ASF-RMCP payload length",
            "ASF-RMCP":    "variable  Alert Standard Format / Remote Management and Control Protocol alert",
            "Alert Type":  "alerts from platform management hardware (IPMI-style over LAN)",
            "CAUTION":     "ASF-RMCP carries unauthenticated management alerts; use 802.1X port-auth before processing ASF alerts",
        },
        applications="Platform management alerts from BMC/IPMI over 802.1X authenticated port",
    ),

    "eapol_mka": dict(
        name="EAPOL-MKA — MACsec Key Agreement (IEEE 802.1X-2020 §11.11)",
        transport="EAPOL (EtherType 0x888E Type=5)",
        header_bytes=4,
        fields={
            "EAPOL Type":   "1B  0x05",
            "Length":       "2B  MKPDU length",
            "MKA Version":  "1B  MACsec Key Agreement Protocol version",
            "Body Length":  "2B  total MKPDU body length",
            "Basic Parameter Set":"20B  SCI(8B)+KeyServerPriority(1B)+MACsecCapability(2b)+Latest-SAK-Wrapped(16B)+...",
            "SCI":          "8B  Secure Channel Identifier = Src MAC(6B) + Port(2B)",
            "CAK":          "not transmitted — Connectivity Association Key pre-shared or derived from EAP",
            "SAK":          "Session-specific key wrapped in CAK and distributed by elected Key Server",
            "TLVs":         "variable  Live-Peer-List, Potential-Peer-List, SAK-Use, Distributed-SAK, Announcement",
            "CAUTION":      "MKA elected Key Server distributes SAKs; KS election based on priority+SCI; key server failure stops MACsec if peers cannot agree",
        },
        applications="Negotiate and distribute MACsec SAKs between 802.1X authenticated peers — enables hop-by-hop encryption",
    ),

    "eapol_announce": dict(
        name="EAPOL-Announcement (IEEE 802.1X-2020 §11.13)",
        transport="EAPOL (EtherType 0x888E Types 6/7/9/10/11)",
        header_bytes=4,
        fields={
            "EAPOL Type":     "1B  6=Announcement 7=Announcement-Req 9=PC-Announcement 10=PC-Announcement-Req 11=Announcement-RESP",
            "Length":         "2B  TLV payload length",
            "TLVs":           "variable  Type(2B)+Length(2B)+Value — announces port/VLAN capabilities",
            "VID Set TLV":    "Type=0x0001 — VLAN ID set for this port",
            "MAC/PHY Config": "Type=0x0005 — IEEE 802.3 MAC/PHY configuration",
            "Power Via MDI":  "Type=0x000A — PoE power capabilities per IEEE 802.3",
            "Port VLAN ID":   "Type=0x8001 — port VLAN-ID for access/trunk classification",
            "CAUTION":        "Announcements are informational — no cryptographic binding; use MKA/MACSec for integrity",
        },
        applications="Announce port capabilities and VLAN assignments to 802.1X authenticator",
    ),

    "eapol_supp": dict(
        name="EAPOL-SUPP-PDU — Supplicant Pre-Authentication",
        transport="EAPOL (EtherType 0x888E Type=8)",
        header_bytes=4,
        fields={
            "EAPOL Type": "1B  0x08",
            "Length":     "2B  PDU length",
            "Data":       "variable  supplicant pre-authentication data for fast re-auth",
            "Note":       "Carries cached authentication credentials for re-association without full EAP exchange",
        },
        applications="Fast re-authentication after roaming — reduces 802.1X latency for mobile clients",
    ),

    # ── CFM additional opcodes — IEEE 802.1ag + ITU-T Y.1731 ─────────────────
    "cfm_tst": dict(
        name="CFM TST — Test Signal (ITU-T Y.1731 §9.5)",
        transport="CFM (EtherType 0x8902 Opcode=37)",
        header_bytes=4,
        fields={
            "MD Level":     "3b  Maintenance Domain level 0-7",
            "Version":      "5b  must be 0",
            "Opcode":       "1B  37 = TST",
            "Flags":        "1B  bit 0=HWonly (hardware test only)",
            "TLV Offset":   "1B  offset to first TLV",
            "Sequence No":  "4B  monotonically increasing per transmission",
            "CRC-32":       "4B  optional CRC over data TLV for error detection",
            "Data TLV":     "Type=0x03 Length(2B) + Pattern + test data payload",
            "Pattern":      "0x00=Null 0x01=PRBS2^31-1 0x02=AllZeros 0x03=AllOnes",
            "CAUTION":      "TST frames may be mistaken for user traffic if not filtered — use dedicated MEP; frame loss measurement requires accurate timestamp",
        },
        applications="Layer 2 BER/frame loss testing — measures error ratio without affecting user traffic",
    ),

    "cfm_aps": dict(
        name="CFM APS — Automatic Protection Switching (ITU-T Y.1731 §9.9)",
        transport="CFM (EtherType 0x8902 Opcode=43)",
        header_bytes=4,
        fields={
            "MD Level":     "3b",
            "Version":      "5b  0",
            "Opcode":       "1B  43 = APS",
            "Flags":        "1B",
            "TLV Offset":   "1B",
            "Request/State":"4B  request(4b)+protection-type(2b)+req-signal(4b)+bridged-signal(4b)+APS-specific(16b)",
            "Request":      "4b: 15=LockOut 14=ForcedSwitch 12=SF-P 11=SF-W 9=SD-P 8=SD-W 6=ManualSwitch 4=WTR 1=ReverseRequest 0=NoRequest",
            "Protection Type":"2b: bit1=Bidirectional bit0=Revertive",
            "APS Specific":  "2B  protection switching coordination data",
            "CAUTION":       "APS coordination requires matching protection domain; misconfigured Request values cause protection loop or lockout",
        },
        applications="Linear protection switching coordination — 1+1 or 1:1 Ethernet protection",
    ),

    "cfm_raps": dict(
        name="CFM RAPS — Ring APS (ITU-T G.8032 / Y.1731)",
        transport="CFM (EtherType 0x8902 Opcode=44)",
        header_bytes=4,
        fields={
            "MD Level":     "3b",
            "Version":      "5b  version 0 (basic) or 1 (enhanced)",
            "Opcode":       "1B  44 = RAPS",
            "Flags":        "1B  DNF(b7)=Do-Not-Flush  BPR(b6)=Blocked-Port-Reference",
            "TLV Offset":   "1B",
            "Request/State":"1B  R-APS request: 1101=MS 1011=FS 1100=SF 1010=SD 0111=NR 0001=NR+RB",
            "Sub-code":     "1B  0=SF 2=MS 4=FS",
            "Status":       "1B  BPR(1b)+DNF(1b)+FLUSH(1b)",
            "Node-ID":      "6B  MAC address of sending ring node",
            "Reserved":     "24B",
            "Dst MAC":      "01:19:A7:00:00:00 or 01:19:A7:00:00:01 (G.8032 R-APS multicast)",
            "CAUTION":      "RAPS must only be sent on ring ports; wrong domain = false ring recovery blocking user traffic",
        },
        applications="Ethernet Ring Protection Switching — sub-50ms Ethernet ring recovery (G.8032 ERP)",
    ),

    "cfm_mcc": dict(
        name="CFM MCC — Maintenance Communication Channel (ITU-T Y.1731)",
        transport="CFM (EtherType 0x8902 Opcode=45)",
        header_bytes=4,
        fields={
            "MD Level":     "3b",
            "Version":      "5b  0",
            "Opcode":       "1B  45 = MCC",
            "Flags":        "1B",
            "TLV Offset":   "1B",
            "OUI":          "3B  organisation identifier for application-specific data",
            "Subopcode":    "1B  application-defined sub-operation",
            "Data TLV":     "variable  application-specific maintenance data",
            "CAUTION":      "MCC provides out-of-band communication path over Ethernet OAM channel — used for vendor coordination",
        },
        applications="Proprietary maintenance data exchange over CFM OAM path — used in G.8013/Y.1731 deployments",
    ),

    # ── AVTP additional formats — IEEE 1722-2016 ──────────────────────────────
    "avtp_mma": dict(
        name="AVTP MMA-Stream — MIDI over AVB (IEEE 1722-2016 §9.5)",
        transport="AVTP (EtherType 0x88E8 Subtype=0x01)",
        header_bytes=24,
        fields={
            "Subtype":      "1B  0x01 = MMA-Stream",
            "SV":           "1b  stream_id valid",
            "Version":      "3b  0",
            "MR":           "1b  media clock restart",
            "TV":           "1b  avtp_timestamp valid",
            "Sequence No":  "1B  incremented per packet",
            "TU":           "1b  timestamp uncertain",
            "Stream ID":    "8B  EUI-64 stream identifier",
            "AVTP Timestamp":"4B  presentation time (gPTP time units)",
            "Stream Data":  "variable  packed MIDI 2.0 UMP messages or MIDI 1.0 messages",
            "CAUTION":      "MMA-Stream requires gPTP time synchronisation for presentation timing; missing PTP sync = incorrect playback timing",
        },
        applications="MIDI 2.0 / MIDI 1.0 professional audio transmission over AVB/TSN Ethernet fabric",
    ),

    "avtp_ntscf": dict(
        name="AVTP NTSCF — Non-Time-Sensitive Control Format (IEEE 1722-2016 §9.6)",
        transport="AVTP (EtherType 0x88E8 Subtype=0x05)",
        header_bytes=12,
        fields={
            "Subtype":      "1B  0x05 = NTSCF",
            "Version":      "3b  0",
            "Stream ID":    "8B  control stream identifier",
            "Data Length":  "2B  NTSCF payload length",
            "NTSCF Data":   "variable  control data TLVs (device discovery, stream management)",
            "Note":         "No timestamp — control messages not time-sensitive",
            "CAUTION":      "NTSCF is best-effort delivery — use for control, not media; do not mix NTSCF and TSCF on same stream",
        },
        applications="AVB device control plane — stream start/stop, parameter exchange, device management without timing constraints",
    ),

    "avtp_tscf": dict(
        name="AVTP TSCF — Time-Sensitive Control Format (IEEE 1722-2016 §9.7)",
        transport="AVTP (EtherType 0x88E8 Subtype=0x6A)",
        header_bytes=24,
        fields={
            "Subtype":       "1B  0x6A = TSCF",
            "Version":       "3b  0",
            "MR":            "1b  media clock restart",
            "TV":            "1b  AVTP timestamp valid",
            "Sequence No":   "1B",
            "TU":            "1b  timestamp uncertain",
            "Stream ID":     "8B",
            "AVTP Timestamp":"4B  presentation time (gPTP)",
            "Data Length":   "2B  control data payload length",
            "TSCF Data":     "variable  time-sensitive control TLVs — actuator commands, servo setpoints",
            "CAUTION":       "TSCF requires gPTP sync — used for deterministic control in industrial automation (IEC/IEEE 60802)",
        },
        applications="Time-synchronised control messages over AVB/TSN — industrial motion control, audio routing commands",
    ),

    # ── Proprietary/Vendor terminal L4 handlers ────────────────────────────────
    "ip_as_frame": dict(
        name="IP Autonomous Systems Frame (RFC 1701 GRE key)",
        transport="IP-AS (EtherType 0x876C)",
        header_bytes=8,
        fields={
            "AS Number": "2B  16-bit BGP Autonomous System number",
            "Reserved":  "2B  0x0000",
            "IP Payload":"variable  encapsulated IP datagram",
            "Note":      "RFC 1701 legacy — use BGP with GRE tunnelling for modern AS-tagged routing",
        },
        applications="Historic AS-tagged IP forwarding — obsolete; documented for legacy network analysis",
    ),

    "secure_data_frame": dict(
        name="Secure Data Frame (RFC 1701 GRE key)",
        transport="Secure Data (EtherType 0x876D)",
        header_bytes=8,
        fields={
            "Key":      "4B  identifies secure tunnel or VLAN context",
            "Sequence": "4B  optional anti-replay sequence number",
            "Payload":  "variable  encrypted or signed data payload",
            "Note":     "RFC 1701 historical — use MACsec (0x88E5) or IPsec for current secure L2/L3",
        },
        applications="Legacy secure data transport — historic analysis only",
    ),

    "cobranet_audio": dict(
        name="CobraNet Audio Bundle",
        transport="CobraNet (EtherType 0x8819)",
        header_bytes=4,
        fields={
            "Sub-Type":  "1B  0=Beat(real-time) 1=Bundle(packed)",
            "Bundle No": "2B  audio bundle number 0-65535",
            "Samples":   "variable  PCM audio samples at 48kHz/24-bit",
            "Channels":  "up to 8 channels per bundle at 48kHz; up to 4 at 96kHz",
            "Latency":   "<1ms typical on 100Mbps full-duplex Ethernet",
            "CAUTION":   "CobraNet is time-sensitive — requires <1ms latency; 100Mbps full-duplex required; QoS priority must be set",
        },
        applications="Professional audio distribution — live sound, broadcast, fixed installation",
    ),

    "cobranet_mgmt": dict(
        name="CobraNet Management Frame",
        transport="CobraNet (EtherType 0x8819 Sub-Type=Management)",
        header_bytes=4,
        fields={
            "Sub-Type":  "1B  2=Management",
            "Operation": "1B  device discovery, configuration, status",
            "Data":      "variable  management payload",
            "Note":      "Cirrus Logic proprietary management — requires CobraNet-aware control software",
        },
        applications="CobraNet device discovery and configuration",
    ),

    "nic_test_frame": dict(
        name="Wind River NIC Test Frame",
        transport="Wind River Test (EtherType 0x8822)",
        header_bytes=4,
        fields={
            "Test Type": "1B  1=Loopback  2=Pattern",
            "Pattern":   "1B  fill byte value for pattern test",
            "Length":    "2B  test payload length",
            "Data":      "variable  loopback or fill-pattern test data",
            "CAUTION":   "Test frames MUST NOT reach production or customer-facing ports — send only on isolated test segments",
        },
        applications="Ethernet NIC hardware loopback and data integrity testing during development/QA",
    ),

    "axis_frame": dict(
        name="Axis Bootstrap Frame",
        transport="Axis (EtherType 0x8856)",
        header_bytes=25,
        fields={
            "Msg Type":  "1B  0x01=Discovery  0x02=IPAssign",
            "Serial":    "8B  Axis device serial number (factory assigned)",
            "Current IP":"4B  device current IPv4 address (0.0.0.0 if unconfigured)",
            "New IP":    "4B  IP address to assign (IPAssign only)",
            "Subnet":    "4B  subnet mask",
            "Gateway":   "4B  default gateway (if included)",
            "CAUTION":   "Unauthenticated IP assignment — attacker on LAN can reassign camera IP; isolate camera VLANs and disable after configuration",
        },
        applications="Axis IP camera initial network configuration — assign IP before HTTP access",
    ),

    "homeplug_mme": dict(
        name="HomePlug 1.0 Management Message Entry",
        transport="HomePlug 1.0 (EtherType 0x887B)",
        header_bytes=2,
        fields={
            "MMType":    "2B  management message type code (HomePlug Alliance spec)",
            "MME Data":  "variable  management payload per MMType",
            "Note":      "HomePlug 1.0 Alliance proprietary — powerline PHY management",
        },
        applications="HomePlug 1.0 powerline device management and configuration",
    ),

    "homeplug_av_mme": dict(
        name="HomePlug AV Management Message",
        transport="HomePlug AV (EtherType 0x88E1)",
        header_bytes=4,
        fields={
            "MMType":   "2B  AV management message type; 0x6000-0x6003=CM 0xA000-0xAFFF=vendor",
            "FMI":      "2B  FMI(4b)+FMSN(4b)+FMID(8b) fragmentation/sequence info",
            "MMENTRY":  "variable  AV management payload (capabilities/beacons/link stats)",
            "CAUTION":  "HomePlug AV powerline — no physical isolation; all devices on same electrical circuit share all traffic including management",
        },
        applications="HomePlug AV device discovery, channel estimation, EV charging coordination (ISO 15118)",
    ),

    "homeplug_av2_mme": dict(
        name="HomePlug AV2 Management Message",
        transport="HomePlug AV2 (EtherType 0x8912)",
        header_bytes=4,
        fields={
            "MMType":   "2B  AV2 management message type code",
            "FMI":      "2B  fragmentation/sequence",
            "MMENTRY":  "variable  AV2 capabilities, beacons, link stats, MIMO config",
        },
        applications="HomePlug AV2 smart grid, EV charging, home networking management",
    ),

    "cclink_ie_pdu": dict(
        name="CC-Link IE PDU — CLPA",
        transport="CC-Link IE (EtherType 0x890F)",
        header_bytes=5,
        fields={
            "CC-Link IE Type":"1B  0x01=Field 0x02=Controller 0x03=Motion 0x04=TSN",
            "Station No":     "1B  source station number (0=master, 1-120=slaves)",
            "Dst Station":    "1B  destination (0xFF=broadcast)",
            "Seq No":         "2B  token ring sequence number",
            "PDU Type":       "variable  cyclic data (RX/TX buffers) or transient message",
            "Token Mechanism":"Token passing — only station holding token may transmit",
            "CAUTION":        "Mitsubishi proprietary — requires CC-Link IE certified hardware; non-certified switches disrupt token ring timing",
        },
        applications="Mitsubishi CC-Link IE Field/Controller industrial fieldbus — PLC I/O over 1Gbps ring",
    ),

    "local_exp_payload": dict(
        name="IEEE 802 Local Experimental Payload",
        transport="Experimental (EtherType 0x88B5 or 0x88B6)",
        header_bytes=0,
        fields={
            "Payload":  "variable  format defined by local/private agreement",
            "Scope":    "Local network segment only — MUST NOT be forwarded by bridges",
            "Standard": "RFC 9542 §3 — EtherTypes 0x88B5 and 0x88B6 reserved for local experimental use",
        },
        applications="Protocol research and development — prototype before IANA/IEEE EtherType assignment",
    ),
}

NON_IP_L4_REGISTRY.update(SUPPLEMENTAL_L4_REGISTRY)

# ── Extended L4 Registry — all handlers for new L3 protocols ──────────────────
EXTENDED_L4_REGISTRY: dict[str, dict] = {

    # ── STP BPDU handlers — IEEE 802.1D/802.1w/802.1s ────────────────────────
    "stp_config": dict(
        name="IEEE 802.1D-1998 STP Configuration BPDU",
        transport="STP (LLC 0x42/0x42 or PVST+ SNAP) BPDU Type=0x00 Version=0x00",
        header_bytes=35,
        fields={
            "Protocol ID":   "2B  0x0000 — always zero for IEEE STP",
            "Version":       "1B  0x00 = IEEE 802.1D-1998 STP",
            "BPDU Type":     "1B  0x00 = Configuration BPDU",
            "Flags":         "1B  bit0=TC(Topology Change) bit7=TCA(TC Acknowledgement) — bits 1-6 RESERVED must be 0",
            "Root Bridge ID":"8B  Priority(16b full, any value)+MAC(48b) — NO sys-ext in 802.1D-1998",
            "Root Path Cost":"4B  cumulative cost to root; 0=this bridge IS root",
            "Bridge ID":     "8B  this bridge's identifier — lower ID wins election",
            "Port ID":       "2B  PortPriority(8b 0-255)+PortNumber(8b 0-255)",
            "Message Age":   "2B  1/256-sec units; hops from root; discarded when ≥ Max Age",
            "Max Age":       "2B  default 5120 (20s×256); max allowed BridgeID age",
            "Hello Time":    "2B  default 512 (2s×256); BPDU transmit interval at root",
            "Forward Delay": "2B  default 3840 (15s×256); Listening+Learning state time",
            "Path Costs":    "802.1D-1998 original: 10Mbps=100 100Mbps=10 1Gbps=1 | 802.1D-2004: 10M=2000000 100M=200000 1G=20000",
            "CAUTION":       "STP 802.1D-1998 priority is full 16-bit — NOT restricted to ×4096; bits 1-6 of Flags field MUST be zero; non-zero reserved bits = discard per spec",
        },
        applications="Classic STP root election and loop prevention — 30-50s convergence after topology change",
    ),

    "stp_tcn": dict(
        name="IEEE 802.1D STP Topology Change Notification BPDU",
        transport="STP (LLC 0x42/0x42) BPDU Type=0x80 Version=0x00",
        header_bytes=4,
        fields={
            "Protocol ID": "2B  0x0000",
            "Version":     "1B  0x00",
            "BPDU Type":   "1B  0x80 = TCN — minimal 4-byte frame, NO flags, NO bridge IDs, NO timers",
            "Purpose":     "Sent upstream (toward root) when a port transitions to Forwarding or a topology change is detected",
            "Response":    "Root responds by setting TC bit in Config BPDUs for max_age+fwd_delay seconds",
            "CAUTION":     "TCN causes root to flush MAC tables — causes temporary flooding; TCN storms indicate unstable topology (flapping port or rogue STP device)",
        },
        applications="Notify root bridge of topology change — triggers MAC table flush",
    ),

    "rstp_bpdu": dict(
        name="IEEE 802.1w RSTP RST BPDU",
        transport="RSTP (LLC 0x42/0x42) BPDU Type=0x02 Version=0x02",
        header_bytes=36,
        fields={
            "Protocol ID":   "2B  0x0000",
            "Version":       "1B  0x02 = RSTP",
            "BPDU Type":     "1B  0x02 = RST BPDU (only BPDU type in RSTP; no separate TCN)",
            "Flags":         "1B  bit0=TC bit1=Proposal bit2-3=PortRole(00=Unknown 01=Alt/Backup 10=Root 11=Designated) bit4=Learning bit5=Forwarding bit6=Agreement bit7=TCA",
            "Root Bridge ID":"8B  Priority(4b×4096)+SystemIDExt=0(12b)+MAC(48b)",
            "Root Path Cost":"4B  802.1D-2004 costs: 10M=2000000 100M=200000 1G=20000 10G=2000",
            "Bridge ID":     "8B  same format as Root Bridge ID",
            "Port ID":       "2B  PortPriority(4b×16: 0-240)+PortNumber(12b: 0-4095)",
            "Message Age":   "2B  1/256-sec",
            "Max Age":       "2B  1/256-sec",
            "Hello Time":    "2B  1/256-sec",
            "Forward Delay": "2B  1/256-sec — only used for legacy STP interop fallback",
            "Version1 Length":"1B  0x00 — always zero per IEEE 802.1w §9.3.3",
            "Proposal/Agreement":"RSTP converges <1s via Proposal/Agreement handshake on P2P links instead of timer-based Listening/Learning",
            "CAUTION":       "RSTP System-ID-Extension = 0 (single tree, no VLAN distinction); priority MUST be ×4096; Version1Length MUST be 0x00",
        },
        applications="RSTP rapid convergence — <1s via Proposal/Agreement on point-to-point links",
    ),

    "mstp_bpdu": dict(
        name="IEEE 802.1s MSTP MST BPDU",
        transport="MSTP (LLC 0x42/0x42) BPDU Type=0x02 Version=0x03",
        header_bytes=102,
        fields={
            "Protocol ID":    "2B  0x0000",
            "Version":        "1B  0x03 = MSTP",
            "BPDU Type":      "1B  0x02 = MST BPDU",
            "CIST Flags":     "1B  same 8-bit layout as RSTP",
            "CIST Root ID":   "8B  CIST root across ALL MST regions (inter-regional root)",
            "CIST Ext Cost":  "4B  external path cost from this region boundary to CIST root",
            "CIST Bridge ID": "8B  Priority(4b×4096)+MSTI-ID=0(12b)+MAC(48b)",
            "Port ID":        "2B  PortPriority(4b×16)+PortNumber(12b)",
            "Message Age":    "2B  1/256-sec",
            "Max Age":        "2B  1/256-sec",
            "Hello Time":     "2B  1/256-sec",
            "Forward Delay":  "2B  1/256-sec",
            "Version1 Length":"1B  0x00",
            "Version3 Length":"2B  length of MST extension data",
            "MST Config ID":  "51B  FormatSelector(1B=0)+RegionName(32B)+RevisionLevel(2B)+ConfigDigest(16B MD5)",
            "CIST Int Cost":  "4B  internal path cost within MST region to CIST regional root",
            "CIST Bridge ID (regional)":"8B  this bridge as CIST regional root candidate",
            "CIST Rem Hops":  "1B  remaining hops in MST region (default MaxHops=20)",
            "MSTI Records":   "16B each — Flags(1B)+RegRoot(8B)+IntCost(4B)+BridgePrio(1B)+PortPrio(1B)+RemHops(1B)+Reserved(1B)",
            "MSTI Reg Root":  "8B  Priority(4b×4096)+MSTI-number(12b)+MAC(48b)",
            "MSTI BridgePrio":"1B  upper nibble only (0x00,0x10...0xF0 in steps of 0x10)",
            "CAUTION":        "All bridges in same MST region MUST have identical: RegionName+RevisionLevel+ConfigDigest; ConfigDigest = MD5 of VLAN-to-instance 4096-entry table; mismatch = separate regions = different CIST topology",
        },
        applications="MSTP multiple spanning trees — group VLANs per instance, one tree per group for load balancing",
    ),

    # ── XTP handlers ──────────────────────────────────────────────────────────
    "xtp_data": dict(
        name="XTP Data Segment (ANSI X3T9.5)",
        transport="XTP (EtherType 0x817D Type=0)",
        header_bytes=12,
        fields={
            "Key":     "4B  XTP session key at receiver",
            "TYPE":    "1B  0=Data",
            "DKEY":    "4B  destination key",
            "SKEY":    "4B  source key",
            "SEQ":     "4B  segment sequence number",
            "Data":    "variable  payload data",
            "CAUTION": "XTP obsolete — ANSI X3T9.5 withdrawn standard; not deployed in modern networks",
        },
        applications="Legacy XTP data transfer — documented for historical analysis",
    ),

    "xtp_ctrl": dict(
        name="XTP Control Segment (ANSI X3T9.5)",
        transport="XTP (EtherType 0x817D Type=1/3)",
        header_bytes=12,
        fields={
            "Key":    "4B",
            "TYPE":   "1B  1=Control 3=Async-Control",
            "DKEY":   "4B",
            "SKEY":   "4B",
            "Rseq":   "4B  receive sequence number (acknowledgement)",
            "Alloc":  "4B  receive buffer allocation",
        },
        applications="XTP flow and error control",
    ),

    "xtp_err": dict(
        name="XTP Error Segment (ANSI X3T9.5)",
        transport="XTP (EtherType 0x817D Type=2)",
        header_bytes=12,
        fields={
            "Key":       "4B",
            "TYPE":      "1B  2=Error",
            "Error Code":"2B  XTP error type",
            "CAUTION":   "XTP obsolete",
        },
        applications="XTP error reporting",
    ),

    # ── MPLS inner dispatch handler ───────────────────────────────────────────
    "mpls_inner": dict(
        name="MPLS Inner Payload (RFC 3032 bottom-of-stack)",
        transport="MPLS (EtherType 0x8847/0x8848) S=1 payload",
        header_bytes=4,
        fields={
            "Label":    "20b  MPLS label identifying forwarding entry",
            "TC":       "3b   Traffic Class (QoS/ECN bits; formerly 'EXP')",
            "S":        "1b   Bottom-of-stack; 1=this is the last label",
            "TTL":      "8b   decremented per LSR; 0=discard",
            "PHP":      "Label 3=Implicit-Null triggers Penultimate Hop Pop — egress label removed by penultimate router",
            "NULL labels": "Label 0=IPv4-Explicit-Null  Label 2=IPv6-Explicit-Null — preserve TC bits to egress",
            "CAUTION":  "Unlabelled packet after PHP may be unreadable at egress if LSP was IPv6 but IP version nibble check expects IPv4",
        },
        applications="MPLS LSR forwarding — post-pop payload identification for further processing",
    ),

    # ── GRE inner payload handler ─────────────────────────────────────────────
    "gre_eth_inner": dict(
        name="Transparent Ethernet Bridging over GRE (RFC 1701/2784)",
        transport="GRE (Protocol Type=0x6558)",
        header_bytes=14,
        fields={
            "Inner Dst MAC":"6B  original frame destination MAC",
            "Inner Src MAC":"6B  original frame source MAC",
            "Inner EtherType":"2B  original frame EtherType (0x0800/0x86DD etc.)",
            "Inner Payload": "variable  original Ethernet payload",
            "Note":          "Full Ethernet frame (without outer headers) tunnelled inside GRE",
            "CAUTION":       "Transparent bridging passes L2 broadcasts including ARP/STP — can cause STP loops or ARP storms across GRE tunnel; use L2VPN controls",
        },
        applications="L2VPN over GRE — transparent Ethernet bridging across IP networks",
    ),

    "erspan_pdu": dict(
        name="ERSPAN — Encapsulated Remote SPAN (Cisco / RFC-draft)",
        transport="GRE (Protocol Type=0x88BE Type-II or 0x22EB Type-III)",
        header_bytes=8,
        fields={
            "Version":      "4b  1=Type-II  2=Type-III",
            "VLAN":         "12b  original VLAN ID of monitored traffic",
            "COS":          "3b   class of service from original frame",
            "EN":           "2b   encapsulation type: 0=original 1=ISL 2=802.1Q",
            "T":            "1b   Truncated flag — frame was truncated",
            "Session ID":   "10b  identifies ERSPAN session (1-1023)",
            "Index":        "20b  Type-II: port index; Type-III: timestamp sub-header",
            "Type-III Timestamp":"Type-III only: 32b hardware timestamp + optional BSO+WR+FT+P+FCS fields",
            "Inner Frame":  "variable  captured/mirrored Ethernet frame",
            "CAUTION":      "ERSPAN doubles bandwidth consumption; session IDs must be unique per monitor target; Type-III timestamp requires hardware support",
        },
        applications="Remote port mirroring over IP networks — captures Ethernet frames and ships them to remote analyser",
    ),

    # ── DECnet Phase V handlers ────────────────────────────────────────────────
    "decnet_routing": dict(
        name="DECnet Phase V DNA Routing Message",
        transport="DECnet Phase V (LLC 0xFE/0xFE Phase V)",
        header_bytes=3,
        fields={
            "DSAP":     "1B  0xFE",
            "SSAP":     "1B  0xFE",
            "DNA Type": "1B  0x01=Routing",
            "Routing Data":"variable  DECnet routing PDU",
            "CAUTION":  "DECnet Phase V obsolete — only on pre-1995 DEC/Compaq networks",
        },
        applications="DECnet Phase V inter-area routing",
    ),

    "decnet_hello": dict(
        name="DECnet Phase V Hello PDU",
        transport="DECnet Phase V",
        header_bytes=3,
        fields={
            "DNA Type": "1B  0x02=Router-Hello 0x03=End-Node-Hello",
            "Router Priority":"1B  higher = preferred Designated Router",
            "Hello Timer":    "2B  hello interval seconds",
            "Area":           "2B  DECnet area number",
            "Node ID":        "6B  DECnet node address",
        },
        applications="DECnet adjacency establishment",
    ),

    "decnet_lsp": dict(
        name="DECnet Phase V Link State PDU",
        transport="DECnet Phase V",
        header_bytes=3,
        fields={
            "DNA Type":   "1B  0x05=L1-LSP 0x06=L2-LSP",
            "PDU Length": "2B",
            "Remaining Lifetime":"2B  0=flush from database",
            "Sequence Number":"4B",
            "Checksum":   "2B",
            "IS Neighbors":"TLV type 2 — neighbour IS addresses and metrics",
        },
        applications="DECnet link state database distribution",
    ),

    # ── Banyan VINES handlers ─────────────────────────────────────────────────
    "vines_ctrl": dict(
        name="Banyan VINES ICP/ARP",
        transport="VINES IP (EtherType 0x0BAD)",
        header_bytes=18,
        fields={
            "Protocol Type": "1B  0xBA=ICP 0xBB=ARP",
            "VINES Net":     "4B  target VINES network number",
            "VINES Subnet":  "2B  target subnet ID",
            "Operation":     "1B  ICP/ARP operation code",
            "CAUTION":       "VINES obsolete since Banyan Systems dissolution in 1999",
        },
        applications="VINES network layer control — address resolution and management",
    ),

    "vines_rtp": dict(
        name="Banyan VINES RTP — Routing Table Protocol",
        transport="VINES IP Protocol 0xBC",
        header_bytes=18,
        fields={
            "Op":    "1B  0x01=Request 0x02=Update 0x04=Redirect 0x06=Withdraw",
            "Metric":"2B  VINES routing metric (delay in machine ticks)",
            "Net":   "4B  advertised network",
            "CAUTION":"VINES RTP broadcasts every 90s; disable on all modern networks",
        },
        applications="VINES network routing updates — legacy distance-vector protocol",
    ),

    "vines_data": dict(
        name="Banyan VINES IPC/SPP Data",
        transport="VINES IP Protocol 0xBD/0xBE",
        header_bytes=18,
        fields={
            "Src Port":  "2B  VINES source socket",
            "Dst Port":  "2B  VINES destination socket",
            "Op":        "1B  IPC: 0=DATA 1=ERR 2=DISC  SPP: 0=DATA 1=ACK 2=DISC",
            "Sequence":  "2B  SPP sequence number",
            "Data":      "variable  application payload",
        },
        applications="VINES file/print services and application data transport",
    ),

    # ── AppleTalk DDP handlers ────────────────────────────────────────────────
    "ddp_rtmp": dict(
        name="AppleTalk RTMP — Routing Table Maintenance Protocol",
        transport="AppleTalk DDP Type 1/5",
        header_bytes=13,
        fields={
            "Router Net": "2B  router's AppleTalk network number",
            "ID Length":  "1B  node ID length (1=8-bit)",
            "Router ID":  "1B  router node ID",
            "Tuples":     "variable  Net(2B)+Distance(1B) per route entry",
            "CAUTION":    "RTMP broadcasts full routing table every 10s — causes congestion at scale; AppleTalk removed from macOS 10.6",
        },
        applications="AppleTalk routing table exchange — legacy network topology discovery",
    ),

    "ddp_nbp": dict(
        name="AppleTalk NBP — Name Binding Protocol",
        transport="AppleTalk DDP Type 2",
        header_bytes=13,
        fields={
            "Function":   "4b  1=BrRq 2=LkUp 3=LkUpReply 4=FwdReq",
            "TupleCnt":   "4b  number of NBP tuples",
            "NBPID":      "1B  transaction ID",
            "Tuples":     "variable  Socket(3B)+Enumerator(1B)+NBPName(object:type@zone)",
            "CAUTION":    "NBP name lookup is broadcast-based — produces frequent broadcast traffic; AppleTalk deprecated",
        },
        applications="AppleTalk name-to-address resolution — analogous to DNS for AppleTalk services",
    ),

    "ddp_atp": dict(
        name="AppleTalk ATP — AppleTalk Transaction Protocol",
        transport="AppleTalk DDP Type 3",
        header_bytes=8,
        fields={
            "Ctrl":  "8b  XO(exactly-once)+TREQ+TRESP+TREL+STS+EOM+SendSts",
            "Bitmap":"1B  bitmap of requested/received response packets",
            "TIDX":  "2B  transaction ID for request/response matching",
            "UserData":"4B  application user bytes",
            "Data":  "variable  request/response payload",
        },
        applications="AppleTalk reliable transaction service — AFP remote filing protocol",
    ),

    "ddp_zip": dict(
        name="AppleTalk ZIP — Zone Information Protocol",
        transport="AppleTalk DDP Type 6",
        header_bytes=13,
        fields={
            "Function":"1B  1=Query 2=Reply 5=GetNetInfo 6=GetNetInfoReply 7=Notify 8=Extended-Reply",
            "NumNets": "1B  number of networks in query/reply",
            "Zones":   "variable  zone name list",
            "CAUTION": "ZIP GetNetInfo broadcast every router startup — AppleTalk only",
        },
        applications="AppleTalk zone name resolution — maps networks to zone names for NBP",
    ),

    "ddp_asp": dict(
        name="AppleTalk ASP/AFP — Session/Filing Protocol",
        transport="AppleTalk DDP Type 22/35 via ATP",
        header_bytes=8,
        fields={
            "ASP Function":"1B  0=CloseSession 1=Command 2=GetStatus 3=OpenSession 4=Reply 5=WriteContinue 6=Write 7=WriteContinue",
            "Seq No":      "2B  ASP sequence number",
            "AFP Command": "1B  AFP function code",
            "Params":      "variable  AFP command parameters",
            "CAUTION":     "AFP/ASP over AppleTalk obsolete — AFP now runs over TCP/IP (port 548)",
        },
        applications="AppleTalk Filing Protocol — legacy Mac file sharing over AppleTalk",
    ),

    "aarp_pdu": dict(
        name="AARP PDU — AppleTalk Address Resolution (EtherType 0x80F3)",
        transport="AARP (EtherType 0x80F3)",
        header_bytes=28,
        fields={
            "HW Type":   "2B  1=Ethernet",
            "Proto Type":"2B  0x809B=AppleTalk",
            "HW Len":    "1B  6",
            "Proto Len": "1B  4",
            "Function":  "2B  1=Request 2=Response 3=Probe",
            "Src HW":    "6B  sender MAC",
            "Src Proto": "4B  sender AppleTalk address: Net(2B)+Node(1B)+Socket(1B)",
            "Dst HW":    "6B  target MAC (zeros in request/probe)",
            "Dst Proto": "4B  target AppleTalk address",
            "Probe Use": "Function=3 Probe: sent during address self-assignment; if reply received the address is in use",
            "CAUTION":   "AARP obsolete — Apple removed AppleTalk in macOS 10.6 (2009)",
        },
        applications="AppleTalk address-to-MAC resolution and address conflict detection",
    ),

    # ── Novell IPX handlers ───────────────────────────────────────────────────
    "ipx_rip": dict(
        name="IPX RIP — Routing Information Protocol (Novell)",
        transport="IPX Packet Type 1",
        header_bytes=30,
        fields={
            "IPX Header":   "30B  standard IPX header",
            "Operation":    "2B  1=Request 2=Response",
            "Entries":      "variable  Network(4B)+Hops(2B)+Ticks(2B) per route entry",
            "Ticks":        "2B  routing metric in 1/18-second ticks (lower=better)",
            "Hops":         "2B  hop count (max 15; 16=unreachable)",
            "Broadcast":    "IPX RIP broadcasts full table every 60s to 0xFFFFFFFF:0xFFFF:0x0453",
            "CAUTION":      "IPX RIP causes network storms at scale — disables NetWare connectivity if not properly contained; completely obsolete",
        },
        applications="Legacy Novell NetWare network topology discovery and routing",
    ),

    "ipx_spx": dict(
        name="IPX SPX — Sequenced Packet Exchange",
        transport="IPX Packet Type 5",
        header_bytes=42,
        fields={
            "IPX Header":    "30B  standard IPX header",
            "Conn Control":  "1B  SACK+ATN+EOM+SYS bits",
            "Data Stream":   "1B  0xFF=end-of-message",
            "Src Conn ID":   "2B  connection identifier at source",
            "Dst Conn ID":   "2B  connection identifier at destination",
            "Seq No":        "2B  transmitted sequence number",
            "ACK No":        "2B  acknowledgement number",
            "Alloc No":      "2B  receiver window allocation",
            "CAUTION":       "SPX is obsolete — Novell replaced with TCP for NCP in NetWare 5+",
        },
        applications="Novell NetWare reliable connection-oriented transport — legacy file/print",
    ),

    "ipx_ncp": dict(
        name="IPX NCP — NetWare Core Protocol",
        transport="IPX Packet Type 17 / Socket 0x0451",
        header_bytes=46,
        fields={
            "IPX Header":     "30B",
            "Request Type":   "2B  0x1111=Request 0x2222=Reply 0x5555=Destroy 0x7777=Burst",
            "Sequence No":    "1B  0-255 wrapping",
            "Connection No Lo":"1B  lower byte of connection number",
            "Task No":        "1B  application task number",
            "Connection No Hi":"1B  upper byte (NetWare 4+)",
            "Function Code":  "1B  NCP function (e.g. 0x16=GetFileServerInfo 0x1A=Negotiate-Buffer)",
            "Subfunction":    "1B  sub-operation code",
            "Data":           "variable  request or reply data",
            "CAUTION":        "NCP has no authentication in base form — NetWare 4+ added NDS/signature; completely replaced by TCP-NCP in NetWare 5",
        },
        applications="Novell NetWare file, print, directory, and bindery services",
    ),

    # ── XNS handlers ─────────────────────────────────────────────────────────
    "ipx_rip_xns": dict(
        name="XNS RIP",
        transport="XNS IDP Transport=0",
        header_bytes=30,
        fields={
            "Operation":"2B  1=Request 2=Response",
            "Entries":  "variable  Net(4B)+Hops(2B) per entry",
            "CAUTION":  "XNS entirely obsolete",
        },
        applications="XNS routing table maintenance — historical",
    ),

    # ── SNAP dispatch handler ─────────────────────────────────────────────────
    "snap_payload": dict(
        name="IEEE 802.2 SNAP Payload",
        transport="SNAP (DSAP=0xAA SSAP=0xAA Control=0x03)",
        header_bytes=5,
        fields={
            "OUI":     "3B  0x000000=IANA standard; 0x00000C=Cisco; 0x0080C2=IEEE 802.1",
            "PID":     "2B  Protocol ID; when OUI=0x000000 PID=EtherType",
            "Payload": "variable  encapsulated protocol data",
            "Max SDU": "MTU - 8B SNAP overhead = 1492B on standard Ethernet",
            "CAUTION": "SNAP uses LLC framing — EtherType in Length/Type field is frame length not protocol; max frame ≤1500B",
        },
        applications="Protocol multiplexing within IEEE 802.2 LLC frames — 802.11 WiFi, Token Ring, Cisco proprietary",
    ),

    # ── LACP extended handler ─────────────────────────────────────────────────
    "lacp_ext_pdu": dict(
        name="LACP Extended PDU — IEEE 802.1AX DRNI",
        transport="Slow Protocols (EtherType 0x8809 Subtype=0x01) extended",
        header_bytes=110,
        fields={
            "Subtype":           "1B  0x01=LACP",
            "Version":           "1B  0x01",
            "Actor TLV Type":    "1B  0x01",
            "Actor TLV Length":  "1B  0x14=20B",
            "Actor Sys Priority":"2B  system priority (0=highest, 65535=lowest)",
            "Actor Sys ID":      "6B  system MAC address",
            "Actor Key":         "2B  operational key — must match to aggregate",
            "Actor Port Priority":"2B  port priority within system",
            "Actor Port":        "2B  port number",
            "Actor State":       "1B  LACP_Activity(b0)+Timeout(b1)+Aggregation(b2)+Sync(b3)+Collecting(b4)+Distributing(b5)+Defaulted(b6)+Expired(b7)",
            "Actor Reserved":    "3B  0x000000",
            "Partner TLV":       "20B  mirror of Actor TLV structure for partner",
            "Collector TLV":     "16B  Type=0x03 Len=0x10 MaxDelay(2B) Reserved(12B)",
            "Terminator TLV":    "2B  Type=0x00 Len=0x00",
            "Reserved":          "50B  padding to minimum frame size",
            "CAUTION":           "Actor Key mismatch prevents bundling; LACP Timeout b1=0 is slow (30s) b1=1 is fast (1s); Expired state means partner not heard within timeout",
        },
        applications="IEEE 802.1AX LACP for multi-chassis LAG (DRNI) and standard LAG formation",
    ),

    # ── OAM extended handlers ─────────────────────────────────────────────────
    "oam_ext_pdu": dict(
        name="IEEE 802.3ah OAM Extended PDU",
        transport="Slow Protocols (EtherType 0x8809 Subtype=0x03)",
        header_bytes=3,
        fields={
            "Flags":        "2B  LinkFault(b0)+DyingGasp(b1)+CriticalEvent(b2)+LocalEval(b3)+LocalStable(b4)+RemoteEval(b5)+RemoteStable(b6)",
            "Code":         "1B  0x00=Information 0x01=EventNotification 0x02=VarRequest 0x03=VarResponse 0x04=LoopbackCtrl 0xFE=OrgSpecific",
            "Info TLV":     "Type=0x01 Len=0x10: OAMConfig(1B)+PDUConfig(2B)+OUI(3B)+VendorSpecific(4B)",
            "OAM Config":   "1B  b0=Mode b1=Unidirectional b2=RemoteLoopback b3=LinkEvents b4=Variables",
            "Event TLV":    "Type=0x01-0x04  ErrSymPeriod/ErrFrame/ErrFramePeriod/ErrFrameSeconds with threshold+window+errors",
            "Loopback TLV": "Type=0x04 Len=0x01 Data=0x01=Enable 0x02=Disable",
            "CAUTION":      "Remote loopback (Code=0x04 Data=0x01) loops ALL traffic — activating on production link causes immediate service outage",
        },
        applications="EFM link monitoring, fault detection, and remote loopback for DSL/fibre last-mile",
    ),

    # ── GRE dispatch handler ──────────────────────────────────────────────────
    "gre_inner_dispatch": dict(
        name="GRE Inner Protocol Dispatch (RFC 2784)",
        transport="GRE (EtherType 0x6558/0xB7EA/other GRE EtherTypes)",
        header_bytes=4,
        fields={
            "Protocol Type": "2B  same as EtherType — identifies inner payload",
            "IPv4":          "0x0800 — inner IPv4 (most common GRE usage)",
            "IPv6":          "0x86DD — inner IPv6",
            "MPLS-UC":       "0x8847 — inner MPLS unicast",
            "Transparent Eth":"0x6558 — inner Ethernet frame (L2oGRE)",
            "ERSPAN-II":     "0x88BE — Cisco ERSPAN type II",
            "ERSPAN-III":    "0x22EB — Cisco ERSPAN type III",
            "CAUTION":       "GRE adds 4-8B overhead per packet; no built-in authentication; PPTP (GRE version 1) is deprecated (RFC 2637); use IPsec/ESP for security",
        },
        applications="Flexible tunnel encapsulation — VPN, overlay networks, port mirroring, mobile backhaul",
    ),
}

NON_IP_L4_REGISTRY.update(EXTENDED_L4_REGISTRY)


# ════════════════════════════════════════════════════════════════════════════
# UDP PROTOCOL REGISTRY — Active UDP/IP Application-Layer PDU Handlers
# Sources: IETF RFCs, IANA, 3GPP TS, IEEE, Cisco, ITU-T, UPnP Forum
# ════════════════════════════════════════════════════════════════════════════

UDP_L4_REGISTRY: dict[str, dict] = {
    "udp_dns": dict(
        name='DNS — Domain Name System (RFC 1035 / RFC 8484)',
        transport='UDP/53 queries ≤512B; TCP/53 >512B or zone transfer; DoT TCP/853; DoH HTTPS/443',
        status='IETF Standard — RFC 1035, RFC 2535 DNSSEC, RFC 7766 TCP, RFC 8484 DoH',
        description='DNS maps hostnames to IP addresses. Queries are UDP/53 with TCP fallback for large responses. DNSSEC adds signatures. DoH/DoT add privacy.',
        header_bytes=12,
        fields={
            'Transaction ID': '2B  random client nonce matched in response',
            'Flags': '2B  QR(1b)+Opcode(4b)+AA+TC+RD+RA+Z+AD+CD+RCODE(4b)',
            'QR': '1b  0=Query 1=Response',
            'Opcode': '4b  0=QUERY 1=IQUERY(obsolete) 2=STATUS 4=NOTIFY 5=UPDATE(RFC 2136)',
            'AA': '1b  Authoritative Answer',
            'TC': '1b  Truncated — retry over TCP',
            'RD': '1b  Recursion Desired',
            'RA': '1b  Recursion Available',
            'AD': '1b  Authenticated Data — DNSSEC validated',
            'CD': '1b  Checking Disabled — client disables DNSSEC validation',
            'RCODE': '4b  0=NoError 1=FormErr 2=ServFail 3=NXDomain 4=NotImp 5=Refused',
            'QDCOUNT': '2B  number of questions',
            'ANCOUNT': '2B  number of answer RRs',
            'NSCOUNT': '2B  number of authority RRs',
            'ARCOUNT': '2B  number of additional RRs',
            'Question': 'QNAME(labels)+QTYPE(2B)+QCLASS(2B); QNAME: length-prefixed labels ending 0x00',
            'QTYPE': '1=A 2=NS 5=CNAME 6=SOA 12=PTR 15=MX 16=TXT 28=AAAA 33=SRV 41=OPT 43=DS 46=RRSIG 47=NSEC 48=DNSKEY 52=TLSA 255=ANY',
            'QCLASS': '1=IN(Internet) 255=ANY',
            'RR Answer': 'NAME+TYPE(2B)+CLASS(2B)+TTL(4B)+RDLENGTH(2B)+RDATA',
            'RDATA A': '4B IPv4 address',
            'RDATA AAAA': '16B IPv6 address',
            'RDATA MX': 'PREFERENCE(2B)+EXCHANGE(name)',
            'RDATA SRV': 'PRIORITY(2B)+WEIGHT(2B)+PORT(2B)+TARGET(name)',
            'RDATA SOA': 'MNAME+RNAME+SERIAL(4B)+REFRESH(4B)+RETRY(4B)+EXPIRE(4B)+MINIMUM(4B)',
            'EDNS0 OPT': 'NAME=0 TYPE=41 CLASS=UDP-payload-size TTL=extended-RCODE+flags RDATA=options',
            'CAUTION': 'DNS unauthenticated by default — use DNSSEC+DANE; DNS amplification: ANY query→large response; implement BCP38+RRL; cache poisoning mitigated by source port randomisation RFC 5452; DoH/DoT bypass enterprise DNS monitoring',
        },
        applications='Universal name resolution — web, email, VoIP, CDN, service discovery',
    ),

    "udp_dhcpv4": dict(
        name='DHCPv4 — Dynamic Host Configuration Protocol (RFC 2131)',
        transport='UDP/67 (server) UDP/68 (client) — broadcast-based DORA exchange',
        status='IETF Standard — RFC 2131 (base) RFC 2132 (options) RFC 4039 (rapid commit)',
        description='DHCPv4 dynamically assigns IPv4 addresses, masks, gateways, and DNS via DORA: Discover→Offer→Request→Ack.',
        header_bytes=236,
        fields={
            'op': '1B  1=BOOTREQUEST 2=BOOTREPLY',
            'htype': '1B  1=Ethernet',
            'hlen': '1B  6 (MAC length)',
            'hops': '1B  relay agent hop count; max 16',
            'xid': '4B  transaction ID — random nonce matching request to reply',
            'secs': '2B  seconds since client began acquisition',
            'flags': '2B  bit15=Broadcast flag',
            'ciaddr': '4B  client IP (0.0.0.0 if unknown)',
            'yiaddr': '4B  your IP — address assigned by server',
            'siaddr': '4B  next server IP (TFTP for PXE)',
            'giaddr': '4B  relay agent IP (0.0.0.0 if no relay)',
            'chaddr': '16B  client hardware address (MAC in first 6B)',
            'sname': '64B  optional server hostname',
            'file': '128B  boot filename for PXE',
            'magic': '4B  0x63825363 DHCP magic cookie',
            'Opt 1': 'Subnet Mask (4B)',
            'Opt 3': 'Router/Gateway list (4B each)',
            'Opt 6': 'DNS Server list (4B each)',
            'Opt 12': 'Hostname string',
            'Opt 50': 'Requested IP Address (4B)',
            'Opt 51': 'Lease Time (4B seconds)',
            'Opt 53': 'DHCP Message Type: 1=Discover 2=Offer 3=Request 4=Decline 5=ACK 6=NAK 7=Release 8=Inform',
            'Opt 54': 'Server Identifier (4B)',
            'Opt 55': 'Parameter Request List',
            'Opt 60': 'Vendor Class Identifier (PXEClient etc.)',
            'Opt 61': 'Client Identifier: Type(1B)+ID',
            'Opt 66': 'TFTP Server Name (PXE)',
            'Opt 67': 'Bootfile Name (PXE)',
            'Opt 82': 'Relay Agent Info: Circuit-ID(sub1)+Remote-ID(sub2) — added by switch',
            'Opt 121': 'Classless Static Routes RFC 3442 — overrides Opt 3',
            'CAUTION': 'No authentication — rogue DHCP server redirects all traffic; enable DHCP Snooping on all access switches; default communities are attack vector; stale leases cause address exhaustion',
        },
        applications='Automatic IPv4 configuration — workstations, IoT, phones, printers, PXE boot',
    ),

    "udp_dhcpv6": dict(
        name='DHCPv6 — Dynamic Host Configuration Protocol for IPv6 (RFC 8415)',
        transport='UDP/546 (client) UDP/547 (server/relay) — multicast FF02::1:2',
        status='IETF Standard — RFC 8415 consolidates RFC 3315+3319+3736+4242+7083+7550+7598',
        description='DHCPv6 provides stateful IPv6 address/prefix assignment and option delivery alongside SLAAC. Prefix Delegation assigns /48-/64 prefixes to CPE.',
        header_bytes=4,
        fields={
            'msg-type': '1B  1=Solicit 2=Advertise 3=Request 4=Confirm 5=Renew 6=Rebind 7=Reply 8=Release 9=Decline 10=Reconfigure 11=Info-Request 12=Relay-Forward 13=Relay-Reply',
            'transaction-id': '3B  random nonce for correlation',
            'Opt 1 CLIENTID': 'DUID client identifier',
            'Opt 2 SERVERID': 'DUID server identifier',
            'Opt 3 IA_NA': 'IAID(4B)+T1(4B)+T2(4B)+IA-NA-options',
            'Opt 5 IA_ADDR': 'IPv6Addr(16B)+PreferredLT(4B)+ValidLT(4B)',
            'Opt 14 RAPID': 'Rapid Commit — 2-message Solicit+Reply',
            'Opt 23 DNS': 'DNS server addresses (16B each)',
            'Opt 25 IA_PD': 'Prefix Delegation: IAID(4B)+T1+T2+IA-PD-options',
            'Opt 26 IAPREFIX': 'PrefLT(4B)+ValidLT(4B)+PrefixLen(1B)+IPv6Prefix(16B)',
            'DUID types': '1=DUID-LLT 2=DUID-EN 3=DUID-LL 4=DUID-UUID',
            'CAUTION': 'DHCPv6 Guard required on switches; rogue DHCPv6 still possible with SLAAC; RA Guard needed for IPv6 ND protection; PD delegation must be tracked for security auditing',
        },
        applications='IPv6 address assignment, prefix delegation for CPE, DNS/NTP distribution',
    ),

    "udp_ntp": dict(
        name='NTP v4 — Network Time Protocol (RFC 5905)',
        transport='UDP/123 — symmetric client/server and broadcast modes',
        status='IETF Standard — RFC 5905 (NTPv4) RFC 7822 (optional fields) RFC 8633 (BCP) RFC 8915 (NTS)',
        description='NTP synchronises clocks to UTC via hierarchical stratum model. Stratum 0=atomic reference, stratum 1=directly connected. Supports unicast, broadcast, and symmetric peer modes.',
        header_bytes=48,
        fields={
            'LI': '2b  Leap Indicator: 0=no warning 1=add-sec 2=del-sec 3=unsync',
            'VN': '3b  Version: 4=NTPv4',
            'Mode': '3b  1=Sym-Active 2=Sym-Passive 3=Client 4=Server 5=Broadcast 6=Control 7=Private',
            'Stratum': '1B  0=unspecified/KoD 1=primary(GPS/atomic) 2-15=secondary 16=unsynchronised',
            'Poll': '1B  signed log2 of max interval between messages',
            'Precision': '1B  signed log2 of clock precision',
            'Root Delay': '4B  total round-trip delay to reference (16b.16b seconds)',
            'Root Dispersion': '4B  max error relative to reference (16b.16b)',
            'Reference ID': "4B  stratum1: ASCII 'GPS'/'PPS'/'ACTS'; stratum≥2: reference server IP",
            'Reference Timestamp': '8B  when clock was last set (32b.32b seconds since 1900-01-01)',
            'Origin Timestamp': '8B  T1 — time client sent request',
            'Receive Timestamp': '8B  T2 — time server received request',
            'Transmit Timestamp': '8B  T3 — time server sent response',
            'Clock offset': '(T2-T1+T4-T3)/2',
            'Round-trip delay': '(T4-T1)-(T3-T2)',
            'KoD Reference': 'Stratum=0: DENY RSTR RATE INIT STEP — Kiss-of-Death codes',
            'NTS extension': 'RFC 8915: NTS-Cookie+NTS-Auth fields for authenticated NTP',
            'CAUTION': 'NTP amplification DDoS — disable monlist; NTPv4 without NTS is unauthenticated — attacker can shift clocks causing cert expiry or TOTP failure; NTP epoch wraps Feb 2036',
        },
        applications='Clock sync for servers, switches, routers, logging timestamps, TLS certificates, TOTP 2FA',
    ),

    "udp_snmpv1": dict(
        name='SNMPv1/v2c — Simple Network Management Protocol (RFC 1157/3416)',
        transport='UDP/161 (agent polling) UDP/162 (trap receiver)',
        status='IETF Standard — RFC 1157 (v1) RFC 3416 (v2c) — use SNMPv3 for security',
        description='SNMP monitors and manages network devices via MIB variable read/write. v1/v2c use cleartext community strings. v2c adds bulk retrieval.',
        header_bytes=0,
        fields={
            'Version': 'INTEGER  0=v1 1=v2c (ASN.1 BER)',
            'Community': 'OCTET STRING  cleartext community string — effectively a password',
            'PDU Type v1': '0=GetRequest 1=GetNextRequest 2=GetResponse 3=SetRequest 4=Trap',
            'PDU Type v2c': '0=GetRequest 1=GetNextRequest 2=Response 3=SetRequest 5=GetBulkRequest 6=InformRequest 7=SNMPv2-Trap 8=Report',
            'Request-ID': 'INTEGER  request/response correlation',
            'Error-Status': 'INTEGER  0=noError 1=tooBig 2=noSuchName 3=badValue 4=readOnly 5=genErr',
            'Error-Index': 'INTEGER  failing VarBind index (1-based)',
            'NonRepeaters': 'INTEGER  GetBulk: non-repeating variable count',
            'MaxRepetitions': 'INTEGER  GetBulk: max repetitions for repeating vars',
            'VarBindList': 'SEQUENCE OF OID+Value pairs',
            'Common OIDs': 'sysDescr=1.3.6.1.2.1.1.1.0  ifTable=1.3.6.1.2.1.2.2  ifInOctets=.10.x  hrSystemUptime=1.3.6.1.2.1.25.1.1',
            'Trap v1': 'Enterprise-OID+AgentAddr(4B)+GenericTrap(0-6)+SpecificTrap+Timestamp+VarBinds',
            'Generic Traps': '0=coldStart 1=warmStart 2=linkDown 3=linkUp 4=authFailure 6=enterpriseSpecific',
            'CAUTION': 'Community strings cleartext — default public/private must be changed; SNMPv2c write = full device compromise; use SNMPv3 authPriv in production; SNMP amplification attack possible with spoofed source',
        },
        applications='Network device monitoring: bandwidth, CPU, interface stats, hardware inventory',
    ),

    "udp_snmpv3": dict(
        name='SNMPv3 — Secure SNMP (RFC 3411-3419)',
        transport='UDP/161 (agent) UDP/162 (trap/inform)',
        status='IETF Standard — RFC 3411 (arch) RFC 3414 (USM auth/priv) RFC 3415 (VACM)',
        description='SNMPv3 adds MD5/SHA authentication and DES/AES encryption via USM. VACM controls per-user MIB access.',
        header_bytes=0,
        fields={
            'msgVersion': 'INTEGER  3',
            'msgID': '4B  message correlation ID',
            'msgMaxSize': '4B  maximum message size (≥484B)',
            'msgFlags': '1B  bit0=Auth bit1=Priv bit2=Reportable; 0x07=authPriv (most secure)',
            'msgSecurityModel': '1B  3=USM (User-based Security Model)',
            'msgAuthoritativeEngineID': 'variable  unique engine identifier — prevents cross-engine replay',
            'msgAuthoritativeEngineBoots': '4B  reboot counter — anti-replay',
            'msgAuthoritativeEngineTime': '4B  seconds since boot — replay window ±150s',
            'msgUserName': 'string  USM username',
            'msgAuthenticationParameters': '12B  HMAC-MD5 or HMAC-SHA MAC',
            'msgPrivacyParameters': '8B  AES-IV or DES-IV',
            'PDU': 'encapsulated v2c-style PDU (plain or AES/DES encrypted)',
            'Auth protocols': 'HMAC-MD5(weak) HMAC-SHA HMAC-SHA-256 HMAC-SHA-384 HMAC-SHA-512',
            'Priv protocols': 'DES(56b weak) AES-128 AES-192 AES-256',
            'CAUTION': 'MD5 and DES cryptographically broken — use SHA-256+AES-128 minimum; NTP sync required (±150s window); Discovery uses empty credentials; protect with VACM',
        },
        applications='Secure network management requiring authenticated+encrypted SNMP',
    ),

    "udp_tftp": dict(
        name='TFTP — Trivial File Transfer Protocol (RFC 1350)',
        transport='UDP/69 initial; transfer uses ephemeral ports; 512B blocks stop-and-wait',
        status='IETF Standard — RFC 1350 (base) RFC 2347 (options) RFC 2348 (blocksize) RFC 2349 (timeout+tsize)',
        description='TFTP is minimal file transfer with no authentication, used for PXE booting and device firmware upgrade.',
        header_bytes=4,
        fields={
            'Opcode': '2B  1=RRQ 2=WRQ 3=DATA 4=ACK 5=ERROR 6=OACK',
            '── RRQ/WRQ ──': 'Opcode(2B)+Filename(string+0x00)+Mode(string+0x00)+[Options]',
            'Filename': 'null-terminated ASCII filename',
            'Mode': "'netascii' or 'octet' (binary) or 'mail'(deprecated)",
            'blksize': 'RFC 2348 option: block size 8-65464B (default 512B)',
            'timeout': 'RFC 2349 option: retransmit timeout 1-255s (default 5s)',
            'tsize': 'RFC 2349 option: transfer size in bytes',
            '── DATA ──': 'Opcode(2B=3)+Block#(2B)+Data(0-512B or blksize)',
            'Block#': '2B  1-65535 wrapping; last block <max_size = EOF',
            '── ACK ──': 'Opcode(2B=4)+Block#(2B)',
            '── ERROR ──': 'Opcode(2B=5)+ErrorCode(2B)+ErrMsg(string+0x00)',
            'Error Codes': '0=Undefined 1=FileNotFound 2=AccessViolation 3=DiskFull 4=IllegalOp 5=UnknownTID 6=FileExists 7=NoSuchUser',
            'CAUTION': 'No authentication or encryption — never use over untrusted networks; server exposes files; PXE boot via TFTP can be hijacked; firewall UDP/69 to trusted segments only',
        },
        applications='PXE network booting, switch/router firmware upgrade, legacy config backup',
    ),

    "udp_syslog": dict(
        name='Syslog — System Logging Protocol (RFC 5424)',
        transport='UDP/514 (legacy unencrypted) TCP/514 or TLS/6514 (reliable/secure)',
        status='IETF Standard — RFC 5424 (format) RFC 5426 (UDP) RFC 5425 (TLS) RFC 6587 (TCP framing)',
        description='Syslog transports log messages to a central collector. UDP/514 is fire-and-forget. RFC 5424 defines structured format; BSD syslog is RFC 3164.',
        header_bytes=0,
        fields={
            'PRIORITY': '<PRI> = Facility(0-23)×8 + Severity(0-7); e.g. <134>=Facility16(local0) Severity6(info)',
            'Facility': '0=kern 1=user 2=mail 3=daemon 4=auth 5=syslog 9=cron 10=authpriv 16-23=local0-7',
            'Severity': '0=Emergency 1=Alert 2=Critical 3=Error 4=Warning 5=Notice 6=Info 7=Debug',
            'VERSION': '1=RFC 5424',
            'TIMESTAMP': "RFC 3339: 2024-01-15T10:30:00.123456+00:00 or '-'",
            'HOSTNAME': 'max 255 chars FQDN or IP',
            'APP-NAME': 'max 48 chars application name',
            'PROCID': "max 128 chars PID or '-'",
            'MSGID': 'max 32 chars message type ID',
            'STRUCTURED-DATA': "[element-id param-name=value ...] or '-'",
            'MSG': 'UTF-8 message text',
            'BSD Syslog': 'RFC 3164: <PRI>TIMESTAMP HOSTNAME APP: MSG (max 1024B, no structured data)',
            'CAUTION': 'UDP/514 unencrypted+unauthenticated — on-path attacker injects/modifies logs; use TLS/6514 with mutual auth for compliance; UDP provides no delivery guarantee; log injection via unsanitised user input',
        },
        applications='Centralised log collection from network devices, servers, firewalls, IDS/IPS',
    ),

    "udp_rtp": dict(
        name='RTP — Real-time Transport Protocol (RFC 3550)',
        transport='UDP/dynamic even ports (RTCP on next odd port) typically 16384-32767; SRTP for secure',
        status='IETF Standard — RFC 3550 RFC 3711 (SRTP) RFC 4585 (RTCP-FB) RFC 3264 (SDP offer/answer)',
        description='RTP carries real-time audio/video with sequence numbers and timestamps for jitter compensation. SDP negotiates payload types. SRTP adds AES encryption.',
        header_bytes=12,
        fields={
            'V': '2b  version=2 always',
            'P': '1b  padding bytes at end',
            'X': '1b  extension header follows fixed header',
            'CC': '4b  CSRC count',
            'M': '1b  marker — end-of-talkspurt or video frame boundary',
            'PT': '7b  payload type — dynamic mapping via SDP',
            'Common PTs': '0=PCMU(G.711µ) 8=PCMA(G.711A) 9=G.722 18=G.729 31=H.261 34=H.263 96-127=dynamic',
            'Sequence No': '2B  incremented per packet; detects loss and reorder',
            'Timestamp': '4B  first octet sampling instant; unit=codec clock (8000 G.711; 90000 video)',
            'SSRC': '4B  Synchronisation Source — random unique stream ID',
            'CSRC': '4B×CC  Contributing Sources for mixed streams',
            'Extension': 'Profile-Defined(2B)+Length(2B)+data×4B when X=1',
            'CAUTION': 'No authentication or encryption — use SRTP always; SSRC collision at 1/2^32; timestamp/sequence wrap must be handled; UDP loss normal — app must handle missing frames',
        },
        applications='VoIP, video conferencing, streaming media, WebRTC, IPTV',
    ),

    "udp_rtcp": dict(
        name='RTCP — RTP Control Protocol (RFC 3550)',
        transport='UDP/dynamic (RTP port+1) — 5% of session bandwidth',
        status='IETF Standard — RFC 3550 RFC 4585 (AVPF) RFC 5104 (CCMB)',
        description='RTCP carries statistics for RTP sessions: SR/RR report loss+jitter, SDES carries CNAME for A/V sync, BYE terminates sessions.',
        header_bytes=4,
        fields={
            'V': '2b  2',
            'P': '1b  padding',
            'RC/SC': '5b  reception/source report count',
            'PT': '1B  200=SR 201=RR 202=SDES 203=BYE 204=APP 205=RTPFB 206=PSFB',
            'Length': '2B  length in 32b words minus 1',
            '── SR ──': 'SSRC(4B)+NTP(8B)+RTP-TS(4B)+PktCount(4B)+OctetCount(4B)+ReportBlocks',
            'Report Block': 'SSRC(4B)+FracLost(1B)+CumLost(3B)+ExtSeq(4B)+Jitter(4B)+LSR(4B)+DLSR(4B)',
            'FracLost': '1B  fraction lost since last SR/RR (Q0.8)',
            'Jitter': '4B  interarrival jitter in RTP timestamp units',
            'LSR': '4B  compact NTP of last SR received (middle 32 bits)',
            'DLSR': '4B  delay since last SR in 1/65536 second units',
            '── SDES ──': 'SSRC+TLV items: 1=CNAME 2=NAME 3=EMAIL 5=LOC 6=TOOL 0=END',
            'CNAME': 'Canonical name — links audio+video SSRCs for lip-sync',
            '── NACK ──': 'RFC 4585: PID(2B)+BLP(2B) — requests retransmit of lost RTP packets',
            'CAUTION': 'RTCP bandwidth ≤5% session; CNAME must be globally unique random string RFC 7022; SSRC in RTCP must match RTP SSRC',
        },
        applications='QoS monitoring for VoIP/video, jitter/loss reporting, WebRTC statistics, lip-sync',
    ),

    "udp_radius": dict(
        name='RADIUS — Remote Authentication Dial-In User Service (RFC 2865/2866)',
        transport='UDP/1812 (auth) UDP/1813 (accounting) — legacy 1645/1646',
        status='IETF Standard — RFC 2865 (auth) RFC 2866 (acctg) RFC 5080 (impl) RFC 6614 (RADIUS/TLS)',
        description='RADIUS provides centralised AAA for 802.1X, VPN, Wi-Fi, and dial-up. NAS proxies authentication to RADIUS server.',
        header_bytes=20,
        fields={
            'Code': '1B  1=Access-Request 2=Access-Accept 3=Access-Reject 4=Accounting-Request 5=Accounting-Response 11=Access-Challenge 12=Status-Server 40=Disconnect-Request 43=CoA-Request 44=CoA-ACK 45=CoA-NAK',
            'Identifier': '1B  0-255 request/response correlation per NAS',
            'Length': '2B  total packet length',
            'Authenticator': '16B  Access-Req: random 16B | Response: MD5(Code+ID+Len+ReqAuth+Attrs+Secret)',
            'Attr 1': 'User-Name (string)',
            'Attr 2': 'User-Password — 16B blocks XOR with MD5(secret+RequestAuth)',
            'Attr 3': 'CHAP-Password: CHAP-ID(1B)+MD5-response(16B)',
            'Attr 4': 'NAS-IP-Address (4B)',
            'Attr 6': 'Service-Type: 1=Login 2=Framed 8=Authenticate-Only',
            'Attr 8': 'Framed-IP-Address — assigned IP for PPP',
            'Attr 25': 'Class — opaque; echoed in Accounting',
            'Attr 26': 'Vendor-Specific: VendorID(4B)+Type(1B)+Len(1B)+Data',
            'Attr 31': 'Calling-Station-Id — client MAC or calling number',
            'Attr 53': 'Message-Type for Access-Challenge',
            'Attr 61': 'NAS-Port-Type: 15=Ethernet 19=802.11',
            'Attr 79': 'EAP-Message — carries EAP frames RFC 3579',
            'Attr 80': 'Message-Authenticator — HMAC-MD5 REQUIRED for EAP',
            'CAUTION': 'Shared secret via MD5 — use long random ≥16 char secrets; UDP = no reliable delivery; Message-Authenticator MUST be present for EAP; use RADIUS/TLS RFC 6614 or IPsec; CoA allows mid-session policy change — authenticate source IP',
        },
        applications='802.1X port auth, WPA2-Enterprise Wi-Fi, VPN user auth, router/switch login',
    ),

    "udp_coap": dict(
        name='CoAP — Constrained Application Protocol (RFC 7252)',
        transport='UDP/5683 (CoAP) UDP/5684 (CoAPS/DTLS) — also TCP/5683 RFC 8323',
        status='IETF Standard — RFC 7252 RFC 7641 (Observe) RFC 7959 (Block) RFC 8974 (Extended Token)',
        description='CoAP is REST-like for constrained IoT devices. Binary 4-byte base header. Supports observe/notify for sensor streaming.',
        header_bytes=4,
        fields={
            'Ver': '2b  1',
            'T': '2b  0=CON(Confirmable) 1=NON 2=ACK 3=RST',
            'TKL': '4b  Token Length 0-8 bytes',
            'Code': '8b  class(3b).detail(5b)',
            'Request codes': '0.01=GET 0.02=POST 0.03=PUT 0.04=DELETE',
            '2xx codes': '2.01=Created 2.04=Changed 2.05=Content',
            '4xx codes': '4.00=BadReq 4.01=Unauth 4.04=NotFound 4.05=MethodNotAllowed',
            'Message ID': '2B  deduplication and ACK matching',
            'Token': '0-8B  end-to-end correlation',
            'Opt 6': 'Observe: 0=register 1=deregister RFC 7641',
            'Opt 11': 'Uri-Path — one option per path segment',
            'Opt 12': 'Content-Format: 0=text/plain 42=octet-stream 50=JSON 60=CBOR',
            'Opt 23': 'Block2: NUM+M+SZX — response block transfer',
            'Opt 27': 'Block1: request block transfer',
            'Payload': 'preceded by 0xFF marker if present',
            'CAUTION': 'Use OSCORE RFC 8613 or DTLS for security; Observe subscriptions hijackable without auth; CoAP amplification with spoofed source — use DTLS or token validation',
        },
        applications='IoT sensor data, device config, smart energy, IPSO smart objects',
    ),

    "udp_mdns": dict(
        name='mDNS — Multicast DNS (RFC 6762)',
        transport='UDP/5353 multicast 224.0.0.251 (IPv4) FF02::FB (IPv6) — link-local only',
        status='IETF Standard — RFC 6762 (mDNS) RFC 6763 (DNS-SD)',
        description='mDNS enables zero-config DNS on local networks without a server. Used by Bonjour (Apple), Avahi (Linux), Windows.',
        header_bytes=12,
        fields={
            'Header': 'same 12B as DNS but ID=0 for multicast queries',
            'QU bit': 'bit15 of QCLASS: 1=unicast response preferred',
            'Cache-flush': 'bit15 of RRCLASS in response — flush conflicting records',
            'Probe': 'QType=ANY before claiming name — conflict detection',
            'Announce': 'Unsolicited response after probe — gratuitous cache population',
            'TTL': '4500s (75min) for services; 120s for host records',
            'DNS-SD PTR': '_service._tcp.local. PTR ServiceName._service._tcp.local.',
            'DNS-SD SRV': 'ServiceName._service._tcp.local. SRV priority weight port hostname.local.',
            'DNS-SD TXT': 'ServiceName._service._tcp.local. TXT key=value pairs',
            'CAUTION': 'Unauthenticated — name conflict attacks possible; multicast storms on large LANs; mDNS proxy needed across subnets; leaks service topology; disable in enterprise',
        },
        applications='Printer/AirPlay/Chromecast discovery, IoT zero-conf, Apple Bonjour',
    ),

    "udp_llmnr": dict(
        name='LLMNR — Link-Local Multicast Name Resolution (RFC 4795)',
        transport='UDP/5355 multicast 224.0.0.252 (IPv4) FF02::1:3 (IPv6) — link-local only',
        status='IETF Informational — RFC 4795; Microsoft default in Windows Vista+',
        description='LLMNR resolves hostnames on local link when DNS unavailable. Same format as DNS but multicast. Widely abused in NTLM hash capture attacks.',
        header_bytes=12,
        fields={
            'ID': '2B  correlation (non-zero for queries)',
            'QR': '1b  0=query 1=response',
            'C': '1b  Conflict bit',
            'TC': '1b  Truncated',
            'T': '1b  Tentative — not yet authoritative',
            'RCODE': '4b  0=NoError 4=NotImpl',
            'QDCOUNT': '2B  exactly 1 (LLMNR queries have one question)',
            'Question': 'QNAME+QTYPE+QCLASS',
            'CAUTION': 'Heavily abused — Responder tool poisons LLMNR responses to capture NTLM hashes; DISABLE via GPO in all enterprise environments; NBT-NS+LLMNR are primary credential capture vectors in pen-tests',
        },
        applications='Windows name resolution fallback — DISABLE in enterprise environments',
    ),

    "udp_vxlan": dict(
        name='VXLAN — Virtual Extensible LAN (RFC 7348)',
        transport='UDP/4789 — ECMP via source port variation; outer UDP wraps inner Ethernet',
        status='IETF Standard — RFC 7348 (base) RFC 8365 (NVO3/EVPN) RFC 7637 (NVGRE comparison)',
        description='VXLAN encapsulates L2 Ethernet frames in UDP/IP creating overlay networks across L3 boundaries. 24-bit VNI = 16M segments. Datacenter fabric standard.',
        header_bytes=8,
        fields={
            'Flags': '1B  bit3(I)=VNI valid MUST be set; bits 0-2,4-7 reserved (RFC 7348)',
            'Reserved': '3B  0x000000',
            'VNI': '24b  Virtual Network Identifier',
            'Reserved2': '8b  0x00',
            'Inner Frame': 'complete Ethernet frame: inner Dst+Src MAC+EtherType+Payload',
            'Outer Ethernet': 'switch fabric or spine MACs',
            'Outer IP': 'Src=VTEP IP Dst=remote VTEP or multicast group',
            'Outer UDP': 'Src=entropy(14-bit) for ECMP Dst=4789',
            'VTEP': 'VXLAN Tunnel Endpoint — encapsulates/decapsulates',
            'BUM traffic': 'Broadcast/Unknown-unicast/Multicast flooded to multicast group per VNI',
            'EVPN control': 'RFC 8365: BGP EVPN replaces flood/learn with unicast MAC advertisements',
            'MTU overhead': '50B (14 eth + 20 IP + 8 UDP + 8 VXLAN) — inner MTU must be ≤ outer MTU - 50B',
            'CAUTION': 'MTU mismatch = silent black-holing; no built-in encryption — use IPsec between VTEPs; VNI spoofing possible without EVPN access control',
        },
        applications='Datacenter overlay, Kubernetes CNI (Flannel/Calico), OpenStack Neutron, VMware NSX',
    ),

    "udp_geneve": dict(
        name='Geneve — Generic Network Virtualisation Encapsulation (RFC 8926)',
        transport='UDP/6081 — flexible NVE encapsulation replacing VXLAN/NVGRE/STT',
        status='IETF Standard — RFC 8926 (2020)',
        description='Geneve unifies VXLAN, NVGRE, and STT. Flexible TLV options for metadata, OVS, and hardware offload hints.',
        header_bytes=8,
        fields={
            'Version': '2b  0',
            'Opt Length': '6b  options length in 4B words (0-63)',
            'O': '1b  OAM control packet — do not forward as data',
            'C': '1b  critical options — receiver must understand all C=1 options',
            'Reserved': '6b  0',
            'Protocol Type': '2B  EtherType of inner payload: 0x6558=Eth 0x0800=IPv4 0x86DD=IPv6',
            'VNI': '24b  Virtual Network Identifier',
            'Reserved2': '8b  0',
            'Options TLV': 'Class(2B)+Type(1B)+R(3b)+C(1b)+Length(5b)+Data',
            'Option Classes': '0x0100=Linux 0x0101=Open Virtual Network 0x0102=Transport Security',
            'Inner Frame': 'complete inner Ethernet frame',
            'MTU overhead': '8B fixed + 4×OptLen + outer headers',
            'CAUTION': 'C=1 options not understood MUST cause discard; test option compat before deploy; no built-in encryption — use IPsec or TLS overlay',
        },
        applications='AWS VPC networking, OVS/DPDK overlays, hardware NIC offload, service mesh',
    ),

    "udp_gtp_u": dict(
        name='GTP-U — GPRS Tunnelling Protocol User Plane (3GPP TS 29.281)',
        transport='UDP/2152 — user data between eNodeB/gNB and PGW/UPF in LTE/5G',
        status='3GPP Standard — TS 29.281 v17 (5G NR User Plane)',
        description='GTP-U tunnels UE IP packets between base stations and packet gateway. Each UE bearer has a unique TEID.',
        header_bytes=8,
        fields={
            'Version': '3b  1=GTPv1',
            'PT': '1b  1=GTP 0=GTP-prime',
            'Reserved': '1b  0',
            'E': '1b  Extension header present',
            'S': '1b  Sequence number present',
            'PN': '1b  N-PDU number present',
            'Msg Type': '1B  255=G-PDU(user data) 26=Error-Indication 31=Supported-Ext-Headers',
            'Length': '2B  payload length after mandatory 8B',
            'TEID': '4B  Tunnel Endpoint Identifier — unique per UE bearer; allocated by PGW/UPF',
            'Seq No': '2B  (if S=1)',
            'Ext Types': '0x85=PDU Session Container(5G) 0x20=PDCP PDU Number',
            'PDU Session Container': '5G: QFI(6b)+PDU Type(4b) — 0=DL 1=UL',
            'Inner IP': 'UE IPv4/IPv6 datagram',
            'Overhead': '28-36B (8 GTP + 8 UDP + 20 IP) reduces effective MTU',
            'CAUTION': 'TEID must match at both endpoints — mismatch = silent discard; GTP-U has no auth — use IPsec on S1-U/N3 in roaming; GTP scanning attacks can trigger fake bearer manipulation',
        },
        applications='LTE/5G mobile user plane — UE Internet traffic, VoLTE media',
    ),

    "udp_gtp_c": dict(
        name='GTP-C v2 — GPRS Tunnelling Protocol Control Plane (3GPP TS 29.274)',
        transport='UDP/2123 — signalling between MME/AMF and SGW/PGW/UPF',
        status='3GPP Standard — TS 29.274 v17 (EPC/5G GTPv2-C)',
        description='GTPv2-C handles session management signalling: Create/Modify/Delete Bearer and Session, TEID allocation.',
        header_bytes=8,
        fields={
            'Version': '3b  2=GTPv2',
            'P': '1b  Piggybacking',
            'T': '1b  TEID field present',
            'Msg Type': '1B  1=Echo-Req 2=Echo-Resp 32=Create-Session-Req 33=Create-Session-Resp 36=Delete-Session-Req 38=Create-Bearer-Req',
            'Length': '2B  excluding first 4B',
            'TEID': '4B  (if T=1) sender TEID',
            'Sequence No': '3B  request/response correlation',
            'IEs': 'Type(1B)+Length(2B)+Spare(4b)+Instance(4b)+Value',
            'IE Type 73': 'EPS Bearer ID',
            'IE Type 74': 'Bearer QoS',
            'IE Type 77': 'F-TEID: Interface-Type(6b)+IP+TEID',
            'IE Type 87': 'ULI: CGI/SAI/RAI/TAI/ECGI',
            'CAUTION': 'GTPv2-C no built-in auth — protect SGW/PGW interfaces with IPsec; TEID must not be predictable; GTP-C scanning can trigger fake bearer creation/deletion',
        },
        applications='LTE/5G session establishment, bearer QoS management, handover signalling',
    ),

    "udp_pfcp": dict(
        name='PFCP — Packet Forwarding Control Protocol (3GPP TS 29.244)',
        transport='UDP/8805 — between SMF and UPF in 5G SA',
        status='3GPP Standard — TS 29.244 v17',
        description='PFCP separates 5G control (SMF) from user plane (UPF). SMF installs PDR/FAR/QER rules into UPF.',
        header_bytes=4,
        fields={
            'Version': '3b  1=PFCP',
            'FO': '1b  Follow On',
            'MP': '1b  Message Priority present',
            'S': '1b  SEID present',
            'Msg Type': '1B  1=Heartbeat-Req 2=Heartbeat-Resp 50=Session-Establishment-Req 51=Session-Establishment-Resp 52=Session-Modification-Req 54=Session-Deletion-Req',
            'Length': '2B',
            'SEID': '8B  (if S=1) Session Endpoint Identifier',
            'Seq No': '3B  request/response correlation',
            'PDR IE': 'Create PDR: Precedence+PDI(UE-IP+SDF-filter)+FAR-ID+QER-ID',
            'FAR IE': 'Create FAR: Action(DROP/FORW/BUFF)+Forwarding-Parameters(dest-interface+outer-hdr)',
            'QER IE': 'Create QER: QER-ID+GBR(UL+DL)+MBR(UL+DL)+QFI',
            'URR IE': 'Create URR: Measurement-Method+Reporting-Triggers+Volume/Time-Threshold',
            'CAUTION': 'N4 interface MUST be protected by IPsec or management VRF; incorrect FAR = wrong traffic routing; QER misconfiguration causes GBR/MBR violations',
        },
        applications='5G UPF traffic routing, QoS enforcement, charging, deep packet inspection',
    ),

    "udp_sflow": dict(
        name='sFlow v5 — Sampled Flow Monitoring (RFC 3176 / sFlow.org)',
        transport='UDP/6343 — agent→collector, fire-and-forget',
        status='Industry Standard — RFC 3176 (v2/v4) sFlow.org spec v5',
        description='sFlow forwards sampled packets and interface counters to collector. Sampling (e.g. 1-in-1000) provides scalable visibility.',
        header_bytes=28,
        fields={
            'Version': '4B  5=sFlow v5',
            'IP Version': '4B  1=IPv4 2=IPv6',
            'Agent Address': '4B or 16B  switch/router IP',
            'Sub-Agent ID': '4B  for multi-agent devices',
            'Sequence No': '4B  monotonically increasing',
            'Uptime': '4B  agent uptime ms',
            'Num Samples': '4B  sample records in datagram',
            'Sample Records': 'Enterprise(20b)+Format(12b)+Length(4B)+Data',
            'Format 1': 'Flow Sample: Seq+SourceID+SamplingRate+SamplePool+Drops+Input+Output+Records',
            'Format 2': 'Counter Sample: Seq+SourceID+NumCounterRecords+Records',
            'Flow Record 1': 'Raw Packet Header: Protocol+FrameLen+Stripped+HeaderLen+Header(sampled bytes)',
            'Flow Record 3': 'IPv4: Length+Protocol+SrcIP+DstIP+SrcPort+DstPort+TCPFlags',
            'Counter Record 1': 'Generic Interface: IfIndex+Type+Speed+Dir+AdminStatus+OperStatus+InOctets+...',
            'CAUTION': 'Statistical sampling — traffic below threshold invisible; sampled headers may contain PII; UDP loss = silent data gap; ensure collector allows UDP/6343 from monitored devices only',
        },
        applications='Traffic analysis, bandwidth trending, anomaly detection, capacity planning',
    ),

    "udp_netflow": dict(
        name='NetFlow v9 / v5 — Cisco Flow Monitoring (RFC 3954)',
        transport='UDP/2055 (default) — v5 fixed format; v9 template-based',
        status='Cisco → IETF Informational RFC 3954 (v9); superseded by IPFIX RFC 7011',
        description='NetFlow exports flow records for network conversations. v9 uses templates for flexible fields.',
        header_bytes=20,
        fields={
            '── v9 Header ──': '',
            'Version': '2B  9',
            'Count': '2B  FlowSets in packet',
            'Sys Uptime': '4B  ms since boot',
            'UNIX Secs': '4B  current UTC',
            'Sequence No': '4B  total flows exported',
            'Source ID': '4B  exporting process',
            'FlowSet ID': '2B  0=Template 1=Options-Template 256+=Data(=Template-ID)',
            'Template Record': 'Template-ID(2B)+FieldCount(2B)+[FieldType(2B)+FieldLen(2B)]×N',
            'Field Types': '1=IN_BYTES 2=IN_PKTS 4=PROTOCOL 7=L4_SRC_PORT 8=IPV4_SRC_ADDR 11=L4_DST_PORT 12=IPV4_DST_ADDR 21=LAST_SWITCHED 22=FIRST_SWITCHED 27=IPV6_SRC_ADDR 61=DIRECTION',
            '── v5 Header ──': 'Version(2B=5)+Count(2B)+SysUptime+UnixSecs+UnixNsecs+FlowSeq+Engine+SamplingInterval',
            'v5 Flow': '28B: SrcAddr+DstAddr+NextHop+InIf+OutIf+dPkts+dOctets+First+Last+SrcPort+DstPort+TCPFlags+Prot+ToS+SrcAS+DstAS+SrcMask+DstMask',
            'CAUTION': 'UDP = no delivery guarantee; v5 IPv4-only; collector must cache v9 templates; clock skew affects flow timing; flows may be sampled — check Sampling Interval',
        },
        applications='Traffic accounting, billing, network forensics, capacity planning',
    ),

    "udp_ipfix": dict(
        name='IPFIX — IP Flow Information Export (RFC 7011)',
        transport='UDP/4739 or TCP/4739 or SCTP — TLS/DTLS RFC 7011 §8',
        status='IETF Standard — RFC 7011 (base) RFC 7012 (info model) RFC 7013 (guidelines)',
        description='IPFIX is the IETF standard superseding NetFlow v9. Template-based with IANA-registered Information Elements.',
        header_bytes=16,
        fields={
            'Version': '2B  10=IPFIX',
            'Length': '2B  total message length',
            'Export Time': '4B  Unix timestamp seconds',
            'Sequence No': '4B  record count for loss detection',
            'Observation Domain': '4B  exporting process domain',
            'Set ID': '2B  2=Template 3=Options-Template 256+=Data(=Template-ID)',
            'Template': 'TemplateID(2B)+FieldCount(2B)+[IANA-IE(15b)+Enterprise(1b)+FieldLen(2B)]×N',
            'Enterprise IE': 'bit15=1 then 4B PEN (Private Enterprise Number) follows',
            'Variable Len': '0xFF followed by 2B length for fields >254B',
            'Common IEs': '4=protocol 7=srcTransportPort 8=srcIPv4Addr 11=dstTransportPort 12=dstIPv4Addr 27=srcIPv6Addr 152=flowStartMs 153=flowEndMs',
            'CAUTION': 'UDP = no reliability; templates may be lost; enterprise IEs require IANA PEN; IPFIX does not encrypt flow data — use TLS transport',
        },
        applications='Carrier flow monitoring, SIEM input, forensics, billing, SD-WAN telemetry',
    ),

    "udp_bfd": dict(
        name='BFD — Bidirectional Forwarding Detection (RFC 5880/5881)',
        transport='UDP/3784 (control) UDP/3785 (echo) — both Tx and Rx same port',
        status='IETF Standard — RFC 5880 (base) RFC 5881 (IPv4/v6) RFC 5883 (multihop) RFC 7130 (LAG)',
        description='BFD provides sub-second failure detection for BGP, OSPF, IS-IS, and static routes. Hardware-assisted BFD <50ms.',
        header_bytes=24,
        fields={
            'Version': '3b  1',
            'Diag': '5b  0=NoDiag 1=ControlDetect 2=EchoFail 3=NeighborDown 4=FwdReset 5=PathDown',
            'Sta': '2b  0=AdminDown 1=Down 2=Init 3=Up',
            'P': '1b  Poll — expects Final in response',
            'F': '1b  Final — response to Poll',
            'C': '1b  Control Plane Independent',
            'A': '1b  Authentication present',
            'D': '1b  Demand mode',
            'Detect Mult': '1B  detection multiplier; failure = Detect-Mult × Rx-Interval without packet',
            'Length': '1B  24B (no auth) or 26-68B with auth',
            'My Discriminator': '4B  locally unique non-zero ID',
            'Your Discriminator': '4B  echoes peer discriminator (0 if not Up)',
            'Desired Min TX Interval': '4B  µs — minimum Tx interval wanted',
            'Required Min RX Interval': '4B  µs — minimum Rx interval supported',
            'Required Min Echo RX': '4B  µs — 0=echo not required',
            'Auth Type': '1B  1=Simple-Password 2=MD5 4=SHA1 5=Met-SHA1',
            'CAUTION': 'Your-Discriminator=0 means session not matched — cannot reach Up; BFD flap causes routing convergence — tune intervals carefully; C-bit requires hardware dataplane; BFD-LAG uses micro-BFD per member link RFC 7130',
        },
        applications='Sub-second failure detection for BGP, OSPF, IS-IS, MPLS LSP, static routes',
    ),

    "udp_pim": dict(
        name='PIM-SM — Protocol Independent Multicast Sparse Mode (RFC 7761)',
        transport='IP Protocol 103 (not UDP) dst 224.0.0.13 (All-PIM-Routers)',
        status='IETF Standard — RFC 7761 (PIM-SM) RFC 3973 (PIM-DM) RFC 5015 (PIM-BIDIR)',
        description='PIM builds multicast distribution trees. PIM-SM uses RP for shared trees then switches to SPT.',
        header_bytes=4,
        fields={
            'Version': '4b  2',
            'Type': '4b  0=Hello 1=Register 2=Register-Stop 3=Join/Prune 4=Bootstrap 5=Assert',
            'Reserved': '8b  0',
            'Checksum': '2B',
            'Hello Hold': 'Opt 1: HoldTime(2B) — 0=immediate delete',
            'Hello DR Prio': 'Opt 19: DR Priority(4B)',
            'Hello GenID': 'Opt 20: Generation ID(4B) — random, changed on restart',
            'J/P': 'UpstreamNbr+NumGroups(1B)+HoldTime(2B)+[GroupAddr+NumJoins+NumPrunes+Addrs]',
            'Assert': 'GroupAddr+SourceAddr+R(1b)+Metric-Pref(31b)+Metric(4B)',
            'Register': 'Border(1b)+Null(1b)+Reserved(30b)+inner-multicast-packet',
            'CAUTION': 'Assert winner based on metric-preference+metric — misconfigured route pref changes paths; Register messages contain full IP packet = large overhead; RP misconfiguration = multicast blackhole; SSM avoids RP requirement',
        },
        applications='IP multicast — IPTV, financial data, video conferencing, stock tickers',
    ),

    "udp_vrrp": dict(
        name='VRRP v3 — Virtual Router Redundancy Protocol (RFC 5798)',
        transport='IP Protocol 112 (not UDP) dst 224.0.0.18 (IPv4) FF02::12 (IPv6)',
        status='IETF Standard — RFC 5798 (VRRPv3) RFC 3768 (VRRPv2 IPv4 only)',
        description='VRRP provides default gateway redundancy. Master owns virtual IP; backup takes over on failure.',
        header_bytes=8,
        fields={
            'Version': '4b  2=VRRPv2 3=VRRPv3',
            'Type': '4b  1=Advertisement',
            'Virtual Rtr ID': '1B  VRID 1-255',
            'Priority': '1B  0=release; 1-254=backup; 255=IP owner; higher=preferred',
            'Count': '1B  number of virtual IP addresses',
            'Adver Interval': '12b(v3 centiseconds) 1B(v2 seconds) — advertisement interval',
            'Checksum': '2B',
            'Virtual IPs': '4B each IPv4 or 16B each IPv6',
            'Election': 'Higher priority wins; tie-break by primary IP (higher wins)',
            'Virtual MAC': 'VRRPv2: 0000.0C07.ACxx VRRPv3: 0000.5E00.01xx (xx=VRID)',
            'CAUTION': 'VRRPv2 auth deprecated — rogue device with priority 255 becomes master; use IPsec AH; VRID collision with HSRP causes election conflict; VRID 0 and 255 reserved',
        },
        applications='Default gateway redundancy for servers and network devices',
    ),

    "udp_hsrp": dict(
        name='HSRP — Hot Standby Router Protocol (RFC 2281 / Cisco)',
        transport='UDP/1985 dst 224.0.0.2 (HSRPv1) 224.0.0.102 (HSRPv2)',
        status='Cisco Proprietary — RFC 2281 (HSRPv1) Informational',
        description="HSRP is Cisco's FHRP. Active router owns virtual IP+MAC; standby takes over on failure.",
        header_bytes=20,
        fields={
            'Version': '1B  0=v1 1=v2',
            'Op Code': '1B  0=Hello 1=Coup 2=Resign',
            'State': '1B  0=Initial 1=Learn 2=Listen 4=Speak 8=Standby 16=Active',
            'Hellotime': '1B  seconds between hellos (default 3s)',
            'Holdtime': '1B  seconds before declaring active dead (default 10s)',
            'Priority': '1B  1-255; higher=preferred active (default 100)',
            'Group': '1B(v1: 0-255) or 2B(v2: 0-4095)',
            'Authentication': "8B  cleartext (default 'cisco') or MD5 extension",
            'Virtual IP': '4B  virtual router IPv4 address',
            'Virtual MAC': 'HSRPv1: 0000.0C07.ACxx  HSRPv2: 0000.0C9F.Fxxx',
            'CAUTION': "Default auth 'cisco' cleartext — change immediately; rogue device becomes active by announcing higher priority; preemption disabled by default in HSRP (unlike VRRP)",
        },
        applications='Cisco router/switch default gateway redundancy',
    ),

    "udp_sip": dict(
        name='SIP — Session Initiation Protocol (RFC 3261)',
        transport='UDP/5060 TLS/5061 — also TCP/5060; media on RTP/dynamic',
        status='IETF Standard — RFC 3261 (base) RFC 3262 (reliable prov) RFC 3263 (DNS) RFC 3264 (SDP)',
        description='SIP establishes, modifies, terminates multimedia sessions. Text-based like HTTP. Uses SDP for media negotiation.',
        header_bytes=0,
        fields={
            'Request-Line': 'METHOD SP Request-URI SP SIP/2.0 CRLF',
            'Methods': 'REGISTER INVITE ACK BYE CANCEL OPTIONS INFO REFER NOTIFY SUBSCRIBE MESSAGE UPDATE PRACK',
            'Status-Line': 'SIP/2.0 SP Status-Code SP Reason CRLF',
            '1xx': '100=Trying 180=Ringing 183=Session-Progress',
            '2xx': '200=OK',
            '3xx': '301=Moved-Permanently 302=Moved-Temporarily',
            '4xx': '401=Unauthorized 403=Forbidden 404=NotFound 407=Proxy-Auth-Req 486=Busy-Here',
            'Via': 'Via: SIP/2.0/UDP host;branch=z9hG4bK-value (MUST start z9hG4bK)',
            'From': 'From: sip:user@domain;tag=random',
            'To': 'To: sip:user@domain  (tag added in response to form dialog)',
            'Call-ID': 'globally unique dialog identifier',
            'CSeq': 'CSeq: 314159 INVITE — sequence per method',
            'Contact': 'direct address for subsequent requests',
            'Max-Forwards': 'integer decremented per hop (default 70)',
            'Content-Type': 'application/sdp for SDP body',
            'SDP Body': 'v=0 o= s= c= t= m=audio 49170 RTP/AVP 0',
            'CAUTION': 'SIP UDP unreliable for responses — use TCP or PRACK; SIP INVITEs over NAT need STUN/TURN/ICE; toll fraud via REGISTER hijacking; SIP scanning on 5060 common attack; use SBC to protect SIP exposure',
        },
        applications='VoIP, video calling, WebRTC signalling, unified communications, VoLTE',
    ),

    "udp_quic": dict(
        name='QUIC — IETF QUIC Transport (RFC 9000)',
        transport='UDP/443 (HTTP/3) or UDP/any — multiplexed streams over single UDP flow',
        status='IETF Standard — RFC 9000 (transport) RFC 9001 (TLS 1.3) RFC 9002 (loss recovery)',
        description='QUIC is TLS 1.3 + multiplexed streams + 0-RTT + connection migration, all over UDP. HTTP/3 (RFC 9114) runs on QUIC.',
        header_bytes=0,
        fields={
            'Header Form': '1b  1=Long Header(setup) 0=Short Header(data)',
            'Fixed bit': '1b  must be 1',
            'Long Pkt Type': '2b  0=Initial 1=0-RTT 2=Handshake 3=Retry',
            'Version': '4B  0x00000001=RFC9000; 0=Version-Negotiation',
            'Dst CID': '0-20B  Connection ID routing to correct connection',
            'Src CID': '0-20B  echoed as Dst CID in responses',
            'CRYPTO frame': '0x06 — TLS handshake data',
            'STREAM frame': '0x08-0x0F — stream ID+offset+length+data',
            'ACK frame': '0x02-0x03 — range-based acknowledgement',
            'MAX_DATA': '0x10 — connection-level flow control',
            'CONNECTION_CLOSE': '0x1C-0x1D — error code + reason',
            '0-RTT': 'first-flight data reusing previous TLS ticket — no extra RTT',
            'Connection ID': 'opaque identifier supporting NAT rebinding and connection migration',
            'CAUTION': 'Encryption prevents DPI/firewall inspection; UDP/443 may be blocked; 0-RTT replay-susceptible for non-idempotent ops; high CPU on software UDP path; loss recovery differs from TCP',
        },
        applications='HTTP/3, WebTransport, DNS-over-QUIC, MASQUE tunnelling, real-time gaming',
    ),

    "udp_dtls": dict(
        name='DTLS 1.3 — Datagram TLS (RFC 9147)',
        transport='UDP/any — same port as protected application (CoAPS=5684, IPFIX=4739)',
        status='IETF Standard — RFC 9147 (DTLS 1.3) RFC 6347 (DTLS 1.2)',
        description='DTLS adapts TLS 1.3 for datagrams. Handles reorder, loss, and replay without reliable delivery.',
        header_bytes=13,
        fields={
            'Content Type': '1B  20=ChangeCipherSpec 21=Alert 22=Handshake 23=AppData',
            'Version': '2B  0xFEFD=DTLS1.2; DTLS1.3 uses Unified Header',
            'Epoch': '2B(v1.2) or 2b(v1.3) — incremented on new keys',
            'Sequence No': '6B(v1.2) — per-record monotonic; sliding window anti-replay',
            'Length': '2B  fragment length',
            'Cookie': 'HelloVerifyRequest — stateless cookie prevents IP-spoofed handshake flood',
            'Fragment': 'Offset(3B)+Length(3B)+Data — handshake fragmentation across records',
            'Anti-replay': '64-record sliding window per epoch',
            'CAUTION': 'Handshake multiple RTTs — not for time-critical bootstrap; DTLS 1.2 with CBC vulnerable to BEAST — use GCM; cookie exchange required when ClientHello large; epoch sequence management critical for connection state',
        },
        applications='CoAPS, WebRTC DTLS-SRTP key negotiation, IPFIX security, 6LoWPAN',
    ),

    "udp_wireguard": dict(
        name='WireGuard — Modern VPN (Donenfeld 2017 / Linux kernel 5.6+)',
        transport='UDP/51820 (default configurable) — opaque encrypted datagrams',
        status='De Facto Standard — Linux kernel 5.6+ (2020); not IETF RFC but widely adopted',
        description='WireGuard VPN using Curve25519, ChaCha20-Poly1305, BLAKE2s. Noise protocol handshake. Minimal 4000 LOC attack surface.',
        header_bytes=4,
        fields={
            'Message Type': '4B  1=Initiation 2=Response 3=Cookie-Reply 4=Data',
            '── Initiation ──': 'sender_index(4B)+ephemeral(32B)+static(48B)+timestamp(28B)+MAC1(16B)+MAC2(16B)=148B',
            'sender_index': '4B  randomly chosen per session',
            'ephemeral': '32B  Curve25519 ephemeral public key',
            'encrypted_static': '48B  AEAD of initiator static public key',
            'encrypted_timestamp': '28B  TAI64N timestamp — replay prevention',
            'MAC1': '16B  BLAKE2s(peer_pubkey, msg) — cookie validation',
            '── Response ──': 'sender_index(4B)+receiver_index(4B)+ephemeral(32B)+nothing(16B)+MAC1+MAC2=92B',
            '── Data ──': 'receiver_index(4B)+counter(8B)+encrypted_inner_IP+tag(16B)',
            'counter': '8B  monotonic anti-replay',
            'Key exchange': 'Noise_IKpsk2 — 1-RTT X25519 ECDH',
            'Rekeying': 'After 3 min or 2^60 packets',
            'Stealth': 'No response to unauthorised datagrams — port appears closed',
            'CAUTION': 'Both-sides-NAT requires persistent keepalive 25s; out-of-band key exchange required; 1-RTT means first packet after idle needs re-handshake',
        },
        applications='Modern VPN — cloud access, remote work, IoT VPN, Kubernetes network policy',
    ),

    "udp_rip": dict(
        name='RIPv2 — Routing Information Protocol v2 (RFC 2453)',
        transport='UDP/520 dst 224.0.0.9 (multicast) or broadcast',
        status='IETF Standard — RFC 2453 (RIPv2) RFC 1058 (RIPv1) RFC 2080 (RIPng)',
        description='RIP is distance-vector with hop count metric. RIPv2 adds subnet mask, next-hop, multicast. Max 15 hops.',
        header_bytes=4,
        fields={
            'Command': '1B  1=Request 2=Response',
            'Version': '1B  2=RIPv2',
            'Zero': '2B  0x0000',
            'Auth Entry': 'AFI=0xFFFF+RouteTag=AuthType(2=Simple 3=MD5)+16B auth (if first RTE)',
            'RTE': 'AddressFamily(2B=2)+RouteTag(2B)+IPAddr(4B)+Mask(4B)+NextHop(4B)+Metric(4B)',
            'Address Family': '2=IP; 0xFFFF=Authentication',
            'Subnet Mask': '4B  network mask (RIPv1 was classful — no mask)',
            'Next Hop': '4B  0.0.0.0=use originating router',
            'Metric': '4B  1-15=reachable; 16=infinity',
            'CAUTION': 'Without auth trivially spoofable — rogue router poisons table with metric=1; use MD5 auth; 30s update interval = up to 3.5min convergence; filter default-route injection from RIP',
        },
        applications='Small branch routing, legacy embedded systems, simple lab networks',
    ),

    "udp_ripng": dict(
        name='RIPng — RIP for IPv6 (RFC 2080)',
        transport='UDP/521 dst FF02::9 (multicast) — link-local source only',
        status='IETF Standard — RFC 2080',
        description='RIPng extends RIPv2 for IPv6. Link-local addresses for updates, no auth field (relies on IPsec AH).',
        header_bytes=4,
        fields={
            'Command': '1B  1=Request 2=Response',
            'Version': '1B  1=RIPng',
            'Zero': '2B  0x0000',
            'RTE': 'IPv6-Prefix(16B)+RouteTag(2B)+PrefixLen(1B)+Metric(1B)',
            'Metric': '1B  1-15; 16=infinity',
            'Next Hop RTE': 'special RTE: Prefix=IPv6-link-local Metric=0xFF — applies to subsequent RTEs',
            'CAUTION': 'Relies on IPsec for auth — no built-in auth field; source MUST be link-local; filter default-route redistribution',
        },
        applications='IPv6 routing in small/stub networks, CPE devices',
    ),

    "udp_ssdp": dict(
        name='SSDP — Simple Service Discovery Protocol (UPnP UDA 2.0)',
        transport='UDP/1900 multicast 239.255.255.250 (IPv4) FF05::C (IPv6)',
        status='UPnP Forum — UDA 2.0; IETF rejected original submission',
        description='SSDP is UPnP device/service discovery. HTTP-like over UDP multicast.',
        header_bytes=0,
        fields={
            'Request Line': 'M-SEARCH * HTTP/1.1 (discover) | NOTIFY * HTTP/1.1 (announce)',
            'HOST': '239.255.255.250:1900',
            'MAN': 'M-SEARCH: ssdp:discover',
            'MX': 'M-SEARCH: max seconds to wait (1-120)',
            'ST': 'Search Target: ssdp:all | upnp:rootdevice | uuid:UUID | urn:schemas-upnp-org:device:type:ver',
            'NT': 'NOTIFY Notification Type',
            'NTS': 'ssdp:alive | ssdp:byebye | ssdp:update',
            'USN': 'Unique Service Name: uuid:UUID::upnp:rootdevice',
            'LOCATION': 'HTTP URL of UPnP device description XML',
            'CACHE-CONTROL': 'max-age=<seconds>',
            'SERVER': 'OS/ver UPnP/2.0 product/ver',
            'CAUTION': 'SSDP amplification DDoS — M-SEARCH to 239.255.255.250 → devices respond to spoofed source; block UDP/1900 at perimeter; UPnP NAT port-mapping without auth — malware abuses; disable on all routers unless needed',
        },
        applications='Home/SMB device discovery — printers, media servers, smart TVs, gaming consoles',
    ),

    "udp_netbios_ns": dict(
        name='NetBIOS Name Service — NBNS (RFC 1002)',
        transport='UDP/137 broadcast or WINS server unicast',
        status='IETF Standard — RFC 1001/1002; superseded by DNS; Microsoft WINS extension',
        description='NBNS resolves NetBIOS names (≤15 char) to IP addresses. B-node=broadcast; P-node=WINS; H-node=WINS then broadcast.',
        header_bytes=12,
        fields={
            'Name_TRN_ID': '2B  transaction ID',
            'FLAGS': '2B  R(1b)+Opcode(4b)+AA+TC+RD+RA+Broadcast(1b)+RCODE(4b)',
            'Opcode': '4b  0=Query 5=Registration 6=Release 7=WACK 8=Refresh',
            'Question Name': '34B NetBIOS encoded: 0x20+32B(2-char per nibble)+0x00',
            'Type': 'NB=0x0020(name) NBSTAT=0x0021(node status)',
            'RR Data': 'NB: flags(2B)+IP(4B) | NBSTAT: node list',
            'Name suffix': '16th byte: 0x00=Workstation 0x03=Messenger 0x20=FileServer 0x1C=DomainControllers',
            'CAUTION': 'NBNS poisoning primary attack vector — Responder intercepts queries returning attacker IP to capture NTLM hashes; disable via registry NbtType=2 or DHCP Opt46; NEVER expose UDP/137 to untrusted segments',
        },
        applications='Legacy Windows name resolution — disable in modern enterprise environments',
    ),

    "udp_netbios_dgm": dict(
        name='NetBIOS Datagram Service (RFC 1002)',
        transport='UDP/138 broadcast',
        status='IETF Standard — RFC 1001/1002; legacy Windows',
        description='NetBIOS Datagram carries connectionless data for browser service and mailslot messages.',
        header_bytes=14,
        fields={
            'Msg Type': '1B  0x10=Direct-Unique 0x11=Direct-Group 0x12=Broadcast 0x13=Error',
            'Flags': '1B  SNT(2b)=node type + F(1b)=first frag + MORE(1b)',
            'DGM_ID': '2B  datagram ID for fragment reassembly',
            'Source IP': '4B',
            'Source Port': '2B  138',
            'DGM_Length': '2B',
            'Packet_Offset': '2B  fragment offset',
            'Source Name': '34B NetBIOS encoded sender',
            'Dest Name': '34B NetBIOS encoded destination',
            'User Data': 'SMB browse frames, mailslot messages',
            'CAUTION': 'UDP/138 broadcasts reveal internal domain structure; browser service elections cause storms; disable NetBIOS over TCP/IP where not needed',
        },
        applications='Windows workgroup browser service, NetBIOS mailslot messages (legacy)',
    ),

    "udp_igmp": dict(
        name='IGMPv3 — Internet Group Management Protocol (RFC 3376)',
        transport='IP Protocol 2 (not UDP) TTL=1 link-local; dst 224.0.0.1 or group',
        status='IETF Standard — RFC 3376 (IGMPv3) RFC 2236 (IGMPv2) RFC 1112 (IGMPv1)',
        description='IGMP manages multicast group membership. IGMPv3 adds SSM supporting include/exclude source lists.',
        header_bytes=8,
        fields={
            'Type': '1B  0x11=Query 0x16=v2-Report 0x17=v2-Leave 0x22=v3-Report',
            'Max Resp Code': '1B  query max response time in 1/10-sec units',
            'Checksum': '2B  IP checksum',
            'Group Addr': '4B  0.0.0.0=general-query; group-specific for group query',
            '── v3 Query ──': 'S(1b)+QRV(3b)+QQIC(1B)+Num-Sources(2B)+[SourceAddrs]',
            'S bit': 'Suppress Router-Side Processing',
            'QRV': 'Querier Robustness Variable (default 2)',
            '── v3 Report ──': 'Reserved(2B)+Num-Group-Records(2B)+[GroupRecord]',
            'Group Record': 'RecordType(1B)+AuxLen(1B)+NumSrc(2B)+McastAddr(4B)+[Src]+[Aux]',
            'Record Types': '1=IS_INCLUDE 2=IS_EXCLUDE 3=TO_INCLUDE 4=TO_EXCLUDE 5=ALLOW 6=BLOCK',
            'CAUTION': 'IGMP snooping required — without it multicast=broadcast; missing querier causes group expiry; IGMP can join attacker multicast groups without access control',
        },
        applications='IP multicast membership — IPTV STBs, video conferencing join/leave',
    ),

    "udp_mld": dict(
        name='MLDv2 — Multicast Listener Discovery for IPv6 (RFC 3810)',
        transport='ICMPv6 (IP Protocol 58) link-local Hop-Limit=1; Router Alert option required',
        status='IETF Standard — RFC 3810 (MLDv2) RFC 2710 (MLDv1)',
        description='MLD is the IPv6 equivalent of IGMP. MLDv2 adds SSM source-specific include/exclude.',
        header_bytes=8,
        fields={
            'ICMPv6 Type': '1B  130=Query 131=v1-Report 132=v1-Done 143=v2-Report',
            'Code': '1B  0',
            'Checksum': '2B',
            'Max Resp': '2B  milliseconds',
            'Reserved': '2B  0',
            'Multicast': '16B  ::=general-query; specific group for group query',
            '── MLDv2 Query ──': 'S(1b)+QRV(3b)+QQIC(1B)+NumSrc(2B)+[Sources]',
            '── MLDv2 Report ──': 'Reserved(2B)+NumMAR(2B)+[Multicast-Addr-Record]',
            'MAR': 'RecordType(1B)+AuxLen(1B)+NumSrc(2B)+IPv6Addr(16B)+[Src]',
            'Record Types': '1=IS_INCLUDE 2=IS_EXCLUDE 3=TO_INCLUDE 4=TO_EXCLUDE 5=ALLOW 6=BLOCK',
            'Router Alert': 'IPv6 Hop-by-Hop Opt Type=5 Value=0x0000 — MUST be present',
            'CAUTION': 'Router Alert MUST be present; MLD Snooping required on switches; FF02::/16 well-known addrs MUST NOT be joined by hosts',
        },
        applications='IPv6 multicast membership — IPTV, mDNS (FF02::FB), routing protocols',
    ),

    "udp_kerberos": dict(
        name='Kerberos v5 — Network Authentication (RFC 4120)',
        transport='UDP/88 (<1500B) TCP/88 (larger msgs required for large PAC)',
        status='IETF Standard — RFC 4120 (Kerberos v5) RFC 4121 (GSS-API) RFC 6113 (FAST)',
        description='Kerberos provides mutual authentication via time-limited tickets. KDC issues TGT and service tickets. Used by Active Directory.',
        header_bytes=0,
        fields={
            'Encoding': 'ASN.1 DER for all messages',
            'AS-REQ (10)': 'KDC-OPTIONS+CNAME+REALM+SNAME+TILL+NONCE+ETYPE+[Preauth]',
            'AS-REP (11)': 'PVNO+CREALM+CNAME+TICKET+ENC-PART(encrypted with client key)',
            'TGS-REQ (12)': 'AP-REQ(TGT+Authenticator)+REALM+SNAME+TILL+NONCE',
            'TGS-REP (13)': 'same structure as AS-REP with service ticket',
            'AP-REQ (14)': 'TICKET+AUTHENTICATOR(encrypted with session key)',
            'AP-REP (15)': 'mutual authentication confirmation',
            'KRB-ERROR (30)': 'Error-Code+REALM+SNAME+E-TEXT+E-DATA',
            'TICKET': 'ENC-PART(service key): flags+sesskey+crealm+cname+transited+authtime+starttime+endtime',
            'Preauth': 'PA-ENC-TIMESTAMP (type=2): encrypted timestamp prevents AS-REP roasting',
            'PAC': 'Privilege Attribute Certificate — MS extension with group memberships',
            'Error Codes': '6=C_PRINCIPAL_UNKNOWN 18=CLIENT_REVOKED 23=KEY_EXPIRED 25=PREAUTH_FAILED',
            'CAUTION': 'Kerberoasting: TGS ticket encrypted with service key = offline crackable; AS-REP Roasting: no preauth = AS-REP offline attack; golden ticket: forged TGT via krbtgt hash; clock skew ±5min enforced — NTP critical; large PAC requires TCP/88',
        },
        applications='Active Directory SSO, NFS v4, SSH GSSAPI, SMTP AUTH, database SSO',
    ),

    "udp_ldap": dict(
        name='LDAP — Lightweight Directory Access Protocol (RFC 4511)',
        transport='UDP/389 (CLDAP DC-discovery only) TCP/389 TLS/636 (LDAPS)',
        status='IETF Standard — RFC 4511 (LDAPv3) RFC 4513 (auth) RFC 4517 (syntax)',
        description='LDAP accesses X.500 directory services for user auth, authorisation, and lookup. AD, OpenLDAP, FreeIPA common implementations.',
        header_bytes=0,
        fields={
            'Encoding': 'ASN.1 BER for all messages',
            'MessageID': 'INTEGER 1-2147483647 — correlates request to response',
            'ProtocolOps': 'bind(0/1) unbind(2) search(3/4/5/6) modify(7/8) add(9/10) del(11/12) modDN(13/14) compare(15/16) abandon(17) extended(23/24)',
            'bindRequest': 'Version(3)+DN+Auth(simple=password | sasl=mechanism+creds)',
            'searchRequest': 'BaseObject+Scope(0=base 1=one 2=sub)+SizeLimit+TimeLimit+Filter+Attributes',
            'Filter': 'and/or/not/equalityMatch/substrings/greaterEqual/lessEqual/present/approx',
            'searchResEntry': 'DN+Attributes: type+SET-OF-values',
            'LDAP DN': 'cn=user,ou=people,dc=example,dc=com',
            'modifyRequest': 'Object+SEQUENCE OF: op(add/del/replace)+type+values',
            'Paged Results': 'Control OID 1.2.840.113556.1.4.319: pageSize+cookie',
            'CLDAP UDP': 'DC discovery via Netlogon(1.2.840.113556.1.4.1781) on UDP/389 only',
            'CAUTION': 'Simple bind sends password cleartext over TCP — use LDAPS/636 or STARTTLS; LDAP injection via unsanitised filters; anonymous bind exposing directory common misconfiguration; AD rootDSE reveals domain info to unauthenticated users; LDAP referral chasing can redirect to attacker server',
        },
        applications='Active Directory auth, LDAP address books, PKI cert lookup, POSIX user management',
    ),

    "udp_wol_udp": dict(
        name='WoL over UDP (de facto standard — UDP/9)',
        transport='UDP/9 (discard) or UDP/7 (echo) — subnet directed broadcast or 255.255.255.255',
        status='De facto standard — IEEE 802 defines magic packet; UDP encapsulation is convention',
        description='WoL magic packets sent over UDP/9 to cross routers via directed subnet broadcast. Same magic packet as EtherType 0x0842.',
        header_bytes=0,
        fields={
            'UDP Dst Port': '9 (discard) or 7 (echo) — both work',
            'Dst IP': 'subnet directed broadcast (192.168.1.255) or 255.255.255.255',
            'Sync Stream': '6B  0xFF×6',
            'Target MAC×16': '96B  destination MAC repeated 16 times',
            'SecureOn': 'optional 4B or 6B password',
            'Total payload': '102B or 106/108B with password',
            'CAUTION': 'Directed broadcast must be enabled on router (ip directed-broadcast on Cisco); many routers block by default; unlike EtherType 0x0842 this traverses routers; target NIC must have WoL enabled in BIOS',
        },
        applications='Remote power-on across routed networks — IT asset management',
    ),

    "udp_lisp": dict(
        name='LISP — Locator/ID Separation Protocol (RFC 9301)',
        transport='UDP/4341 (data) UDP/4342 (control Map-Register/Notify)',
        status='IETF Standard — RFC 9301 (arch) RFC 9302 (data) RFC 9303 (control)',
        description='LISP separates endpoint identity (EID) from routing locator (RLOC). Used for IP mobility, multihoming, and DFZ table reduction.',
        header_bytes=8,
        fields={
            'N bit': '1b  nonce present',
            'L bit': '1b  RLOC-probe echo',
            'E bit': '1b  echo nonce',
            'V bit': '1b  Map-Version present',
            'I bit': '1b  Instance ID present (24b VNI)',
            'Nonce': '24b or 64b  liveliness probe',
            'LISP VNI': '24b  Virtual Network Instance for multitenancy',
            'Inner Hdr': 'original IP header + payload',
            'Map-Register': 'Type=3+Nonce+Key-ID+AuthData+TTL+EID-Records',
            'Map-Request': 'Type=1+A+M+P+Nonce+SourceEID+ITR-RLOCs+EID-Records',
            'Map-Reply': 'Type=2+P+Nonce+EID-Records with RLOC-Records',
            'Overhead': '36B (8 LISP+8 UDP+20 IP) — MTU must account for overhead',
            'CAUTION': 'EID→RLOC cache TTL must be respected to avoid stale black holes; PxTR needed for LISP↔non-LISP interop; UDP checksum SHOULD be enabled',
        },
        applications='VM mobility, multi-tenant overlay, SD-WAN, DFZ routing table reduction',
    ),

    "udp_nfs": dict(
        name='NFS v3/v4 — Network File System (RFC 1813/7530)',
        transport='UDP/2049 (NFSv3) TCP/2049 (NFSv4 TCP-only) via ONC RPC RFC 5531',
        status='IETF Standard — RFC 1813 (NFSv3) RFC 7530 (NFSv4.1) RFC 8166 (RDMA)',
        description='NFS provides distributed file access. NFSv3 supports UDP+TCP. NFSv4 is TCP-only with stateful semantics, ACLs, and Kerberos.',
        header_bytes=0,
        fields={
            'RPC XID': '4B  transaction ID',
            'Message Type': '4B  0=Call 1=Reply',
            'RPC Version': '4B  2',
            'Program': '4B  100003=NFS 100005=MOUNT 100021=NLM',
            'NFS Version': '4B  3=NFSv3 4=NFSv4',
            'Procedure': 'NFSv3: 1=GETATTR 3=LOOKUP 4=ACCESS 6=READ 7=WRITE 8=CREATE 12=REMOVE 14=RENAME 16=READDIR',
            'Credentials': 'AUTH_SYS: stamp+machine+uid+gid+gids | AUTH_GSSAPI: GSS token',
            'GETATTR': 'FileHandle→fattr3: type+mode+nlink+uid+gid+size+atime+mtime+ctime',
            'READ': 'FileHandle+Offset(8B)+Count(4B)→data+EOF',
            'WRITE': 'FileHandle+Offset(8B)+Count(4B)+Stable(0=UNSTABLE 2=FILE_SYNC)+Data',
            'FileHandle': 'opaque 0-64B server-defined — stable across reboots (NFSv3)',
            'NFSv4 COMPOUND': 'sequence of operations in single RPC: SEQUENCE+PUTFH+READ',
            'CAUTION': 'NFSv3 AUTH_SYS trusts client UID/GID — root client accesses all files; use Kerberos AUTH_GSSAPI in production; NFS root_squash maps root to nobody but other UID impersonation still possible; NFSv4 requires Kerberos for security',
        },
        applications='Shared storage for Linux clusters, VMware NFS datastores, home directory mounting',
    ),

}

NON_IP_L4_REGISTRY.update(UDP_L4_REGISTRY)


# ════════════════════════════════════════════════════════════════════════════
# EXTENDED ACTIVE PROTOCOL REGISTRY — IP, TCP, and other transport protocols
# Sources: IETF RFCs, 3GPP, OpenConfig, Cisco, ITU, CNCF
# ════════════════════════════════════════════════════════════════════════════

EXTENDED_ACTIVE_L4_REGISTRY: dict[str, dict] = {
    "udp_diameter": dict(
        name='Diameter — Next-Gen AAA Protocol (RFC 6733)',
        transport='TCP/3868 or SCTP/3868 (recommended) UDP/3868 (base exchange only); TLS/5868',
        status='IETF Standard — RFC 6733 (base), RFC 7155 (NAS), RFC 4006 (Credit-Control), RFC 5779 (MIPv6)',
        description='Diameter is the successor to RADIUS providing AAA for mobile networks (3GPP Cx/Rx/Gx/Gy/S6a interfaces), IMS, and EPC. Uses peer-to-peer model with capabilities exchange. Mandatory AVP support per application.',
        header_bytes=20,
        fields={
            'Version': '1B  1',
            'Message Length': '3B  total length including header',
            'Command Flags': '1B  R(1b)=Request/Answer + P(1b)=Proxiable + E(1b)=Error + T(1b)=Retransmit',
            'Command Code': '3B  257=CER/CEA 258=RAR/RAA 265=AAR/AAA 271=ACR/ACA 272=CC-Request/Answer 280=DWR/DWA 282=DPR/DPA 300=UAR/UAA 301=SAR/SAA 303=LIR/LIA 316=MIR/MIA 318=RTR/RTA',
            'Application ID': '4B  0=Base 1=NASREQ 4=Credit-Control 16777216=3GPP-Cx 16777217=3GPP-Sh 16777222=3GPP-Gx 16777238=3GPP-Rx 16777251=3GPP-S6a 16777252=3GPP-S13',
            'Hop-by-Hop ID': '4B  routing identifier; echoed in answer',
            'End-to-End ID': '4B  duplicate detection; NOT echoed (unlike H2H)',
            'AVP': 'Attribute-Value Pairs: Code(4B)+Flags(1B)+Length(3B)+[VendorID(4B)]+Value',
            'AVP Flags': 'V(1b)=VendorID present M(1b)=Mandatory P(1b)=Encrypted',
            'Common AVPs': '264=Origin-Host 296=Origin-Realm 293=Destination-Host 283=Destination-Realm 268=Result-Code 277=Auth-Request-Type 258=Auth-Application-Id 278=Auth-Session-State 415=CC-Request-Type 416=CC-Request-Number',
            'Result Codes': '2001=DIAMETER_SUCCESS 3001=DIAMETER_COMMAND_UNSUPPORTED 3002=DIAMETER_UNABLE_TO_DELIVER 3010=DIAMETER_REDIRECT_INDICATION 4001=DIAMETER_AUTHENTICATION_REJECTED 5001=DIAMETER_AVP_UNSUPPORTED 5012=DIAMETER_UNABLE_TO_COMPLY',
            '3GPP S6a': 'Authentication-Info-Request/Answer(AIR/AIA) + Update-Location-Req/Ans(ULR/ULA) — LTE attach',
            '3GPP Gx': 'Credit-Control-Request/Answer(CCR/CCA) — PCC policy and charging rules',
            '3GPP Rx': 'AA-Request/Answer — media component authorisation for IMS',
            'CER/CEA': 'Capabilities-Exchange for peer discovery: Origin-Host+Realm+Auth-Application-Id+Firmware-Revision',
            'DWR/DWA': 'Device-Watchdog heartbeat — detect silent peer failure',
            'CAUTION': 'Diameter has no built-in encryption — use TLS/DTLS or IPsec for all inter-domain links; AVP M-bit must be honoured — M=1 AVP not understood MUST cause DIAMETER_AVP_UNSUPPORTED; loop detection via Route-Record AVP; Diameter agents (proxy/relay/redirect) must inspect and potentially modify messages; 3GPP S6a HSS exposure is highest-value target for SS7-style attacks',
        },
        applications='3GPP LTE/5G EPC HSS, IMS CSCF, online charging (OCS), policy control (PCRF)',
    ),

    "udp_isakmp": dict(
        name='IKEv2 — Internet Key Exchange v2 (RFC 7296)',
        transport='UDP/500 (IKE) UDP/4500 (NAT-T IKE + ESP-in-UDP) — both bidirectional',
        status='IETF Standard — RFC 7296 (IKEv2), RFC 3947 (NAT-T), RFC 4303 (ESP), RFC 5282 (AES-GCM)',
        description='IKEv2 establishes IPsec SAs (Security Associations) with mutual authentication and key derivation. Phase 1 creates IKE_SA; Phase 2 creates CHILD_SA for ESP/AH traffic. Supports EAP, certificate, and pre-shared key authentication.',
        header_bytes=28,
        fields={
            'IKE SPI Initiator': '8B  randomly chosen non-zero value by initiator',
            'IKE SPI Responder': '8B  chosen by responder (0 in initial IKE_SA_INIT)',
            'Next Payload': '1B  type of first payload',
            'Version': '1B  high nibble=major(2) low nibble=minor(0) for IKEv2',
            'Exchange Type': '1B  34=IKE_SA_INIT 35=IKE_AUTH 36=CREATE_CHILD_SA 37=INFORMATIONAL',
            'Flags': '1B  bit5=RESPONSE bit4=VERSION bit3=INITIATOR',
            'Message ID': '4B  monotonically increasing; retransmit same ID',
            'Length': '4B  total IKE message length',
            '── Payloads ──': 'Payload Header: Next(1B)+CRITICAL(1b)+Reserved(7b)+Length(2B)',
            'SA Payload (33)': 'PROPOSAL: Num+Protocol(1=IKE 3=ESP 2=AH)+SPI-Size+Transform-Count+[SPI]+[Transforms]',
            'Transform': 'Type(1B: 1=ENCR 2=PRF 3=INTEG 4=DH 5=ESN)+Reserved+ID(2B)+[Attribute]',
            'ENCR IDs': '12=AES-CBC 20=AES-GCM-8 19=AES-GCM-12 18=AES-GCM-16 28=ChaCha20-Poly1305',
            'PRF IDs': '2=PRF-HMAC-SHA1 5=PRF-HMAC-SHA2-256 7=PRF-HMAC-SHA2-384 8=PRF-HMAC-SHA2-512',
            'INTEG IDs': '2=HMAC-SHA1-96 12=HMAC-SHA2-256-128 13=HMAC-SHA2-384-192 14=HMAC-SHA2-512-256',
            'DH Groups': '1=768b 2=1024b 14=2048b 19=ECDH-256 20=ECDH-384 21=ECDH-521',
            'KE Payload (34)': 'DH-Group(2B)+Reserved(2B)+Key-Exchange-Data',
            'Nonce Payload (40)': 'random nonce 16-256B',
            'IDi/IDr (35/36)': 'ID-Type(1B)+Reserved(3B)+ID-Data; types: 1=IPv4 2=FQDN 3=RFC822 11=IPv6 17=DER-ASN1-DN',
            'CERT Payload (37)': 'Encoding(1B)+Certificate-Data; 4=X.509-Sig 12=X.509-Hash-URL',
            'AUTH Payload (39)': 'Auth-Method(1B: 1=RSA-Sig 2=PSK 3=DSA 9=ECDSA-256 14=Digital-Sig)+Auth-Data',
            'TSi/TSr (44/45)': 'Traffic Selectors: Num(1B)+[Type(1B)+Len(2B)+Proto(1B)+Port-Range+Addr-Range]',
            'CAUTION': 'IKEv1 aggressive mode leaks PSK hash for offline cracking — use IKEv2 only; DH groups 1/2/5 broken — use group 14+ or ECDH; PSK must be ≥20 random chars; IKE_SA_INIT reveals responder existence — use anti-enumeration (RFC 7619 Puzzle); certificate revocation must be checked (OCSP/CRL); fragment IKE packets on small MTU links',
        },
        applications='IPsec VPN (site-to-site, remote access), strongSwan, Cisco IOS IPsec, iOS/Android VPN',
    ),

    "udp_natt": dict(
        name='IKEv2 NAT-T / ESP-in-UDP — NAT Traversal (RFC 3947/3948)',
        transport='UDP/4500 — IKE and ESP both move from 500 to 4500 when NAT detected',
        status='IETF Standard — RFC 3947 (IKE NAT-T), RFC 3948 (ESP-in-UDP)',
        description='NAT Traversal encapsulates ESP inside UDP/4500 so IPsec traffic survives NAT devices. IKEv2 detects NAT via NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP notify payloads.',
        header_bytes=4,
        fields={
            'Non-ESP Marker': '4B  0x00000000 — distinguishes IKE from ESP in UDP/4500',
            'IKE/ESP detect': 'If first 4B = 0x00000000 → IKE packet; else → ESP packet (SPI ≠ 0)',
            'ESP-in-UDP': 'UDP/4500 payload: SPI(4B)+SeqNo(4B)+IV+Ciphertext+ICV — standard ESP',
            'NAT_DETECTION': 'IKEv2 Notify types: 16388=NAT_DETECTION_SOURCE_IP 16389=NAT_DETECTION_DEST_IP',
            'NAT hash': 'SHA1(SPI-I+SPI-R+IP+Port) — if received hash differs, NAT detected',
            'Keepalive': '1B 0xFF — sent every 20-30s to keep NAT mapping alive',
            'Port float': 'After NAT detected both IKE and ESP float to UDP/4500',
            'CAUTION': 'NAT-T keepalive interval must be < NAT mapping timeout (typically 30s); double-NAT can still break if both endpoints behind NAT and no STUN server; ESP-in-UDP disables hardware ESP offload on some NICs',
        },
        applications='Remote access VPN through NAT — roadwarrior clients, home office IPsec',
    ),

    "udp_esp": dict(
        name='IPsec ESP — Encapsulating Security Payload (RFC 4303)',
        transport='IP Protocol 50 (raw IP) or UDP/4500 (NAT-T encapsulation)',
        status='IETF Standard — RFC 4303 (ESP), RFC 8221 (algorithm requirements 2018)',
        description='ESP provides confidentiality, data-origin authentication, and anti-replay for IP packets. Operates in tunnel mode (full IP header) or transport mode (payload only). The ESP SPI+SeqNo identify the SA.',
        header_bytes=8,
        fields={
            'SPI': '4B  Security Parameters Index — identifies SA at receiver (non-zero)',
            'Sequence Number': '4B  monotonically increasing anti-replay counter; 64b extended seq (RFC 4304)',
            'IV': 'variable  initialisation vector; AES-CBC=16B AES-GCM=8B ChaCha20=0B(nonce in header)',
            'Payload': 'variable  encrypted inner IP packet (tunnel) or transport payload',
            'Padding': '0-255B  alignment padding',
            'Pad Length': '1B  number of padding bytes',
            'Next Header': '1B  inner protocol: 4=IPv4 41=IPv6 6=TCP 17=UDP 59=NoNextHdr(tunnel)',
            'ICV': 'variable  Integrity Check Value: HMAC-SHA1-96=12B HMAC-SHA2-256-128=16B AES-GCM=8/12/16B',
            'Combined-mode': 'AES-GCM/AES-CCM/ChaCha20-Poly1305 provide encrypt+auth in single pass',
            'ESN': 'Extended Sequence Numbers (RFC 4304): 64-bit seqno for high-bandwidth links',
            'CAUTION': 'SPI=0x00000001-0xFF are reserved; ESP without AH provides no header integrity — use AES-GCM which covers header in AAD; CBC mode vulnerable to padding oracle — prefer AEAD modes; sequence number wrap MUST trigger SA rekey; anti-replay window typically 32-1024 packets',
        },
        applications='IPsec VPN tunnels, L3 encryption between sites, mobile VPN endpoints',
    ),

    "udp_ah": dict(
        name='IPsec AH — Authentication Header (RFC 4302)',
        transport='IP Protocol 51 (raw IP) — NAT incompatible (checksum over outer IP)',
        status='IETF Standard — RFC 4302; rarely deployed standalone (ESP-with-auth preferred)',
        description='AH provides data-origin authentication and integrity for IP packets including the outer IP header. Provides no confidentiality. Incompatible with NAT because AH covers outer IP addresses.',
        header_bytes=12,
        fields={
            'Next Header': '1B  protocol of protected data: 4=IPv4 41=IPv6 6=TCP 17=UDP',
            'Payload Length': '1B  AH length in 32b words minus 2 (e.g. 4=24B AH header)',
            'Reserved': '2B  0x0000',
            'SPI': '4B  Security Parameters Index identifying SA',
            'Sequence Number': '4B  anti-replay counter',
            'ICV': 'variable  Integrity Check Value: HMAC-SHA1-96=12B HMAC-SHA2-256-128=16B',
            'Mutable fields': 'AH sets mutable IP fields to 0 before HMAC calculation: TTL, Flags, Fragment Offset, Header Checksum, DS field',
            'Transport mode': 'AH inserted between IP header and upper-layer payload',
            'Tunnel mode': 'AH + new outer IP header; inner IP header fully authenticated',
            'CAUTION': 'AH incompatible with NAT — NAT modifies IP addresses covered by ICV; use ESP-with-auth instead for NATted environments; AH does not encrypt data; combining AH+ESP in tunnel mode is redundant — use ESP-GCM instead',
        },
        applications='IPsec integrity-only paths, routing protocol authentication over IPsec',
    ),

    "udp_l2tp": dict(
        name='L2TP — Layer 2 Tunnelling Protocol (RFC 2661 / RFC 3931)',
        transport='UDP/1701 (L2TPv2) or IP Protocol 115 (L2TPv3 native)',
        status='IETF Standard — RFC 2661 (L2TPv2), RFC 3931 (L2TPv3), RFC 6073 (pseudowire)',
        description='L2TP tunnels PPP frames (v2) or any L2 frames (v3) across IP networks. L2TPv2 is used for remote-access VPN (paired with IPsec for security). L2TPv3 creates pseudowires for VPLS and Ethernet services.',
        header_bytes=8,
        fields={
            'Flags/Version': '2B  T(1b)+L(1b)+R(1b)+F(1b)+S(1b)+O(1b)+P(1b)+reserved(4b)+Version(4b=2)',
            'T bit': '1b  1=Control message 0=Data message',
            'L bit': '1b  Length field present',
            'S bit': '1b  Ns/Nr sequence fields present',
            'Length': '2B  (if L=1) total length including header',
            'Tunnel ID': '2B  L2TPv2: identifies tunnel to peer (locally significant)',
            'Session ID': '2B  L2TPv2: identifies PPP session within tunnel',
            'Ns': '2B  (if S=1) sequence number of this message',
            'Nr': '2B  (if S=1) sequence number expected next from peer',
            '── L2TPv3 ──': '',
            'Session ID v3': '4B  L2TPv3: 32-bit session (0=reserved; for control use header)',
            'Cookie': '0/4/8B  optional anti-spoofing cookie per RFC 4591',
            'Control Messages': '1=SCCRQ 2=SCCRP 3=SCCCN 4=StopCCN 10=ICRQ 11=ICRP 12=ICCN 14=CDN 6=HELLO',
            'AVPs in Control': 'Mandatory(M)+Hidden(H)+Reserved+Length+VendorID+AttributeType+Value',
            'PPP payload': 'L2TPv2 data: PPP frame inside tunnel',
            'CAUTION': 'L2TPv2 without IPsec sends PPP frames in plaintext — always pair with IPsec; L2TPv3 cookie SHOULD be 8B random for anti-spoofing; Tunnel ID/Session ID are locally significant — both endpoints allocate their own values; SCCRQ/SCCRP hostname reveals server identity to unauthenticated peers',
        },
        applications='L2TP/IPsec remote access VPN (Windows built-in), VPLS pseudowire, carrier Ethernet services',
    ),

    "udp_stun": dict(
        name='STUN — Session Traversal Utilities for NAT (RFC 8489)',
        transport='UDP/3478 TCP/3478 TLS/5349 — also used by ICE for WebRTC',
        status='IETF Standard — RFC 8489 (STUNbis), RFC 8445 (ICE), RFC 8656 (TURN)',
        description='STUN discovers NAT-mapped public IP:port and tests NAT binding behaviour. Used by WebRTC ICE for peer-to-peer media path discovery. Message-Integrity HMAC protects against spoofing.',
        header_bytes=20,
        fields={
            'Message Type': '2B  bits[15:14]=00(STUN); bits[13:12]=class; bits[11:0]=method',
            'Class': '2b  00=Request 01=Indication 10=Success-Response 11=Error-Response',
            'Method': '12b  0x001=Binding 0x003=Allocate(TURN) 0x004=Refresh 0x006=Send 0x008=CreatePermission 0x009=ChannelBind',
            'Message Length': '2B  length of attributes (multiples of 4B, excluding 20B header)',
            'Magic Cookie': '4B  0x2112A442 — differentiates STUNbis from RFC 3489',
            'Transaction ID': '12B  96-bit random identifier matching request to response',
            'Attributes': 'Type(2B)+Length(2B)+Value(padded to 4B boundary)',
            '0x0001 MAPPED-ADDRESS': 'Family(1B)+Port(2B)+IP — deprecated; use XOR-MAPPED-ADDRESS',
            '0x0020 XOR-MAPPED-ADDRESS': 'Family+XOR-Port(2B)+XOR-IP — port XORed with magic cookie MSBs',
            '0x0006 USERNAME': 'UTF-8 username (for short-term or long-term credential)',
            '0x0008 MESSAGE-INTEGRITY': 'HMAC-SHA1 over message (using credentials key)',
            '0x0009 ERROR-CODE': 'Class(3b)+Number(7b)+Reason; 300=Try-Alternate 400=Bad-Request 401=Unauthorized 420=Unknown-Attribute 438=Stale-Nonce',
            '0x0025 USE-CANDIDATE': 'ICE: marks candidate pair as selected',
            '0x8028 FINGERPRINT': 'CRC32 over message XOR 0x5354554E — detects packet corruption',
            '0x8054 MESSAGE-INTEGRITY-SHA256': 'RFC 8489 upgrade from SHA1',
            'ICE/WebRTC': 'ICE uses STUN Binding to test connectivity of candidate pairs; credentials = ICE-ufrag + ICE-pwd',
            'CAUTION': "STUN amplification: STUN binding response larger than request — implement source IP validation; MESSAGE-INTEGRITY MUST be verified if present; FINGERPRINT MUST be verified; don't trust MAPPED-ADDRESS without credential validation; STUN over UDP has no reliability — ICE handles retransmits",
        },
        applications='WebRTC peer-to-peer, VoIP NAT traversal, ICE candidate gathering',
    ),

    "udp_turn": dict(
        name='TURN — Traversal Using Relays around NAT (RFC 8656)',
        transport='UDP/3478 TCP/3478 TLS/5349 DTLS/5349',
        status='IETF Standard — RFC 8656 (TURNbis), RFC 8445 (ICE), RFC 7065 (TURN URI)',
        description='TURN provides relay allocation for WebRTC when direct P2P or STUN fails (symmetric NAT). Client requests Allocate; server assigns relayed transport address; data forwarded via Send/Data indications or channels.',
        header_bytes=20,
        fields={
            'STUN Header': 'same 20B STUN header with Method=Allocate/Refresh/Send/Data/CreatePermission/ChannelBind',
            '0x000C CHANNEL-NUMBER': '2B channel (0x4000-0x7FFE) + 2B reserved',
            '0x000D LIFETIME': '4B seconds remaining in allocation',
            '0x0012 XOR-PEER-ADDRESS': 'peer transport address (XOR-encoded)',
            '0x0013 DATA': 'relay payload in Data indication',
            '0x0016 REALM': 'UTF-8 realm for long-term credentials',
            '0x0017 NONCE': 'opaque nonce from server for long-term auth',
            '0x0011 REQUESTED-ADDRESS-FAMILY': '1B 0x01=IPv4 0x02=IPv6',
            '0x0019 REQUESTED-TRANSPORT': '1B 17=UDP (TURN only supports UDP relay)',
            '0x8000 ADDITIONAL-ADDRESS-FAMILY': 'extra address family for dual-stack',
            'Channel Data': '4B Channel-Number(2B)+Length(2B)+AppData — compact relay format',
            'Allocate': 'Request: REQUESTED-TRANSPORT+LIFETIME | Response: XOR-RELAYED-ADDRESS+LIFETIME+XOR-MAPPED-ADDRESS',
            'CreatePermission': 'Installs 5-minute permission for peer IP to send to relay',
            'CAUTION': 'TURN relay costs bandwidth — server must enforce per-user allocation limits; long-term credentials (username+password) must be per-user not shared; TURN server exposed to public internet is bandwidth-abuse target; enforce rate limiting and allocation quotas; channel bindings reduce overhead but require coordination',
        },
        applications='WebRTC relay for symmetric NAT, enterprise VoIP fallback relay',
    ),

    "udp_sctp": dict(
        name='SCTP — Stream Control Transmission Protocol (RFC 9260)',
        transport='IP Protocol 132 (not UDP/TCP) — multihoming, multistreaming',
        status='IETF Standard — RFC 9260 (SCTPbis), RFC 8261 (SCTP over DTLS), RFC 6951 (SCTP over UDP)',
        description='SCTP is a transport protocol combining TCP reliability with UDP message boundaries. Supports multihoming (multiple IP addresses per endpoint), multistreaming (independent delivery streams), and partial reliability. Used in 3GPP Diameter, M3UA, SUA, and WebRTC data channels.',
        header_bytes=12,
        fields={
            'Source Port': '2B',
            'Destination Port': '2B',
            'Verification Tag': '4B  chosen by sender during association; receiver validates',
            'Checksum': '4B  CRC-32c over entire SCTP packet',
            'Chunks': 'repeated: Type(1B)+Flags(1B)+Length(2B)+Value',
            'Chunk 0 DATA': 'Flags: E(end)+B(begin)+U(unordered)+I(immediate)+reserved | TSN(4B)+Stream-ID(2B)+SSN(2B)+PPID(4B)+Data',
            'PPID': '32b Payload Protocol Identifier: 0=unspecified 47=WebRTC-DCEP 50=WebRTC-string 51=WebRTC-binary 3=M3UA 2=M2UA',
            'Chunk 1 INIT': 'Initiate Tag(4B)+A-RWND(4B)+OS(2B)+MIS(2B)+Init-TSN(4B)+Params',
            'Chunk 2 INIT ACK': 'echoes INIT with State Cookie',
            'Chunk 3 SACK': 'Cumulative TSN Ack(4B)+A-RWND(4B)+NumGapAck(2B)+NumDupTSN(2B)+[Gap Blocks]+[Dup TSNs]',
            'Chunk 10 COOKIE ECHO': 'State Cookie from INIT-ACK — 4-way handshake prevents blind SYN flood',
            'Chunk 11 COOKIE ACK': 'completes association establishment',
            'Chunk 6 ABORT': 'flags+Error-Causes — immediate association termination',
            'Chunk 7 SHUTDOWN': 'Cumulative TSN Ack — graceful teardown',
            'Chunk 14 HEARTBEAT': 'Heartbeat-Info Parameter — path reachability check',
            'Multihoming': 'multiple IPs per endpoint; failover to alternate path on primary failure',
            'CAUTION': 'Verification Tag 0 allowed only in INIT — reject all other Vtag=0 packets; CRC-32c must be validated; SCTP over UDP (RFC 6951) wraps in UDP/9899 for NAT traversal; PPID=0 is unspecified — applications should set meaningful PPID; INIT flooding attack — cookie mechanism provides protection but server must implement cookie MAC',
        },
        applications='3GPP Diameter/SS7 signalling (M3UA/SUA), WebRTC data channels, SIGTRAN',
    ),

    "udp_ospf": dict(
        name='OSPFv2/v3 — Open Shortest Path First (RFC 2328 / RFC 5340)',
        transport='IP Protocol 89 (not UDP) dst 224.0.0.5 (AllSPFRouters) 224.0.0.6 (AllDRRouters)',
        status='IETF Standard — RFC 2328 (OSPFv2 IPv4), RFC 5340 (OSPFv3 IPv6), RFC 4552 (OSPFv3 auth)',
        description='OSPF is a link-state IGP using Dijkstra SPF for loop-free routing. Routers exchange LSAs (Link State Advertisements) to build identical LSDB. DR/BDR election reduces flooding on broadcast segments.',
        header_bytes=24,
        fields={
            'Version': '1B  2=OSPFv2(IPv4) 3=OSPFv3(IPv6)',
            'Type': '1B  1=Hello 2=DB-Description 3=LS-Request 4=LS-Update 5=LS-Ack',
            'Packet Length': '2B  total packet length',
            'Router ID': '4B  32-bit router identifier (often loopback IP) — unique per AS',
            'Area ID': '4B  0.0.0.0=backbone; stub/NSSA areas filter LSAs',
            'Checksum': '2B  IP checksum (0 for OSPFv3 which uses IPsec)',
            'AuType': '2B  OSPFv2: 0=None 1=Simple-Password 2=MD5-Crypto',
            '── Hello ──': 'Mask(4B)+Interval(2B)+Options(1B)+Priority(1B)+Dead(4B)+DR(4B)+BDR(4B)+[Neighbors]',
            'Hello Interval': '2B  default 10s broadcast; 30s NBMA/P2P',
            'Dead Interval': '4B  default 4×hello; adjacency down if no Hello received',
            'DR/BDR': 'Designated Router and Backup DR — elected on broadcast segments',
            'Options bits': 'E(external LSA) N(NSSA) L(LLS) DC(demand-circuit) O(opaque-LSA) V6(OSPFv3)',
            '── LSA Types ──': '1=Router 2=Network 3=Summary(ABR) 4=ASBR-Summary 5=AS-External 7=NSSA-External 8=Link(v3) 9=Intra-Area-Prefix(v3)',
            'LSA Header': 'Age(2B)+Options(1B)+Type(1B)+LSID(4B)+AdvRouter(4B)+SeqNo(4B)+Checksum(2B)+Length(2B)',
            'Auth MD5': 'OSPFv2 Type-2: KeyID(1B)+AuthDataLen(1B)+CryptoSeqNo(4B) then MD5 appended',
            'OSPFv3 Auth': 'RFC 4552 uses IPsec AH/ESP over OSPFv3 packets',
            'CAUTION': 'OSPFv2 MD5 auth with same key on all routers — any compromised router injects routes; OSPFv3 requires IPsec for auth (no built-in); router-ID collision causes neighbour issues; MaxAge=3600 LSA flood triggers premature re-flooding; OSPF area 0 must be contiguous — virtual-links needed otherwise; LSA sequence number wrap requires graceful handling',
        },
        applications='Enterprise and ISP IPv4/IPv6 IGP routing, datacenter fabric underlay',
    ),

    "udp_bgp": dict(
        name='BGP-4 — Border Gateway Protocol (RFC 4271)',
        transport='TCP/179 — session-oriented, each BGP speaker listens and connects',
        status='IETF Standard — RFC 4271 (BGP-4), RFC 4760 (MP-BGP), RFC 4364 (BGP/MPLS VPN), RFC 9072 (BGP-LS)',
        description='BGP is the inter-domain routing protocol of the Internet. Uses path vector with policy-based best-path selection. MP-BGP (RFC 4760) carries IPv6, VPN, L2VPN, EVPN, and flow-spec. RPKI provides origin validation.',
        header_bytes=19,
        fields={
            'Marker': '16B  0xFF×16 — synchronisation marker',
            'Length': '2B  total message length (19-4096B)',
            'Type': '1B  1=OPEN 2=UPDATE 3=NOTIFICATION 4=KEEPALIVE 5=ROUTE-REFRESH',
            '── OPEN ──': 'Version(1B=4)+AS(2B)+HoldTime(2B)+BGP-ID(4B)+OptParamLen(1B)+[OptParams]',
            'AS Number': '2B in OPEN (for 4-byte AS use Capability code 65 with 4B AS value)',
            'Hold Time': '2B  seconds; 0=no keepalive; minimum of both sides used',
            'BGP Identifier': '4B  IPv4 address identifying BGP speaker (typically loopback)',
            'Capabilities': 'Opt Param Type=2: Capability-Code(1B)+Len(1B)+Data; 1=MP-BGP 2=Route-Refresh 64=Graceful-Restart 65=4-byte-AS 70=ADD-PATH 71=Enhanced-Route-Refresh',
            '── UPDATE ──': 'Withdrawn-Routes(2B len+prefixes)+Path-Attrs(2B len+attrs)+NLRI(prefixes)',
            'Path Attributes': 'Flags(1B)+TypeCode(1B)+[Length(1/2B)]+Value',
            'Attr Flags': 'O(Optional)+T(Transitive)+P(Partial)+E(Extended-Length)',
            'Attr 1 ORIGIN': '1B  0=IGP 1=EGP 2=INCOMPLETE',
            'Attr 2 AS_PATH': 'AS_SEQUENCE(1) or AS_SET(2) + count + AS list (2B or 4B each)',
            'Attr 3 NEXT_HOP': '4B IPv4 next-hop for NLRI',
            'Attr 4 MED': '4B  Multi-Exit Discriminator — prefer lower (optional, non-transitive)',
            'Attr 5 LOCAL_PREF': '4B  local preference — prefer higher (iBGP only, well-known)',
            'Attr 8 COMMUNITY': '4B each  standard communities: AS:VALUE; well-known: NO_EXPORT(0xFFFFFF01) NO_ADVERTISE(0xFFFFFF02)',
            'Attr 14 MP_REACH': 'AFI(2B)+SAFI(1B)+NH-Len(1B)+Next-Hop+SNPA+NLRI; AFI/SAFI: 1/1=IPv4 2/1=IPv6 1/128=VPN-IPv4 25/70=EVPN',
            'Attr 32 LARGE_COMMUNITY': '12B each: GlobalAdmin(4B)+LocalData1(4B)+LocalData2(4B)',
            '── NOTIFICATION ──': 'Error-Code(1B)+Sub-Code(1B)+Data',
            'Error Codes': '1=Message-Header 2=OPEN-Message 3=UPDATE-Message 4=Hold-Timer-Expired 5=FSM-Error 6=Cease',
            'FSM States': 'Idle→Connect→Active→OpenSent→OpenConfirm→Established',
            'CAUTION': 'BGP has no authentication by default — use MD5 TCP-AO (RFC 5925) for all eBGP sessions; RPKI ROV must be enabled to reject hijacked prefixes; max-prefix limits prevent route table overflow from misconfigured peers; BGP route leaks cause global outages — implement NO_EXPORT and prefix-lists; BGP hijacking (prefix announcement with longer AS path) detectable by RPKI/BGPsec',
        },
        applications='Internet inter-domain routing, datacenter EVPN fabric, MPLS VPN (BGP-4), SD-WAN',
    ),

    "udp_eigrp": dict(
        name='EIGRP — Enhanced Interior Gateway Routing Protocol (RFC 7868)',
        transport='IP Protocol 88 dst 224.0.0.10 (EIGRP multicast) or unicast',
        status='IETF Standard — RFC 7868 (2016, open-sourced by Cisco)',
        description='EIGRP is a Cisco-developed distance-vector routing protocol using DUAL algorithm for loop-free rapid convergence. Supports equal-cost and unequal-cost load balancing. Successor to IGRP.',
        header_bytes=20,
        fields={
            'Version': '1B  2=EIGRP',
            'Opcode': '1B  1=Update 3=Query 4=Reply 5=Hello 6=IPX-Update 10=SIA-Query 11=SIA-Reply',
            'Checksum': '2B  EIGRP checksum',
            'Flags': '4B  0x00000001=INIT 0x00000002=Conditional-Receive 0x00000004=RS-Flag 0x00000008=End-of-Table',
            'Sequence': '4B  reliable delivery sequence number',
            'Acknowledge': '4B  acknowledges up to this sequence',
            'Virtual Router ID': '2B  0=unicast AF 1=multicast AF',
            'AS Number': '2B  EIGRP Autonomous System — routers must match to peer',
            'TLVs': 'Type(2B)+Length(2B)+Value',
            'TLV 0x0001': 'EIGRP Parameters: K1-K6 metric weights + HoldTime(2B)',
            'TLV 0x0002': 'Authentication: AuthType(2B)+AuthLen(2B)+KeyID(4B)+KeySeq(4B)+HMAC',
            'TLV 0x0102': 'IPv4 Internal Route: Next-Hop(4B)+Delay(4B)+Bandwidth(4B)+MTU(3B)+HopCount(1B)+Reliability(1B)+Load(1B)+Reserved(2B)+Prefix(1B)+Dest(variable)',
            'TLV 0x0103': 'IPv4 External Route: same + Originating-Router+AS+Protocol+Tag+Flags',
            'TLV 0x0402': 'IPv6 Internal Route: similar IPv6-addressed variant',
            'DUAL metric': 'Composite = (K1×BW + K2×BW/(256-Load) + K3×Delay) × (K5/(Reliability+K4))',
            'Default K values': 'K1=1 K2=0 K3=1 K4=0 K5=0 — simplifies to bandwidth+delay',
            'CAUTION': 'AS number mismatch prevents adjacency; K-value mismatch prevents peering; unequal-cost load balance (variance command) can cause routing loops if misconfigured; EIGRP authentication should be MD5 or SHA-256; stub routing prevents transit traffic but blocks needed query responses if mis-applied',
        },
        applications='Cisco enterprise routing, WAN edge, voice/video quality routing with unequal-cost balancing',
    ),

    "udp_ldp": dict(
        name='LDP — Label Distribution Protocol (RFC 5036)',
        transport='TCP/646 (sessions, reliable) UDP/646 (hello discovery) — both same port',
        status='IETF Standard — RFC 5036 (base), RFC 5283 (MPLS-TE FEC), RFC 6388 (multicast LDP)',
        description='LDP distributes MPLS labels for established IP paths. LSRs exchange FEC-label bindings over TCP sessions discovered via UDP hellos. Used for MPLS label switched paths in service provider networks.',
        header_bytes=10,
        fields={
            '── UDP Hello ──': 'sent to 224.0.0.2 dst port 646 for peer discovery',
            'Version': '2B  1',
            'PDU Length': '2B  remaining length after this field',
            'LSR ID': '4B  router identifier (loopback)',
            'Label Space': '2B  0=per-platform 1+=per-interface',
            '── Messages ──': 'Type(2B)+Length(2B)+Message-ID(4B)+[Mandatory TVs]+[Optional TVs]',
            'Msg 0x0001 Notification': 'Status TLV + optional LDP-Message-ID',
            'Msg 0x0100 Hello': 'Hello Parameters TLV: Hold-Time(2B)+Flags(T=targeted,R=request-targeted)+[IPv4/v6 Transport Address]',
            'Msg 0x0200 Initialisation': 'Common Session TLV: Version+KeepAlive+A(label-adv)+D(loop-detect)+Path-Vector-Limit+Max-PDU+LSR-ID+Label-Space',
            'Msg 0x0201 KeepAlive': 'empty — resets hold timer',
            'Msg 0x0300 Addr': 'Address TLV: Address-Family(2B)+[IP Addresses]',
            'Msg 0x0400 Label Mapping': 'FEC TLV + Label TLV',
            'Msg 0x0401 Label Request': 'FEC TLV',
            'Msg 0x0402 Label Withdraw': 'FEC TLV + [Label TLV]',
            'Msg 0x0404 Label Release': 'FEC TLV + [Label TLV]',
            'FEC TLV': 'Type(1B)+Length(1B)+[FEC Elements]: 0x01=Wildcard 0x02=Prefix(AFI+PrefixLen+Prefix)',
            'Label TLV': '0x0200=Generic-Label(4B value) 0x0201=ATM-Label 0x0202=FR-Label',
            'CAUTION': 'LDP TCP session uses MD5 authentication (RFC 2385) — configure on all sessions; LDP downstream-unsolicited is default — LSR accepts unsolicited label bindings (potential for label injection); targeted LDP hello traverses L3 boundaries — may be mistaken for scan; DoS possible via LDP session reset if authentication absent',
        },
        applications='MPLS LSP establishment for L3VPN, pseudowire, LDP-IGP sync',
    ),

    "udp_rsvp": dict(
        name='RSVP — Resource Reservation Protocol (RFC 2205)',
        transport='IP Protocol 46 (raw IP) — routers process RSVP at each hop',
        status='IETF Standard — RFC 2205 (base), RFC 3209 (RSVP-TE), RFC 4090 (fast-reroute)',
        description='RSVP reserves bandwidth along a path for QoS guarantees. RSVP-TE (RFC 3209) extends this for MPLS traffic engineering LSP setup. PATH messages flow downstream; RESV messages flow upstream.',
        header_bytes=8,
        fields={
            'Version': '4b  1',
            'Flags': '4b  reserved',
            'Message Type': '1B  1=PATH 2=RESV 3=PATH-ERR 4=RESV-ERR 5=PATH-TEAR 6=RESV-TEAR 7=RESV-CONFIRM 20=BUNDLE 25=ACK 26=SREFRESH',
            'Checksum': '2B',
            'TTL': '1B  IP TTL of original sender (for loop detection)',
            'Reserved': '1B  0',
            'RSVP Length': '2B',
            'Objects': 'Length(2B)+Class(1B)+C-Type(1B)+Data',
            'SESSION (Class 1)': 'DestIP(4B)+Protocol(1B)+DstPort(2B) or LSP-Tunnel: TunDst+TunnelID+ExtTunID',
            'RSVP-HOP (Class 3)': 'PreviousHopIP(4B)+LIH(4B logical interface handle)',
            'TIME_VALUES (Class 5)': 'Refresh Period(4B) milliseconds',
            'SENDER_TEMPLATE (Class 11)': 'SrcIP(4B)+SrcPort(2B) or LSP: SrcIP+LSP-ID',
            'SENDER_TSPEC (Class 12)': 'Token Bucket: Rate(float)+Bucket-Depth(float)+PeakRate+MinUnit+MaxBurst',
            'FILTERSPEC (Class 10)': 'same as SENDER_TEMPLATE',
            'FLOWSPEC (Class 9)': 'same as TSPEC',
            'LABEL_REQUEST (Class 19)': 'L3pid(2B=0x0800/0x86DD) for RSVP-TE',
            'LABEL (Class 16)': '4B MPLS label value — sent upstream in RESV',
            'ERO (Class 20)': 'Explicit Route Object: subobjects=IPv4(flags+pfxlen+IP)+AS+Label',
            'RRO (Class 21)': 'Record Route Object: accumulates hops in RESV',
            'CAUTION': 'RSVP soft state requires periodic PATH+RESV refresh — hold timer mismatch causes reservation expiry; RSVP-TE label reuse on tunnel teardown must be handled carefully; graceful restart RFC 3473 required for hitless restart; RSVP scales poorly — thousands of LSPs consume memory and CPU; LDP preferred for untraffic-engineered MPLS',
        },
        applications='MPLS Traffic Engineering LSP setup, QoS reservation for real-time services',
    ),

    "udp_tacacs": dict(
        name='TACACS+ — Terminal Access Controller Access-Control System Plus (RFC 8907)',
        transport='TCP/49 — full-session encrypted (unlike RADIUS which encrypts only password)',
        status='IETF Standard — RFC 8907 (2020, first formal RFC for TACACS+); Cisco origin',
        description='TACACS+ separates Authentication, Authorisation, and Accounting into independent steps. Encrypts the entire payload (unlike RADIUS). Used for network device management access (router/switch CLI).',
        header_bytes=12,
        fields={
            'Major Version': '4b  0xC=TACACS+',
            'Minor Version': '4b  0=default 1=draft',
            'Type': '1B  1=TAC_PLUS_AUTHEN 2=TAC_PLUS_AUTHOR 3=TAC_PLUS_ACCT',
            'Seq No': '1B  incremented per packet in session; starts at 1',
            'Flags': '1B  bit0=UNENCRYPTED bit2=SINGLE-CONNECT',
            'Session ID': '4B  random per session',
            'Length': '4B  body length (body is XOR-encrypted if UNENCRYPTED not set)',
            'Body Encryption': 'XOR pad from MD5(session_id+key+version+seq_no) repeatedly hashed',
            '── Authen START ──': 'Action(1B)+Priv-Level(1B)+Auth-Type(1B)+Service(1B)+User-Len+Port-Len+Rem-Addr-Len+Data-Len+[User+Port+Rem-Addr+Data]',
            'Auth Types': '1=ASCII 2=PAP 3=CHAP 4=ARAP 6=MSCHAP 7=MSCHAPv2',
            '── Authen REPLY ──': 'Status(1B)+Flags(1B)+Server-Msg-Len(2B)+Data-Len(2B)+[Msg+Data]',
            'Status': '1=PASS 2=FAIL 4=GETDATA 5=GETUSER 6=GETPASS 7=RESTART 8=ERROR 21=FOLLOW',
            '── Author REQUEST ──': 'Auth-Method(1B)+Priv-Level(1B)+Auth-Type(1B)+Service(1B)+User-Len+Port-Len+Rem-Addr-Len+Arg-Count(1B)+[Arg-Len×N]+[User+Port+Rem-Addr+Args]',
            'Authorization Args': 'service=shell priv-level=15 cmd=show cmd-arg=version',
            '── Acct REQUEST ──': 'Flags(1B)+Auth-Method+Priv-Level+Auth-Type+Service+User+Port+Rem-Addr+Args',
            'CAUTION': 'TACACS+ XOR encryption with MD5 is weak — use over encrypted transport (SSH tunnel, TLS wrapper); session_id brute-force possible if weak key; key management — all devices share single key; TACACS+ TCP/49 must be firewalled; privilege level 15 grants unrestricted access — use per-command authorisation instead',
        },
        applications='Network device CLI authentication, command authorisation (per-command), accounting for compliance',
    ),

    "udp_ospf_v3": dict(
        name='OSPFv3 — Open Shortest Path First for IPv6 (RFC 5340)',
        transport='IP Protocol 89 dst FF02::5 (AllSPFRouters) FF02::6 (AllDRRouters) — link-local source',
        status='IETF Standard — RFC 5340 (OSPFv3), RFC 6845 (NBMA), RFC 7503 (OSPFv3 auth trailer)',
        description='OSPFv3 extends OSPFv2 for IPv6. Protocol-independent (runs over IPv6 link-local only). Uses link-local addresses for adjacency. LSAs redesigned. Authentication via IPsec AH or OSPFv3 Authentication Trailer (RFC 7503).',
        header_bytes=16,
        fields={
            'Version': '1B  3=OSPFv3',
            'Type': '1B  1=Hello 2=DB-Description 3=LS-Request 4=LS-Update 5=LS-Ack',
            'Packet Length': '2B',
            'Router ID': '4B  32-bit identifier — not an IP address in OSPFv3',
            'Area ID': '4B',
            'Checksum': '2B  0 for OSPFv3 using IPsec AH; standard checksum otherwise',
            'Instance ID': '1B  0=default; allows multiple OSPFv3 instances per link',
            'Reserved': '1B  0',
            '── Hello ──': 'Interface-ID(4B)+Priority(1B)+Options(3B)+Hello-Interval(2B)+Dead-Interval(2B)+DR(4B)+BDR(4B)+[Neighbor-IDs]',
            'Interface-ID': '4B  local interface MIB ifIndex — used instead of IP address',
            'Options v3': 'DC+R+N+MC+E+V6 — V6 bit must be set on v6-capable routers',
            'LSA Types v3': '0x2001=Router 0x2002=Network 0x2003=Inter-Area-Prefix 0x2004=Inter-Area-Router 0x4005=AS-External 0x2007=NSSA 0x0008=Link 0x2009=Intra-Area-Prefix',
            'Link LSA': 'Rtr-Priority(1B)+Options(3B)+Link-local(16B)+Prefix-Count(4B)+[Prefixes]',
            'Auth Trailer': 'RFC 7503: Type(2B)+Length(2B)+Reserved(2B)+SA-ID(2B)+CryptoSeqNo(8B)+AuthData',
            'CAUTION': 'OSPFv3 uses link-local only — ensure all participating interfaces have link-local; Instance ID must match on both ends of link; Auth Trailer RFC 7503 preferred over IPsec AH for OSPFv3 auth; Router ID uniqueness required — collision causes LSA thrashing',
        },
        applications='IPv6 IGP routing in enterprise and service provider networks',
    ),

    "udp_netconf": dict(
        name='NETCONF — Network Configuration Protocol (RFC 6241)',
        transport='SSH/830 (mandatory) BEEP TCP/831 TLS/6513 — XML-over-SSH',
        status='IETF Standard — RFC 6241 (NETCONF), RFC 6022 (YANG), RFC 8040 (RESTCONF), RFC 8526 (NMDA)',
        description='NETCONF provides XML-based network device configuration via a structured RPC mechanism. Uses YANG (RFC 7950) data models. Supports candidate datastore, transactions, and rollback.',
        header_bytes=0,
        fields={
            'Framing': "SSH subsystem 'netconf'; messages delimited by ]]>]]> (old) or chunk framing RFC 6242",
            'Chunk Framing': '#length CRLF xml-data CRLF ## CRLF — for NETCONF 1.1',
            'hello': "<hello xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability>...</capabilities></hello>",
            'Capabilities': 'base:1.1 + writable-running + candidate + confirmed-commit + rollback-on-error + validate + startup + url + xpath + with-defaults',
            'RPC': "<rpc message-id='101' xmlns='...'><operation>...</operation></rpc>",
            'Operations': '<get> <get-config> <edit-config> <copy-config> <delete-config> <lock> <unlock> <close-session> <kill-session>',
            'edit-config': '<edit-config><target><candidate/></target><config>...YANG XML...</config></edit-config>',
            'operation attr': "nc:operation='merge|replace|create|delete|remove' on any element",
            'rpc-reply': "<rpc-reply message-id='101'><ok/></rpc-reply> or <data>...</data>",
            'rpc-error': '<rpc-error><error-type>application</error-type><error-tag>invalid-value</error-tag><error-severity>error</error-severity><error-message>...</error-message></rpc-error>',
            'Datastores': 'running | candidate | startup | operational(RFC 8342 NMDA)',
            'commit': '<commit/> applies candidate to running; <discard-changes/> reverts',
            'CAUTION': 'NETCONF over SSH — use key-based auth not password; candidate datastore lock must be released after commit/discard; partial edit-config can leave inconsistent config if session drops; lock contention between operators; xpath filtering in <get> can be expensive on large configs',
        },
        applications='Automated network device configuration, ZTP (zero-touch provisioning), network automation',
    ),

    "udp_gnmi": dict(
        name='gNMI — gRPC Network Management Interface (OpenConfig)',
        transport='gRPC TCP/9339 (gNMI) or TCP/57400 (Cisco) over HTTP/2+TLS',
        status='OpenConfig / gRPC / CNCF — OpenConfig spec v0.10.0; IETF draft-openconfig-netmod-opstate',
        description='gNMI uses gRPC and Protocol Buffers for high-performance streaming telemetry and configuration. Subscribe RPC enables efficient push-based model instead of SNMP polling. Supports YANG paths.',
        header_bytes=0,
        fields={
            'gRPC framing': 'HTTP/2 with Content-Type: application/grpc; length-prefixed protobuf frames',
            'Service': 'gnmi.gNMI: Capabilities Get Set Subscribe',
            'CapabilityRequest': 'empty → CapabilityResponse: supported-models+supported-encodings+gNMI-version',
            'GetRequest': 'prefix+path+type(CONFIG/STATE/OPERATIONAL/ALL)+encoding(JSON_IETF/PROTO/ASCII)',
            'SetRequest': 'prefix+[delete-paths]+[replace-updates]+[update-updates]',
            'Update': 'path+value (TypedValue: any/json_ietf/ascii/int/uint/float/decimal/bool/bytes)',
            'SetResponse': 'prefix+[UpdateResult: path+op(DELETE/REPLACE/UPDATE)+message]',
            'SubscribeRequest': 'subscribe(SubscriptionList) or poll or aliases',
            'SubscriptionList': 'prefix+[subscription]+mode(STREAM/ONCE/POLL)+encoding+updates_only',
            'Subscription': 'path+mode(TARGET_DEFINED/ON_CHANGE/SAMPLE)+sample_interval(ns)+suppress_redundant+heartbeat_interval',
            'SubscribeResponse': 'update(Notification)+sync_response(bool)+error',
            'Notification': 'timestamp(int64 ns)+prefix+[Update]+[delete-paths]',
            'Path': 'origin+[PathElem: name+key-map] e.g. interfaces/interface[name=eth0]/state/counters',
            'CAUTION': 'gNMI requires TLS — never expose port 9339 without TLS+client-certificate auth; ON_CHANGE subscriptions can flood collector if many changes occur; large configs in Get response may timeout; path traversal security — restrict YANG paths accessible per certificate/user; gRPC keepalive required for long-lived streams through NAT/firewalls',
        },
        applications='Modern network telemetry streaming, OpenConfig-based config push, real-time interface stats',
    ),

    "udp_pcep": dict(
        name='PCEP — Path Computation Element Protocol (RFC 5440)',
        transport='TCP/4189 — persistent session between PCC (client) and PCE (computation server)',
        status='IETF Standard — RFC 5440 (base), RFC 8231 (stateful PCE), RFC 8281 (PCE-initiated LSP)',
        description='PCEP allows a PCC (router) to request LSP path computation from a PCE (path computation server). Stateful PCE (RFC 8231) maintains LSP state and can update/initiate LSPs on routers.',
        header_bytes=4,
        fields={
            'Version': '3b  1',
            'Flags': '5b  reserved',
            'Type': '1B  1=Open 2=Keepalive 3=PCReq 4=PCRep 5=Notification 6=PCErr 7=Close 10=PCReport 11=PCUpdate 12=PCInitiate',
            'Length': '2B  total message length',
            '── Open ──': 'Object: Class=1 Type=1 — Version(3b)+Keepalive(1B)+DeadTimer(1B)+SID(1B)+[TLVs]',
            '── PCReq ──': 'RP object (mandatory): Request-ID+Flags(L+B+O+B+R+P+S+E+M+D+B2+syn+strictReachability)+Misc',
            'Objects': 'Class(7b)+Type(4b)+Flags(P+I bits: M=mandatory I=ignore-if-unknown)+Reserved+Length+Value',
            'Common Objects': 'RP(1) NOPATH(3) ENDPOINTS(4) BANDWIDTH(5) METRIC(6) ERO(7) RRO(8) LSPA(9) IRO(10) SVEC(11) NOTF(12) PCEP-ERROR(13) CLOSE(15)',
            'LSPA object': 'Exclude-Any+Include-Any+Include-All affinity+Setup-Prio+Hold-Prio+L-flag',
            'Stateful PCE': 'LSP object: PLSP-ID(20b)+Flags(D+S+R+A+O)+TLVs(symbolic-path-name+LSP-Error-Code)',
            'PCUpdate': 'SRP object(Stateful-Request-Param-ID)+LSP object+ERO',
            'PCInitiate': 'SRP+LSP+Endpoints+ERO — PCE creates new LSP on router',
            'CAUTION': 'PCEP TCP must use MD5 auth (RFC 5440 §10.4) or TLS RFC 8253; rogue PCE can reroute all RSVP-TE LSPs; PLSP-ID must be unique per PCC; PCE-initiated LSPs bypass router operator — strong authentication mandatory; stateful PCE failure causes LSP delegation loss',
        },
        applications='Traffic engineering LSP computation, MPLS-TE optimisation, SR policy computation',
    ),

    "udp_mosh": dict(
        name='Mosh — Mobile Shell (mosh.org)',
        transport='UDP/60001+ (single random high port per session) — over DTLS or SSP',
        status='De Facto Standard — mosh.org spec; not IETF RFC but open source widely deployed',
        description='Mosh uses UDP for roaming-resistant, low-latency remote shell. AES-OCB encrypts each datagram independently. SSP (State Synchronisation Protocol) diffs terminal state rather than streaming bytes. Tolerates IP change (WiFi to cellular handoff).',
        header_bytes=0,
        fields={
            'Bootstrap': 'SSH to port 22; server starts mosh-server; returns key+UDP-port to client',
            'SSP framing': 'Sequence(8B)+Timestamp(2B)+Timestamp-Reply(2B)+Payload',
            'Sequence number': '8B  monotonically increasing per datagram',
            'Payload': 'AES-128-OCB encrypted MsgTransportInstruction or MsgClientFB',
            'Key': '22-char base64 random AES-128 key exchanged via SSH',
            'Fallback': 'If UDP blocked, Mosh does NOT fall back to TCP',
            'State diff': 'Client sends terminal state diffs; server applies to authoritative state',
            'Roaming': 'Client sends from new IP; server detects and updates peer address',
            'CAUTION': 'UDP port range 60001-61000 must be open in firewall; AES-OCB patent (now expired) caused earlier deployment concerns; no server authentication beyond SSH — trust SSH key; Mosh session remains open after SSH closes — must explicitly exit; UDP traffic not logged by many firewall/IDS solutions',
        },
        applications='Remote shell over mobile/unreliable networks, terminal multiplexing with roaming support',
    ),

    "udp_openvpn": dict(
        name='OpenVPN — Secure VPN Protocol (openvpn.net)',
        transport='UDP/1194 (default) or TCP/1194 or TCP/443 — configurable',
        status='De Facto Standard — OpenVPN Technologies; not IETF RFC; widely deployed open-source',
        description='OpenVPN uses TLS for control channel and custom packet format for data channel. Supports TUN (L3) and TAP (L2) modes. Uses certificates or pre-shared keys. Data channel uses AES-GCM or CHACHA20-POLY1305.',
        header_bytes=1,
        fields={
            'Opcode': '5b  P_CONTROL_HARD_RESET_CLIENT(1) P_CONTROL_HARD_RESET_SERVER(2) P_CONTROL_SOFT_RESET(3) P_CONTROL_V1(4) P_ACK_V1(5) P_DATA_V1(6) P_DATA_V2(9)',
            'Key-ID': '3b  0-7 key rotation index',
            '── P_CONTROL ──': 'SessionID(8B)+[ACK count(1B)+ACK packet-IDs+RemoteSessionID]+PacketID(4B)+TLS-payload',
            'SessionID': '8B  random — identifies OpenVPN session',
            'Packet ID': '4B  monotonic counter for reliable delivery over UDP',
            'ACK': 'packet-IDs being acknowledged — TCP-like reliability on control channel',
            'TLS Payload': 'TLS handshake or TLS application data (TLS-over-UDP)',
            '── P_DATA_V2 ──': 'Peer-ID(3B)+KeyID(1B=5b-opcode+3b-keyid)+IV+Ciphertext+Auth-Tag',
            'Peer-ID': '3B  server-assigned client identifier for multiplexed server',
            'Data cipher': 'AES-128/256-GCM (preferred) or CHACHA20-POLY1305 — negotiated in TLS',
            'tls-auth/tls-crypt': 'pre-shared HMAC wrapping all TLS packets — prevents TLS DoS attacks',
            'tls-crypt-v2': 'client-unique wrapping key — prevents cross-client impersonation',
            'CAUTION': 'UDP mode preferred — TCP-over-TCP causes performance collapse under packet loss; tls-crypt-v2 strongly recommended to prevent unauthenticated TLS handshakes; cipher BF-CBC (Blowfish) completely broken — never use; certificate revocation (CRL/OCSP) must be configured; reneg-sec 3600 = hourly data key renegotiation; client certificate expiry causes silent connection failure',
        },
        applications='Remote access VPN, site-to-site VPN, bypass firewalls (TCP/443 mode), mobile client VPN',
    ),

    "udp_grpc": dict(
        name='gRPC — Google Remote Procedure Call (CNCF)',
        transport='HTTP/2 over TLS TCP/any — typically 443 or service-specific ports',
        status='CNCF Standard / De Facto — open-source; used in Kubernetes, gNMI, QUIC/HTTP3',
        description='gRPC uses HTTP/2 for multiplexed streams and Protocol Buffers for efficient binary serialisation. Supports unary, server-streaming, client-streaming, and bidirectional streaming RPCs.',
        header_bytes=5,
        fields={
            'HTTP/2 framing': 'Frame: Length(3B)+Type(1B)+Flags(1B)+StreamID(31b)+Payload',
            'HTTP/2 Types': '0=DATA 1=HEADERS 4=SETTINGS 8=WINDOW_UPDATE 9=CONTINUATION',
            'gRPC prefix': 'Compressed(1B: 0=plain 1=gzip)+Message-Length(4B)+Proto-Buf-Payload',
            'Content-Type': 'application/grpc or application/grpc+proto or application/grpc+json',
            'Status': 'grpc-status trailer: 0=OK 1=CANCELLED 2=UNKNOWN 3=INVALID_ARGUMENT 4=DEADLINE_EXCEEDED 5=NOT_FOUND 7=PERMISSION_DENIED 12=UNIMPLEMENTED 13=INTERNAL 14=UNAVAILABLE',
            'Metadata': 'gRPC headers as HTTP/2 HEADERS frames: :method POST :path /pkg.Service/Method :authority host',
            'Deadlines': 'grpc-timeout header: 1H=1hour 100m=100ms 5S=5sec — server enforces',
            'Auth': 'Authorization: Bearer JWT | SSL client certificate | per-RPC credentials',
            'Streaming': 'Server-streaming: single request many responses | Client-streaming: many→one | Bidirectional: many↔many',
            'Reflection': 'grpc.reflection.v1alpha.ServerReflection — discover services at runtime',
            'CAUTION': 'gRPC requires HTTP/2 TLS — plaintext gRPC (h2c) only for testing; grpc-status=0 in trailer means success but check application-level response; deadline propagation across services required to prevent cascading; reflection service should be disabled in production (exposes API surface); HTTP/2 connection reuse means single TLS cert covers all services on port',
        },
        applications='Microservices RPC, Kubernetes API server, gNMI telemetry, Envoy/Istio sidecar communication',
    ),

    "udp_rpc": dict(
        name='ONC RPC — Open Network Computing Remote Procedure Call (RFC 1833/5531)',
        transport='UDP/111 (portmapper/rpcbind) + dynamic ports; TCP/111 for large replies',
        status='IETF Standard — RFC 5531 (ONC RPC), RFC 1833 (rpcbind), used by NFS/NLM/NSM',
        description='ONC RPC provides the transport-independent RPC mechanism for NFS and related protocols. Portmapper/rpcbind maps program/version/protocol to dynamic ports. XDR (eXternal Data Representation) serialises data.',
        header_bytes=24,
        fields={
            'XID': '4B  transaction ID — matches Call to Reply',
            'Message Type': '4B  0=CALL 1=REPLY',
            '── CALL ──': 'RPC-Version(4B=2)+Program(4B)+Version(4B)+Procedure(4B)+Credentials+Verifier+Payload',
            'Program': '4B  100000=portmapper 100003=NFS 100005=MOUNT 100021=NLM 100024=STATUS',
            'Procedure': '4B  portmapper: 1=GETPORT 2=SET 3=UNSET 4=DUMP 5=CALLIT',
            'Credentials': 'Flavour(4B)+Length(4B)+Data; 0=AUTH_NONE 1=AUTH_SYS 6=RPCSEC_GSS',
            'AUTH_SYS': 'Stamp(4B)+Machine-name+UID(4B)+GID(4B)+[GIDs]',
            'RPCSEC_GSS': 'Version(4B)+Procedure(4B)+SeqNo(4B)+Service(none/integ/priv)+Context-Handle+Verifier',
            '── REPLY ──': 'Reply-Stat(4B: 0=MSG_ACCEPTED 1=MSG_DENIED)+Verifier+Data',
            'Accept Stat': '0=SUCCESS 1=PROG_UNAVAIL 2=PROG_MISMATCH 3=PROC_UNAVAIL 4=GARBAGE_ARGS 5=SYSTEM_ERR',
            'Reject Stat': '0=RPC_MISMATCH 1=AUTH_ERROR',
            'TCP framing': '4B big-endian record mark: high bit=last fragment; lower 31b=fragment length',
            'GETPORT req': 'Program+Version+Protocol(6=TCP 17=UDP)+Port(0)',
            'CAUTION': 'portmapper/rpcbind UDP/111 must be firewalled — exposes service map; AUTH_SYS trusts client-supplied UID/GID — any client with root can impersonate; RPCSEC_GSS/Kerberos required for production NFS; ONC RPC callback ports are dynamic — firewall rules complex; NFS CALLIT (proc=5) can amplify UDP — disable if not needed',
        },
        applications='NFS filesystem access, NLM file locking, NSM status monitor, Sun RPC-based services',
    ),

}

NON_IP_L4_REGISTRY.update(EXTENDED_ACTIVE_L4_REGISTRY)

# AppleTalk AURP — standalone addition
NON_IP_L4_REGISTRY["aurp"] = dict(
    name="AppleTalk AURP — AppleTalk Update Routing Protocol",
    transport="AppleTalk DDP Type 11 (tunnel socket 0x0066) — WAN tunnel for remote AppleTalk zones",
    header_bytes=8,
    fields={
        "Connection ID":  "2B  identifies AURP connection between peer routers",
        "Sequence":       "2B  monotonically increasing for reliable delivery",
        "Command":        "2B  1=Open-Req 2=Open-Ack 3=Router-Down 4=Zone-Info 5=Update 6=Get-Update-Req 7=RD-Close",
        "Flags":          "2B  B(bidirectional)+HB(hop-count-carry)+version(3b)",
        "CAUTION":        "AURP completely obsolete — Apple deprecated AppleTalk in macOS 10.6 (2009); only on pre-2009 Mac networks",
    },
    applications="AppleTalk AURP — Update Routing Protocol for WAN-connected AppleTalk zones (obsolete 2009)",
)

# ═══════════════════════════════════════════════════════════════════════════════
# L4 FIELD COMPLETENESS FIXES — all based on RFC/spec cross-reference
# ═══════════════════════════════════════════════════════════════════════════════

# NTP — add ref_id field (RFC 5905 §7.3)
NON_IP_L4_REGISTRY["udp_ntp"]["fields"]["Ref ID"] = (
    "4B  Reference ID — stratum 0:'Kiss-Code' 1:source-name(ASCII) 2+:ref-source-IPv4")
NON_IP_L4_REGISTRY["udp_ntp"]["fields"]["Ref Timestamp"] = (
    "8B  Reference Timestamp — when clock was last set/corrected (NTP 64-bit)")
NON_IP_L4_REGISTRY["udp_ntp"]["fields"]["Orig Timestamp"] = (
    "8B  Origin Timestamp — T1: time request departed client")
NON_IP_L4_REGISTRY["udp_ntp"]["fields"]["Rx Timestamp"] = (
    "8B  Receive Timestamp — T2: time request arrived at server")

# SNMPv3 — add missing fields (RFC 3412 §6)
NON_IP_L4_REGISTRY["udp_snmpv3"]["fields"]["MsgMaxSize"] = (
    "4B  maximum message size sender can receive (≥484 bytes per RFC 3412)")
NON_IP_L4_REGISTRY["udp_snmpv3"]["fields"]["MsgSecModel"] = (
    "1B  security model: 1=SNMPv1 2=SNMPv2c 3=USM(RFC 3414)")
NON_IP_L4_REGISTRY["udp_snmpv3"]["fields"]["MsgSecLevel"] = (
    "2b  noAuthNoPriv(1) authNoPriv(2) authPriv(3)")

# GTP-U — add messageType per 3GPP TS 29.281
NON_IP_L4_REGISTRY["udp_gtp_u"]["fields"]["Message Type"] = (
    "1B  0xFF=G-PDU(user-data) 0x01=Echo-Req 0x02=Echo-Resp 0xFE=Error-Indication "
    "0x04=Supported-Ext-Hdr-Notify per 3GPP TS 29.281 Table 6.1-1")

# GTP-C — add messageType per 3GPP TS 29.274
NON_IP_L4_REGISTRY["udp_gtp_c"]["fields"]["Message Type"] = (
    "1B  0x01=Echo-Req 0x02=Echo-Resp 0x20=Create-Session-Req 0x21=Create-Session-Resp "
    "0x24=Delete-Session-Req 0x25=Delete-Session-Resp per 3GPP TS 29.274 Table 6.1-1")

# BFD — add state field (RFC 5880 §4.1)
NON_IP_L4_REGISTRY["udp_bfd"]["fields"]["State"] = (
    "2b  AdminDown=0 Down=1 Init=2 Up=3 — BFD session state machine per RFC 5880 §6.2")

# SIP — add Request-Line field (RFC 3261 §7.1)
NON_IP_L4_REGISTRY["udp_sip"]["fields"]["Request Line"] = (
    "Method SP Request-URI SP SIP-Version CRLF — e.g. INVITE sip:bob@biloxi.com SIP/2.0")
NON_IP_L4_REGISTRY["udp_sip"]["fields"]["Status Line"] = (
    "SIP-Version SP Status-Code SP Reason-Phrase CRLF — e.g. SIP/2.0 200 OK (response only)")

# DHCPv4 — rename/align with RFC 2131 field names
if "udp_dhcpv4" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_dhcpv4"]["fields"]["Magic Cookie"] = (
        "4B  0x63825363 — RFC 2131 magic cookie identifies DHCP vs BOOTP")
    NON_IP_L4_REGISTRY["udp_dhcpv4"]["fields"]["Option 53"] = (
        "1B value  DHCP Message Type: 1=Discover 2=Offer 3=Request 4=Decline "
        "5=Ack 6=Nak 7=Release 8=Inform")

# Add aliases for UDP protocols discovered missing in audit
# udp_dhcp4 → alias for udp_dhcpv4
if "udp_dhcp4" not in NON_IP_L4_REGISTRY and "udp_dhcpv4" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_dhcp4"] = NON_IP_L4_REGISTRY["udp_dhcpv4"]

# udp_dhcp6 → alias for udp_dhcpv6
if "udp_dhcp6" not in NON_IP_L4_REGISTRY and "udp_dhcpv6" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_dhcp6"] = NON_IP_L4_REGISTRY["udp_dhcpv6"]

# udp_snmpv2c → alias for udp_snmpv1 (same encoding, version field differs)
if "udp_snmpv2c" not in NON_IP_L4_REGISTRY and "udp_snmpv1" in NON_IP_L4_REGISTRY:
    import copy
    v2c = copy.deepcopy(NON_IP_L4_REGISTRY["udp_snmpv1"])
    v2c["name"] = "SNMPv2c — RFC 1901 Community-based SNMP v2"
    v2c["fields"]["Version"] = "1B  0x01=SNMPv2c (RFC 1901)"
    v2c["fields"]["Community"] = "variable  community string (cleartext)"
    NON_IP_L4_REGISTRY["udp_snmpv2c"] = v2c

# udp_rip2 → alias for udp_rip (RIPv2)
if "udp_rip2" not in NON_IP_L4_REGISTRY and "udp_rip" in NON_IP_L4_REGISTRY:
    import copy
    rip2 = copy.deepcopy(NON_IP_L4_REGISTRY["udp_rip"])
    rip2["name"] = "RIPv2 — Routing Information Protocol Version 2 (RFC 2453)"
    rip2["fields"]["Version"] = "1B  0x02=RIPv2 at offset 1"
    rip2["fields"]["Subnet Mask"] = "4B  subnet mask per RTE (RIPv2 extension over RIPv1)"
    rip2["fields"]["Next Hop"] = "4B  next-hop router address (0=use source IP)"
    rip2["fields"]["Route Tag"] = "2B  route tag for external route identification"
    NON_IP_L4_REGISTRY["udp_rip2"] = rip2

# udp_ike → alias for udp_isakmp (IKEv2 uses same UDP/500 port)
if "udp_ike" not in NON_IP_L4_REGISTRY and "udp_isakmp" in NON_IP_L4_REGISTRY:
    import copy
    ikev2 = copy.deepcopy(NON_IP_L4_REGISTRY["udp_isakmp"])
    ikev2["name"] = "IKEv2 — Internet Key Exchange v2 (RFC 7296)"
    ikev2["fields"]["Version"] = "4b  Major=2 Minor=0 for IKEv2 (RFC 7296 §3.1)"
    ikev2["fields"]["IKE_SA_INIT"] = "Exchange Type 34 — first message pair for IKE_SA"
    ikev2["fields"]["IKE_AUTH"] = "Exchange Type 35 — authentication of IKE peers"
    ikev2["fields"]["CREATE_CHILD_SA"] = "Exchange Type 36 — create/rekey child SA"
    NON_IP_L4_REGISTRY["udp_ike"] = ikev2

# udp_nat_t → alias for udp_natt (NAT Traversal)
if "udp_nat_t" not in NON_IP_L4_REGISTRY and "udp_natt" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_nat_t"] = NON_IP_L4_REGISTRY["udp_natt"]

# udp_bgp4 → alias for udp_bgp (BGP-4)
if "udp_bgp4" not in NON_IP_L4_REGISTRY and "udp_bgp" in NON_IP_L4_REGISTRY:
    import copy
    bgp4 = copy.deepcopy(NON_IP_L4_REGISTRY["udp_bgp"])
    bgp4["name"] = "BGP-4 — Border Gateway Protocol 4 (RFC 4271)"
    NON_IP_L4_REGISTRY["udp_bgp4"] = bgp4

# ── L2 HomePlug field expansion ───────────────────────────────────────────────
# HomePlug 1.0 (0x887B) — expand to full spec
# HomePlug AV (0x88E1) — expand

# ── L4: Add missing IP protocol entries to IP_PROTOCOL_REGISTRY ───────────────
# These will be added in l3_builder.py via a separate pass

# ═══════════════════════════════════════════════════════════════════════════════
# L4 FIELD COMPLETENESS PATCHES — all verified against RFC/IEEE specs
# ═══════════════════════════════════════════════════════════════════════════════

# NTP — add Tx Timestamp (RFC 5905 §7.3)
if "udp_ntp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_ntp"]["fields"]["Tx Timestamp"] = (
        "8B  Transmit Timestamp T3 — time NTP packet left server (64-bit NTP format)")

# DHCPv6 — add IA_TA and IAADDR per RFC 3315
if "udp_dhcpv6" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_dhcpv6"]["fields"].update({
        "IA_TA":        "Option 4 — Identity Association for Temporary Addresses: IAID(4B)",
        "IAADDR":       "Option 5 — IA Address: IPv6-address(16B)+preferred-lifetime(4B)+valid-lifetime(4B)",
        "Relay Agent":  "msg-type=12(Relay-Forw) 13(Relay-Reply): hop-count(1B)+link-addr(16B)+peer-addr(16B)+options",
    })

# RADIUS — add Attributes per RFC 2865
if "udp_radius" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_radius"]["fields"].update({
        "Attributes":   "variable  TLV: Type(1B)+Length(1B)+Value — Attr 1=User-Name 2=User-Password 4=NAS-IP 5=NAS-Port 6=Service-Type 61=NAS-Port-Type 79=EAP-Message 80=Message-Authenticator",
        "Attr 1":       "User-Name — RADIUS user identity string",
        "Attr 80":      "Message-Authenticator — HMAC-MD5 of entire RADIUS packet (RFC 3579)",
    })

# Geneve — add Protocol Type per RFC 8926
if "udp_geneve" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_geneve"]["fields"].update({
        "Protocol Type": "2B  inner frame EtherType: 0x6558=Trans-Eth-Bridge 0x0800=IPv4 0x86DD=IPv6 0x8847=MPLS",
        "Options":       "variable  Geneve options TLVs: Class(2B)+Type(1B)+R(3b)+Length(5b)+Value per RFC 8926 §3.5",
    })

# BFD — add Multipoint (RFC 7419)
if "udp_bfd" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_bfd"]["fields"].update({
        "Multipoint":    "1b  M bit — set in BFD Demand mode for P2MP BFD (RFC 7419)",
        "Auth Type":     "1B  (if AuthPresent) 1=Simple 2=Keyed-MD5 3=Met-Keyed-MD5 4=Keyed-SHA1 5=Met-SHA1",
    })

# RTP — add Sequence Number (distinct from CC/M/PT byte fields)
if "udp_rtp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_rtp"]["fields"].update({
        "Sequence Number": "2B  incremented per RTP packet; used for loss detection and jitter calculation per RFC 3550 §5.1",
        "CSRC List":     "0-60B  CC×4B contributing source IDs (CC determines count 0-15)",
    })

# RTCP — add Version field
if "udp_rtcp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_rtcp"]["fields"].update({
        "Version":       "2b  RTP version = 2 per RFC 3550 §6.4",
        "SC/RC":         "5b  source/reception report count",
        "PT":            "1B  RTCP packet type: 200=SR 201=RR 202=SDES 203=BYE 204=APP",
    })

# SIP — add Content-Length
if "udp_sip" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_sip"]["fields"].update({
        "Content-Length":"mandatory header: byte count of message body (0 if no body)",
        "Contact":       "optional: SIP URI for direct communication",
        "Max-Forwards":  "1B decimal: hop limit (default 70) decremented per proxy",
    })

# CoAP — add Version, Type, Options per RFC 7252
if "udp_coap" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_coap"]["fields"].update({
        "Version":       "2b  CoAP version = 1 per RFC 7252 §3",
        "Type":          "2b  0=CON(Confirmable) 1=NON 2=ACK 3=RST per RFC 7252 §4.2",
        "Options":       "variable  delta-encoded options: Option Delta(4b)+Length(4b)+[ExtDelta]+[ExtLen]+Value",
        "Option Numbers":"1=If-Match 3=Uri-Host 4=ETag 5=If-None-Match 7=Uri-Port 8=Location-Path 11=Uri-Path 12=Content-Format 14=Max-Age 15=Uri-Query 17=Accept 20=Location-Query 35=Proxy-Uri 39=Proxy-Scheme 60=Size1",
    })

# QUIC — add key fields per RFC 9000
if "udp_quic" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_quic"]["fields"].update({
        "DCIL":          "4b  Destination Connection ID Length",
        "SCIL":          "4b  Source Connection ID Length",
        "Destination Connection ID": "0-20B  recipient connection identifier per RFC 9000 §17.2",
        "Source Connection ID": "0-20B  sender connection identifier (long header only)",
        "Packet Number": "1-4B  packet number (encrypted, variable length) per RFC 9000 §17.1",
        "Payload":       "variable  QUIC frames: STREAM/CRYPTO/ACK/PADDING etc. (AEAD encrypted)",
    })

# PIM — add version field
if "udp_pim" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_pim"]["fields"].update({
        "PIM Version":   "4b  Protocol Independent Multicast version = 2 per RFC 7761 §4.9",
        "Reserved":      "4b  reserved = 0",
    })

# VRRP — add Count IP Addr and Advert Interval
if "udp_vrrp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_vrrp"]["fields"].update({
        "Count IP Addr": "1B  number of virtual IP addresses contained in advertisement",
        "Advert Int":    "1B  advertisement interval in seconds (default 1) per RFC 3768 §5.1",
    })

# OSPF — add AU Type
if "udp_ospf" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_ospf"]["fields"].update({
        "AU Type":       "2B  authentication type: 0=Null 1=Simple-Password 2=Cryptographic-MD5 per RFC 2328 §A.3.1",
        "Authentication":"8B  authentication data (zero for null; password bytes for simple; key-id+length+seq for crypto)",
    })

# BGP — add My Autonomous System
if "udp_bgp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_bgp"]["fields"].update({
        "My Autonomous System": "2B  local AS number (2-byte) in OPEN; use 4-byte AS via AS4_PATH attr (RFC 6793)",
        "Hold Time":     "2B  proposed hold time in seconds (0=disabled; negotiated lower value used)",
        "Optional Params":"variable  optional BGP OPEN parameters: type(1B)+len(1B)+value",
    })

# LDP — add Label Space ID
if "udp_ldp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_ldp"]["fields"].update({
        "Label Space ID":"2B  label space identifier: 0=per-interface 1=per-platform per RFC 5036 §2.1",
        "U bit":         "1b  Unknown TLV handling: 0=drop+notify 1=ignore+forward",
        "F bit":         "1b  Forward Unknown: controls unknown TLV forwarding",
    })

# ISAKMP — add Initiator/Responder SPI and version fields
if "udp_isakmp" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_isakmp"]["fields"].update({
        "Initiator SPI": "8B  IKE Security Parameter Index chosen by initiator (random)",
        "Responder SPI": "8B  IKE SPI chosen by responder (zero in IKE_SA_INIT request)",
        "Major Version": "4b  IKE major version: 1=IKEv1(RFC 2408) 2=IKEv2(RFC 7296)",
        "Minor Version": "4b  IKE minor version: 0 for both IKEv1 and IKEv2",
    })

# NAT-T — add IKE header reference
if "udp_natt" in NON_IP_L4_REGISTRY:
    NON_IP_L4_REGISTRY["udp_natt"]["fields"].update({
        "IKE Header":    "20B  IKE header follows: Init-SPI(8B)+Resp-SPI(8B)+NextPay(1B)+Ver(1B)+ExchType(1B)+Flags(1B)+MsgID(4B)+Length(4B)",
        "Non-ESP Marker":"4B  0x00000000 = IKE packet; non-zero = ESP packet (per RFC 3948 §2.2)",
    })

# Thin L4 entries — expand fields
NON_IP_L4_REGISTRY["ethercat_nv"]["fields"].update({
    "NV Type":       "2B  Network Variable type identifier",
    "NV Data":       "variable  network variable value data",
    "Timestamp":     "optional 4B  hardware timestamp if supported",
})
NON_IP_L4_REGISTRY["frer_payload"]["fields"].update({
    "R-Tag":         "4B  Redundancy Tag per IEEE 802.1CB: TPID(2B=0xF1C1)+SeqNum(12b)+Reserved(4b)",
    "Sequence Num":  "12b  R-Tag sequence number for FRER duplicate detection",
    "Inner Frame":   "variable  original Ethernet payload following R-Tag",
})
NON_IP_L4_REGISTRY["geonet_beacon"]["fields"].update({
    "Long PV":       "24B  Long Position Vector: GN-ADDR(8B)+TST(4B)+Lat(4B)+Long(4B)+PAI(1b)+Speed(15b)+Heading(16b)",
    "GN-ADDR":       "8B  GeoNetworking address: M(1b)+ST(5b)+Reserved(10b)+MAC(48b)",
    "TST":           "4B  timestamp in milliseconds since 2004-01-04 00:00:00 UTC",
})
NON_IP_L4_REGISTRY["homeplug_av2_mme"]["fields"].update({
    "OUI":           "3B  0x00:B0:52 HomePlug Alliance OUI",
    "MMType":        "2B  AV2 management message type",
    "FMI":           "2B  Fragment Management Information",
})
NON_IP_L4_REGISTRY["homeplug_mme"]["fields"].update({
    "MMType":        "2B  HomePlug 1.0 management message type: 0x0000=Request 0x0001=Confirm",
    "MME Data":      "variable  MME body: key exchange, tone map, metering data",
    "NPW Derivation":"network password (NPW) hashed to generate Network Encryption Key",
})
NON_IP_L4_REGISTRY["ipv4_inner"]["fields"].update({
    "Version":       "4b  IP version = 4",
    "IHL":           "4b  header length in 32-bit words (min 5=20B)",
    "Inner Payload": "variable  inner IPv4 datagram (after VLAN tag)",
})
NON_IP_L4_REGISTRY["ipx_rip_xns"]["fields"].update({
    "Operation":     "2B  1=Request 2=Response",
    "Network":       "4B  target network number",
    "Hop Count":     "2B  distance in hops to network",
})
NON_IP_L4_REGISTRY["local_exp_payload"]["fields"].update({
    "Experiment":    "variable  experimenter-defined payload structure",
    "Exp ID":        "optional  experiment identifier prefix",
    "Data":          "variable  experiment data",
})
NON_IP_L4_REGISTRY["loopback_test"]["fields"].update({
    "Function":      "2B  0x0001=Reply  0x0002=Forward-Data",
    "Reply Count":   "2B  number of skips before sending reply",
    "Receipt Number":"2B  echoed from request — identifies which request this replies to",
})
NON_IP_L4_REGISTRY["pep"]["fields"].update({
    "Op":            "1B  XNS PEP operation code",
    "Data":          "variable  Packet Exchange Protocol data",
    "Client":        "2B  client type for PEP routing",
})
NON_IP_L4_REGISTRY["ppp_ipv4"]["fields"].update({
    "PPP Protocol":  "2B  0x0021 IPv4",
    "IP Datagram":   "variable  standard IPv4 packet",
    "ACCM":          "Async Control Character Map (for async PPP links); not present in sync",
})
NON_IP_L4_REGISTRY["pup_error"]["fields"].update({
    "Error Code":    "2B  PUP error type code",
    "Error Param":   "2B  error-specific parameter value",
    "Original PUP":  "variable  first 22 bytes of offending PUP datagram",
})
NON_IP_L4_REGISTRY["qinq_inner"]["fields"].update({
    "Inner EtherType":"2B  EtherType of inner payload (typically 0x0800=IPv4 0x86DD=IPv6)",
    "Inner Payload": "variable  payload following the double VLAN tags",
    "C-VID":         "12b  Customer VLAN ID in inner 802.1Q tag",
})
NON_IP_L4_REGISTRY["vines_arp"]["fields"].update({
    "Operation":     "2B  1=Request 2=Reply",
    "Sender Network":"4B  VINES network number of sender",
    "Sender Subnet": "2B  VINES subnetwork address of sender",
})
NON_IP_L4_REGISTRY["vines_icp"]["fields"].update({
    "ICP Type":      "2B  VINES ICP message type code",
    "Exception":     "1B  exception number",
    "Data":          "variable  ICP-specific data",
})
NON_IP_L4_REGISTRY["xns_error"]["fields"].update({
    "Error Number":  "2B  XNS IDP error code",
    "Error Param":   "2B  error parameter value",
    "Offending Pkt": "variable  first 42 bytes of offending XNS packet",
})
NON_IP_L4_REGISTRY["xns_rip"]["fields"].update({
    "Operation":     "2B  1=Request 2=Response",
    "Network":       "4B  target network number",
    "Hop Count":     "2B  distance in hops (RIP metric)",
})
NON_IP_L4_REGISTRY["zip"]["fields"].update({
    "Command":       "1B  ZIP command: 1=Query 2=Reply 3=TakeDown 4=BringUp",
    "Net Count":     "1B  number of network ranges in this packet",
    "Network Range": "2B+2B  first/last network number of range",
})
