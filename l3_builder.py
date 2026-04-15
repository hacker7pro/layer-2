"""
l3_builder.py  —  Layer 3 Intelligence Engine
===============================================
Centralises ALL Layer-3 knowledge:
  • Full IPv4 / IPv6 / ARP / ICMP / IGMP / GRE / IPsec / MPLS / OSPF logic
  • Protocol-number registry        (IANA + commonly used values)
  • L3 → L4 auto-mapping            (IP protocol field)
  • MPLS recursive label-stack      (pops labels, resolves inner payload)
  • PPP extraction                  (strips PPP, resolves inner L3)
  • ARP termination                 (ARP has no L4 — stops here)
  • Field-level concise detail per protocol
  • process_l3() integration function called by main.py

Compatible with main.py's existing builders:
  build_ipv4 / build_arp / build_icmp / build_stp / build_lacp / etc.
"""

from __future__ import annotations
import struct
import socket
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — IP PROTOCOL NUMBER REGISTRY
#  IANA-assigned protocol numbers  (RFC 5237 + later assignments)
#  key   : int protocol number
#  value : dict(name, full_name, pdu, category, status, l4_proto, fields, usage)
# ══════════════════════════════════════════════════════════════════════════════

IP_PROTOCOL_REGISTRY: dict[int, dict] = {

    # ── ICMP family ───────────────────────────────────────────────────────────
    1: dict(name="ICMP",    full_name="Internet Control Message Protocol",
            pdu="ICMP Message",   category="Standard", status="Active",
            l4_proto="icmp",      usage="Control/Diagnostics",
            fields={"Type":"1B message type","Code":"1B sub-type",
                    "Checksum":"2B one's-complement","Rest":"4B type-specific",
                    "Data":"variable payload"}),

    58: dict(name="ICMPv6", full_name="ICMP for IPv6",
             pdu="ICMPv6 Message", category="Standard", status="Active",
             l4_proto="icmpv6",   usage="Control/Diagnostics (IPv6)",
             fields={"Type":"1B","Code":"1B","Checksum":"2B",
                     "Body":"type-specific (NDP, MLD, etc.)"}),

    # ── Transport ─────────────────────────────────────────────────────────────
    6: dict(name="TCP",     full_name="Transmission Control Protocol",
            pdu="TCP Segment",    category="Standard", status="Active",
            l4_proto="tcp",       usage="Transport (reliable)",
            fields={"Src Port":"2B","Dst Port":"2B","Seq":"4B","Ack":"4B",
                    "Data Offset":"4b header len ÷4","Flags":"9b SYN ACK FIN RST PSH URG",
                    "Window":"2B receive buffer","Checksum":"2B pseudo-hdr+seg",
                    "Urgent":"2B pointer"}),

    17: dict(name="UDP",    full_name="User Datagram Protocol",
             pdu="UDP Datagram",   category="Standard", status="Active",
             l4_proto="udp",       usage="Transport (fast/connectionless)",
             fields={"Src Port":"2B","Dst Port":"2B",
                     "Length":"2B header+data","Checksum":"2B optional"}),

    # ── Tunneling / Encapsulation ──────────────────────────────────────────────
    4: dict(name="IP-IP",   full_name="IP in IP Encapsulation",
            pdu="IPv4 Packet",    category="Standard", status="Active",
            l4_proto="ipv4",      usage="Tunneling",
            fields={"Outer IPv4":"standard IPv4 header","Inner IPv4":"encapsulated datagram"}),

    41: dict(name="IPv6",   full_name="IPv6 Encapsulation (6in4)",
             pdu="IPv6 Packet",   category="Standard", status="Active",
             l4_proto="ipv6",     usage="Tunneling (6in4)",
             fields={"Outer IPv4":"standard header","Inner IPv6":"encapsulated datagram"}),

    47: dict(name="GRE",    full_name="Generic Routing Encapsulation",
             pdu="GRE Frame",     category="Standard", status="Active",
             l4_proto="gre",      usage="Tunneling",
             fields={"Flags+Ver":"2B","Protocol":"2B inner EtherType",
                     "Checksum":"opt 4B","Key":"opt 4B","Seq":"opt 4B",
                     "Inner Pkt":"encapsulated datagram"}),

    # ── IPsec ─────────────────────────────────────────────────────────────────
    50: dict(name="ESP",    full_name="Encapsulating Security Payload",
             pdu="ESP Packet",    category="Standard", status="Active",
             l4_proto="esp",      usage="Security/Encryption",
             fields={"SPI":"4B Security Parameters Index",
                     "Seq":"4B anti-replay counter",
                     "Payload":"encrypted (variable)",
                     "Pad":"0-255B","Pad-len":"1B","Next-Hdr":"1B",
                     "ICV":"integrity check value (8-16B)"}),

    51: dict(name="AH",     full_name="Authentication Header",
             pdu="AH Packet",     category="Standard", status="Active",
             l4_proto="ah",       usage="Security/Integrity",
             fields={"Next-Hdr":"1B","Payload-Len":"1B",
                     "Reserved":"2B","SPI":"4B","Seq":"4B",
                     "ICV":"variable integrity check value"}),

    # ── Routing protocols ─────────────────────────────────────────────────────
    89: dict(name="OSPF",   full_name="Open Shortest Path First",
             pdu="OSPF Packet",   category="Standard", status="Active",
             l4_proto="ospf",     usage="Routing",
             fields={"Version":"1B","Type":"1B 1=Hello 2=DBD 3=LSReq 4=LSU 5=LSAck",
                     "Length":"2B","Router-ID":"4B","Area-ID":"4B",
                     "Checksum":"2B","Auth-Type":"2B","Auth":"8B"}),

    88: dict(name="EIGRP",  full_name="Enhanced Interior Gateway Routing Protocol",
             pdu="EIGRP Packet",  category="Vendor", status="Vendor-specific",
             l4_proto="eigrp",    usage="Routing (Cisco)",
             fields={"Version":"1B","Opcode":"1B","Checksum":"2B",
                     "Flags":"4B","Seq":"4B","Ack":"4B","AS":"4B","TLVs":"chain"}),

    112: dict(name="VRRP",  full_name="Virtual Router Redundancy Protocol",
              pdu="VRRP Packet",  category="Standard", status="Active",
              l4_proto="vrrp",    usage="Routing/Redundancy",
              fields={"Version+Type":"1B","VRID":"1B virtual router ID",
                      "Priority":"1B 0-255","Count-IPvX-Addrs":"1B",
                      "Adver-Int":"2B advertisement interval","Checksum":"2B",
                      "IP Addresses":"list of virtual router IPs"}),

    # ── Multicast ─────────────────────────────────────────────────────────────
    2: dict(name="IGMP",    full_name="Internet Group Management Protocol",
            pdu="IGMP Message",   category="Standard", status="Active",
            l4_proto="igmp",      usage="Multicast Control",
            fields={"Type":"1B 0x11=Query 0x16=Report 0x17=Leave",
                    "Max Resp Time":"1B","Checksum":"2B","Group-Addr":"4B"}),

    103: dict(name="PIM",   full_name="Protocol Independent Multicast",
              pdu="PIM Message",  category="Standard", status="Active",
              l4_proto="pim",     usage="Multicast Routing",
              fields={"Version+Type":"1B","Reserved":"1B","Checksum":"2B",
                      "Body":"type-specific (Hello/Join/Prune/Register)"}),

    # ── SCTP / DCCP ───────────────────────────────────────────────────────────
    132: dict(name="SCTP",  full_name="Stream Control Transmission Protocol",
              pdu="SCTP Packet",  category="Standard", status="Active",
              l4_proto="sctp",    usage="Transport (multi-stream)",
              fields={"Src Port":"2B","Dst Port":"2B","Verif-Tag":"4B",
                      "Checksum":"4B Adler32","Chunks":"variable"}),

    33: dict(name="DCCP",   full_name="Datagram Congestion Control Protocol",
             pdu="DCCP Packet",   category="Standard", status="Active",
             l4_proto="dccp",     usage="Transport (semi-reliable)",
             fields={"Src Port":"2B","Dst Port":"2B","Data Offset":"1B",
                     "CCVal":"4b","CsCov":"4b","Checksum":"2B","Type":"4b"}),

    # ── Mobility ──────────────────────────────────────────────────────────────
    55: dict(name="Mobile IP",full_name="Mobile IP",
             pdu="MIP Packet",    category="Standard", status="Active",
             l4_proto=None,       usage="Mobile networking",
             fields={"Type":"1B","Flags":"1B","Lifetime":"2B",
                     "Home-Addr":"4B","CoA":"4B","ID":"8B","Extensions":"var"}),

    # ── L2TP / misc tunnel ────────────────────────────────────────────────────
    115: dict(name="L2TP",  full_name="Layer 2 Tunneling Protocol",
              pdu="L2TP Packet",  category="Standard", status="Active",
              l4_proto="l2tp",    usage="Tunneling (VPN/DSL)",
              fields={"Flags":"2B","Version":"4b","Length":"opt 2B",
                      "Tunnel-ID":"2B","Session-ID":"2B","Seq":"opt 2B","Data":"var"}),

    # ── IS-IS ─────────────────────────────────────────────────────────────────
    124: dict(name="IS-IS", full_name="Intermediate System to Intermediate System",
              pdu="ISIS PDU",     category="Standard", status="Active",
              l4_proto="isis",    usage="Routing",
              fields={"Note":"usually runs direct on L2 (CLNS), not in IPv4"}),

    # ── No Next Header ────────────────────────────────────────────────────────
    59: dict(name="No Next Header", full_name="No next header (IPv6)",
             pdu="RAW",            category="Standard", status="Active",
             l4_proto=None,        usage="IPv6 empty payload marker",
             fields={"Note":"0x3B — no layer 4 follows this header"}),

    # ── Encapsulating protocols ───────────────────────────────────────────────
    98: dict(name="ENCAP",  full_name="Encapsulation Header",
             pdu="RAW",            category="Standard", status="Deprecated",
             l4_proto=None,        usage="RFC 1241 encapsulation",
             fields={}),

    # ── RSVP ─────────────────────────────────────────────────────────────────
    46: dict(name="RSVP",   full_name="Resource Reservation Protocol",
             pdu="RSVP Message",   category="Standard", status="Active",
             l4_proto="rsvp",      usage="QoS signalling",
             fields={"Version":"4b","Flags":"4b","Msg-Type":"1B",
                     "Checksum":"2B","Length":"2B","Objects":"variable"}),

    # ── Experimental ─────────────────────────────────────────────────────────
    253: dict(name="Exp-253", full_name="Experimental protocol 253",
              pdu="RAW",           category="Standard", status="Experimental",
              l4_proto=None,       usage="RFC 3692 experimental",
              fields={}),
    254: dict(name="Exp-254", full_name="Experimental protocol 254",
              pdu="RAW",           category="Standard", status="Experimental",
              l4_proto=None,       usage="RFC 3692 experimental",
              fields={}),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — ICMP TYPE/CODE TABLE (extended)
# ══════════════════════════════════════════════════════════════════════════════

ICMP_EXTENDED: dict[int, dict] = {
    0:  dict(name="Echo Reply",              codes={0:"Echo reply"},
             usage="Ping response", direction="reply"),
    3:  dict(name="Destination Unreachable", codes={
                0:"Net unreachable",    1:"Host unreachable",
                2:"Protocol unreachable",3:"Port unreachable",
                4:"Fragmentation needed/DF set",5:"Source route failed",
                6:"Dst network unknown",7:"Dst host unknown",
                8:"Src host isolated",  9:"Net admin prohibited",
               10:"Host admin prohibited",11:"Net TOS unreachable",
               12:"Host TOS unreachable",13:"Comm admin prohibited",
               14:"Host precedence violation",15:"Precedence cutoff"},
             usage="Error reporting", direction="error"),
    4:  dict(name="Source Quench",           codes={0:"Source quench (congestion)"},
             usage="Congestion (deprecated)", direction="control"),
    5:  dict(name="Redirect",                codes={
                0:"Redirect for network",1:"Redirect for host",
                2:"Redirect for TOS+network",3:"Redirect for TOS+host"},
             usage="Routing hint", direction="control"),
    8:  dict(name="Echo Request",            codes={0:"Echo request"},
             usage="Ping probe",   direction="request"),
    9:  dict(name="Router Advertisement",    codes={0:"Normal advertisement"},
             usage="Router discovery", direction="broadcast"),
    10: dict(name="Router Solicitation",     codes={0:"Router solicitation"},
             usage="Router discovery", direction="request"),
    11: dict(name="Time Exceeded",           codes={0:"TTL exceeded in transit",
                                                     1:"Fragment reassembly time exceeded"},
             usage="Traceroute / loop prevention", direction="error"),
    12: dict(name="Parameter Problem",       codes={0:"Pointer indicates error",
                                                     1:"Missing required option",
                                                     2:"Bad length"},
             usage="Header error", direction="error"),
    13: dict(name="Timestamp Request",       codes={0:"Timestamp request"},
             usage="Time synchronisation", direction="request"),
    14: dict(name="Timestamp Reply",         codes={0:"Timestamp reply"},
             usage="Time synchronisation", direction="reply"),
    15: dict(name="Information Request",     codes={0:"Information request"},
             usage="Deprecated (use DHCP)", direction="request"),
    16: dict(name="Information Reply",       codes={0:"Information reply"},
             usage="Deprecated (use DHCP)", direction="reply"),
    17: dict(name="Address Mask Request",    codes={0:"Address mask request"},
             usage="Subnet mask discovery (deprecated)", direction="request"),
    18: dict(name="Address Mask Reply",      codes={0:"Address mask reply"},
             usage="Subnet mask discovery (deprecated)", direction="reply"),
    30: dict(name="Traceroute",              codes={0:"Information request (deprecated)"},
             usage="Obsolete traceroute", direction="info"),
    40: dict(name="Photuris",                codes={0:"Bad SPI",1:"Authentication failed",
                                                     2:"Decomp failed",3:"Decrypt failed",
                                                     4:"Need auth",5:"Need authenc"},
             usage="Security failures", direction="error"),
    42: dict(name="Extended Echo Request",   codes={0:"No error"},
             usage="Extended ping (RFC 8335)", direction="request"),
    43: dict(name="Extended Echo Reply",     codes={0:"No error",1:"Malformed query",
                                                     2:"No such interface",3:"No such table entry",
                                                     4:"Multiple interfaces satisfy query"},
             usage="Extended ping reply", direction="reply"),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — IPv4 OPTIONS TABLE
# ══════════════════════════════════════════════════════════════════════════════

IPv4_OPTIONS: dict[int, dict] = {
    0x00: dict(name="End of Option List", size=1, usage="Terminates option list"),
    0x01: dict(name="NOP",               size=1, usage="Padding/alignment"),
    0x07: dict(name="Record Route",      size="variable",
               usage="Routers record outbound interface IP"),
    0x44: dict(name="Timestamp",         size="variable",
               usage="Routers record timestamps"),
    0x83: dict(name="Loose Source Route",size="variable",
               usage="Sender specifies loose route hops"),
    0x89: dict(name="Strict Source Route",size="variable",
               usage="Sender specifies exact route hops"),
    0x94: dict(name="Router Alert",      size=4,
               usage="Ask each router to examine packet"),
    0x88: dict(name="Stream ID",         size=4,
               usage="Stream identifier (obsolete)"),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — IPv6 NEXT-HEADER TABLE
# ══════════════════════════════════════════════════════════════════════════════

IPv6_NEXT_HEADER: dict[int, str] = {
    0:  "Hop-by-Hop Options",
    43: "Routing Header",
    44: "Fragment Header",
    50: "ESP",
    51: "AH",
    59: "No Next Header",
    60: "Destination Options",
    135:"MIPv6",
    139:"HIP",
    140:"Shim6",
    6:  "TCP",
    17: "UDP",
    58: "ICMPv6",
    89: "OSPF",
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — GRE PROTOCOL REGISTRY  (inner EtherType carried in GRE)
# ══════════════════════════════════════════════════════════════════════════════

GRE_PROTO_MAP: dict[int, str] = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x8847: "MPLS Unicast",
    0x8848: "MPLS Multicast",
    0x88BE: "ERSPAN Type II",
    0x22EB: "ERSPAN Type III",
    0x6558: "Transparent Ethernet Bridging",
    0x880B: "PPP",
    0x0001: "HDLC",
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — MPLS LABEL STACK INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

# Well-known MPLS labels (RFC 3032 + extensions)
MPLS_RESERVED_LABELS: dict[int, str] = {
    0:  "IPv4 Explicit Null",
    1:  "Router Alert",
    2:  "IPv6 Explicit Null",
    3:  "Implicit Null (PHP)",
    7:  "Entropy Label Indicator (ELI)",
    8:  "Entropy Label (EL)",
    13: "GAL (Generic Associated Channel Label)",
    14: "OAM Alert Label",
    15: "Extension Label (XL)",
}

def decode_mpls_stack(data: bytes) -> list[dict]:
    """
    Decode an MPLS label stack from raw bytes.
    Returns list of dicts {label, tc, s, ttl, reserved_name}.
    Stops when S=1 (bottom of stack).
    """
    entries = []
    offset  = 0
    while offset + 4 <= len(data):
        word = struct.unpack("!I", data[offset:offset+4])[0]
        label = (word >> 12) & 0xFFFFF
        tc    = (word >> 9)  & 0x7
        s     = (word >> 8)  & 0x1
        ttl   =  word        & 0xFF
        entries.append(dict(
            label        = label,
            tc           = tc,
            s            = s,
            ttl          = ttl,
            reserved_name= MPLS_RESERVED_LABELS.get(label),
            bottom       = bool(s),
        ))
        offset += 4
        if s:
            break   # bottom of stack reached
    return entries


def mpls_infer_payload_type(inner_data: bytes) -> str:
    """
    After popping all MPLS labels, infer the inner payload type
    from the first nibble of remaining data.
    """
    if not inner_data:
        return "empty"
    first_nibble = (inner_data[0] >> 4) & 0xF
    if first_nibble == 4:
        return "ipv4"
    if first_nibble == 6:
        return "ipv6"
    if inner_data[:2] == b'\xFF\x03':
        return "ppp"
    return "raw"


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — AUTO-MAPPING ENGINE  (L3 → L4)
# ══════════════════════════════════════════════════════════════════════════════

def protocol_to_l4(proto_num: int) -> dict:
    """
    Given IPv4/IPv6 protocol number, return L4 metadata.
    """
    entry = IP_PROTOCOL_REGISTRY.get(proto_num)
    if entry:
        return dict(
            proto_num  = proto_num,
            name       = entry["name"],
            full_name  = entry["full_name"],
            pdu        = entry["pdu"],
            category   = entry["category"],
            status     = entry["status"],
            l4_proto   = entry["l4_proto"],
            usage      = entry["usage"],
            fields     = entry["fields"],
            source     = "registry",
        )
    return dict(
        proto_num = proto_num,
        name      = f"Proto-{proto_num}",
        full_name = f"Unknown protocol {proto_num}",
        pdu       = "RAW",
        category  = "Unknown",
        status    = "Unknown",
        l4_proto  = None,
        usage     = "Unknown",
        fields    = {},
        source    = "dynamic-unknown",
    )


def gre_inner_proto(proto: int) -> str:
    """Return a human name for the GRE inner protocol field."""
    return GRE_PROTO_MAP.get(proto, f"0x{proto:04X}")


def ipv6_next_header_name(nh: int) -> str:
    return IPv6_NEXT_HEADER.get(nh, f"Unknown-{nh}")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — IPv4 PACKET ANALYSER  (for process_l3)
# ══════════════════════════════════════════════════════════════════════════════

def analyse_ipv4_header(raw: bytes) -> dict:
    """
    Parse a raw IPv4 header (first 20+ bytes) and return a detail dict.
    Does NOT re-implement build_ipv4 — used for metadata extraction only.
    """
    if len(raw) < 20:
        return dict(valid=False, reason="Too short for IPv4")

    version  = (raw[0] >> 4) & 0xF
    ihl      = (raw[0] & 0xF) * 4
    if version != 4:
        return dict(valid=False, reason=f"Version={version} expected 4")

    dscp     = (raw[1] >> 2) & 0x3F
    ecn      = raw[1] & 0x3
    tot_len  = struct.unpack("!H", raw[2:4])[0]
    ip_id    = struct.unpack("!H", raw[4:6])[0]
    flags_ff = struct.unpack("!H", raw[6:8])[0]
    df       = bool(flags_ff & 0x4000)
    mf       = bool(flags_ff & 0x2000)
    frag_off = flags_ff & 0x1FFF
    ttl      = raw[8]
    proto    = raw[9]
    cksum    = struct.unpack("!H", raw[10:12])[0]
    src_ip   = socket.inet_ntoa(raw[12:16])
    dst_ip   = socket.inet_ntoa(raw[16:20])

    return dict(
        valid    = True,
        version  = version,
        ihl      = ihl,
        dscp     = dscp,
        ecn      = ecn,
        tot_len  = tot_len,
        ip_id    = ip_id,
        df       = df,
        mf       = mf,
        frag_off = frag_off,
        ttl      = ttl,
        proto    = proto,
        cksum    = cksum,
        src_ip   = src_ip,
        dst_ip   = dst_ip,
        l4_proto = protocol_to_l4(proto)["l4_proto"],
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — COMBINATION / NESTING SUPPORT
# ══════════════════════════════════════════════════════════════════════════════

# Maps l2 next_layer → expected l3 class
L2_TO_L3_CLASS: dict[str, str] = {
    "ipv4":   "ipv4",
    "ipv6":   "ipv6",
    "arp":    "arp",        # terminates — no L4
    "rarp":   "rarp",       # terminates — no L4
    "mpls":   "mpls",       # recursive until BOS
    "pppoe":  "pppoe",      # inner PPP → inner L3
    "gre":    "gre",        # inner proto → inner L3
    "esp":    "esp",        # encrypted — no parsed L4
    "ah":     "ah",         # inner proto after AH
}

# Protocols that do NOT propagate to L4
L3_TERMINATES: set = {"arp", "rarp", "stp", "dtp", "pagp", "lldp",
                       "pfc", "pause", "vlan_only", "esp"}

# Protocols requiring recursive L3 processing
L3_RECURSIVE: set  = {"mpls", "gre", "pppoe", "ipip", "6in4"}


def resolve_l3_chain(l2_next: str) -> dict:
    """
    Given the L2's next_layer hint, describe the L3 processing chain.
    Returns dict(l3_class, has_l4, recursive, reason).
    """
    if l2_next is None:
        return dict(l3_class=None, has_l4=False, recursive=False,
                    reason="No L3 implied by this L2 protocol")

    l3 = L2_TO_L3_CLASS.get(l2_next, l2_next)
    terminates = l3 in L3_TERMINATES
    recursive  = l3 in L3_RECURSIVE

    return dict(
        l3_class  = l3,
        has_l4    = not terminates,
        recursive = recursive,
        reason    = (
            "ARP/STP/control — no L4" if terminates else
            "Recursive tunnel — peel another L3 layer" if recursive else
            "Standard L3 — maps to L4 via protocol field"
        ),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — process_l3()  (called by main.py)
# ══════════════════════════════════════════════════════════════════════════════

def process_l3(
    l2_data:       dict,
    proto_num:     int  | None = None,
    raw_header:    bytes | None = None,
    src_ip:        str  | None = None,
    dst_ip:        str  | None = None,
    extra:         dict | None = None,
) -> dict:
    """
    Central L3 intelligence dispatcher.

    Parameters
    ----------
    l2_data    : dict returned by process_l2() — provides l2 context + next_layer hint
    proto_num  : IPv4/IPv6 protocol field (if known at call time)
    raw_header : raw bytes of the L3 header (optional — for analysis)
    src_ip     : source IPv4/IPv6 address string
    dst_ip     : destination IPv4/IPv6 address string
    extra      : additional context

    Returns
    -------
    dict with keys:
        l3_class, proto_num, l4_mapping, has_l4,
        l3_chain, header_analysis, field_detail, next_layer
    """
    extra = extra or {}

    # ── Determine L3 class from L2 context ───────────────────────────────────
    l2_next  = l2_data.get("next_layer")
    l3_chain = resolve_l3_chain(l2_next)
    l3_class = l3_chain["l3_class"]

    # ── Resolve L4 mapping ────────────────────────────────────────────────────
    if proto_num is not None:
        l4_mapping = protocol_to_l4(proto_num)
    else:
        l4_mapping = dict(l4_proto=None, name="Unknown", pdu="RAW")

    next_layer = l4_mapping.get("l4_proto")

    # ── Analyse raw header if provided ───────────────────────────────────────
    header_analysis = {}
    if raw_header:
        if l3_class == "ipv4" or (raw_header and (raw_header[0] >> 4) == 4):
            header_analysis = analyse_ipv4_header(raw_header)
            if not proto_num and header_analysis.get("valid"):
                proto_num  = header_analysis["proto"]
                l4_mapping = protocol_to_l4(proto_num)
                next_layer = l4_mapping.get("l4_proto")

    # ── Field detail for L3 protocol ─────────────────────────────────────────
    field_detail = {}
    if proto_num is not None:
        entry = IP_PROTOCOL_REGISTRY.get(proto_num, {})
        field_detail = entry.get("fields", {})

    # ── MPLS label stack decode ───────────────────────────────────────────────
    mpls_stack = []
    if l3_class == "mpls" and raw_header:
        mpls_stack    = decode_mpls_stack(raw_header)
        inner_payload = raw_header[len(mpls_stack) * 4:]
        inner_type    = mpls_infer_payload_type(inner_payload)
        next_layer    = inner_type

    return dict(
        l3_class         = l3_class,
        proto_num        = proto_num,
        src_ip           = src_ip,
        dst_ip           = dst_ip,
        l4_mapping       = l4_mapping,
        has_l4           = l3_chain["has_l4"],
        l3_chain         = l3_chain,
        header_analysis  = header_analysis,
        field_detail     = field_detail,
        next_layer       = next_layer,
        mpls_stack       = mpls_stack,
        l2_context       = l2_data,
        extra            = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — CONVENIENCE WRAPPERS
# ══════════════════════════════════════════════════════════════════════════════

def process_l3_ipv4(l2_data: dict, proto_num: int,
                    src_ip: str, dst_ip: str, raw: bytes | None = None) -> dict:
    return process_l3(l2_data, proto_num=proto_num,
                      raw_header=raw, src_ip=src_ip, dst_ip=dst_ip)


def process_l3_arp(l2_data: dict) -> dict:
    """ARP has no L4 — terminates at L3."""
    return process_l3(l2_data, proto_num=None,
                      extra={"terminates": True, "reason": "ARP has no Layer 4"})


def process_l3_mpls(l2_data: dict, raw_label_stack: bytes) -> dict:
    return process_l3(l2_data, raw_header=raw_label_stack,
                      extra={"recursive": True})


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — LISTING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def list_ip_protocols(
    category: str | None = None,
    status:   str | None = None,
) -> list[tuple[int, str, str, str]]:
    """List (num, name, category, status) optionally filtered."""
    result = []
    for num, info in IP_PROTOCOL_REGISTRY.items():
        if category and info["category"] != category:
            continue
        if status and info["status"] != status:
            continue
        result.append((num, info["name"], info["category"], info["status"]))
    return sorted(result, key=lambda x: x[0])


def get_icmp_type_info(icmp_type: int) -> dict:
    """Return ICMP type metadata including code table."""
    return ICMP_EXTENDED.get(icmp_type, dict(
        name=f"ICMP Type {icmp_type}", codes={}, usage="Unknown", direction="unknown"))


def get_ipv4_option_info(option_type: int) -> dict:
    return IPv4_OPTIONS.get(option_type, dict(
        name=f"Option 0x{option_type:02X}", size="unknown", usage="Unknown"))


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — NON-IP L3 PROTOCOL REGISTRIES
#  Covers: XNS/IDP, Novell IPX, AppleTalk DDP, Banyan VINES VIP,
#          DECnet Phase IV, DEC LAT, IBM SNA, Xerox PUP
#  Each entry: l4_dispatch  → maps L3 type/packet-type field to L4 class
# ══════════════════════════════════════════════════════════════════════════════

# ── XNS IDP Packet Types → L4 ─────────────────────────────────────────────────
XNS_PACKET_TYPES: dict[int, dict] = {
    0: dict(name="Raw IDP",  l4="raw_idp",  usage="Direct socket access — no L4 header"),
    1: dict(name="RIP",      l4="xns_rip",  usage="Routing Information Protocol — distance vector"),
    2: dict(name="Echo",     l4="xns_echo", usage="Reachability test (≈ ICMP echo)"),
    3: dict(name="Error",    l4="xns_error",usage="Error reporting (≈ ICMP unreachable/exceeded)"),
    4: dict(name="PEP",      l4="pep",      usage="Packet Exchange Protocol — unreliable request/response (≈ UDP)"),
    5: dict(name="SPP",      l4="spp",      usage="Sequenced Packet Protocol — reliable stream (≈ TCP)"),
}

XNS_SPP_FIELDS: dict = {
    "Connection ID (src)": "2B source connection identifier",
    "Connection ID (dst)": "2B destination connection identifier",
    "Sequence Number":     "2B byte sequence number",
    "Acknowledge Number":  "2B acknowledged sequence",
    "Allocation Number":   "2B window = next seq peer may send",
    "Datastream Type":     "1B sub-stream: 0=normal 1=end-of-msg 254=attention 255=probe",
    "Flags":               "1B: SendAck(bit1) Attention(bit2) EndOfMessage(bit3) SystemPacket(bit7)",
}

XNS_ECHO_FIELDS: dict = {
    "Type":  "2B  1=Echo Request  2=Echo Reply",
    "Data":  "variable — copied from request to reply",
}

XNS_ERROR_FIELDS: dict = {
    "Error Type": "2B error code: 0=Unspecified 1=BadChecksum 2=NoSocket 3=PacketTooLarge",
    "Error Param":"2B parameter (e.g. max size for PacketTooLarge)",
    "Original":   "first 42B of offending IDP packet",
}

XNS_RIP_FIELDS: dict = {
    "Packet Type": "2B  1=RIP Request  2=RIP Response",
    "Entries":     "variable (network,hops) pairs: Network(4B)+Hop-Count(2B)",
    "Max Hops":    "15 = infinity (unreachable)",
}

# ── Novell IPX Packet Types → L4 ──────────────────────────────────────────────
IPX_PACKET_TYPES: dict[int, dict] = {
    0:  dict(name="Unknown/Raw", l4="raw_ipx",  usage="Raw IPX datagram — no L4"),
    4:  dict(name="PXP/IPX",     l4="raw_ipx",  usage="NetWare IPX datagram (≈ UDP)"),
    5:  dict(name="SPX",         l4="spx",      usage="Sequenced Packet Exchange — reliable (≈ TCP)"),
    17: dict(name="NCP",         l4="ncp",      usage="NetWare Core Protocol — file/print services"),
    20: dict(name="NetBIOS",     l4="netbios",  usage="NetBIOS broadcast propagation (type-20 forwarding)"),
}

IPX_SPX_FIELDS: dict = {
    "Connection Control":  "1B flags: End-of-Message(bit4) Attention(bit5) ACK-Req(bit6) Sys-Pkt(bit7)",
    "Datastream Type":     "1B sub-stream: 0=normal 1=end-of-msg 254=attention 255=probe",
    "Src Connection ID":   "2B",
    "Dst Connection ID":   "2B",
    "Sequence Number":     "2B",
    "Acknowledge Number":  "2B",
    "Allocation Number":   "2B window",
}

IPX_NCP_FIELDS: dict = {
    "Request Type":   "2B  0x1111=Create-Service 0x2222=Service-Request 0x3333=Service-Reply 0x5555=Destroy 0x9999=Broadcast",
    "Sequence Number":"1B",
    "Connection Low": "1B low byte of connection number",
    "Task Number":    "1B",
    "Connection High":"1B high byte",
    "Function Code":  "1B: 21=Read 22=Write 72=OpenFile 66=CloseFile 0x17=NDS",
    "Data":           "variable — function-specific request/response data",
}

IPX_SAP_FIELDS: dict = {
    "Query Type":    "2B  1=General-Service-Query 2=General-Service-Response 3=Nearest-Query 4=Nearest-Response",
    "Server Type":   "2B  4=File-Server 7=Print-Server 24=Remote-Bridge 640+=application-specific",
    "Server Name":   "48B null-terminated server name",
    "Network":       "4B server network number",
    "Node":          "6B server node address",
    "Socket":        "2B service socket",
    "Hops to Server":"2B hop count (16=down/unreachable)",
}

# ── AppleTalk DDP Types → L4 ──────────────────────────────────────────────────
DDP_TYPES: dict[int, dict] = {
    1:  dict(name="RTMP Data",       l4="rtmp",  usage="Routing Table Maintenance Protocol — routing updates"),
    2:  dict(name="NBP",             l4="nbp",   usage="Name Binding Protocol — name↔address resolution"),
    3:  dict(name="ATP",             l4="atp",   usage="AppleTalk Transaction Protocol — reliable request/response"),
    4:  dict(name="AEP",             l4="aep",   usage="AppleTalk Echo Protocol — reachability (≈ ICMP ping)"),
    5:  dict(name="RTMP Request",    l4="rtmp",  usage="RTMP route request"),
    6:  dict(name="ZIP",             l4="zip",   usage="Zone Information Protocol — zone name management"),
    7:  dict(name="ADSP",            l4="adsp",  usage="AppleTalk Data Stream Protocol — reliable byte stream (≈ TCP)"),
    8:  dict(name="SNMP (via DDP)",  l4="snmp",  usage="SNMP over DDP (Apple management)"),
    22: dict(name="AURP",            l4="aurp",  usage="AppleTalk Update Routing Protocol — WAN routing"),
}

ATP_FIELDS: dict = {
    "Control":        "1B: TReq(0x40) TResp(0x80) TRel(0xC0) | XO(bit5) EOM(bit4) STS(bit3)",
    "Bitmap/Seq":     "1B: in TReq=response bitmap (which responses wanted); in TResp=sequence 0-7",
    "Transaction ID": "2B unique transaction identifier",
    "User Bytes":     "4B user-defined (ASP uses for command type+bitmap)",
    "Data":           "variable (TReq: command; TResp: response data up to 578B per response)",
}

NBP_FIELDS: dict = {
    "Function":       "4b: BrRq(1) LkUp(2) LkUp-Reply(3) FwdReq(4) NuLkUp(5) NuLkUp-Reply(6) Confirm(7)",
    "Tuple Count":    "4b number of NBP tuples",
    "CBId":           "1B callback ID (correlates request/reply)",
    "Tuples":         "variable: Network(2B)+Node(1B)+Socket(1B)+Enumerator(1B)+Name(var) per tuple",
    "Name format":    "Object:Type@Zone  — each component 1-32 chars Pascal string",
}

RTMP_FIELDS: dict = {
    "Sender Net":   "2B sender's AppleTalk network number",
    "ID Len":       "1B=8 (node ID length in bits)",
    "Sender ID":    "1B sender's node ID",
    "Routing Tuples":"variable: StartNet(2B)+Distance(1B)+EndNet(2B) per route entry",
}

ZIP_FIELDS: dict = {
    "Function":   "1B: GetZoneList(1) GetLocalZones(2) GetMyZone(3) Query(5) Reply(6) TakeMyZone(7) Notify(8)",
    "Zone Count": "1B number of zone names",
    "Zone Names": "variable Pascal strings — zone@network mappings",
}

# ── Banyan VINES VIP Types → L4 ──────────────────────────────────────────────
VINES_PROTOCOL_TYPES: dict[int, dict] = {
    0: dict(name="IPC",  l4="vines_ipc",  usage="Interprocess Communication — reliable message delivery"),
    1: dict(name="SPP",  l4="vines_spp",  usage="Sequenced Packet Protocol — reliable stream"),
    2: dict(name="ARP",  l4="vines_arp",  usage="VINES ARP — address query/response/assignment"),
    4: dict(name="RTP",  l4="vines_rtp",  usage="Routing Table Protocol — distance vector"),
    5: dict(name="ICP",  l4="vines_icp",  usage="Internet Control Protocol — errors + routing cost"),
}

VINES_IPC_FIELDS: dict = {
    "Source Port":      "2B",
    "Dst Port":         "2B",
    "Packet Type":      "1B 0=Data 1=Error 2=Discard 3=Probe 4=Ack",
    "Control":          "1B flags: Ack-req, End-of-msg etc.",
    "Local Connection": "2B connection ID on sender side",
    "Remote Connection":"2B connection ID on receiver side",
    "Sequence Number":  "4B",
    "Ack Number":       "4B",
}

VINES_ARP_FIELDS: dict = {
    "Type":         "2B  1=Request 2=Response 3=Assign-Assignment",
    "Network":      "4B VINES network number",
    "Subnetwork":   "2B VINES subnetwork",
}

# ── DECnet NSP (Network Services Protocol) ────────────────────────────────────
DECNET_NSP_MSG_FLAGS: dict[int, dict] = {
    0x00: dict(name="Data Segment",      usage="User data — reliable ordered delivery"),
    0x10: dict(name="Other Data",        usage="Expedited / out-of-band data segment"),
    0x20: dict(name="Connect Initiate",  usage="Open a logical link — ≈ TCP SYN"),
    0x28: dict(name="Connect Confirm",   usage="Accept logical link — ≈ TCP SYN-ACK"),
    0x30: dict(name="Disconnect Initiate",usage="Close logical link — ≈ TCP FIN"),
    0x38: dict(name="Disconnect Confirm",usage="ACK disconnect — ≈ TCP FIN-ACK"),
    0x04: dict(name="Data ACK",          usage="Acknowledge data segment(s)"),
    0x14: dict(name="Other Data ACK",    usage="Acknowledge expedited data"),
    0x08: dict(name="No-Resource ACK",   usage="Cannot receive (flow control)"),
    0x01: dict(name="Interrupt",         usage="Interrupt message (1B payload max)"),
}

DECNET_NSP_FIELDS: dict = {
    "Msg Flags":    "1B message type + sub-type (see NSP_MSG_FLAGS)",
    "Dst Addr":     "2B destination logical address",
    "Src Addr":     "2B source logical address",
    "Ack Num":      "2B (in data segments) — acknowledged sequence",
    "Seq Num":      "2B (in data segments) — this segment sequence",
    "Reason":       "2B reason code (in CI/CC/DI/DC messages)",
    "Data":         "variable user payload (data segments only)",
}

# ── Non-IP L3 registry for process_l3() dispatch ──────────────────────────────
NON_IP_L3_REGISTRY: dict[str, dict] = {
    "idp": dict(
        name="XNS IDP (Xerox Internet Datagram Protocol)",
        header_bytes=30,
        type_field="Packet Type (1B) at offset 5",
        type_map=XNS_PACKET_TYPES,
        fields={"Checksum":"2B 0xFFFF=disabled","Length":"2B","Transport Ctrl":"1B hops",
                "Packet Type":"1B","Dst Net":"4B","Dst Host":"6B","Dst Socket":"2B",
                "Src Net":"4B","Src Host":"6B","Src Socket":"2B"},
        l4_key="packet_type",
    ),
    "ipx": dict(
        name="Novell IPX (Internetwork Packet Exchange)",
        header_bytes=30,
        type_field="Packet Type (1B) at offset 5",
        type_map=IPX_PACKET_TYPES,
        fields={"Checksum":"2B 0xFFFF=unused","Length":"2B","Transport Ctrl":"1B hops",
                "Packet Type":"1B","Dst Net":"4B","Dst Node":"6B","Dst Socket":"2B",
                "Src Net":"4B","Src Node":"6B","Src Socket":"2B"},
        l4_key="packet_type",
    ),
    "ddp": dict(
        name="AppleTalk DDP (Datagram Delivery Protocol)",
        header_bytes=13,
        type_field="DDP Type (1B) at offset 12 (long-form header)",
        type_map=DDP_TYPES,
        fields={"Reserved":"2b","Hop Count":"4b","Length":"10b","Checksum":"2B",
                "Dst Network":"2B","Src Network":"2B","Dst Node":"1B","Src Node":"1B",
                "Dst Socket":"1B","Src Socket":"1B","Type":"1B"},
        l4_key="ddp_type",
    ),
    "vip": dict(
        name="Banyan VINES VIP (VINES Internetwork Protocol)",
        header_bytes=18,
        type_field="Protocol (1B) at offset 6",
        type_map=VINES_PROTOCOL_TYPES,
        fields={"Checksum":"2B","Length":"2B","Transport Ctrl":"1B","Protocol":"1B",
                "Dst Net":"4B","Dst Subnet":"2B","Src Net":"4B","Src Subnet":"2B"},
        l4_key="vip_protocol",
    ),
    "decnet": dict(
        name="DECnet Phase IV Routing",
        header_bytes="variable (6-26B)",
        type_field="Protocol Type (1B) in routing header",
        type_map={1: dict(name="NSP", l4="nsp", usage="Network Services Protocol — user data")},
        fields={"Flags":"1B routing flags","Dst Area+Node":"2B","Src Area+Node":"2B",
                "Visit Count":"1B","Protocol Type":"1B"},
        l4_key="protocol_type",
    ),
    "lat": dict(
        name="DEC LAT (Local Area Transport)",
        header_bytes="variable",
        type_field="Header Type (1B)",
        type_map={0: dict(name="Command/Status", l4="lat_session", usage="Circuit control"),
                  1: dict(name="Run (Data)",     l4="lat_session", usage="Data with terminal slots"),
                  0x0A: dict(name="Start Solicit",l4="lat_session", usage="Service solicitation")},
        fields={"Header Type":"1B","Circuit Timer":"1B","Message Length":"1B",
                "Dst Circuit":"2B","Src Circuit":"2B","Msg Seq":"1B","ACK Seq":"1B",
                "Slots":"variable 3-5B each"},
        l4_key="header_type",
    ),
    "sna": dict(
        name="IBM SNA (Systems Network Architecture)",
        header_bytes="variable TH+RH",
        type_field="TH FID Type (4b at bit 7-4 of first byte)",
        type_map={2: dict(name="FID2", l4="sna_ru", usage="Subarea routing — most common SNA type")},
        fields={"TH":"Transmission Header 2-26B (FID type+path+seq)",
                "RH":"Request/Response Header 3B (category+flags)",
                "RU":"Request/Response Unit (variable application data)"},
        l4_key="fid_type",
    ),
    "pup": dict(
        name="Xerox PUP (PARC Universal Packet)",
        header_bytes=26,
        type_field="Packet Type (1B)",
        type_map={0: dict(name="Raw", l4=None, usage="Raw PUP datagram"),
                  128: dict(name="Error", l4="pup_error", usage="Error report"),
                  130: dict(name="Echo", l4="pup_echo", usage="Echo request"),
                  131: dict(name="Echo Reply", l4="pup_echo", usage="Echo reply")},
        fields={"Length":"2B","Transport Ctrl":"1B","Type":"1B","ID":"4B",
                "Dst Net":"1B","Dst Host":"1B","Dst Socket":"4B",
                "Src Net":"1B","Src Host":"1B","Src Socket":"4B","Checksum":"2B"},
        l4_key="packet_type",
    ),
}


# ── Storage Network L3 registries (direct-over-Ethernet) ─────────────────────
STORAGE_L3_REGISTRY: dict[str, dict] = {
    "fcoe": dict(
        name="FCoE (Fibre Channel over Ethernet — 0x8906)",
        header_bytes="variable (SOF+FC-header+payload+CRC+EOF)",
        type_field="FC TYPE field (1B) in FC Frame Header at offset 8",
        type_map={
            0x01: dict(name="BLS",   l4="fcoe_bls",  usage="Basic Link Service — ABTS/BA_ACC/BA_RJT"),
            0x08: dict(name="FCP",   l4="fcoe_fcp",  usage="Fibre Channel Protocol — SCSI block I/O"),
            0x20: dict(name="IP-FC", l4="fcoe_ip",   usage="IP over Fibre Channel"),
            0xFE: dict(name="ELS",   l4="fcoe_els",  usage="Extended Link Service — FLOGI/PLOGI/LOGO"),
        },
        fields={
            "SOF":       "1B Start-of-Frame: 0x2E=SOFi3 0x36=SOFn3",
            "R_CTL":     "1B routing+info control",
            "D_ID":      "3B destination N_Port ID",
            "S_ID":      "3B source N_Port ID",
            "TYPE":      "1B FC protocol type",
            "F_CTL":     "3B frame control flags",
            "SEQ_ID":    "1B sequence identifier",
            "SEQ_CNT":   "2B sequence count",
            "OX_ID":     "2B originator exchange ID",
            "RX_ID":     "2B responder exchange ID",
            "Payload":   "variable FCP/ELS data",
            "CRC":       "4B FC CRC-32",
            "EOF":       "1B end-of-frame delimiter",
        },
        l4_key="fc_type",
        caution="Requires lossless Ethernet — PFC on CoS 3 mandatory",
    ),
    "fip": dict(
        name="FIP (FCoE Initialization Protocol — 0x8914)",
        header_bytes=4,
        type_field="FIP Operation (2B) at offset 2",
        type_map={
            1: dict(name="Discovery",     l4="fip_discovery", usage="FCF solicitation and advertisement"),
            2: dict(name="Link-Service",  l4="fip_linkserv",  usage="FLOGI/FDISC/LOGO over FIP"),
            3: dict(name="Control",       l4="fip_ctrl",      usage="Keep-alive and clear-virtual-links"),
            4: dict(name="VLAN",          l4="fip_vlan",      usage="VLAN discovery request/response"),
        },
        fields={
            "Version":        "4b must be 1",
            "FIP Subcode":    "2B operation subcode",
            "Desc ListLen":   "2B in 32-bit words",
            "Flags":          "2B FP+A+S bits",
        },
        l4_key="fip_op",
    ),
    "aoe": dict(
        name="ATA over Ethernet (AoE — 0x88A2)",
        header_bytes=10,
        type_field="Command field (1B) at offset 7",
        type_map={
            0: dict(name="ATA",        l4="aoe_ata",    usage="ATA command (read/write/identify)"),
            1: dict(name="QueryConfig",l4="aoe_config", usage="Target capability query"),
            2: dict(name="MacMask",    l4="aoe_macmask",usage="MAC address access control list"),
        },
        fields={
            "Ver":    "4b must be 1",
            "Flags":  "4b Response+Error+DevCmd+AsyncCmd",
            "Error":  "1B error code",
            "Major":  "2B shelf number",
            "Minor":  "1B slot number",
            "Cmd":    "1B command type",
            "Tag":    "4B transaction tag",
        },
        l4_key="aoe_cmd",
        caution="No auth/encryption — dedicated VLAN or isolated switch required",
    ),
    "roce": dict(
        name="RoCE v1 (RDMA over Converged Ethernet — 0x8915)",
        header_bytes=12,
        type_field="BTH OpCode (1B) at offset 0",
        type_map={
            0:  dict(name="RC-Send-First",  l4="roce_verb", usage="Reliable Connected Send First"),
            4:  dict(name="RC-Send-Only",   l4="roce_verb", usage="Reliable Connected Send Only"),
            6:  dict(name="RC-Write-First", l4="roce_verb", usage="RDMA Write First"),
            10: dict(name="RC-Write-Only",  l4="roce_verb", usage="RDMA Write Only"),
            12: dict(name="RC-Read-Req",    l4="roce_verb", usage="RDMA Read Request"),
            16: dict(name="RC-ACK",         l4="roce_ack",  usage="Reliable Connected ACK/NAK"),
        },
        fields={
            "BTH":    "12B Base Transport Header",
            "OpCode": "1B RDMA verb type",
            "SE":     "1b solicited event",
            "M":      "1b migration state",
            "P_Key":  "2B partition key",
            "Dest QP":"3B destination Queue Pair",
            "PSN":    "3B packet sequence number",
        },
        l4_key="bth_opcode",
        caution="RoCEv1 single-subnet only — use RoCEv2 (UDP 4791) for routed networks",
    ),
    "iscsi_eth": dict(
        name="iSCSI over Ethernet L2 (0x8988)",
        header_bytes=48,
        type_field="BHS Opcode (1B) at offset 0",
        type_map={
            0x01: dict(name="SCSI-Command",  l4="iscsi_scsi",  usage="Initiator → Target SCSI CDB"),
            0x21: dict(name="SCSI-Response", l4="iscsi_scsi",  usage="Target → Initiator status"),
            0x04: dict(name="SCSI-Data-Out", l4="iscsi_data",  usage="Write data from initiator"),
            0x25: dict(name="SCSI-Data-In",  l4="iscsi_data",  usage="Read data to initiator"),
            0x31: dict(name="R2T",           l4="iscsi_r2t",   usage="Ready to Transfer (flow ctrl)"),
            0x00: dict(name="NOP-Out",        l4="iscsi_nop",   usage="Keepalive / ping"),
            0x3F: dict(name="NOP-In",         l4="iscsi_nop",   usage="Keepalive response"),
        },
        fields={
            "BHS":        "48B Basic Header Segment",
            "Opcode":     "1B PDU type",
            "Flags":      "1B F+W+R+Attr bits",
            "LUN":        "8B Logical Unit Number",
            "ITT":        "4B Initiator Task Tag",
            "CmdSN":      "4B Command Sequence Number",
            "DataSegLen": "3B data segment length",
        },
        l4_key="bhs_opcode",
        caution="L2-direct only — standard iSCSI uses TCP port 3260 over IPv4",
    ),
    "nvme_eth": dict(
        name="NVMe over Ethernet L2 (0x8893)",
        header_bytes=8,
        type_field="PDU Type (1B) at offset 0",
        type_map={
            0: dict(name="CapsuleCommand",  l4="nvme_cmd",  usage="NVMe command SQE"),
            1: dict(name="CapsuleResponse", l4="nvme_resp", usage="NVMe completion CQE"),
            2: dict(name="H2C-Data",        l4="nvme_data", usage="Host to controller data"),
            3: dict(name="C2H-Data",        l4="nvme_data", usage="Controller to host data"),
        },
        fields={
            "PDU Type":  "1B capsule type",
            "Flags":     "1B HDGSTF+DDGSTF+LAST_PDU",
            "HDR Len":   "1B header length in DWords",
            "PLEN":      "4B total PDU length",
        },
        l4_key="pdu_type",
        caution="Standard NVMe-oF uses RoCEv2 or TCP port 4420 — this is L2-direct only",
    ),
    "hyperscsi": dict(
        name="HyperSCSI (deprecated — 0x889A)",
        header_bytes=4,
        type_field="Type (1B) at offset 1",
        type_map={
            0: dict(name="Command",  l4="hyperscsi_pdu", usage="SCSI command"),
            1: dict(name="Data",     l4="hyperscsi_pdu", usage="Data transfer"),
            2: dict(name="Response", l4="hyperscsi_pdu", usage="SCSI response"),
        },
        fields={
            "Version":   "1B=0",
            "Type":      "1B PDU type",
            "Sequence":  "2B",
        },
        l4_key="h_type",
        caution="Deprecated — use iSCSI or FCoE instead",
    ),
    "iser": dict(
        name="iSER (iSCSI Extensions for RDMA — 0x8989)",
        header_bytes=28,
        type_field="Flags (1B) at offset 0",
        type_map={
            0: dict(name="iSER-Control",  l4="iser_pdu", usage="iSCSI BHS over RDMA"),
        },
        fields={
            "Flags":      "1B W+R bits",
            "Write STag": "4B RDMA Steering Tag for write",
            "Write TO":   "8B Tagged Offset for write",
            "Read STag":  "4B RDMA Steering Tag for read",
            "Read TO":    "8B Tagged Offset for read",
            "iSCSI BHS":  "48B standard iSCSI header",
        },
        l4_key="iser_type",
    ),
}

# ── Switch/OAM L3 registries ──────────────────────────────────────────────────
SWITCH_L3_REGISTRY: dict[str, dict] = {
    "eapol": dict(
        name="EAPOL (IEEE 802.1X — 0x888E)",
        header_bytes=4,
        type_field="EAPOL Type (1B) at offset 1",
        type_map={
            0: dict(name="EAP-Packet",   l4="eapol_eap",   usage="EAP authentication message"),
            1: dict(name="EAPOL-Start",  l4="eapol_ctrl",  usage="Supplicant starts auth"),
            2: dict(name="EAPOL-Logoff", l4="eapol_ctrl",  usage="Supplicant logs off"),
            3: dict(name="EAPOL-Key",    l4="eapol_key",   usage="WPA key material exchange"),
        },
        fields={"Version":"1B","Type":"1B","Length":"2B"},
        l4_key="eapol_type",
    ),
    "lldp": dict(
        name="LLDP (IEEE 802.1AB — 0x88CC)",
        header_bytes=0,
        type_field="TLV Type (7b) in each TLV",
        type_map={
            1: dict(name="ChassisID", l4="lldp_tlv",  usage="Mandatory — chassis identifier"),
            2: dict(name="PortID",    l4="lldp_tlv",  usage="Mandatory — port identifier"),
            3: dict(name="TTL",       l4="lldp_tlv",  usage="Mandatory — time to live"),
            4: dict(name="PortDesc",  l4="lldp_tlv",  usage="Optional — port description"),
            5: dict(name="SysName",   l4="lldp_tlv",  usage="Optional — system name"),
            6: dict(name="SysDesc",   l4="lldp_tlv",  usage="Optional — system description"),
            7: dict(name="SysCap",    l4="lldp_tlv",  usage="Optional — capabilities"),
            8: dict(name="MgmtAddr", l4="lldp_tlv",   usage="Optional — management address"),
            127: dict(name="OrgSpec", l4="lldp_orgspec",usage="Optional — org-specific TLVs"),
            0: dict(name="End",       l4=None,          usage="Mandatory — end of LLDPDU"),
        },
        fields={
            "TLV Format":       "Each TLV: Type(7b)+Length(9b)+Value(0-511B)",
            "ChassisID TLV":    "Type=1 Mandatory: SubType(1B)+ChassisID — SubType 4=MAC 5=NetworkAddr 7=Local",
            "PortID TLV":       "Type=2 Mandatory: SubType(1B)+PortID — SubType 3=MAC 5=IfName 7=Local",
            "TTL TLV":          "Type=3 Mandatory: Length=2 Seconds(2B) 0=remove neighbour from cache",
            "PortDesc TLV":     "Type=4 Optional: port description string",
            "SysName TLV":      "Type=5 Optional: fully qualified system name",
            "SysDesc TLV":      "Type=6 Optional: system description",
            "SysCap TLV":       "Type=7 Optional: SysCap(2B)+EnabledCap(2B) — bits: Bridge/Router/WAP/DOCSIS etc.",
            "MgmtAddr TLV":     "Type=8 Optional: AddrLen(1B)+AddrSubType(1B)+MgmtAddr+IfSubType(1B)+IfNum(4B)+OIDLen(1B)+OID",
            "OrgSpec TLV":      "Type=127 Optional: OUI(3B)+Subtype(1B)+InfoStr — IEEE 802.1/802.3/MED/PNO",
            "End TLV":          "Type=0 Length=0 Mandatory last TLV",
            "Order":            "Mandatory order: ChassisID → PortID → TTL → (optional TLVs) → End",
            "CAUTION":          "ChassisID and PortID together uniquely identify LLDP neighbour — duplicate pair = misconfigured device",
        },
        l4_key="tlv_type",
    ),
    "cfm": dict(
        name="CFM (IEEE 802.1ag — 0x8902)",
        header_bytes=4,
        type_field="Opcode (1B) at offset 1",
        type_map={
            1:  dict(name="CCM",  l4="cfm_ccm",  usage="Continuity Check Message"),
            3:  dict(name="LBM",  l4="cfm_lb",   usage="Loopback Message"),
            2:  dict(name="LBR",  l4="cfm_lb",   usage="Loopback Reply"),
            5:  dict(name="LTM",  l4="cfm_lt",   usage="Linktrace Message"),
            4:  dict(name="LTR",  l4="cfm_lt",   usage="Linktrace Reply"),
            47: dict(name="DMM",  l4="cfm_dm",   usage="Delay Measurement Message"),
            46: dict(name="DMR",  l4="cfm_dm",   usage="Delay Measurement Reply"),
            55: dict(name="SLM",  l4="cfm_sl",   usage="Synthetic Loss Message"),
            56: dict(name="SLR",  l4="cfm_sl",   usage="Synthetic Loss Reply"),
        },
        fields={"MD Level":"3b","Version":"5b","Opcode":"1B","Flags":"1B","TLV-Offset":"1B"},
        l4_key="cfm_opcode",
    ),
    "y1731": dict(
        name="Y.1731 OAM (ITU-T — 0x8903)",
        header_bytes=4,
        type_field="Opcode (1B) at offset 1",
        type_map={
            47: dict(name="DMM",  l4="cfm_dm",   usage="Delay Measurement"),
            46: dict(name="DMR",  l4="cfm_dm",   usage="Delay Reply"),
            49: dict(name="1DM",  l4="cfm_dm",   usage="One-way Delay Measurement"),
            43: dict(name="LMM",  l4="cfm_dm",   usage="Loss Measurement Message"),
            42: dict(name="LMR",  l4="cfm_dm",   usage="Loss Measurement Reply"),
            55: dict(name="SLM",  l4="cfm_sl",   usage="Synthetic Loss Message"),
            56: dict(name="SLR",  l4="cfm_sl",   usage="Synthetic Loss Reply"),
            33: dict(name="AIS",  l4="cfm_ais",  usage="Alarm Indication Signal"),
            35: dict(name="LCK",  l4="cfm_ais",  usage="Lock Signal"),
        },
        fields={"MD Level":"3b","Version":"5b","Opcode":"1B","Flags":"1B","TLV-Offset":"1B"},
        l4_key="y1731_opcode",
    ),
    "macsec": dict(
        name="MACSec (IEEE 802.1AE — 0x88E5)",
        header_bytes=8,
        type_field="SecTAG TCI (1B) at offset 0",
        type_map={
            0: dict(name="MACSec-Frame", l4="macsec_payload", usage="Encrypted/integrity-protected frame"),
        },
        fields={"TCI":"1B","AN":"2b","SL":"6b","PN":"4B","SCI":"8B optional"},
        l4_key="macsec_type",
    ),
    "ptp": dict(
        name="PTP (IEEE 1588-2019 — 0x88F7)",
        header_bytes=34,
        type_field="messageType (4b) at bits [3:0] of first byte",
        type_map={
            0:  dict(name="Sync",                    l4="ptp_msg", usage="Master clock sync pulse — two-step with Follow_Up"),
            1:  dict(name="Delay_Req",               l4="ptp_msg", usage="Slave→Master delay measurement request"),
            2:  dict(name="Pdelay_Req",              l4="ptp_msg", usage="Peer delay request — P2P delay mechanism"),
            3:  dict(name="Pdelay_Resp",             l4="ptp_msg", usage="Peer delay response"),
            8:  dict(name="Follow_Up",               l4="ptp_msg", usage="Two-step precise egress timestamp for Sync"),
            9:  dict(name="Delay_Resp",              l4="ptp_msg", usage="Master→Slave delay response with corrected timestamp"),
            10: dict(name="Pdelay_Resp_Follow_Up",  l4="ptp_msg", usage="Two-step precise timestamp for Pdelay_Resp"),
            11: dict(name="Announce",               l4="ptp_msg", usage="Best Master Clock Algorithm (BMCA) announcement"),
            12: dict(name="Signaling",              l4="ptp_msg", usage="Unicast negotiation — request/grant Sync/Announce rates"),
            13: dict(name="Management",             l4="ptp_msg", usage="PTP management — clock config and status"),
        },
        fields={
            "Msg Type":        "4b  messageType at bits[3:0] of byte0",
            "Transport Spec":  "4b  bits[7:4] of byte0 — 0=IEEE 1588 1=ITU-T G.8265 4=IEEE 802.1AS",
            "Version":         "4b  1=IEEE 1588-2008  2=IEEE 1588-2019 (PTPv2)",
            "Message Length":  "2B  total PDU length in bytes",
            "Domain Number":   "1B  clock domain 0-127 — separate sync domains on same network",
            "Minor Version":   "1B  sub-version (0 for base IEEE 1588-2019)",
            "Flags":           "2B  twoStepFlag(1b)+unicastFlag(1b)+PTPProfileSpecific(2b)+reserved(3b)+alternateMasterFlag(1b)+frequencyTraceable(1b)+timeTraceable(1b)+ptpTimescale(1b)+utcReasonable(1b)+leap59(1b)+leap61(1b)",
            "CorrectionField": "8B  correction in nanoseconds×2^16 — added by transparent clocks",
            "MessageTypeSpec": "4B  profile-specific or reserved",
            "ClockIdentity":   "8B  EUI-64 of clock (usually OUI+port+MAC)",
            "SourcePortID":    "2B  port number within clock",
            "SequenceID":      "2B  matches Sync→Follow_Up; Pdelay_Req→Pdelay_Resp→Pdelay_Resp_FUP",
            "ControlField":    "1B  0=Sync 1=Delay_Req 2=Follow_Up 3=Delay_Resp 4=Management 5=All-others",
            "LogMsgInterval":  "1B  signed — log₂ of inter-message interval",
            "OriginTimestamp": "10B  Sync/Delay_Req: 6B seconds + 4B nanoseconds",
        },
        l4_key="msg_type",
    ),
    "mvrp": dict(
        name="MVRP (IEEE 802.1Q — 0x88F5)",
        header_bytes=2,
        type_field="MRP Attribute Type (1B)",
        type_map={1: dict(name="VLAN-ID-Attr", l4="mrp_attr", usage="VLAN registration attribute")},
        fields={"Protocol ID":"2B=0x0000","Attr Type":"1B","Attr Length":"1B","MRP Event":"3b","VLAN ID":"12b"},
        l4_key="attr_type",
    ),
    "mmrp": dict(
        name="MMRP (IEEE 802.1Q — 0x88F6)",
        header_bytes=2,
        type_field="MRP Attribute Type (1B)",
        type_map={
            1: dict(name="Service-Req", l4="mrp_attr", usage="Service requirement"),
            2: dict(name="MAC-VID",     l4="mrp_attr", usage="Multicast MAC + VID"),
        },
        fields={"Protocol ID":"2B=0x0000","Attr Type":"1B","MRP Event":"3b","MAC":"6B","VID":"12b"},
        l4_key="attr_type",
    ),
    "mrp": dict(
        name="MRP (IEC 62439-2 — 0x88E3)",
        header_bytes=2,
        type_field="Type (2B) at offset 2",
        type_map={
            1: dict(name="Common",          l4="mrp_pdu", usage="Common ring PDU"),
            2: dict(name="Test",            l4="mrp_pdu", usage="Ring continuity test"),
            3: dict(name="TopologyChange",  l4="mrp_pdu", usage="Ring topology change"),
            4: dict(name="LinkDown",        l4="mrp_pdu", usage="Link failure notification"),
            5: dict(name="LinkUp",          l4="mrp_pdu", usage="Link recovery notification"),
        },
        fields={"Version":"2B","Type":"2B","Length":"2B","Priority":"2B","SA":"6B"},
        l4_key="mrp_type",
    ),
    "prp": dict(
        name="PRP (IEC 62439-3 — 0x88FB trailer)",
        header_bytes=6,
        type_field="LAN-ID (4b) in trailer",
        type_map={
            0xA: dict(name="LAN-A", l4="prp_payload", usage="Frame sent on LAN-A"),
            0xB: dict(name="LAN-B", l4="prp_payload", usage="Frame sent on LAN-B"),
        },
        fields={"Sequence":"2B","LAN-ID":"4b","LSDU-Size":"12b","Suffix":"2B=0x88FB"},
        l4_key="lan_id",
    ),
    "trill": dict(
        name="TRILL (RFC 6325 — 0x22F3)",
        header_bytes=6,
        type_field="Egress RB nickname (16b)",
        type_map={0: dict(name="TRILL-Frame", l4="trill_inner", usage="Inner Ethernet frame")},
        fields={"Version":"2b","M":"1b","Op-Length":"5b","Hop-Count":"6b","Egress RB":"16b","Ingress RB":"16b"},
        l4_key="trill_type",
    ),
    "l2isis": dict(
        name="L2-IS-IS (for TRILL — 0x22F4)",
        header_bytes=3,
        type_field="PDU Type (1B) at offset 4",
        type_map={
            15: dict(name="L1-Hello",  l4="isis_pdu", usage="Level-1 hello"),
            16: dict(name="L2-Hello",  l4="isis_pdu", usage="Level-2 hello"),
            20: dict(name="L2-LSP",    l4="isis_pdu", usage="Level-2 link state"),
            25: dict(name="L2-CSNP",   l4="isis_pdu", usage="Complete sequence numbers"),
        },
        fields={"NLPID":"1B=0x83","Hdr Length":"1B","IS Version":"1B","PDU Type":"1B"},
        l4_key="pdu_type",
    ),
    "nsh": dict(
        name="NSH (RFC 8300 — 0x894F)",
        header_bytes=8,
        type_field="NextProto (1B) at offset 3",
        type_map={
            1: dict(name="IPv4",     l4=None, usage="Inner IPv4 packet"),
            2: dict(name="IPv6",     l4=None, usage="Inner IPv6 packet"),
            3: dict(name="Ethernet", l4=None, usage="Inner Ethernet frame"),
            5: dict(name="MPLS",     l4=None, usage="Inner MPLS label stack"),
        },
        fields={"Base Hdr":"4B","Service Path Hdr":"4B","Context Hdr":"variable"},
        l4_key="next_proto",
    ),
    "fqtss": dict(
        name="FQTSS (IEEE 802.1Qav — 0x22EA)",
        header_bytes=8,
        type_field="None — stream reservation descriptor",
        type_map={0: dict(name="StreamReservation", l4="avb_stream", usage="AVB stream reservation")},
        fields={"StreamID":"8B","Priority":"3b","MaxInterval":"2B","MaxFrameSize":"2B"},
        l4_key="fqtss_type",
    ),
    "tsn_tas": dict(
        name="TSN TAS (IEEE 802.1Qbv — 0x8944)",
        header_bytes=10,
        type_field="None — gate control list descriptor",
        type_map={0: dict(name="GCL-Entry", l4="tsn_gcl", usage="Gate control list entry")},
        fields={"GCL Entry":"variable","BaseTime":"10B","CycleTime":"8B","MaxSDU":"4B"},
        l4_key="tsn_type",
    ),
    "msrp": dict(
        name="MSRP (IEEE 802.1Qbe — 0x8929)",
        header_bytes=2,
        type_field="MRP Attribute Type (1B)",
        type_map={
            1: dict(name="Talker-Advertise", l4="msrp_attr", usage="Talker stream declaration"),
            2: dict(name="Talker-Failed",    l4="msrp_attr", usage="Talker failure"),
            3: dict(name="Listener",         l4="msrp_attr", usage="Listener registration"),
        },
        fields={"Protocol ID":"2B","Attr Type":"1B","MRP Event":"3b","StreamID":"8B"},
        l4_key="msrp_type",
    ),
    "ecp": dict(
        name="ECP (IEEE 802.1Qbg — 0x8940)",
        header_bytes=4,
        type_field="Subtype (2B) at offset 0",
        type_map={1: dict(name="VDP", l4="ecp_vdp", usage="VSI Discovery Protocol")},
        fields={"Subtype":"2B","Sequence":"2B","Op":"4b"},
        l4_key="ecp_subtype",
    ),
    "oui_ext": dict(
        name="IEEE 802 OUI-Extended (0x88B7)",
        header_bytes=5,
        type_field="OUI(3B)+Ext-EtherType(2B)",
        type_map={0: dict(name="OUI-Payload", l4="oui_ext_payload", usage="OUI-specific payload")},
        fields={"OUI":"3B","Ext EtherType":"2B","Payload":"variable"},
        l4_key="oui_type",
    ),
    "mih": dict(
        name="IEEE 802.21 MIH (0x8917)",
        header_bytes=6,
        type_field="AID (12b) at offset 0",
        type_map={0: dict(name="MIH-PDU", l4="mih_pdu", usage="Media Independent Handover PDU")},
        fields={"Version":"4b","AID":"12b","OPCode":"4b","TransactionID":"12b","PayloadLen":"16b"},
        l4_key="mih_aid",
    ),
}

# ── Merge switch L3 into NON_IP_L3_REGISTRY ──────────────────────────────────
NON_IP_L3_REGISTRY.update(STORAGE_L3_REGISTRY)
NON_IP_L3_REGISTRY.update(SWITCH_L3_REGISTRY)

# ── Additional L3 registries for new EtherTypes ────────────────────────────────
ADDITIONAL_L3_REGISTRY: dict[str, dict] = {
    "qinq": dict(
        name="Q-in-Q Double Tagging (802.1ad/Vendor)",
        header_bytes=8,
        type_field="Inner EtherType (2B) determines inner protocol",
        type_map={
            0x0800: dict(name="IPv4", l4="ipv4_inner", usage="IPv4 payload inside Q-in-Q"),
            0x86DD: dict(name="IPv6", l4="ipv6_inner", usage="IPv6 payload inside Q-in-Q"),
            0x0806: dict(name="ARP",  l4=None,         usage="ARP inside Q-in-Q"),
            0x8847: dict(name="MPLS", l4=None,         usage="MPLS inside Q-in-Q"),
        },
        fields={"S-Tag TPID":"2B","PCP":"3b","DEI":"1b","S-VID":"12b",
                "C-Tag TPID":"2B=0x8100","C-VID":"12b","Inner EtherType":"2B"},
        l4_key="inner_ethertype",
    ),
    "pbb": dict(
        name="PBB I-Tag (IEEE 802.1ah Provider Backbone)",
        header_bytes=18,
        type_field="Inner payload after B-Tag+I-Tag",
        type_map={0: dict(name="MAC-in-MAC", l4="pbb_payload", usage="Customer Ethernet frame inside PBB")},
        fields={"TPID":"2B=0x88E7","PCP":"3b","DEI":"1b","UCA":"1b","I-SID":"24b",
                "B-DA":"6B","B-SA":"6B","B-Tag TPID":"2B=0x88A8","B-VID":"12b"},
        l4_key="pbb_type",
    ),
    "avtp": dict(
        name="AVTP (IEEE 1722 Audio Video Transport)",
        header_bytes=24,
        type_field="Subtype (1B) at offset 0",
        type_map={
            0x00: dict(name="IEC61883/IIDC", l4="avtp_iec61883", usage="IEC 61883 audio/video over AVTP"),
            0x02: dict(name="AAF",           l4="avtp_aaf",     usage="AVTP Audio Format — PCM/AES3"),
            0x03: dict(name="CVF",           l4="avtp_cvf",     usage="Compressed Video Format — H.264/MJPEG"),
            0x04: dict(name="CRF",           l4="avtp_crf",     usage="Clock Reference Format — media clock"),
            0x7F: dict(name="AVTP-Control",  l4="avtp_ctrl",    usage="AVTP control message"),
        },
        fields={"Subtype":"1B","SV":"1b","Version":"3b","MR+TV":"2b","Seq":"1B",
                "Stream ID":"8B","AVTP Timestamp":"4B","Format-Specific":"4B"},
        l4_key="avtp_subtype",
    ),
    "bfd_eth": dict(
        name="BFD over Ethernet (0x8999)",
        header_bytes=24,
        type_field="None — single PDU type (control packet)",
        type_map={0: dict(name="BFD-Control", l4="bfd_control", usage="BFD bidirectional forwarding detection")},
        fields={"Version":"3b=1","Diag":"5b","Sta":"2b","Flags":"6b",
                "Detect Mult":"1B","Length":"1B=24","My Discrim":"4B","Your Discrim":"4B",
                "Desired Min TX":"4B","Required Min RX":"4B","Required Min Echo":"4B"},
        l4_key="bfd_type",
    ),
    "spb_isis": dict(
        name="SPB IS-IS (IEEE 802.1aq — 0x893B)",
        header_bytes=3,
        type_field="PDU Type (1B) at offset 4",
        type_map={
            16: dict(name="L2-Hello",  l4="isis_pdu", usage="SPB L2 adjacency hello"),
            20: dict(name="L2-LSP",    l4="isis_pdu", usage="SPB link state packet"),
            25: dict(name="L2-CSNP",   l4="isis_pdu", usage="SPB complete sequence numbers"),
        },
        fields={"NLPID":"1B=0x83","Hdr Length":"1B","IS Version":"1B","PDU Type":"1B",
                "SPB TLV 144":"I-SID(3B)+BaseVID(2B)+flags",
                "SPB TLV 145":"Unicast ECT algorithms"},
        l4_key="pdu_type",
    ),
    "frer": dict(
        name="FRER R-Tag (IEEE 802.1CB — 0x893F)",
        header_bytes=4,
        type_field="None — sequence tag only",
        type_map={0: dict(name="FRER-Frame", l4="frer_payload", usage="Sequenced redundant frame")},
        fields={"R-Tag TPID":"2B=0x893F","Reserved":"4b","Sequence Num":"12b",
                "Inner EtherType":"2B"},
        l4_key="frer_type",
    ),
    "ncsi": dict(
        name="NC-SI (DMTF DSP0222 — 0x88F8)",
        header_bytes=8,
        type_field="Type (1B) at offset 4",
        type_map={
            0x00: dict(name="Clear-Init",      l4="ncsi_cmd", usage="Reset NIC to initial state"),
            0x01: dict(name="Select-Pkg",      l4="ncsi_cmd", usage="Select active NIC package"),
            0x03: dict(name="Enable-Ch",       l4="ncsi_cmd", usage="Enable NIC channel"),
            0x06: dict(name="Get-Link-Status", l4="ncsi_cmd", usage="Query NIC link state"),
            0x08: dict(name="Set-Link",        l4="ncsi_cmd", usage="Configure NIC link parameters"),
            0x0D: dict(name="Set-MAC-Addr",    l4="ncsi_cmd", usage="Assign MAC address to BMC passthrough"),
            0x14: dict(name="Get-Cap",         l4="ncsi_cmd", usage="Query NIC capabilities"),
            0xFF: dict(name="Response",        l4="ncsi_cmd", usage="Response to any command"),
        },
        fields={"MC ID":"1B","Hdr Rev":"1B=0x01","Reserved":"1B=0x00","IID":"1B",
                "Type":"1B","Channel":"1B","Payload Len":"2B","Payload":"variable","Checksum":"4B"},
        l4_key="ncsi_type",
    ),
    "gre_eth": dict(
        name="GRE Transparent Ethernet (RFC 1701 — 0x6558)",
        header_bytes=4,
        type_field="GRE Protocol Type (2B) at offset 2",
        type_map={0x6558: dict(name="Eth-in-GRE", l4="gre_inner_eth", usage="Ethernet frame in GRE tunnel")},
        fields={"GRE Flags":"2B C+R+K+S bits","Protocol":"2B=0x6558",
                "Checksum":"optional 2B","Key":"optional 4B","Seq":"optional 4B",
                "Payload":"Ethernet frame (Dst MAC onward)"},
        l4_key="gre_proto",
    ),
    "gre_fr": dict(
        name="GRE Frame Relay (RFC 1701 — 0x6559)",
        header_bytes=4,
        type_field="DLCI field",
        type_map={0: dict(name="FR-in-GRE", l4="gre_inner_fr", usage="Frame Relay PVC in GRE")},
        fields={"GRE Flags":"2B","Protocol":"2B=0x6559","DLCI":"2-4B","Payload":"variable"},
        l4_key="gre_fr_type",
    ),
    "gre_ctrl": dict(
        name="GRE Control Channel (RFC 8157 — 0xB7EA)",
        header_bytes=4,
        type_field="Control Type (2B) at offset 0",
        type_map={
            1: dict(name="Keepalive-Req",  l4="gre_ctrl_msg", usage="GRE tunnel keepalive probe"),
            2: dict(name="Keepalive-Reply",l4="gre_ctrl_msg", usage="GRE tunnel keepalive response"),
            3: dict(name="Error",          l4="gre_ctrl_msg", usage="GRE control error notification"),
            4: dict(name="BFD-Discrim",    l4="gre_ctrl_msg", usage="BFD discriminator exchange"),
        },
        fields={"Control Type":"2B","Trans ID":"2B","Payload":"variable"},
        l4_key="ctrl_type",
    ),
    "vjcomp": dict(
        name="Van Jacobson Compressed TCP/IP (0x876B)",
        header_bytes=1,
        type_field="Type byte at offset 0",
        type_map={
            0x45: dict(name="Uncompressed-TCP", l4="vjcomp_pdu", usage="Uncompressed — sends full IP header"),
            0x70: dict(name="Compressed-TCP",   l4="vjcomp_pdu", usage="Compressed — sends only deltas"),
        },
        fields={"Type":"1B","Connection":"1B (compressed)","Delta":"variable"},
        l4_key="vj_type",
    ),
    "ppp_eth": dict(
        name="PPP Direct over Ethernet (0x880B)",
        header_bytes=4,
        type_field="PPP Protocol (2B) at offset 3",
        type_map={
            0x0021: dict(name="IPv4",  l4=None, usage="IPv4 over PPP"),
            0x0057: dict(name="IPv6",  l4=None, usage="IPv6 over PPP"),
            0xC021: dict(name="LCP",   l4="ppp_lcp", usage="PPP Link Control Protocol"),
            0xC023: dict(name="PAP",   l4="ppp_auth", usage="Password Authentication Protocol"),
            0xC223: dict(name="CHAP",  l4="ppp_auth", usage="Challenge Handshake Auth Protocol"),
        },
        fields={"Flag":"1B=0x7E","Address":"1B=0xFF","Control":"1B=0x03",
                "Protocol":"2B","Payload":"variable","FCS":"2-4B","End Flag":"1B=0x7E"},
        l4_key="ppp_proto",
    ),
    "gsmp": dict(
        name="GSMP (RFC 3292 General Switch Management — 0x880C)",
        header_bytes=8,
        type_field="Message Type (1B) at offset 1",
        type_map={
            1:  dict(name="Port-Mgmt",   l4="gsmp_msg", usage="Port enable/disable/config"),
            2:  dict(name="Config",      l4="gsmp_msg", usage="Switch configuration"),
            3:  dict(name="Connection",  l4="gsmp_msg", usage="VC/VP connection management"),
            10: dict(name="Statistics",  l4="gsmp_msg", usage="Counter/statistics retrieval"),
            11: dict(name="Port-Control",l4="gsmp_msg", usage="Physical port control"),
        },
        fields={"Version":"4b=3","Reserved":"4b","Message Type":"1B","Result":"1B",
                "Code":"1B","Port Sesh No":"1B","Transaction ID":"4B","Adjacency":"variable"},
        l4_key="gsmp_type",
    ),
    "mcap": dict(
        name="MCAP (Multicast Channel Allocation — 0x8861)",
        header_bytes=8,
        type_field="Op (1B) at offset 0",
        type_map={
            1: dict(name="GetReq",  l4="mcap_msg", usage="Request channel allocation"),
            2: dict(name="GetResp", l4="mcap_msg", usage="Channel allocation response"),
            3: dict(name="Setup",   l4="mcap_msg", usage="Set up allocated channel"),
            4: dict(name="Delete",  l4="mcap_msg", usage="Release channel"),
        },
        fields={"Op":"1B","Rpt Count":"1B","Trans ID":"2B","Channel ID":"2B",
                "Timestamp":"8B","Duration":"2B"},
        l4_key="mcap_op",
    ),
    "lowpan": dict(
        name="6LoWPAN Encapsulation (RFC 7973 — 0xA0ED)",
        header_bytes=1,
        type_field="Dispatch byte (1B) at offset 0",
        type_map={
            0x41: dict(name="IPv6-Uncomp", l4=None,          usage="Uncompressed IPv6 packet"),
            0x60: dict(name="IPHC",        l4="lowpan_iphc", usage="IPHC compressed IPv6"),
            0xC0: dict(name="Mesh",        l4="lowpan_mesh", usage="Mesh addressing header"),
            0xE0: dict(name="Frag1",       l4="lowpan_frag", usage="First fragment"),
            0xE8: dict(name="FragN",       l4="lowpan_frag", usage="Subsequent fragment"),
        },
        fields={"Dispatch":"1B","IPHC":"optional 2B","Mesh Hdr":"optional","Frag Hdr":"optional 4B",
                "Payload":"compressed IPv6 + payload"},
        l4_key="dispatch",
    ),
    "mt_isis": dict(
        name="Multi-Topology IS-IS (RFC 8377 — 0x8377)",
        header_bytes=3,
        type_field="PDU Type (1B) at offset 4",
        type_map={
            16: dict(name="L2-Hello", l4="isis_pdu", usage="MT IS-IS L2 hello"),
            20: dict(name="L2-LSP",   l4="isis_pdu", usage="MT IS-IS link state"),
            25: dict(name="L2-CSNP",  l4="isis_pdu", usage="MT IS-IS CSNP"),
        },
        fields={"NLPID":"1B=0x83","Hdr Length":"1B","IS Version":"1B","PDU Type":"1B",
                "MT-ID TLV 229":"MT IS Neighbor","MT-ID TLV 235/237":"MT IP Reachability"},
        l4_key="pdu_type",
    ),
    "eth_loopback": dict(
        name="Ethernet Loopback (IEEE 802.3 Annex 57A — 0x9000)",
        header_bytes=4,
        type_field="Function (2B) at offset 0",
        type_map={
            1: dict(name="Reply-Forward", l4="loopback_test", usage="Forward then reply"),
            2: dict(name="Reply-Only",    l4="loopback_test", usage="Reply immediately"),
        },
        fields={"Function":"2B  1=Reply/Forward 2=Reply-Only","Reply Count":"2B","Data":"variable"},
        l4_key="loopback_function",
    ),
}

NON_IP_L3_REGISTRY.update(ADDITIONAL_L3_REGISTRY)

# ── Industrial / ITS / Building-Automation L3 registry ────────────────────────
INDUSTRIAL_L3_REGISTRY: dict[str, dict] = {

    "wol": dict(
        name="Wake-on-LAN Magic Packet",
        header_bytes=6,
        type_field="Sync Stream (6B 0xFF) — fixed pattern identifies WoL",
        type_map={
            0: dict(name="Magic Packet (no password)", l4="wol_magic",
                    usage="6×0xFF + target_MAC×16 (102B total)"),
            1: dict(name="Magic Packet + 4B SecureOn password", l4="wol_secure4",
                    usage="6×0xFF + MAC×16 + 4B password (106B)"),
            2: dict(name="Magic Packet + 6B SecureOn password", l4="wol_secure6",
                    usage="6×0xFF + MAC×16 + 6B password (108B)"),
        },
        fields={
            "Sync Stream":   "6B  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF — marks this as WoL magic packet",
            "Target MAC×16": "96B  destination MAC address repeated exactly 16 times (48 bits × 16 = 96B)",
            "SecureOn Pwd":  "optional 4B or 6B — SecureOn password appended after MAC×16",
        },
        l4_key="wol_type",
    ),

    "dot1q": dict(
        name="IEEE 802.1Q VLAN Tag — inner EtherType dispatch",
        header_bytes=4,
        type_field="Inner EtherType (2B) at offset 2",
        type_map={
            0x0800: dict(name="IPv4 payload",    l4="ipv4_inner",   usage="Tagged IPv4 frame"),
            0x86DD: dict(name="IPv6 payload",    l4="ipv6_inner",   usage="Tagged IPv6 frame"),
            0x0806: dict(name="ARP payload",     l4="arp_inner",    usage="Tagged ARP"),
            0x8847: dict(name="MPLS payload",    l4="mpls_inner",   usage="Tagged MPLS unicast"),
            0x88A8: dict(name="Q-in-Q S-Tag",    l4="qinq_inner",   usage="Double-tagged outer S-Tag"),
            0x8100: dict(name="Double-tagged",   l4="double_tag",   usage="Inner C-Tag (VLAN stacking)"),
        },
        fields={
            "TPID":           "2B  0x8100 Tag Protocol ID (identifies 802.1Q tag)",
            "PCP":            "3b  Priority Code Point 0-7 (802.1p CoS class)",
            "DEI":            "1b  Drop Eligible Indicator",
            "VID":            "12b VLAN Identifier (0=priority-only 1-4094=valid 4095=reserved)",
            "Inner EtherType":"2B  actual payload protocol",
        },
        l4_key="inner_ethertype",
    ),

    "bacnet": dict(
        name="BACnet Network Layer — ASHRAE 135 Annex H",
        header_bytes=2,
        type_field="PDU Type nibble (upper 4 bits of APDU type byte)",
        type_map={
            0: dict(name="Confirmed-Request",   l4="bacnet_confirmed",  usage="ReadProperty/WriteProperty/SubscribeCOV"),
            1: dict(name="Unconfirmed-Request",  l4="bacnet_unconfirmed",usage="WhoIs/IAm/WhoHas/IHave/COVNotification"),
            2: dict(name="Simple-ACK",           l4="bacnet_simple_ack", usage="Acknowledgement without data"),
            3: dict(name="Complex-ACK",          l4="bacnet_complex_ack",usage="ReadProperty response with data"),
            4: dict(name="Segment-ACK",          l4="bacnet_segment",    usage="Segmented transfer acknowledgement"),
            5: dict(name="Error",                l4="bacnet_error",      usage="Error response"),
            6: dict(name="Reject",               l4="bacnet_reject",     usage="Request rejected"),
            7: dict(name="Abort",                l4="bacnet_abort",      usage="Transaction aborted"),
        },
        fields={
            "DSAP":       "1B  0x82 BACnet LSAP",
            "SSAP":       "1B  0x82 BACnet LSAP",
            "Control":    "1B  0x03 LLC UI frame",
            "NPCI Ver":   "1B  0x01 NPCI version",
            "NPCI Ctrl":  "1B  b7=NetMsg b5=DnetPresent b3=SnetPresent b1-0=Priority",
            "DNet/DLEN/DADR": "conditional routing fields if b5 set",
            "SNet/SLEN/SADR": "conditional source routing if b3 set",
            "Hop Count":  "1B  max 255 router hops",
        },
        l4_key="bacnet_pdu_type",
    ),

    "profinet": dict(
        name="PROFINET RT/IRT/DCP Frame Classification",
        header_bytes=2,
        type_field="Frame ID (2B) at offset 0",
        type_map={
            0x0001: dict(name="RT-Class1 Cyclic",    l4="profinet_rt",    usage="Cyclic IO data class 1"),
            0x8000: dict(name="RT-Class2 Cyclic",    l4="profinet_rt",    usage="Cyclic IO data class 2"),
            0xC000: dict(name="RT-Class3/IRT",       l4="profinet_irt",   usage="Isochronous real-time <0.25ms"),
            0xFC00: dict(name="Reserved",            l4="profinet_rsvd",  usage="Reserved range"),
            0xFC01: dict(name="Alarm High",          l4="profinet_alarm", usage="High-priority alarm"),
            0xFE01: dict(name="Alarm Low",           l4="profinet_alarm", usage="Low-priority alarm"),
            0xFF00: dict(name="DCP Multicast",       l4="profinet_dcp",   usage="Device discovery/config multicast"),
            0xFF01: dict(name="DCP Unicast",         l4="profinet_dcp",   usage="Device discovery/config unicast"),
            0xFF40: dict(name="Fragmentation",       l4="profinet_frag",  usage="Large PDU fragmentation"),
        },
        fields={
            "Frame ID":       "2B  identifies PDU type and RT class",
            "Cycle Counter":  "2B  free-running 0-65535 at 32kHz",
            "DataStatus":     "1B  b6=DataValid b5=ProviderState b3=Redundancy b2=PrimaryAR",
            "TransferStatus": "1B  0x00=OK",
            "IO Data":        "variable  process input or output bytes",
            "IOPS":           "1B  per-slot provider status 0x80=GOOD",
            "IOCS":           "1B  per-slot consumer status 0x80=GOOD",
        },
        l4_key="profinet_frame_id",
    ),

    "ethercat": dict(
        name="EtherCAT Datagram Chain — IEC 61158-12",
        header_bytes=2,
        type_field="Type field (3 bits at bits [15:13] of first 2B)",
        type_map={
            1: dict(name="EtherCAT Datagram Chain", l4="ethercat_datagram", usage="Standard EtherCAT PDU chain"),
            4: dict(name="Network Variables",       l4="ethercat_nv",       usage="EtherCAT network variable"),
            5: dict(name="Mailbox Gateway",         l4="ethercat_mbx",      usage="EtherCAT mailbox gateway"),
        },
        fields={
            "Reserved":  "2b  must be 0",
            "Length":    "11b total byte count of all datagrams in this frame",
            "Type":      "3b  1=EtherCAT protocol",
            "Cmd":       "1B  NOP/APRD/APWR/FPRD/FPWR/BRD/BWR/LRD/LWR/LRW",
            "IDX":       "1B  datagram index for TX/RX pairing",
            "Address":   "4B  ADP+ADO or logical address",
            "DLen":      "11b datagram data length",
            "M":         "1b  more datagrams follow",
            "IRQ":       "2B  slave interrupt flags",
            "Data":      "variable  process data",
            "WKC":       "2B  Working Counter",
        },
        l4_key="ethercat_type",
    ),

    "powerlink": dict(
        name="Ethernet POWERLINK v2 — EPSG DS 301",
        header_bytes=3,
        type_field="Message Type (1B) at offset 0",
        type_map={
            0x01: dict(name="SoC — Start of Cycle",       l4="powerlink_soc",  usage="Master broadcasts cycle start"),
            0x03: dict(name="PReq — Poll Request",        l4="powerlink_preq", usage="Master polls single CN"),
            0x04: dict(name="PRes — Poll Response",       l4="powerlink_pres", usage="CN responds with process data"),
            0x05: dict(name="SoA — Start of Async",      l4="powerlink_soa",  usage="Master opens async slot"),
            0x06: dict(name="ASnd — Async Send",          l4="powerlink_asnd", usage="Acyclic NMT/SDO data"),
            0x07: dict(name="AMNI — Async MN Indication", l4="powerlink_amni", usage="Active MN indication"),
        },
        fields={
            "Message Type": "1B  SoC/PReq/PRes/SoA/ASnd/AMNI",
            "Dst Node ID":  "1B  0xFF=broadcast 0xFE=MN 0x01-0xEF=CN",
            "Src Node ID":  "1B  sender node address",
            "Data":         "variable  message-type-specific payload",
        },
        l4_key="powerlink_msg_type",
    ),

    "goose": dict(
        name="IEC 61850-8-1 GOOSE PDU",
        header_bytes=8,
        type_field="APPID range (2B) at offset 0 distinguishes GOOSE from SV",
        type_map={
            0: dict(name="GOOSE PDU",  l4="goose_pdu",  usage="0x0000-0x3FFF Generic GOOSE event"),
            1: dict(name="GSSE PDU",   l4="gsse_pdu",   usage="0x4000-0x7FFF Generic Substation State Event (deprecated)"),
        },
        fields={
            "APPID":    "2B  0x0000-0x3FFF GOOSE application identifier",
            "Length":   "2B  total PDU byte length including APPID and Length",
            "Reserved1":"2B  0x0000 (IEC 62351-6 HMAC field when security enabled)",
            "Reserved2":"2B  0x0000",
            "PDU":      "variable  ASN.1 BER encoded GOOSE PDU",
        },
        l4_key="goose_appid_range",
    ),

    "gse_mgmt": dict(
        name="IEC 61850-8-1 GSE Management",
        header_bytes=8,
        type_field="Management Type (1B) at offset 8 in payload",
        type_map={
            1: dict(name="Enter-Group",              l4="gse_enter",   usage="Subscribe to GOOSE/GSSE multicast"),
            2: dict(name="Leave-Group",              l4="gse_leave",   usage="Unsubscribe from GOOSE/GSSE multicast"),
            3: dict(name="GetGoReference",           l4="gse_getref",  usage="Query GOOSE reference"),
            4: dict(name="GetGSSEDataSetReference",  l4="gse_getdsr",  usage="Query GSSE dataset reference"),
            5: dict(name="GetAllData",               l4="gse_getall",  usage="Retrieve all GOOSE/GSSE data"),
        },
        fields={
            "APPID":           "2B  application identifier",
            "Length":          "2B  total PDU length",
            "Reserved1":       "2B  0x0000",
            "Reserved2":       "2B  0x0000",
            "Management Type": "1B  1=Enter 2=Leave 3=GetGoRef 4=GetGSSEDSRef 5=GetAll",
            "MaxTime":         "2B  max retransmission interval ms",
            "MinTime":         "2B  min retransmission interval ms",
            "DatSet":          "VisibleString  dataset reference",
        },
        l4_key="gse_mgmt_type",
    ),

    "sv": dict(
        name="IEC 61850-9-2 Sampled Values",
        header_bytes=8,
        type_field="APPID range (2B) at offset 0",
        type_map={
            0: dict(name="Sampled Values PDU", l4="sv_pdu", usage="0x4000-0x7FFF instrument transformer streams"),
        },
        fields={
            "APPID":    "2B  0x4000-0x7FFF sampled values identifier",
            "Length":   "2B  total PDU byte length",
            "Reserved1":"2B  0x0000",
            "Reserved2":"2B  0x0000",
            "PDU":      "variable  ASN.1 BER savPdu with noASDU + SEQUENCE OF ASDU",
        },
        l4_key="sv_appid",
    ),

    "sercos3": dict(
        name="SERCOS III Telegram — IEC 61784-2-14",
        header_bytes=1,
        type_field="Frame Type (1B) at offset 0",
        type_map={
            0x01: dict(name="HP-Telegram (Hot-Plug)",  l4="sercos3_hp",  usage="Hot-plug device management"),
            0x11: dict(name="CP-Telegram (CyclePacket)",l4="sercos3_cp", usage="Standard cyclic data"),
            0x02: dict(name="AT (Amplifier Telegram)",  l4="sercos3_at", usage="Feedback from servo drive"),
            0x12: dict(name="MDT (Master Data Telegram)",l4="sercos3_mdt",usage="Command to servo drive"),
        },
        fields={
            "Frame Type":     "1B  HP=0x01 CP=0x11 AT=0x02 MDT=0x12",
            "Slave Address":  "2B  target slave (AT) or 0xFFFF broadcast (MDT)",
            "Telegram Length":"2B  payload byte count",
            "Service Channel":"2B  IDN-based parameter access",
            "Data":           "variable  AT=feedback MDT=setpoint",
        },
        l4_key="sercos3_frame_type",
    ),

    "wsmp": dict(
        name="IEEE 1609.3 WAVE Short Message Protocol",
        header_bytes=2,
        type_field="PSID value determines application service",
        type_map={
            0x20:   dict(name="Basic Safety Message (BSM)",    l4="wsmp_bsm",   usage="SAE J2735 BSM — vehicle position+speed+heading"),
            0x7E:   dict(name="SPAT — Signal Phase and Timing",l4="wsmp_spat",  usage="Traffic signal state for V2I"),
            0x80:   dict(name="MAP — Intersection Geometry",   l4="wsmp_map",   usage="Road geometry for intersection assistance"),
            0x8002: dict(name="TIM — Traveller Information",   l4="wsmp_tim",   usage="Road conditions warnings"),
            0x8003: dict(name="Certificate/Security",          l4="wsmp_cert",  usage="IEEE 1609.2 certificate management"),
            0x8007: dict(name="PDM — Probe Data Management",   l4="wsmp_pdm",   usage="Vehicle probe data collection"),
        },
        fields={
            "Version":  "4b  0x3=WSMPv3",
            "PSID":     "variable 1-4B VLC encoded Provider Service ID",
            "WSM Len":  "2B  application payload length",
            "WSM Data": "variable  application layer payload",
        },
        l4_key="wsmp_psid",
    ),

    "geonet": dict(
        name="ETSI ITS GeoNetworking — EN 302 636-4-1",
        header_bytes=4,
        type_field="HT (Header Type, 4b) at bits [15:12] of Common Header",
        type_map={
            1: dict(name="BEACON",     l4="geonet_beacon", usage="Periodic position beacon"),
            2: dict(name="GUC",        l4="geonet_guc",    usage="Geo Unicast to single vehicle"),
            3: dict(name="GAC",        l4="geonet_gac",    usage="Geo Area Broadcast to area"),
            4: dict(name="GBC",        l4="geonet_gbc",    usage="Geo Broadcast to area"),
            5: dict(name="TSB",        l4="geonet_tsb",    usage="Topological Scoped Broadcast"),
            6: dict(name="LS",         l4="geonet_ls",     usage="Location Service request/reply"),
        },
        fields={
            "Basic Header":  "4B  Version(4b)+NH(4b)+Reserved(8b)+Lifetime(8b)+RHL(8b)",
            "Common Header": "8B  NH(4b)+HT(4b)+HST(4b)+TC(8b)+Flags(8b)+PL(16b)+MHL(8b)+Res(8b)",
            "Extended Hdr":  "variable  GUC=8B GBC/GAC=20B BEACON=0B TSB=4B",
            "BTP Payload":   "variable  BTP-A/B + CAM/DENM/SPAT/MAP application",
        },
        l4_key="geonet_header_type",
    ),

    "tdls": dict(
        name="IEEE 802.11r Fast BSS Transition / 802.11z TDLS",
        header_bytes=1,
        type_field="Payload Type (1B) at offset 0",
        type_map={
            1: dict(name="TDLS — Tunneled Direct Link Setup",   l4="tdls_setup",  usage="802.11z TDLS setup/teardown/peer traffic"),
            2: dict(name="FBT — Fast BSS Transition",          l4="fbt_action",  usage="802.11r fast roaming transition action"),
        },
        fields={
            "Payload Type": "1B  1=TDLS 2=Fast-BSS-Transition",
            "Category":     "1B  IEEE 802.11 action frame category (12=TDLS 6=FBT)",
            "Action Code":  "1B  TDLS: 0=Setup-Req 1=Setup-Resp 2=Setup-Confirm 3=Teardown | FBT: 1=Action 2=Ack",
            "Dialog Token": "1B  request/response pairing",
            "Data":         "variable  action-specific information elements",
        },
        l4_key="tdls_payload_type",
    ),
}

NON_IP_L3_REGISTRY.update(INDUSTRIAL_L3_REGISTRY)

# ── Supplemental L3 Registry — fills all remaining spec gaps ──────────────────
SUPPLEMENTAL_L3_REGISTRY: dict[str, dict] = {

    # ── PPPoE L3 dispatcher (0x8863 Discovery + 0x8864 Session) ───────────────
    "pppoe": dict(
        name="PPPoE — Point-to-Point Protocol over Ethernet (RFC 2516)",
        header_bytes=6,
        type_field="CODE field (1B) at offset 1 — discovery stage; PPP Protocol (2B) for session",
        type_map={
            # Discovery stage (0x8863) CODE values
            0x09: dict(name="PADI — Active Discovery Initiation",   l4="pppoe_padi",
                       usage="Client broadcasts to find PPPoE Access Concentrators"),
            0x07: dict(name="PADO — Active Discovery Offer",         l4="pppoe_pado",
                       usage="AC unicasts offer with AC-Name and Service-Name tags"),
            0x19: dict(name="PADR — Active Discovery Request",       l4="pppoe_padr",
                       usage="Client unicasts to selected AC requesting session"),
            0x65: dict(name="PADS — Active Discovery Session-confirmation", l4="pppoe_pads",
                       usage="AC assigns Session-ID — session established"),
            0xA7: dict(name="PADT — Active Discovery Terminate",     l4="pppoe_padt",
                       usage="Either end terminates session — Session-ID in header"),
            0x00: dict(name="Session Data",                           l4="pppoe_session",
                       usage="0x8864 session stage — CODE=0x00, carries PPP protocol"),
        },
        fields={
            "VER+TYPE": "1B  0x11 — version=1 (4b) + type=1 (4b), always 0x11",
            "CODE":     "1B  0x09=PADI 0x07=PADO 0x19=PADR 0x65=PADS 0xA7=PADT 0x00=Session",
            "Session-ID":"2B  0x0000 during discovery; assigned by AC in PADS",
            "Length":   "2B  total length of payload (not including 6B PPPoE header)",
            "Tags":     "variable  TLV tags: 0x0101=Service-Name 0x0102=AC-Name 0x0103=Host-Uniq 0x0104=AC-Cookie 0x0110=Relay-Session-ID 0x0201=Service-Name-Error 0x0202=AC-System-Error",
        },
        l4_key="pppoe_code",
    ),

    # ── PPPoE Session stage L3 — PPP Protocol dispatch ────────────────────────
    "ppp_session": dict(
        name="PPP Protocol Dispatch (PPPoE Session — RFC 1661)",
        header_bytes=2,
        type_field="PPP Protocol (2B) at start of PPP payload",
        type_map={
            0x0021: dict(name="IPv4",          l4="ppp_ipv4",    usage="IPv4 datagram"),
            0x0057: dict(name="IPv6",          l4="ppp_ipv6",    usage="IPv6 datagram"),
            0x0281: dict(name="MPLS-UC",       l4="ppp_mpls",    usage="MPLS unicast"),
            0x0283: dict(name="MPLS-MC",       l4="ppp_mpls",    usage="MPLS multicast"),
            0x8021: dict(name="IPCP",          l4="ppp_ncp",     usage="IP Control Protocol — negotiate IP addr/DNS"),
            0x8057: dict(name="IPv6CP",        l4="ppp_ncp",     usage="IPv6 Control Protocol"),
            0xC021: dict(name="LCP",           l4="ppp_lcp",     usage="Link Control Protocol — negotiate MTU/auth/MRU"),
            0xC023: dict(name="PAP",           l4="ppp_auth",    usage="Password Authentication Protocol (cleartext)"),
            0xC025: dict(name="LQR",           l4="ppp_lqr",     usage="Link Quality Report"),
            0xC223: dict(name="CHAP",          l4="ppp_auth",    usage="Challenge Handshake Authentication Protocol"),
        },
        fields={
            "PPP Protocol": "2B  identifies encapsulated protocol",
            "PPP Data":     "variable  protocol-specific payload",
        },
        l4_key="ppp_protocol",
    ),

    # ── Proprietary / Vendor terminal L3 entries ──────────────────────────────
    "ip_as": dict(
        name="IP Autonomous Systems — RFC 1701 GRE key space",
        header_bytes=8,
        type_field="Fixed format — no sub-type dispatch",
        type_map={0: dict(name="IP-AS Frame", l4="ip_as_frame", usage="AS-tagged IP datagram")},
        fields={
            "AS Number": "2B  16-bit Autonomous System number",
            "Reserved":  "2B  0x0000",
            "IP Payload":"variable  encapsulated IP datagram",
        },
        l4_key="ip_as_type",
    ),

    "secure_data": dict(
        name="Secure Data — RFC 1701 GRE key space",
        header_bytes=8,
        type_field="Fixed format — no sub-type",
        type_map={0: dict(name="Secure Data", l4="secure_data_frame", usage="Encrypted/secured payload")},
        fields={
            "Key":      "4B  GRE key (tunnel or VLAN context identifier)",
            "Sequence": "4B  optional sequence number",
            "Payload":  "variable  encrypted payload",
        },
        l4_key="secure_type",
    ),

    "cobranet": dict(
        name="CobraNet — Cirrus Logic Audio-over-Ethernet",
        header_bytes=4,
        type_field="Sub-Type (varies)",
        type_map={
            0: dict(name="Beat (Real-time Audio)", l4="cobranet_audio",  usage="Real-time 48kHz audio bundle"),
            1: dict(name="Bundle (Packed Audio)",  l4="cobranet_audio",  usage="Packed audio samples"),
            2: dict(name="Management",             l4="cobranet_mgmt",   usage="Device management and config"),
        },
        fields={
            "Sub-Type":  "1B  0=Beat 1=Bundle 2=Management",
            "Bundle No": "2B  audio bundle number (0-65535)",
            "Payload":   "variable  audio samples or management data",
        },
        l4_key="cobranet_subtype",
    ),

    "nic_test": dict(
        name="Wind River Ethernet NIC Test",
        header_bytes=4,
        type_field="Test Type (1B) at offset 0",
        type_map={
            1: dict(name="Loopback Test", l4="nic_test_frame", usage="Ethernet loopback diagnostic"),
            2: dict(name="Pattern Test",  l4="nic_test_frame", usage="Fill-pattern data integrity test"),
        },
        fields={
            "Test Type": "1B  1=Loopback  2=Pattern",
            "Pattern":   "1B  fill byte for pattern test",
            "Length":    "2B  payload length",
            "Data":      "variable  test payload",
        },
        l4_key="test_type",
    ),

    "axis_boot": dict(
        name="Axis Communications Proprietary Bootstrap",
        header_bytes=5,
        type_field="Msg Type (1B) at offset 0",
        type_map={
            0x01: dict(name="Discovery",  l4="axis_frame", usage="Discover Axis devices on LAN"),
            0x02: dict(name="IP Assign",  l4="axis_frame", usage="Assign IP to Axis device"),
        },
        fields={
            "Msg Type":  "1B  0x01=Discovery  0x02=IPAssign",
            "Serial":    "8B  Axis device serial number",
            "Current IP":"4B  current device IPv4 address",
            "New IP":    "4B  new IPv4 address to assign",
            "Subnet":    "4B  subnet mask",
        },
        l4_key="axis_type",
    ),

    "homeplug": dict(
        name="HomePlug 1.0 MME — HomePlug Alliance",
        header_bytes=2,
        type_field="MMType (2B) at offset 0",
        type_map={
            0x0000: dict(name="MME-Request",   l4="homeplug_mme", usage="Management request"),
            0x0001: dict(name="MME-Confirm",   l4="homeplug_mme", usage="Management confirm"),
            0x0002: dict(name="MME-Indicate",  l4="homeplug_mme", usage="Management indication"),
            0x0003: dict(name="MME-Response",  l4="homeplug_mme", usage="Management response"),
        },
        fields={
            "MMType":   "2B  management message type code",
            "MME Data": "variable  management payload",
        },
        l4_key="homeplug_mmtype",
    ),

    "homeplug_av": dict(
        name="HomePlug AV / Green PHY — IEEE P1901",
        header_bytes=4,
        type_field="MMType (2B) at offset 0",
        type_map={
            0x6000: dict(name="CM_MME_Request",  l4="homeplug_av_mme", usage="AV management request"),
            0x6001: dict(name="CM_MME_Confirm",  l4="homeplug_av_mme", usage="AV management confirm"),
            0x6002: dict(name="CM_MME_Indicate", l4="homeplug_av_mme", usage="AV management indicate"),
            0x6003: dict(name="CM_MME_Response", l4="homeplug_av_mme", usage="AV management response"),
            0xA000: dict(name="Vendor-Specific",  l4="homeplug_av_mme", usage="Vendor-specific AV extension"),
        },
        fields={
            "MMType":  "2B  management message type; 0xA000-0xAFFF=vendor specific",
            "FMI":     "2B  FMI(4b)+FMSN(4b)+FMID(8b) fragmentation/sequence",
            "MMENTRY": "variable  AV management payload",
        },
        l4_key="homeplug_av_mmtype",
    ),

    "homeplug_av2": dict(
        name="HomePlug AV2 — IEEE P1901.2",
        header_bytes=4,
        type_field="MMType (2B) at offset 0",
        type_map={
            0x6000: dict(name="CM_MME_Request",  l4="homeplug_av2_mme", usage="AV2 management request"),
            0x6001: dict(name="CM_MME_Confirm",  l4="homeplug_av2_mme", usage="AV2 management confirm"),
            0xA000: dict(name="Vendor-Specific",  l4="homeplug_av2_mme", usage="Vendor AV2 extension"),
        },
        fields={
            "MMType":   "2B  AV2 management message type code",
            "FMI":      "2B  fragmentation/sequence info",
            "MMENTRY":  "variable  AV2 capabilities/beacons/link-stats payload",
        },
        l4_key="homeplug_av2_mmtype",
    ),

    "cclink_ie": dict(
        name="CC-Link IE Field/Controller — CLPA",
        header_bytes=5,
        type_field="CC-Link IE Type (1B) at offset 0",
        type_map={
            0x01: dict(name="Field",       l4="cclink_ie_pdu", usage="CC-Link IE Field cyclic data"),
            0x02: dict(name="Controller",  l4="cclink_ie_pdu", usage="CC-Link IE Controller"),
            0x03: dict(name="Motion",      l4="cclink_ie_pdu", usage="CC-Link IE Motion synchronous"),
            0x04: dict(name="TSN",         l4="cclink_ie_pdu", usage="CC-Link IE TSN (Time-Sensitive Networking)"),
        },
        fields={
            "CC-Link IE Type":"1B  0x01=Field 0x02=Controller 0x03=Motion 0x04=TSN",
            "Station No":     "1B  source station number (0-120; 0=master)",
            "Dst Station":    "1B  destination station (0xFF=broadcast)",
            "Seq No":         "2B  sequence number for token-passing ring",
            "PDU":            "variable  cyclic RX/TX data or transient message",
            "Token Ring":     "Master passes token; only token holder may transmit",
        },
        l4_key="cclink_type",
    ),

    "local_exp": dict(
        name="IEEE 802 Local Experimental (RFC 9542 §3)",
        header_bytes=0,
        type_field="No standard type field — format defined by local agreement",
        type_map={
            0: dict(name="Experimental Protocol", l4="local_exp_payload",
                    usage="User-defined experimental payload"),
        },
        fields={
            "Payload":  "variable  format defined locally — not standardised",
            "Scope":    "MUST NOT be forwarded beyond local network segment",
            "Use":      "Protocol prototyping before requesting IANA/IEEE EtherType assignment",
        },
        l4_key="exp_type",
    ),
}

NON_IP_L3_REGISTRY.update(SUPPLEMENTAL_L3_REGISTRY)

# ── Extended L3 Registry — additional protocols per IEEE/IANA/RFC/Non-Std ──────
EXTENDED_L3_REGISTRY: dict[str, dict] = {

    # ── IEEE 802.1D / 802.1w / 802.1s STP BPDU dispatcher ────────────────────
    "stp": dict(
        name="IEEE STP/RSTP/MSTP BPDU — IEEE 802.1D/802.1w/802.1s",
        status="IEEE Standard",
        description="Spanning Tree Protocol family — prevents L2 loops by electing "
                    "a root bridge and blocking redundant paths. Version 0=Classic STP "
                    "(30-50s convergence), 2=RSTP (<1s), 3=MSTP (multiple instances).",
        header_bytes=4,
        type_field="BPDU Type (1B) at offset 3, combined with Version (1B) at offset 2",
        type_map={
            # (bpdu_type, version) encoded as composite key
            0x00: dict(name="STP Config BPDU (v0)",    l4="stp_config",
                       usage="IEEE 802.1D-1998 Configuration BPDU — version=0x00 type=0x00"),
            0x80: dict(name="TCN BPDU (v0)",           l4="stp_tcn",
                       usage="Topology Change Notification — minimal 4B frame, sent toward root"),
            0x02: dict(name="RST BPDU (v2 RSTP)",      l4="rstp_bpdu",
                       usage="IEEE 802.1w RST BPDU — version=0x02 type=0x02, full 8-flag byte"),
            0x03: dict(name="MST BPDU (v3 MSTP)",      l4="mstp_bpdu",
                       usage="IEEE 802.1s MST BPDU — version=0x03, includes MST Config ID + MSTI records"),
        },
        fields={
            "Protocol ID":     "2B  0x0000 — IEEE STP always zero",
            "Version":         "1B  0x00=STP(802.1D-1998) 0x02=RSTP(802.1w) 0x03=MSTP(802.1s)",
            "BPDU Type":       "1B  0x00=Config 0x80=TCN 0x02=RST/MST",
            "Flags":           "1B  STP: bit0=TC bit7=TCA (bits1-6 RESERVED=0) | RSTP/MSTP: all 8 bits active",
            "Root Bridge ID":  "8B  Priority(4b)+SysExt(12b)+MAC(48b) — STP uses full 16b priority",
            "Root Path Cost":  "4B  cost from sender to root — 0 means sender IS root",
            "Bridge ID":       "8B  sender's bridge identifier",
            "Port ID":         "2B  STP:Prio(8b)+Num(8b) RSTP/MSTP:Prio(4b,×16)+Num(12b)",
            "Message Age":     "2B  1/256-second units; hops from root; discarded when ≥ Max Age",
            "Max Age":         "2B  default 20s (5120 units); topology recalc if BPDU not received",
            "Hello Time":      "2B  default 2s (512 units); root BPDU interval",
            "Forward Delay":   "2B  default 15s (3840); Listening+Learning time (STP only)",
            "Version1Length":  "1B  RSTP/MSTP only — always 0x00",
            "CAUTION":         "STP bridge priority MUST be multiples of 4096 for RSTP/MSTP (not STP 802.1D-1998); System-ID-Extension = 0 for RSTP, MSTI-number for MSTP, VLAN-ID for PVST+",
        },
        l4_key="bpdu_type",
    ),

    # ── XTP — Xpress Transfer Protocol (ANSI X3T9.5) ─────────────────────────
    "xtp": dict(
        name="XTP — Xpress Transfer Protocol (ANSI X3T9.5 / EtherType 0x817D)",
        status="ANSI / Non-Standard (obsolete)",
        description="XTP is a high-performance transport protocol designed as a "
                    "TCP replacement for high-speed LANs. Designed by Protocol Engines "
                    "Inc., it supports unicast, multicast, and real-time transfer. "
                    "Never achieved widespread adoption; effectively obsolete.",
        header_bytes=12,
        type_field="DKEY (2B) at offset 8 — destination endpoint key",
        type_map={
            0: dict(name="Data Segment",      l4="xtp_data",   usage="XTP data transfer segment"),
            1: dict(name="Control Segment",   l4="xtp_ctrl",   usage="XTP control — flow/error control"),
            2: dict(name="Error Segment",     l4="xtp_err",    usage="XTP error report"),
            3: dict(name="Async Control",     l4="xtp_ctrl",   usage="Asynchronous control message"),
        },
        fields={
            "Key":      "4B  0=reserved; identifies XTP session at receiver",
            "EOM":      "1b  end-of-message flag",
            "MULTI":    "1b  multicast flag",
            "RES":      "6b  reserved",
            "TYPE":     "1B  0=Data 1=Control 2=Error 3=Async-Control",
            "DKEY":     "4B  destination key — receiver demultiplex",
            "SKEY":     "4B  source key",
            "SEQ":      "4B  32-bit sequence number",
            "CAUTION":  "XTP is obsolete — ANSI X3T9.5 withdrawn; not deployed in modern networks; documented for legacy analysis only",
        },
        l4_key="xtp_type",
    ),

    # ── MPLS inner payload dispatch ────────────────────────────────────────────
    "mpls_inner": dict(
        name="MPLS Inner Payload Dispatch — RFC 3032 bottom-of-stack",
        status="IETF Standard — RFC 3032 + RFC 4182 + RFC 4928",
        description="After all MPLS labels are popped (S=1 bottom-of-stack), the "
                    "payload type is identified by the first nibble of the inner "
                    "payload (IP version nibble) or by explicit NULL label. This is "
                    "the MPLS 'implicit null' / 'explicit null' dispatch mechanism.",
        header_bytes=0,
        type_field="First nibble of payload (IP version) or explicit null label value",
        type_map={
            4:  dict(name="IPv4 payload",         l4="ipv4_inner",   usage="Inner IPv4 datagram — first nibble 0x4"),
            6:  dict(name="IPv6 payload",         l4="ipv6_inner",   usage="Inner IPv6 datagram — first nibble 0x6"),
            0:  dict(name="Explicit-NULL IPv4",   l4="ipv4_inner",   usage="Label 0 — IPv4 explicit null, penultimate hop pop"),
            2:  dict(name="Explicit-NULL IPv6",   l4="ipv6_inner",   usage="Label 2 — IPv6 explicit null"),
            3:  dict(name="Implicit-NULL (PHP)",  l4="ipv4_inner",   usage="Label 3 — PHP, payload exposed to penultimate LSR"),
            14: dict(name="OAM Alert Label",      l4="mpls_inner",   usage="Label 14 — MPLS OAM alert per RFC 3429"),
            15: dict(name="Extension Label (XL)", l4="mpls_inner",   usage="Label 15 — Extension Label base per RFC 7274"),
        },
        fields={
            "Bottom-of-Stack": "S=1 bit in last MPLS label indicates payload follows",
            "Version nibble":  "first 4 bits of payload: 4=IPv4 6=IPv6 (implicit type detection)",
            "Explicit NULL":   "Label 0 (IPv4) or Label 2 (IPv6) — preserve EXP/TC bits to egress",
            "PHP":             "Label 3 — Penultimate Hop Popping; last label popped before egress",
            "CAUTION":         "MPLS does not carry explicit EtherType — payload identified by IP version nibble; incorrect S-bit causes wrong decode; TTL must be handled carefully at PHP",
        },
        l4_key="mpls_payload_type",
    ),

    # ── Additional complete L3 protocols ──────────────────────────────────────

    # DECnet Phase IV / V (0x6003, 0x8038, 0x803D) — Digital Equipment Corp
    "decnet_phase5": dict(
        name="DECnet Phase V / DNA (Digital Network Architecture) — Digital Equipment",
        status="Vendor Proprietary (Digital Equipment Corporation) — Legacy",
        description="DECnet Phase V (also called DECnet/OSI or DNA Phase V) extended "
                    "DECnet to support the OSI protocol stack. Used in VAX/VMS clusters "
                    "and Digital's commercial networking products. Superseded by TCP/IP.",
        header_bytes=3,
        type_field="DNA Type (1B) at offset 2",
        type_map={
            0x01: dict(name="DNA Routing",      l4="decnet_routing",  usage="DNA routing message"),
            0x02: dict(name="DNA Hello",        l4="decnet_hello",    usage="Router hello for adjacency"),
            0x03: dict(name="DNA End-Node Hello",l4="decnet_hello",   usage="End-node hello"),
            0x05: dict(name="DNA Level-1 LSP",  l4="decnet_lsp",      usage="Level-1 link state PDU"),
            0x06: dict(name="DNA Level-2 LSP",  l4="decnet_lsp",      usage="Level-2 link state PDU"),
        },
        fields={
            "DSAP":    "1B  0xFE — ISO CONS/CLNS SAP",
            "SSAP":    "1B  0xFE",
            "Control": "1B  0x03 LLC UI frame",
            "DNA Type":"1B  routing message type",
            "Hop Count":"1B  decremented per router; max 63 (6b field)",
            "CAUTION": "DECnet Phase V obsolete since mid-1990s — encountered only on legacy DEC/Compaq networks",
        },
        l4_key="dna_type",
    ),

    # Banyan VINES (0x0BAD) — Banyan Systems
    "vines_ip": dict(
        name="Banyan VINES IP — Banyan Systems (EtherType 0x0BAD)",
        status="Vendor Proprietary (Banyan Systems) — Legacy",
        description="VINES (Virtual Integrated Network Service) was Banyan Systems' "
                    "proprietary enterprise networking protocol suite, popular in the "
                    "late 1980s-1990s for large enterprise networks. Superseded by TCP/IP.",
        header_bytes=18,
        type_field="Protocol (2B) at offset 8",
        type_map={
            0xBA: dict(name="VINES ICP",   l4="vines_ctrl",  usage="VINES Internet Control Protocol"),
            0xBB: dict(name="VINES ARP",   l4="vines_ctrl",  usage="VINES Address Resolution"),
            0xBC: dict(name="VINES RTP",   l4="vines_rtp",   usage="VINES Routing Table Protocol"),
            0xBD: dict(name="VINES IPC",   l4="vines_data",  usage="VINES Inter-Process Communication"),
            0xBE: dict(name="VINES SPP",   l4="vines_data",  usage="VINES Sequenced Packet Protocol"),
        },
        fields={
            "Checksum":     "2B  ones-complement over VINES IP header",
            "Packet Length":"2B  total VINES IP packet length",
            "Transport Ctrl":"1B  hop count and class of service",
            "Protocol Type":"1B  0xBA=ICP 0xBB=ARP 0xBC=RTP 0xBD=IPC 0xBE=SPP",
            "Dest Net":     "4B  destination VINES network number",
            "Dest Subnet":  "2B  destination subnet (host) ID",
            "Src Net":      "4B  source VINES network number",
            "Src Subnet":   "2B  source subnet ID",
            "CAUTION":      "VINES completely obsolete — Banyan Systems dissolved in 1999; documented for legacy traffic analysis only",
        },
        l4_key="vines_protocol",
    ),

    # AppleTalk DDP extended (0x809B) — Apple Computer
    "ddp_ext": dict(
        name="AppleTalk DDP Extended — Apple Computer (EtherType 0x809B)",
        status="Vendor / IEEE — Legacy (Apple deprecated 2009)",
        description="AppleTalk Datagram Delivery Protocol extended (long header form). "
                    "Used in pre-2009 Apple networks. Short-header DDP is encapsulated "
                    "in 802.2 LLC/SNAP. macOS 10.6 removed AppleTalk support entirely.",
        header_bytes=13,
        type_field="DDP Type (1B) at offset 12",
        type_map={
            1:  dict(name="RTMP Data",      l4="ddp_rtmp",   usage="Routing Table Maintenance Protocol data"),
            2:  dict(name="NBP",            l4="ddp_nbp",    usage="Name Binding Protocol — AppleTalk name resolution"),
            3:  dict(name="ATP",            l4="ddp_atp",    usage="AppleTalk Transaction Protocol"),
            4:  dict(name="AEP",            l4="aep",        usage="AppleTalk Echo Protocol"),
            5:  dict(name="RTMP Request",   l4="ddp_rtmp",   usage="RTMP routing request"),
            6:  dict(name="ZIP",            l4="ddp_zip",    usage="Zone Information Protocol"),
            8:  dict(name="SNMP",           l4="snmp",       usage="SNMP over AppleTalk"),
            22: dict(name="ASP",            l4="ddp_asp",    usage="AppleTalk Session Protocol — AFP over ASP"),
            35: dict(name="AFP/DSP",        l4="ddp_asp",    usage="AppleTalk Filing Protocol"),
        },
        fields={
            "Length":    "10b  datagram length (headers + data)",
            "Checksum":  "2B  0x0000 = no checksum (DDP never checksums in practice)",
            "Dest Net":  "2B  destination AppleTalk network number",
            "Src Net":   "2B  source network number",
            "Dest Node": "1B  destination node ID (0xFF=broadcast)",
            "Src Node":  "1B  source node ID",
            "Dest Socket":"1B  destination socket number",
            "Src Socket":"1B  source socket number",
            "DDP Type":  "1B  protocol type",
            "CAUTION":   "AppleTalk removed in macOS 10.6 (2009) — only encountered on pre-2009 Mac networks or legacy print servers",
        },
        l4_key="ddp_type",
    ),

    # AARP — AppleTalk ARP (0x80F3)
    "aarp": dict(
        name="AARP — AppleTalk Address Resolution Protocol (EtherType 0x80F3)",
        status="Vendor — Legacy (Apple deprecated 2009)",
        description="AARP maps AppleTalk node addresses to hardware (MAC) addresses, "
                    "analogous to ARP for IPv4. Also handles AppleTalk address "
                    "self-assignment via probe/request/response mechanism.",
        header_bytes=28,
        type_field="Function (2B) at offset 10",
        type_map={
            1: dict(name="AARP Request",  l4="aarp_pdu", usage="Request: who has this AppleTalk address?"),
            2: dict(name="AARP Response", l4="aarp_pdu", usage="Response: I have this AppleTalk address"),
            3: dict(name="AARP Probe",    l4="aarp_pdu", usage="Probe for address self-assignment conflict detection"),
        },
        fields={
            "HW Type":   "2B  hardware type: 1=Ethernet",
            "Proto Type":"2B  0x809B=AppleTalk",
            "HW Len":    "1B  6 (MAC address length)",
            "Proto Len": "1B  4 (AppleTalk address = network(2B)+node(1B)+socket(1B))",
            "Function":  "2B  1=Request 2=Response 3=Probe",
            "Src HW":    "6B  sender MAC address",
            "Src Proto": "4B  sender AppleTalk address",
            "Dst HW":    "6B  target MAC (zeros in request)",
            "Dst Proto": "4B  target AppleTalk address",
        },
        l4_key="aarp_function",
    ),

    # IPX — Novell (0x8137)
    "ipx": dict(
        name="Novell IPX — Internetwork Packet Exchange (EtherType 0x8137/0x8138)",
        status="Vendor (Novell) — Legacy",
        description="IPX is Novell's connectionless network layer protocol, derived from "
                    "Xerox XNS. Used in NetWare networks for file/print sharing. "
                    "Completely superseded by TCP/IP; Novell deprecated IPX in 2000.",
        header_bytes=30,
        type_field="Packet Type (1B) at offset 5",
        type_map={
            0:  dict(name="Unknown/Raw",  l4="raw_ipx",       usage="Raw IPX datagram"),
            1:  dict(name="RIP",          l4="ipx_rip",       usage="IPX Routing Information Protocol"),
            2:  dict(name="Echo",         l4="raw_ipx",       usage="IPX echo (ping)"),
            3:  dict(name="Error",        l4="raw_ipx",       usage="IPX error packet"),
            4:  dict(name="PEX",          l4="raw_ipx",       usage="Packet Exchange Protocol"),
            5:  dict(name="SPX",          l4="ipx_spx",       usage="Sequenced Packet Exchange — reliable stream"),
            17: dict(name="NCP",          l4="ipx_ncp",       usage="NetWare Core Protocol — file/print services"),
            20: dict(name="NetBIOS",      l4="netbios_ipx",   usage="NetBIOS type-20 broadcast propagation"),
        },
        fields={
            "Checksum":    "2B  0xFFFF=no checksum (IPX never uses checksum in practice)",
            "Length":      "2B  total IPX packet length (header + data)",
            "Hop Count":   "1B  router hops (max 15; 16=unreachable); incremented per router",
            "Packet Type": "1B  service type dispatch",
            "Dest Network":"4B  destination IPX network (0x00000000=local)",
            "Dest Node":   "6B  destination MAC address",
            "Dest Socket": "2B  0x0451=NCP 0x0452=SAP 0x0453=RIP 0x0455=NetBIOS 0x0456=Diagnostics",
            "Src Network": "4B  source network",
            "Src Node":    "6B  source MAC",
            "Src Socket":  "2B  source socket",
            "CAUTION":     "IPX SAP broadcasts every 60s — flood networks at scale; IPX RIP uses hop count not bandwidth; disable on all modern networks",
        },
        l4_key="packet_type",
    ),

    # XNS IDP — Xerox (0x0600)
    "xns": dict(
        name="XNS IDP — Xerox Network Systems (EtherType 0x0600)",
        status="Vendor (Xerox) — Legacy (predecessor to IPX/UDP)",
        description="XNS (Xerox Network Systems) was developed at Xerox PARC in the "
                    "1970s-80s. IDP (Internetwork Datagram Protocol) is its network layer, "
                    "the direct ancestor of Novell IPX and influenced UDP/IP design.",
        header_bytes=30,
        type_field="Transport Type (1B) at offset 4",
        type_map={
            0:  dict(name="RIP",    l4="raw_idp",   usage="XNS Routing Information Protocol"),
            1:  dict(name="Echo",   l4="xns_echo",  usage="XNS Echo Protocol"),
            2:  dict(name="Error",  l4="raw_idp",   usage="XNS Error Protocol"),
            4:  dict(name="PEX",    l4="raw_idp",   usage="Packet Exchange Protocol"),
            5:  dict(name="SPP",    l4="raw_idp",   usage="Sequenced Packet Protocol"),
            12: dict(name="NetBIOS",l4="netbios",   usage="NetBIOS over XNS"),
        },
        fields={
            "Checksum":    "2B  IDP checksum; 0xFFFF=no checksum",
            "Length":      "2B  total IDP packet length including 30B header",
            "Transport":   "1B  packet type",
            "Hop Count":   "1B  router hops (max 15)",
            "Dest Net":    "4B  destination XNS network number",
            "Dest Host":   "6B  destination 48-bit host address",
            "Dest Socket": "2B  destination socket",
            "Src Net":     "4B  source network",
            "Src Host":    "6B  source host",
            "Src Socket":  "2B  source socket",
            "CAUTION":     "XNS entirely obsolete — only found in museum networks and archived Xerox equipment",
        },
        l4_key="xns_transport",
    ),

    # PUP — Xerox PARC Universal Packet (0x0200)
    "pup_l3": dict(
        name="PUP — PARC Universal Packet — Xerox PARC (EtherType 0x0200)",
        status="Vendor (Xerox PARC) — Historical (1970s precursor to UDP/IP)",
        description="PUP was the original internetwork datagram protocol developed at "
                    "Xerox PARC by Bob Metcalfe and others circa 1974, predating UDP/IP. "
                    "It introduced many concepts later used in TCP/IP including socket "
                    "addressing and packet-switched internetworking.",
        header_bytes=20,
        type_field="PUP Type (1B) at offset 3",
        type_map={
            0:  dict(name="Basic PUP",     l4="raw_idp",   usage="Basic PUP datagram"),
            12: dict(name="PUP Echo",      l4="pup_echo",  usage="PUP echo request/reply"),
            13: dict(name="PUP Echo Reply",l4="pup_echo",  usage="PUP echo reply"),
        },
        fields={
            "Length":      "2B  total PUP packet length",
            "Transport":   "1B  hop count + checksum control",
            "PUP Type":    "1B  protocol type",
            "PUP ID":      "4B  transaction ID (sequence + timestamp)",
            "Dest Port":   "10B  dest PUP address: network(4B)+host(6B) (no socket in PUP)",
            "Src Port":    "10B  source PUP address",
            "CAUTION":     "PUP entirely obsolete — only in historical documentation and very old Xerox research equipment",
        },
        l4_key="pup_type",
    ),

    # GRE inner payload dispatch — RFC 2784 / RFC 2890
    "gre_dispatch": dict(
        name="GRE Inner Payload Dispatch — RFC 2784 / RFC 2890",
        status="IETF Standard — RFC 2784 (base), RFC 2890 (key/seq extensions)",
        description="GRE (Generic Routing Encapsulation) carries arbitrary network "
                    "layer payloads identified by the Protocol Type field (same as "
                    "EtherType). RFC 2784 is the canonical GRE spec; RFC 1701 is the "
                    "older version with more options. Used in VPNs and tunnelling.",
        header_bytes=4,
        type_field="Protocol Type (2B) at offset 2 — same values as EtherType",
        type_map={
            0x0800: dict(name="IPv4",          l4="ipv4_inner",   usage="IPv4 payload over GRE tunnel"),
            0x86DD: dict(name="IPv6",          l4="ipv6_inner",   usage="IPv6 payload"),
            0x6558: dict(name="Transparent Eth",l4="gre_eth_inner",usage="Transparent Ethernet Bridging — RFC 1701"),
            0x8847: dict(name="MPLS-UC",        l4="mpls_inner",   usage="MPLS unicast label stack in GRE"),
            0x8848: dict(name="MPLS-MC",        l4="mpls_inner",   usage="MPLS multicast in GRE"),
            0x88BE: dict(name="ERSPAN-II",      l4="erspan_pdu",   usage="Cisco ERSPAN Type II — mirrored traffic"),
            0x22EB: dict(name="ERSPAN-III",     l4="erspan_pdu",   usage="Cisco ERSPAN Type III"),
            0x9000: dict(name="Loopback",       l4="loopback_test",usage="GRE loopback / config test"),
        },
        fields={
            "Flags":          "1B  C(1b)+R(1b)+K(1b)+S(1b)+s(1b)+Recur(3b) — C=Checksum K=Key S=Sequence",
            "Version":        "3b  0 for RFC 2784; 1 for PPTP (RFC 2637)",
            "Protocol Type":  "2B  EtherType of inner payload",
            "Checksum":       "optional 2B — only present if C bit set; covers GRE header + payload",
            "Reserved":       "optional 2B — present with Checksum",
            "Key":            "optional 4B — present if K bit set; identifies GRE tunnel",
            "Sequence No":    "optional 4B — present if S bit set; for in-order delivery",
            "CAUTION":        "GRE has no authentication; use IPsec over GRE (GRE+ESP) for secure tunnels; K bit key is NOT encryption; IP fragmentation applies to outer IP not inner",
        },
        l4_key="gre_protocol",
    ),

    # SNAP inner payload (OUI-extended EtherType dispatch)
    "snap": dict(
        name="IEEE 802.2 LLC/SNAP — Sub-Network Access Protocol (IEEE 802.2)",
        status="IEEE Standard — IEEE 802.2 / RFC 1042",
        description="SNAP extends 802.2 LLC by prepending a 5-byte SNAP header "
                    "(3B OUI + 2B PID) after the DSAP/SSAP=0xAA/0x03 bytes. "
                    "This allows arbitrary EtherType-like dispatch within 802 frames. "
                    "Used by Cisco CDP/VTP/DTP, AppleTalk, Token Ring, and 802.11.",
        header_bytes=8,
        type_field="OUI(3B)+PID(2B) at offset 3 — OUI=0x000000 uses PID as EtherType",
        type_map={
            0x000000_0800: dict(name="IPv4 via SNAP",    l4="ipv4_inner",   usage="IPv4 in 802.2 SNAP frame — RFC 1042"),
            0x000000_0806: dict(name="ARP via SNAP",     l4="arp_inner",    usage="ARP in SNAP"),
            0x000000_86DD: dict(name="IPv6 via SNAP",    l4="ipv6_inner",   usage="IPv6 in SNAP"),
            0x00000C_2000: dict(name="CDP",              l4="cdp_tlv",      usage="Cisco Discovery Protocol"),
            0x00000C_2003: dict(name="VTP",              l4="vtp_pdu",      usage="VLAN Trunking Protocol"),
            0x00000C_2004: dict(name="DTP",              l4="dtp_pdu",      usage="Dynamic Trunking Protocol"),
            0x00000C_010B: dict(name="PVST+",            l4="stp_config",   usage="Cisco Per-VLAN Spanning Tree+"),
            0x000000_809B: dict(name="AppleTalk",        l4="ddp_asp",      usage="AppleTalk DDP via SNAP"),
        },
        fields={
            "DSAP":   "1B  0xAA — SNAP SAP",
            "SSAP":   "1B  0xAA — SNAP SAP",
            "Control":"1B  0x03 — LLC UI (Unnumbered Information)",
            "OUI":    "3B  Organisation Unique Identifier; 0x000000=IANA/standard",
            "PID":    "2B  Protocol ID; when OUI=0x000000, PID = EtherType",
            "CAUTION":"SNAP framing differs from Ethernet II — same payload protocols but different encapsulation; bridges must handle both; maximum payload = MTU - 8B SNAP overhead",
        },
        l4_key="snap_oui_pid",
    ),

    # IEEE 802.11 WiFi control (via TDLS EtherType 0x890D — extended)
    "wifi_ctrl": dict(
        name="IEEE 802.11 WiFi Direct / Tunnelled Control Frames",
        status="IEEE Standard — IEEE 802.11-2020",
        description="Wired-side tunnelling of IEEE 802.11 control and management "
                    "frames used in Wi-Fi tunnelling scenarios including 802.11r FBT, "
                    "802.11z TDLS, and 802.11v BSS Transition management.",
        header_bytes=2,
        type_field="Frame Control (2B) at offset 0 — 802.11 frame type/subtype",
        type_map={
            0x00D0: dict(name="Action Frame",        l4="tdls_setup",   usage="802.11 Action — TDLS/FBT/BSS-TM"),
            0x0040: dict(name="Probe Request",       l4="tdls_setup",   usage="Tunnelled probe request"),
            0x0050: dict(name="Probe Response",      l4="tdls_setup",   usage="Tunnelled probe response"),
            0x0020: dict(name="Reassociation Req",   l4="fbt_action",   usage="FBT fast reassociation"),
        },
        fields={
            "Frame Control": "2B  Protocol Ver(2b)+Type(2b)+Subtype(4b)+ToDS+FromDS+MF+Retry+PwrMgmt+MoreData+Protected+Order",
            "Duration":      "2B  NAV duration in µs",
            "Addr1":         "6B  receiver address",
            "Addr2":         "6B  transmitter address",
            "Addr3":         "6B  BSSID or other address",
            "Seq Control":   "2B  Fragment Number(4b) + Sequence Number(12b)",
            "CAUTION":       "Tunnelled 802.11 frames require AP cooperation; TDLS must be enabled in AP policy; incorrect frame tunnelling can trigger deauthentication",
        },
        l4_key="frame_control",
    ),

    # Slow Protocols extension — LACP details (already in slow_proto but needs sub-dispatch detail)
    "lacp_ext": dict(
        name="LACP Extended — IEEE 802.3-2022 Clause 43 / 802.1AX",
        status="IEEE Standard — IEEE 802.3 Clause 43 / IEEE 802.1AX-2014",
        description="LACP (Link Aggregation Control Protocol) negotiates LAG (Link "
                    "Aggregation Group) formation between two devices. IEEE 802.1AX "
                    "renames 802.3ad and adds DRNI (Distributed Resilient Network "
                    "Interconnect) for multi-chassis LAG.",
        header_bytes=110,
        type_field="Actor TLV Type (1B) at offset 2 — 0x01=Actor 0x02=Partner 0x03=Collector",
        type_map={
            0x01: dict(name="Actor Info",    l4="lacp_actor_partner", usage="Sending port's LACP parameters"),
            0x02: dict(name="Partner Info",  l4="lacp_actor_partner", usage="Received partner's LACP parameters"),
            0x03: dict(name="Collector Info",l4="lacp_actor_partner", usage="Max delay collector can handle"),
            0x00: dict(name="Terminator",    l4=None,                 usage="End of LACP PDU TLV chain"),
        },
        fields={
            "Subtype":          "1B  0x01=LACP",
            "Version":          "1B  0x01",
            "Actor TLV Type":   "1B  0x01",
            "Actor TLV Length": "1B  0x14=20 bytes",
            "Actor Sys Priority":"2B  lower = preferred aggregator (0=highest); default 32768",
            "Actor Sys ID":     "6B  actor system MAC address",
            "Actor Key":        "2B  operational key — same key = compatible bundling",
            "Actor Port Priority":"2B  lower = preferred active port; default 32768",
            "Actor Port":       "2B  port number within system",
            "Actor State":      "1B  LACP_Activity(b0)+LACP_Timeout(b1)+Aggregation(b2)+Sync(b3)+Collecting(b4)+Distributing(b5)+Defaulted(b6)+Expired(b7)",
            "Partner TLV":      "20B  same structure as Actor TLV for partner info",
            "Collector TLV":    "16B  Max Delay(2B) + Reserved(12B)",
            "CAUTION":          "Actor Key must match on both sides to bundle; Active+Active forms LAG; Active+Passive forms LAG; Passive+Passive = no LAG; key mismatch = no bundling",
        },
        l4_key="lacp_tlv_type",
    ),

    # IEEE 802.3ah OAM (via slow_proto subtype=3) — extended fields
    "oam_ext": dict(
        name="IEEE 802.3ah OAM — Ethernet in First Mile EFM (Clause 57)",
        status="IEEE Standard — IEEE 802.3ah-2004 / IEEE 802.3-2022 Clause 57",
        description="EFM OAM (Operations, Administration, and Maintenance) provides "
                    "link-level fault detection, monitoring, and remote diagnostics for "
                    "point-to-point Ethernet links, especially DSL last-mile connections.",
        header_bytes=3,
        type_field="Code (1B) at offset 2 identifies OAM PDU type",
        type_map={
            0x00: dict(name="Information",       l4="oam_pdu",  usage="Mandatory — OAM capability discovery TLVs"),
            0x01: dict(name="Event Notification",l4="oam_pdu",  usage="Link fault events — link fault, dying gasp, critical"),
            0x02: dict(name="Variable Request",  l4="oam_pdu",  usage="Request MIB variable from remote OAM entity"),
            0x03: dict(name="Variable Response", l4="oam_pdu",  usage="Response with requested MIB variable value"),
            0x04: dict(name="Loopback Control",  l4="oam_pdu",  usage="Enable/disable remote loopback on link"),
            0xFE: dict(name="Org-Specific",      l4="oam_pdu",  usage="Vendor-specific OAM PDU"),
        },
        fields={
            "Flags":        "2B  Link-Fault(b0)+Dying-Gasp(b1)+Critical-Event(b2)+Local-Eval(b3)+Local-Stable(b4)+Remote-Eval(b5)+Remote-Stable(b6)+Reserved(b7-15)",
            "Code":         "1B  OAM PDU type",
            "Information TLV":"Local Info(0x01)+Remote Info(0x02)+Org-Spec(0xFE)+End(0x00)",
            "Local Info":   "Type=0x01 Length=0x10: OAM-Config+PDU-Config+OUI+Vendor-Specific",
            "OAM Config":   "1B  OAM-Mode(b0)+Unidirect(b1)+RemoteLoopback(b2)+LinkEvents(b3)+VariableRetrieval(b4)",
            "PDU Config":   "2B  max OAM PDU size (64-1518B)",
            "Event TLV":    "Type=0x01 Err-Sym-Period / 0x02 Err-Frame / 0x03 Err-Frame-Period / 0x04 Err-Frame-Seconds-Summary",
            "CAUTION":      "Remote loopback (Code=0x04) loops ALL traffic — activating on a live link causes full service outage; use with extreme caution",
        },
        l4_key="oam_code",
    ),
}

NON_IP_L3_REGISTRY.update(EXTENDED_L3_REGISTRY)




CISCO_L3_REGISTRY: dict[str, dict] = {
    "mac_ctrl": dict(
        name="IEEE 802.3 MAC Control (0x8808)",
        header_bytes=2,
        type_field="Opcode (2B) at offset 0",
        type_map={
            0x0001: dict(name="Pause",       l4="mac_ctrl_pause",  usage="Symmetric flow control pause frame"),
            0x0101: dict(name="PFC",         l4="mac_ctrl_pfc",    usage="Per-priority flow control (802.1Qbb)"),
            0x0002: dict(name="EPON-Gate",   l4="mac_ctrl_epon",   usage="EPON OAM gate control"),
            0x0003: dict(name="EPON-Report", l4="mac_ctrl_epon",   usage="EPON OAM report"),
        },
        fields={"Opcode":"2B","Pause Quanta":"2B(Pause)","PFC Enable":"2B(PFC)","PFC Quanta[0-7]":"16B(PFC)"},
        l4_key="mac_ctrl_opcode",
    ),
    "slow_proto": dict(
        name="IEEE 802.3 Slow Protocols (0x8809)",
        header_bytes=1,
        type_field="Subtype (1B) at offset 0",
        type_map={
            0x01: dict(name="LACP",    l4="lacp_actor_partner", usage="Link Aggregation Control Protocol"),
            0x02: dict(name="Marker",  l4="lacp_marker",        usage="LACP Marker PDU for loopback detection"),
            0x03: dict(name="OAM",     l4="oam_pdu",            usage="Ethernet OAM (802.3ah) operations"),
            0x0A: dict(name="OSSP",    l4="ossp_pdu",           usage="Organisation Specific Slow Protocol"),
        },
        fields={"Subtype":"1B"},
        l4_key="slow_subtype",
    ),
    "cdp": dict(
        name="Cisco CDP (0x2000 SNAP)",
        header_bytes=4,
        type_field="TLV Type (2B) per TLV",
        type_map={
            0x0001: dict(name="DeviceID",   l4="cdp_tlv", usage="Device hostname or serial"),
            0x0002: dict(name="Addresses",  l4="cdp_tlv", usage="Management IP addresses"),
            0x0003: dict(name="PortID",     l4="cdp_tlv", usage="Interface name"),
            0x0004: dict(name="Capability", l4="cdp_tlv", usage="Device capabilities bitmask"),
            0x0005: dict(name="Software",   l4="cdp_tlv", usage="IOS/NX-OS version"),
            0x0006: dict(name="Platform",   l4="cdp_tlv", usage="Hardware model"),
            0x000A: dict(name="NativeVLAN", l4="cdp_tlv", usage="Native/access VLAN ID"),
            0x000B: dict(name="Duplex",     l4="cdp_tlv", usage="Full/half duplex"),
            0x0010: dict(name="PowerAvail", l4="cdp_tlv", usage="PoE milliwatts available"),
        },
        fields={"CDP Version":"1B","TTL":"1B","Checksum":"2B","TLV chain":"Type(2B)+Len(2B)+Value"},
        l4_key="cdp_tlv_type",
    ),
    "vtp": dict(
        name="Cisco VTP (0x2003 SNAP)",
        header_bytes=36,
        type_field="Code (1B) at offset 1",
        type_map={
            0x01: dict(name="Summary-Advert",  l4="vtp_pdu", usage="VTP domain summary with revision"),
            0x02: dict(name="Subset-Advert",   l4="vtp_pdu", usage="VLAN detail advertisement"),
            0x03: dict(name="Advert-Request",  l4="vtp_pdu", usage="Request full VLAN database"),
            0x04: dict(name="Join",            l4="vtp_pdu", usage="VTPv2 pruning join message"),
        },
        fields={"VTP Version":"1B","Code":"1B","Domain Len":"1B","Domain":"32B","Config Rev":"4B"},
        l4_key="vtp_code",
    ),
    "dtp": dict(
        name="Cisco DTP (0x2004 SNAP)",
        header_bytes=1,
        type_field="TLV Type (2B) per TLV",
        type_map={
            0x01: dict(name="Domain",   l4="dtp_pdu", usage="Trunk domain name"),
            0x02: dict(name="Status",   l4="dtp_pdu", usage="Trunk mode status"),
            0x03: dict(name="DTP-Type", l4="dtp_pdu", usage="Encapsulation type (ISL/802.1Q)"),
            0x04: dict(name="Neighbor", l4="dtp_pdu", usage="Neighbor MAC"),
        },
        fields={"DTP Version":"1B","TLV chain":"Type(2B)+Len(2B)+Value"},
        l4_key="dtp_tlv_type",
    ),
    "pvst": dict(
        name="Cisco PVST+ / Rapid-PVST+ (SNAP PID 0x010B)",
        header_bytes=7,
        type_field="Protocol Version (1B) at offset 2",
        type_map={
            0x00: dict(name="PVST+",       l4="stp_bpdu",   usage="Per-VLAN STP Config/TCN BPDU"),
            0x02: dict(name="Rapid-PVST+", l4="rstp_bpdu",  usage="Per-VLAN RSTP BPDU"),
        },
        fields={"Protocol ID":"2B=0","Version":"1B","BPDU Type":"1B","Flags":"1B",
                "Root BID":"8B","Path Cost":"4B","Bridge BID":"8B","Port ID":"2B",
                "Timers":"8B","VLAN TLV":"4B"},
        l4_key="pvst_version",
    ),
    "udld": dict(
        name="Cisco UDLD (SNAP PID 0x0111)",
        header_bytes=4,
        type_field="Opcode (4b) at offset 0",
        type_map={
            0x01: dict(name="Probe",  l4="udld_pdu", usage="Sends device/port ID to peer"),
            0x02: dict(name="Echo",   l4="udld_pdu", usage="Echoes neighbor list back"),
            0x03: dict(name="Flush",  l4="udld_pdu", usage="Reset UDLD state on port"),
        },
        fields={"Version":"4b=1","Opcode":"4b","Flags":"1B","Checksum":"2B","TLV chain":"Type+Len+Value"},
        l4_key="udld_opcode",
    ),
    "etherchannel": dict(
        name="EtherChannel / Port-Channel LAG (0x01FF conceptual)",
        header_bytes=0,
        type_field="Negotiated via LACP(0x8809/sub=1) or PAgP(SNAP 0x00000C/0x0104)",
        type_map={
            0x01: dict(name="LACP-Active",   l4="lacp_actor_partner", usage="Active LACP negotiation"),
            0x02: dict(name="LACP-Passive",  l4="lacp_actor_partner", usage="Passive LACP responds"),
            0x03: dict(name="PAgP-Desirable",l4="pagp_tlvs",          usage="Active PAgP negotiation"),
            0x04: dict(name="PAgP-Auto",     l4="pagp_tlvs",          usage="Passive PAgP responds"),
        },
        fields={"Protocol":"LACP(IEEE) or PAgP(Cisco)","Mode":"Active/Passive/Desirable/Auto/On"},
        l4_key="lag_mode",
    ),
}

NON_IP_L3_REGISTRY.update(CISCO_L3_REGISTRY)
# ── Fix existing L3 type_map gaps ─────────────────────────────────────────────

# EAPOL: add types 4-11 per IEEE 802.1X-2020
NON_IP_L3_REGISTRY["eapol"]["type_map"].update({
    4:  dict(name="EAPOL-Encapsulated-ASF-Alert", l4="eapol_asf",
             usage="ASF-RMCP alert encapsulated in EAPOL — IEEE 802.1X §11.12"),
    5:  dict(name="EAPOL-MKA",          l4="eapol_mka",
             usage="MACsec Key Agreement — IEEE 802.1X-2020 §11.11"),
    6:  dict(name="EAPOL-Announcement", l4="eapol_announce",
             usage="Unsolicited announcement — IEEE 802.1X-2020 §11.13"),
    7:  dict(name="EAPOL-Announcement-Req", l4="eapol_announce",
             usage="Request for announcement — IEEE 802.1X-2020"),
    8:  dict(name="EAPOL-SUPP-PDU",     l4="eapol_supp",
             usage="Supplicant pre-authentication PDU — IEEE 802.1X"),
    9:  dict(name="EAPOL-PC-Announcement", l4="eapol_announce",
             usage="Per-port channel announcement — IEEE 802.1X-2020"),
    10: dict(name="EAPOL-PC-Announcement-Req", l4="eapol_announce",
             usage="Per-port channel announcement request"),
    11: dict(name="EAPOL-Announcement-RESP",   l4="eapol_announce",
             usage="Announcement response — IEEE 802.1X-2020"),
})

# CFM: add Y.1731 opcodes that belong to 802.1ag framework
NON_IP_L3_REGISTRY["cfm"]["type_map"].update({
    37: dict(name="TST",   l4="cfm_tst",  usage="Test signal — ITU-T Y.1731 §9.5"),
    43: dict(name="APS",   l4="cfm_aps",  usage="Automatic Protection Switching — ITU-T Y.1731 §9.9"),
    44: dict(name="RAPS",  l4="cfm_raps", usage="Ring APS — ITU-T G.8032 / Y.1731"),
    45: dict(name="MCC",   l4="cfm_mcc",  usage="Maintenance Communication Channel — Y.1731"),
    48: dict(name="1DM",   l4="cfm_dm",   usage="One-way Delay Measurement — ITU-T Y.1731 §8.2"),
})

# MAC Control: add remaining EPON MPCP types per IEEE 802.3av
NON_IP_L3_REGISTRY["mac_ctrl"]["type_map"].update({
    4: dict(name="EPON-RegisterReq",  l4="mac_ctrl_epon",
            usage="MPCP Register Request — ONU requests registration with OLT"),
    5: dict(name="EPON-Register",     l4="mac_ctrl_epon",
            usage="MPCP Register — OLT grants LLID to ONU"),
    6: dict(name="EPON-RegisterAck",  l4="mac_ctrl_epon",
            usage="MPCP Register Ack — ONU acknowledges registration"),
})

# PTP: add Pdelay_Resp_Follow_Up
NON_IP_L3_REGISTRY["ptp"]["type_map"][10] = dict(
    name="Pdelay_Resp_Follow_Up", l4="ptp_msg",
    usage="Peer delay response follow-up — IEEE 1588-2019 §11.4.3"
)

# AVTP: add IEEE 1722-2016 additional subtypes
NON_IP_L3_REGISTRY["avtp"]["type_map"].update({
    1:   dict(name="MMA-Stream",  l4="avtp_mma",   usage="MIDI-over-AVB stream — IEEE 1722-2016 §9.5"),
    5:   dict(name="NTSCF",       l4="avtp_ntscf",  usage="Non-Time-Sensitive Control Format — IEEE 1722-2016 §9.6"),
    106: dict(name="TSCF",        l4="avtp_tscf",   usage="Time-Sensitive Control Format — IEEE 1722-2016 §9.7"),
})

# Y.1731: add TST (test signal) opcode 37
NON_IP_L3_REGISTRY["y1731"]["type_map"][37] = dict(
    name="TST", l4="cfm_tst",
    usage="Test Signal — ITU-T Y.1731 §9.5 in-service BER/frame-loss test"
)




def get_non_ip_l3_info(l3_class: str) -> dict:
    """Return non-IP L3 protocol registry entry."""
    return NON_IP_L3_REGISTRY.get(l3_class, {})


def non_ip_l3_to_l4(l3_class: str, type_val: int) -> dict:
    """
    Given a non-IP L3 class and its type/packet-type field value,
    return the L4 dispatch info.
    """
    entry = NON_IP_L3_REGISTRY.get(l3_class, {})
    if not entry:
        return dict(l4=None, name="Unknown", usage="Unknown L3 class")
    type_map = entry.get("type_map", {})
    hit = type_map.get(type_val)
    if hit:
        return hit
    return dict(l4="raw", name=f"Type-{type_val}", usage="Unknown type value — raw payload")


def process_l3_non_ip(l2_data: dict, type_val: int | None = None) -> dict:
    """
    Dispatch for non-IP L3 protocols (XNS/IDP, IPX, DDP, VIP, DECnet, LAT, SNA).
    """
    l3_class = l2_data.get("next_layer", "")
    entry    = NON_IP_L3_REGISTRY.get(l3_class, {})

    l4_info  = non_ip_l3_to_l4(l3_class, type_val) if type_val is not None else {}
    next_l4  = l4_info.get("l4")

    return dict(
        l3_class     = l3_class,
        l3_name      = entry.get("name", l3_class),
        header_bytes = entry.get("header_bytes", "unknown"),
        type_field   = entry.get("type_field", ""),
        type_val     = type_val,
        l4_dispatch  = l4_info,
        next_layer   = next_l4,
        fields       = entry.get("fields", {}),
        has_l4       = next_l4 is not None,
        l2_context   = l2_data,
    )
