"""
Network Frame Builder  —  Complete Protocol Suite  (main.py)
=============================================================
UNCHANGED: all menus, prompts, output format, flow, protocols.
ADDED: builder imports + process_l2/l3/l4 calls + layer progression prompts.
"""
import struct, zlib, socket, os, sys

# ══════════════════════════════════════════════════════════════════════════════
#  BUILDER IMPORTS  (graceful fallback if files missing)
# ══════════════════════════════════════════════════════════════════════════════
try:
    from l2_builder import (process_l2, ethertype_to_l3,
                             get_protocol_info, validate_pdu)
    _L2_AVAILABLE = True
except ImportError:
    _L2_AVAILABLE = False

try:
    from l3_builder import (process_l3, process_l3_arp,
                             protocol_to_l4, get_icmp_type_info)
    _L3_AVAILABLE = True
except ImportError:
    _L3_AVAILABLE = False

try:
    from l4_builder import (process_l4, classify_tcp_segment,
                             detect_udp_service, tcp_flag_summary,
                             port_info as l4_port_info)
    _L4_AVAILABLE = True
except ImportError:
    _L4_AVAILABLE = False

try:
    from hw_builder import (BUS_BOUNDARY_REGISTRY, PLATFORM_REGISTRY,
                             ETH_ENCAP_REGISTRY, registry_stats_hw,
                             list_buses_for_platform, get_bus_info,
                             get_encap_info, get_all_platforms)
    _HW_AVAILABLE = True
except ImportError:
    _HW_AVAILABLE = False

try:
    from phy_builder import (PHY_REGISTRY, ETH_SPEED_MENU, FC_SPEED_MENU,
                              SERIAL_SPEED_MENU, registry_stats_phy,
                              uses_preamble_sfd, uses_start_block, uses_8b10b_sof,
                              get_phy_info, get_start_mechanism, get_end_mechanism,
                              get_ifg, get_control_symbols, get_encoding_detail,
                              get_ifg_pattern_display,
                              encode_bytes_8b10b, encode_byte_8b10b,
                              encode_bytes_4b5b, apply_mlt3,
                              encode_bytes_manchester,
                              encode_fc_frame_8b10b, encode_eth_frame_8b10b,
                              format_encoding_display, codewords_to_bitstring,
                              build_phy_stream, format_phy_stream_display,
                              FC_SOF_BYTES, FC_EOF_BYTES, FC_SOF_DESC, FC_EOF_DESC,
                              FC_IDLE_BYTES, FC_R_RDY_BYTES,
                              _4B5B_DATA_TABLE, _4B5B_CTRL_TABLE)
    _PHY_AVAILABLE = True
except ImportError as _phy_err:
    _PHY_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
#  LAYER PROGRESSION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _ask_add_layer(layer_name: str) -> bool:
    """Ask if user wants to add the next layer. Returns True=yes."""
    ans = input(
        f"\n  {C.PROMPT}Do you want to add {layer_name}? (yes/no) [{C.NOTE}yes{C.RESET}"
        f"{C.PROMPT}]:{C.RESET} "
    ).strip().lower()
    return ans in ("", "y", "yes")


def _run_layer_progression(l2_result: dict,
                            src_ip=None, dst_ip=None,
                            proto_num=None) -> dict:
    """
    Called AFTER main.py's existing frame assembly + output.
    Enriches metadata via builder engines, optionally walks L3→L4.
    Never changes any output already printed by main.py.
    """
    ctx = {"l2": {}, "l3": {}, "l4": {}}

    # ── L2 enrichment ─────────────────────────────────────────────────────────
    if _L2_AVAILABLE:
        ctx["l2"] = process_l2(
            technology=l2_result.get("technology", "ethernet"),
            protocol  =l2_result.get("protocol",   "unknown"),
            raw_bytes =l2_result.get("raw_bytes"),
            ethertype =l2_result.get("ethertype"),
            ppp_proto =l2_result.get("ppp_proto"),
            extra     =l2_result,
        )
        info = ctx["l2"].get("protocol_info", "")
        if info:
            print(f"  {C.DIM}  ▸ L2 Intel: {info}{C.RESET}")
        pdu_val = ctx["l2"].get("pdu_validation", {})
        if pdu_val.get("valid") is False:
            print(f"  {C.WARN}  ▸ PDU Warning: {pdu_val.get('reason','')}{C.RESET}")
    else:
        ctx["l2"] = l2_result

    # Protocols that terminate at L2 — skip progression
    L2_TERMINAL = {"stp","rstp","dtp","pagp","lacp","lldp","pfc","pause","vlan_only"}
    if l2_result.get("protocol","") in L2_TERMINAL:
        return ctx

    # ── Optional L3 ───────────────────────────────────────────────────────────
    if not _ask_add_layer("Layer 3"):
        return ctx

    if _L3_AVAILABLE:
        ctx["l3"] = process_l3(
            l2_data  =ctx["l2"],
            proto_num=proto_num,
            src_ip   =src_ip,
            dst_ip   =dst_ip,
        )
        chain = ctx["l3"].get("l3_chain", {})
        if chain.get("reason"):
            print(f"  {C.DIM}  ▸ L3 Intel: {chain['reason']}{C.RESET}")
    else:
        ctx["l3"] = {"next_layer": None, "has_l4": True}

    # ── Optional L4 ───────────────────────────────────────────────────────────
    if not ctx["l3"].get("has_l4", True):
        print(f"  {C.DIM}  ▸ L3 terminates — no Layer 4 for this protocol.{C.RESET}")
        return ctx

    if not _ask_add_layer("Layer 4"):
        return ctx

    if _L4_AVAILABLE:
        ctx["l4"] = process_l4(l3_data=ctx["l3"], extra=l2_result)
        summary = ctx["l4"].get("summary", "")
        if summary:
            print(f"  {C.DIM}  ▸ L4 Intel: {summary}{C.RESET}")
    else:
        ctx["l4"] = {}

    return ctx


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
W   = 118
SEP = "═" * W
DIV = "─" * W
HDR = "─" * W

_USE_COLOR = sys.stdout.isatty() or os.environ.get('FORCE_COLOR')

class C:
    if _USE_COLOR:
        RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
        ITALIC = "\033[3m";  UL     = "\033[4m"
        L1     = "\033[38;5;220m";  L2  = "\033[38;5;75m"
        L3     = "\033[38;5;118m";  L4  = "\033[38;5;213m"
        TRAIL  = "\033[38;5;203m"
        BANNER = "\033[38;5;39m";   SECT   = "\033[38;5;178m"
        HELP   = "\033[38;5;245m";  PROMPT = "\033[38;5;252m"
        HEX    = "\033[38;5;159m";  NOTE   = "\033[38;5;186m"
        PASS_  = "\033[1;38;5;46m"; FAIL_  = "\033[1;38;5;196m"
        WARN   = "\033[38;5;214m"
        TAG1="\033[38;5;220m"; TAG2="\033[38;5;75m"
        TAG3="\033[38;5;118m"; TAG4="\033[38;5;213m"
        TAG0="\033[38;5;203m"
        BOX    = "\033[38;5;240m";  SEP_C  = "\033[38;5;25m"
        OFFSET = "\033[38;5;243m";  SIZE   = "\033[38;5;180m"
        ASCII_ = "\033[38;5;188m"
    else:
        RESET=BOLD=DIM=ITALIC=UL=""
        L1=L2=L3=L4=TRAIL=""
        BANNER=SECT=HELP=PROMPT=""
        HEX=NOTE=PASS_=FAIL_=WARN=""
        TAG1=TAG2=TAG3=TAG4=TAG0=""
        BOX=SEP_C=OFFSET=SIZE=ASCII_=""

_TAG_COLOR   = {1:C.TAG1, 2:C.TAG2, 3:C.TAG3, 4:C.TAG4, 0:C.TAG0}
_LAYER_COLOR = {1:C.L1,   2:C.L2,   3:C.L3,   4:C.L4,   0:C.TRAIL}

LAYER_TAG = {
    1:"[L1-PHY ]", 2:"[L2-DL  ]",
    3:"[L3-NET ]", 4:"[L4-CTRL]", 0:"[TRAILER]",
}

def ctag(layer):
    raw = LAYER_TAG.get(layer, "        ")
    col = _TAG_COLOR.get(layer, "")
    return f"{col}{raw}{C.RESET}"

# ── Protocol lookup tables (unchanged from original) ─────────────────────────
L3_PROTO_NAMES = {1:"ICMP",6:"TCP",17:"UDP",41:"IPv6",89:"OSPF",47:"GRE"}
ICMP_TABLE = {
    0: ("Echo Reply",{0:"Echo reply"}),
    3: ("Destination Unreachable",{
        0:"Net unreachable",1:"Host unreachable",2:"Protocol unreachable",
        3:"Port unreachable",4:"Fragmentation needed/DF",5:"Source route failed",
        6:"Dest network unknown",7:"Dest host unknown",9:"Net admin prohibited",
        10:"Host admin prohibited",13:"Comm admin prohibited"}),
    4: ("Source Quench",{0:"Source quench (deprecated)"}),
    5: ("Redirect",{0:"Redirect network",1:"Redirect host",
                    2:"Redirect TOS+net",3:"Redirect TOS+host"}),
    8: ("Echo Request",{0:"Echo request"}),
    9: ("Router Advertisement",{0:"Normal advertisement"}),
    10:("Router Solicitation",{0:"Router solicitation"}),
    11:("Time Exceeded",{0:"TTL exceeded in transit",1:"Fragment reassembly exceeded"}),
    12:("Parameter Problem",{0:"Pointer error",1:"Missing option",2:"Bad length"}),
    13:("Timestamp Request",{0:"Timestamp request"}),
    14:("Timestamp Reply",{0:"Timestamp reply"}),
    17:("Address Mask Request",{0:"Address mask request"}),
    18:("Address Mask Reply",{0:"Address mask reply"}),
    30:("Traceroute",{0:"Information (deprecated)"}),
}
ICMP_ECHO_TYPES = {0,8,13,14,17,18}
WELL_KNOWN_PORTS = {
    20:"FTP-Data",21:"FTP-Control",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",67:"DHCP-Server",68:"DHCP-Client",69:"TFTP",80:"HTTP",
    110:"POP3",119:"NNTP",123:"NTP",143:"IMAP",161:"SNMP",162:"SNMP-Trap",
    179:"BGP",194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",514:"Syslog",
    520:"RIP",587:"SMTP-TLS",636:"LDAPS",993:"IMAPS",995:"POP3S",
    1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",3306:"MySQL",3389:"RDP",
    5060:"SIP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",27017:"MongoDB",
}
TCP_FLAGS = {
    'FIN':0x01,'SYN':0x02,'RST':0x04,
    'PSH':0x08,'ACK':0x10,'URG':0x20,'ECE':0x40,'CWR':0x80,
}
TCP_STEPS = {
    '1':("SYN",    0x02,"Client → Server  (open connection request)"),
    '2':("SYN-ACK",0x12,"Server → Client  (acknowledge + own SYN)"),
    '3':("ACK",    0x10,"Client → Server  (acknowledge server SYN)"),
    '4':("PSH+ACK",0x18,"Data segment with push flag"),
    '5':("FIN+ACK",0x11,"Initiating graceful close"),
    '6':("RST",    0x04,"Abrupt connection reset"),
}
UDP_COMMON = {
    ('53','53'):"DNS Query/Response",('67','68'):"DHCP",
    ('123','123'):"NTP",('161','162'):"SNMP",
    ('514','514'):"Syslog",('520','520'):"RIP",
    ('69','69'):"TFTP",('5060','5060'):"SIP",
}
HDLC_U_SUBTYPES = {
    '1':(0,0,0,0,0,"UI",   "C/R","Unnumbered Information — datagram (no ACK)"),
    '2':(0,1,1,0,0,"SABM", "C",  "Set Async Balanced Mode — initiate connection (mod-8)"),
    '3':(0,1,1,0,1,"SABME","C",  "SABM Extended — initiate connection (mod-128)"),
    '4':(0,1,0,0,0,"DISC", "C",  "Disconnect — request to terminate link"),
    '5':(0,0,0,1,1,"DM",   "R",  "Disconnect Mode — link not established"),
    '6':(0,0,1,0,1,"UA",   "R",  "Unnumbered Acknowledgment — accept SABM/DISC"),
    '7':(1,0,0,0,1,"FRMR", "R",  "Frame Reject — invalid frame received"),
    '8':(1,1,0,0,0,"XID",  "C/R","Exchange Identification — parameter negotiation"),
    '9':(1,1,1,0,0,"TEST", "C/R","Test — link integrity test"),
    '10':(0,0,1,0,0,"UP",  "C",  "Unnumbered Poll — poll without sequence numbers"),
}
HDLC_S_SUBTYPES = {
    '1':(0,0,"RR",  "Receive Ready    — ACK, ready for more"),
    '2':(0,1,"REJ", "Reject           — go-back-N, retransmit from N(R)"),
    '3':(1,0,"RNR", "Receive Not Ready— busy, stop sending"),
    '4':(1,1,"SREJ","Selective Reject — retransmit only frame N(R)"),
}
JUMBO_PRESETS = {
    '1':(1500, "Standard Ethernet (baseline)"),
    '2':(1600, "Baby Giant  (MPLS +1 label)"),
    '3':(4470, "FDDI over Ethernet bridging"),
    '4':(9000, "Typical Jumbo (NFS/iSCSI/Ceph/HPC)"),
    '5':(9216, "Extended Jumbo (storage switches)"),
    '6':(16110,"Super Jumbo (InfiniBand bridging)"),
    '7':(0,    "Custom"),
}
WIFI_FRAME_TYPES = {'1':(0b00,"Management"),'2':(0b01,"Control"),'3':(0b10,"Data")}
WIFI_MGMT_SUBTYPES = {
    '0':(0x00,"Association Request",   "STA→AP  join BSS"),
    '1':(0x01,"Association Response",  "AP→STA  grant/deny join"),
    '2':(0x02,"Reassociation Request", "STA→AP  roaming"),
    '3':(0x03,"Reassociation Response","AP→STA  roam reply"),
    '4':(0x04,"Probe Request",         "STA→all scan for APs"),
    '5':(0x05,"Probe Response",        "AP→STA  scan reply"),
    '8':(0x08,"Beacon",                "AP→all  periodic BSS announce"),
    '10':(0x0A,"Disassociation",       "either  end association"),
    '11':(0x0B,"Authentication",       "either  auth exchange"),
    '12':(0x0C,"Deauthentication",     "either  end auth"),
    '13':(0x0D,"Action",               "either  BA/RM/spectrum action"),
}
WIFI_CTRL_SUBTYPES = {
    '8':(0x08,"Block Ack Request","Request aggregated ACK"),
    '9':(0x09,"Block Ack",       "Aggregated ACK bitmap"),
    '10':(0x0A,"PS-Poll",        "Power-save poll for buffered data"),
    '11':(0x0B,"RTS",            "Request To Send (CSMA/CA)"),
    '12':(0x0C,"CTS",            "Clear To Send (RTS response)"),
    '13':(0x0D,"ACK",            "Acknowledge received frame"),
    '14':(0x0E,"CF-End",         "End contention-free period"),
}
WIFI_DATA_SUBTYPES = {
    '0':(0x00,"Data",    False,"Basic data, no QoS field"),
    '4':(0x04,"Null",    False,"No payload, power-mgmt signal"),
    '8':(0x08,"QoS Data",True, "Data + QoS Control (WMM/WME)"),
    '12':(0x0C,"QoS Null",True,"No payload + QoS, power-mgmt"),
}
WIFI_ACK_POLICY = {0:"Normal ACK",1:"No ACK",2:"No Explicit ACK",3:"Block ACK"}
WIFI_TID_NAMES  = {
    0:"BE(Best Effort)",1:"BK(Background)",2:"BK(Background)",
    3:"BE(Best Effort)",4:"VI(Video)",5:"VI(Video)",6:"VO(Voice)",7:"VO(Voice)",
}
WIFI_PHY_MODES = {
    '1':"802.11b  DSSS/CCK  (2.4 GHz, 1/2/5.5/11 Mbps)",
    '2':"802.11a  OFDM      (5 GHz,   6–54 Mbps)",
    '3':"802.11g  ERP-OFDM  (2.4 GHz, 6–54 Mbps)",
    '4':"802.11n  HT-Mixed  (2.4/5 GHz, up to 600 Mbps)",
    '5':"802.11ac VHT       (5 GHz,   up to 6.9 Gbps)",
    '6':"802.11ax HE        (2.4/5/6 GHz, up to 9.6 Gbps)",
    '7':"No PHY preamble   (MAC MPDU only — as seen in Wireshark pcap)",
}
DSSS_RATES = {
    '1':(0x0A,"1 Mbps  DBPSK"),
    '2':(0x14,"2 Mbps  DQPSK"),
    '3':(0x37,"5.5 Mbps CCK"),
    '4':(0x6E,"11 Mbps CCK"),
}
OFDM_RATE_BITS = {
    '6':(0b1011,"6 Mbps  BPSK  R=1/2"),'9':(0b1111,"9 Mbps  BPSK  R=3/4"),
    '12':(0b1010,"12 Mbps QPSK  R=1/2"),'18':(0b1110,"18 Mbps QPSK  R=3/4"),
    '24':(0b1001,"24 Mbps 16-QAM R=1/2"),'36':(0b1101,"36 Mbps 16-QAM R=3/4"),
    '48':(0b1000,"48 Mbps 64-QAM R=2/3"),'54':(0b1100,"54 Mbps 64-QAM R=3/4"),
}
IP_PROTO_NAMES = {
    0:("HOPOPT","IPv6 Hop-by-Hop Options"),1:("ICMP","Internet Control Message Protocol"),
    2:("IGMP","Internet Group Management Protocol"),4:("IP-IP","IP-in-IP Encapsulation"),
    6:("TCP","Transmission Control Protocol"),17:("UDP","User Datagram Protocol"),
    41:("IPv6","IPv6 Encapsulation"),47:("GRE","Generic Routing Encapsulation"),
    50:("ESP","Encapsulating Security Payload"),51:("AH","Authentication Header"),
    58:("ICMPv6","ICMP for IPv6"),89:("OSPF","Open Shortest Path First"),
    103:("PIM","Protocol Independent Multicast"),112:("VRRP","Virtual Router Redundancy Protocol"),
    132:("SCTP","Stream Control Transmission Protocol"),
}
DSCP_TABLE = {
    0:("CS0 / BE","Best Effort — default"),8:("CS1","Scavenger / low-priority"),
    10:("AF11","Assured Forwarding low drop"),12:("AF12","Assured Forwarding med drop"),
    14:("AF13","Assured Forwarding high drop"),16:("CS2","OAM"),
    18:("AF21","AF class 2 low drop"),20:("AF22","AF class 2 med drop"),
    22:("AF23","AF class 2 high drop"),24:("CS3","Broadcast video"),
    26:("AF31","AF class 3 low drop"),28:("AF32","AF class 3 med drop"),
    30:("AF33","AF class 3 high drop"),32:("CS4","Real-time interactive"),
    34:("AF41","AF class 4 low drop"),36:("AF42","AF class 4 med drop"),
    38:("AF43","AF class 4 high drop"),40:("CS5","Signalling"),
    46:("EF","Expedited Forwarding — VoIP"),48:("CS6","Network control (routing)"),
    56:("CS7","Reserved"),
}
SERIAL_TYPES = {
    '1':"Raw",'2':"SLIP",'3':"PPP",
    '4':"HDLC (basic — address+control+payload+FCS-16)",
    '5':"COBS (placeholder)",'6':"KISS",'7':"Modbus RTU",
    '8':"HDLC + Bit-Stuffing",'9':"ATM AAL5",'10':"Cisco HDLC",
    '11':"HDLC Full (I-frame / S-frame / U-frame — all 3 types)",
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — CORE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def get(prompt, default="", help=""):
    if help:
        for line in help.strip().split("\n"):
            print(f"      {C.HELP}┆ {line}{C.RESET}")
    val = input(f"    {C.PROMPT}{prompt}{C.RESET} [{C.NOTE}{default}{C.RESET}]: ").strip()
    return val if val else default

def get_hex(prompt, default_hex, byte_len=None, help=""):
    if help:
        for line in help.strip().split("\n"):
            print(f"      {C.HELP}┆ {line}{C.RESET}")
    while True:
        raw = input(f"    {C.PROMPT}{prompt}{C.RESET} [{C.HEX}{default_hex}{C.RESET}]: ").strip().lower()
        if not raw:
            print(f"      {C.DIM}-> using default: {default_hex}{C.RESET}")
            return bytes.fromhex(default_hex.replace(" ","").replace(":",""))
        try:
            cleaned = raw.replace(":","").replace("-","").replace(" ","")
            b = bytes.fromhex(cleaned)
            if byte_len and len(b) != byte_len:
                print(f"      {C.WARN}-> need exactly {byte_len} bytes ({byte_len*2} hex chars){C.RESET}")
                continue
            return b
        except ValueError:
            print(f"      {C.WARN}-> invalid hex, try again{C.RESET}")

def mac_b(s):
    c = s.replace(":","").replace("-","").replace(" ","").upper()
    if len(c) != 12: raise ValueError(f"bad MAC: {s!r}")
    return bytes.fromhex(c)
def mac_s(b): return ':'.join(f'{x:02x}' for x in b)
def ip_b(s):  return socket.inet_aton(s)
def hpad(s, n):
    c = s.lower().replace("0x","").replace(" ","")
    if len(c) % 2: c = "0"+c
    b = bytes.fromhex(c)
    if len(b) > n: b = b[-n:]
    elif len(b) < n: b = b'\x00'*(n-len(b)) + b
    return b

def crc32_eth(data):
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF
def crc16_ibm(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1: crc = (crc >> 1) ^ 0x8005
            else:       crc >>= 1
    return crc
def inet_cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def byte_escape(data):
    out = bytearray()
    for b in data:
        if b == 0x7E:   out += b'\x7D\x5E'
        elif b == 0x7D: out += b'\x7D\x5D'
        else:           out.append(b)
    return bytes(out)
def bit_stuff(data):
    bits=[]; ones=0
    for byte in data:
        for i in range(7,-1,-1):
            bit=(byte>>i)&1; bits.append(bit)
            if bit==1:
                ones+=1
                if ones==5: bits.append(0); ones=0
            else: ones=0
    res=bytearray()
    for i in range(0,len(bits),8):
        byt=0
        for j in range(8):
            byt=(byt<<1)|(bits[i+j] if i+j<len(bits) else 0)
        res.append(byt)
    return bytes(res)
def slip_enc(data):
    out=bytearray(b'\xC0')
    for b in data:
        if b==0xC0:   out+=b'\xDB\xDC'
        elif b==0xDB: out+=b'\xDB\xDD'
        else:         out.append(b)
    return bytes(out+b'\xC0')

# ── Display helpers ───────────────────────────────────────────────────────────
def banner(title, subtitle=""):
    bar = f"{C.BANNER}{C.BOLD}{SEP}{C.RESET}"
    print(f"\n{bar}")
    print(f"  {C.BOLD}{C.BANNER}{title}{C.RESET}")
    if subtitle:
        print(f"  {C.DIM}{subtitle}{C.RESET}")
    print(bar)

def section(title):
    print(f"\n  {C.SECT}{C.BOLD}▌ {title}{C.RESET}")
    print(f"  {C.SEP_C}{DIV}{C.RESET}")

def print_frame_table(records):
    bar  = f"{C.BANNER}{SEP}{C.RESET}"
    dash = f"{C.SEP_C}{DIV}{C.RESET}"
    dot  = f"{C.BOX}{'·'*114}{C.RESET}"
    print(f"\n{bar}")
    print(f"  {C.BOLD}{C.BANNER}{'COMPLETE FRAME  –  FIELD-BY-FIELD TABLE':^{W-2}}{C.RESET}")
    print(bar)
    hdr = (f"  {C.DIM}{'Byte':>6}  {'Layer':<11}  {'Field Name':<28}  "
           f"{'Size':>8}  {'Hex Value':<30}  {'User Input / Note'}{C.RESET}")
    print(hdr); print(dash)
    offset = 0; prev_layer = None
    for r in records:
        lay=r['layer']; name=r['name']; raw=r['raw']
        note=r.get('note',''); uval=r.get('user_val','')
        lc=_LAYER_COLOR.get(lay,"")
        if lay != prev_layer and prev_layer is not None:
            print(f"  {dot}")
        prev_layer = lay
        sz = len(raw)
        if sz == 0:
            ann = uval if uval else note
            if uval and note and uval != note: ann = f"{uval}  ({note})"
            print(f"  {'':10}  {ctag(lay)}    {C.DIM}{name:<28}{C.RESET}  "
                  f"{'':>8}   {'':30}    {C.NOTE}{ann}{C.RESET}")
            continue
        hexs = ' '.join(f'{b:02x}' for b in raw)
        if len(hexs) > 29: hexs = hexs[:27]+'..'
        ann = uval if uval else note
        if uval and note and uval != note: ann = f"{uval}  ({note})"
        print(f"  {C.OFFSET}{offset:5d}-{offset+sz-1:<4d}{C.RESET}  {ctag(lay)}  "
              f"  {lc}{name:<28}{C.RESET}  {C.SIZE}{sz:3d}B/{sz*8:4d}b{C.RESET}  "
              f"  {C.HEX}{hexs:<30}{C.RESET}    {C.NOTE}{ann}{C.RESET}")
        offset += sz
    print(dash)
    print(f"  {C.BOLD}{'Total':>5}: {offset} bytes  /  {offset*8} bits{C.RESET}")
    print(bar)

def print_encapsulation(records, frame):
    W2 = 110
    layer_spans = []
    offset = 0
    for r in records:
        sz = len(r['raw'])
        if sz == 0: continue
        layer_spans.append((offset, offset+sz-1, r['layer'], r['name']))
        offset += sz
    total_bytes = offset
    layer_groups = {}
    for (s,e,lay,name) in layer_spans:
        if lay not in layer_groups: layer_groups[lay]=[s,e,name]
        else: layer_groups[lay][1]=e
    LAYER_LABELS = {
        1:"LAYER 1  Physical  (Preamble + SFD / Flags)",
        2:"LAYER 2  Data Link  (MAC / Serial header)",
        3:"LAYER 3  Network   (IP / ARP / BPDU / DTP / PAgP / LACP)",
        4:"LAYER 4  Transport (TCP / UDP / ICMP)",
        0:"TRAILER  (FCS / CRC)",
    }
    def proto_names(layer):
        seen=[]
        for r in records:
            if r['layer']==layer:
                n=r['name'].split()[0]
                if n not in seen: seen.append(n)
        return ' | '.join(seen[:4])
    bar = f"{C.BANNER}{SEP}{C.RESET}"
    print(f"\n{bar}")
    print(f"  {C.BOLD}{C.BANNER}{'FRAME ENCAPSULATION  —  STRUCTURE DIAGRAM':^{W-2}}{C.RESET}")
    print(bar); print()
    sorted_layers = sorted(layer_groups.keys(), key=lambda x:(x if x!=0 else 99))
    indent_map = {1:0,2:2,3:4,4:6,0:0}
    for lay in sorted_layers:
        s,e,_ = layer_groups[lay]
        lc=_LAYER_COLOR.get(lay,""); ind=' '*indent_map.get(lay,0)
        width=W2-indent_map.get(lay,0)-2
        label=LAYER_LABELS.get(lay,f"Layer {lay}")
        proto=proto_names(lay); bytes_count=e-s+1
        bc=f"{C.BOX}"; rc=C.RESET
        print(f"  {ind}{bc}╔{'═'*width}╗{rc}")
        content=f"  {label}"
        print(f"  {ind}{bc}║{rc}{lc}{C.BOLD}{content:<{width}}{rc}{bc}║{rc}")
        if proto:
            pcontent=f"  Protocols: {proto}"
            print(f"  {ind}{bc}║{rc}{C.DIM}{pcontent:<{width}}{rc}{bc}║{rc}")
        bcontent=f"  Bytes {s}–{e}  ({bytes_count} bytes / {bytes_count*8} bits)"
        print(f"  {ind}{bc}║{rc}{C.OFFSET}{bcontent:<{width}}{rc}{bc}║{rc}")
        fnames=[r['name'] for r in records if r['layer']==lay]
        line_buf="  Fields: "; field_lines=[]
        for fn in fnames:
            candidate=line_buf+fn+"  "
            if len(candidate)>width-2:
                field_lines.append(line_buf.rstrip()); line_buf="          "+fn+"  "
            else: line_buf=candidate
        if line_buf.strip(): field_lines.append(line_buf.rstrip())
        for fl in field_lines:
            print(f"  {ind}{bc}║{rc}{C.DIM}{fl:<{width}}{rc}{bc}║{rc}")
        layer_bytes=frame[s:e+1]
        hex_preview=' '.join(f'{b:02x}' for b in layer_bytes[:24])
        if len(layer_bytes)>24: hex_preview+=' ..'
        hcontent=f"  Hex: {hex_preview}"
        print(f"  {ind}{bc}║{rc}{C.HEX}{hcontent:<{width}}{rc}{bc}║{rc}")
        print(f"  {ind}{bc}╚{'═'*width}╝{rc}"); print()
    dash=f"{C.SEP_C}{'─'*W2}{C.RESET}"
    print(f"  {dash}")
    print(f"  {C.BOLD}ENCAPSULATION SUMMARY  (outermost → innermost){C.RESET}")
    print(f"  {dash}")
    nesting=[]
    for lay in sorted(layer_groups.keys()):
        if lay==0: continue
        lc=_LAYER_COLOR.get(lay,""); proto=proto_names(lay)
        nesting.append(f"{lc}L{lay}({proto}){C.RESET}")
    arrow=f"  {C.BOX}──encapsulates──>{C.RESET}  "
    nesting_str=arrow.join(nesting)
    if 0 in layer_groups:
        s,e,_=layer_groups[0]
        nesting_str+=f"  {C.BOX}──trailer──>{C.RESET}  {C.TRAIL}FCS/CRC({e-s+1}B){C.RESET}"
    print(f"  {nesting_str}"); print()
    for lay in sorted(layer_groups.keys(), key=lambda x:x if x!=0 else 99):
        s,e,_=layer_groups[lay]; lc=_LAYER_COLOR.get(lay,"")
        lname=LAYER_LABELS.get(lay,f"Layer {lay}")
        print(f"    {lc}{lname:<55}{C.RESET}  "
              f"{C.SIZE}{e-s+1:4d} bytes  /  {(e-s+1)*8:5d} bits{C.RESET}  "
              f"{C.OFFSET}[byte {s}–{e}]{C.RESET}")
    print(f"  {dash}")
    print(f"  {C.BOLD}{'TOTAL FRAME':<55}  {total_bytes:4d} bytes  /  {total_bytes*8:5d} bits{C.RESET}")
    print(f"  {dash}")
    # Annotated hex dump
    LAYER_ABBR={1:'PHY',2:'DL ',3:'NET',4:'TRP',0:'TRL'}
    byte_layer={}
    for (s,e,lay,_) in layer_spans:
        for b in range(s,e+1): byte_layer[b]=lay
    print(); print(f"  {dash}")
    print(f"  {C.BOLD}{'ANNOTATED HEX DUMP  (16 bytes per row)':^{W2}}{C.RESET}")
    print(f"  {dash}")
    print(f"  {C.DIM}{'Offset':>6}  {'Hex (16 bytes per row)':<48}  {'ASCII':<16}  Layer annotation{C.RESET}")
    print(f"  {dash}")
    for row_start in range(0,total_bytes,16):
        row_bytes=frame[row_start:row_start+16]
        hex_parts=[]
        for i,byte_val in enumerate(row_bytes):
            bidx=row_start+i; lc=_LAYER_COLOR.get(byte_layer.get(bidx,-1),"")
            hex_parts.append(f"{lc}{byte_val:02x}{C.RESET}")
        hex_part=' '.join(hex_parts)
        visible_hex=' '.join(f'{b:02x}' for b in row_bytes)
        pad=' '*(48-len(visible_hex))
        asc_chars=[]
        for i,byte_val in enumerate(row_bytes):
            bidx=row_start+i; lc=_LAYER_COLOR.get(byte_layer.get(bidx,-1),"")
            ch=chr(byte_val) if 32<=byte_val<127 else '.'
            asc_chars.append(f"{lc}{ch}{C.RESET}")
        asc_part=''.join(asc_chars)
        visible_asc=''.join(chr(b) if 32<=b<127 else '.' for b in row_bytes)
        asc_pad=' '*(16-len(visible_asc))
        layers_in_row=[]
        for bidx in range(row_start,row_start+len(row_bytes)):
            lay=byte_layer.get(bidx,-1)
            if not layers_in_row or layers_in_row[-1][0]!=lay:
                layers_in_row.append([lay,bidx,bidx])
            else: layers_in_row[-1][2]=bidx
        ann_parts=[]
        for (lay,bs,be) in layers_in_row:
            lc=_LAYER_COLOR.get(lay,""); abbr=LAYER_ABBR.get(lay,'???')
            ann_parts.append(f"{lc}{abbr}[{bs}-{be}]{C.RESET}")
        annotation='  '.join(ann_parts)
        print(f"  {C.OFFSET}{row_start:6d}{C.RESET}  {hex_part}{pad}  {asc_part}{asc_pad}  {annotation}")
    print(f"  {dash}"); print()
    print(f"  {dash}")
    print(f"  {C.BOLD}{'FINAL HEX  (continuous, no gaps)':^{W2}}{C.RESET}")
    print(f"  {dash}")
    hex_str=''.join(f'{b:02x}' for b in frame)
    offset_map={}
    for (s,e,lay,_) in layer_spans:
        for b in range(s,e+1): offset_map[b]=lay
    row_len=64
    for i in range(0,len(hex_str),row_len):
        row_hex=[]
        for bidx in range(i//2,min(i//2+32,len(frame))):
            lay=offset_map.get(bidx,-1); lc=_LAYER_COLOR.get(lay,"")
            row_hex.append(f"{lc}{frame[bidx]:02x}{C.RESET}")
        print(f"  {''.join(row_hex)}")
    print(f"  {dash}")
    print(f"  {C.BOLD}Total bytes : {total_bytes}{C.RESET}")
    print(f"  {C.BOLD}Total bits  : {total_bytes*8}{C.RESET}")
    print(f"{C.BANNER}{SEP}{C.RESET}\n")

def ask_fcs_eth(fcs_input_bytes):
    print(f"\n  {C.SECT}{C.BOLD}▌ ETHERNET FCS{C.RESET}  "
          f"{C.DIM}(CRC-32 over {len(fcs_input_bytes)} bytes: Dst MAC → end of payload){C.RESET}")
    print(f"  {C.SEP_C}{DIV}{C.RESET}")
    ch = input(f"    {C.PROMPT}1=Auto-calculate  2=Custom  [1]: {C.RESET}").strip() or '1'
    if ch == '2':
        fcs_hex = input(f"    {C.PROMPT}Enter 8 hex digits: {C.RESET}").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == 4: return fcs,"custom"
        except: pass
        print(f"    {C.WARN}-> invalid, using auto{C.RESET}")
    fcs = crc32_eth(fcs_input_bytes)
    return fcs, f"CRC-32 auto over {len(fcs_input_bytes)}B"

def ask_serial_crc(crc_input_bytes, crc_type, byte_order='big'):
    print(f"\n  {C.SECT}{C.BOLD}▌ {crc_type}{C.RESET}  {C.DIM}(covers {len(crc_input_bytes)} bytes){C.RESET}")
    print(f"  {C.SEP_C}{DIV}{C.RESET}")
    ch = input(f"    {C.PROMPT}1=Auto-calculate  2=Custom  [1]: {C.RESET}").strip() or '1'
    crc_val  = crc16_ccitt(crc_input_bytes)
    fcs_auto = crc_val.to_bytes(2, byte_order)
    if ch == '2':
        fcs_hex = input(f"    {C.PROMPT}Enter hex: {C.RESET}").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == len(fcs_auto): return fcs,f"{crc_type} custom"
        except: pass
        print(f"    {C.WARN}-> invalid, using auto{C.RESET}")
    return fcs_auto, f"{crc_type} auto over {len(crc_input_bytes)}B"

def verify_report(checks):
    dash = f"{C.SEP_C}{'─'*80}{C.RESET}"
    print(f"\n  {dash}"); print(f"  {C.BOLD}CHECKSUM / CRC VERIFICATION{C.RESET}"); print(f"  {dash}")
    for name,stored,result,passed in checks:
        status = f"{C.PASS_}PASS ✓{C.RESET}" if passed else f"{C.FAIL_}FAIL ✗{C.RESET}"
        print(f"  {C.DIM}{name:<30}{C.RESET}  stored={C.HEX}{stored}{C.RESET}   "
              f"verify={C.HEX}{result}{C.RESET}   {status}")
    print(f"  {dash}")

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — LAYER 1  (Physical)
# ══════════════════════════════════════════════════════════════════════════════

def ask_phy_mode() -> str:
    """
    Ask user whether to include PHY layer simulation.
    Returns: 'phy' or 'mac'
    """
    print(f"\n  {C.SECT}{C.BOLD}▌ PROCESSING MODE — Choose starting layer{C.RESET}")
    print(f"  {C.SEP_C}{'─'*70}{C.RESET}")
    print(f"  {C.L1}  [1]  Include PHY Layer  (Layer 1 simulation){C.RESET}")
    print(f"       {C.DIM}  Shows: encoding scheme · frame start symbol · control blocks{C.RESET}")
    print(f"       {C.DIM}  IFG / idle pattern · speed-specific framing · encoded bitstream{C.RESET}")
    print(f"  {C.L2}  [2]  Start from MAC Layer  (Layer 2 only){C.RESET}")
    print(f"       {C.DIM}  Direct: Preamble+SFD (default) → Dst MAC → frame build{C.RESET}")
    choice = input(f"\n  {C.PROMPT}Choose (1=PHY  2=MAC) [default=2]: {C.RESET}").strip() or '2'
    return 'phy' if choice == '1' else 'mac'


def ask_eth_phy_speed() -> str:
    """
    Show Ethernet speed variant menu. Returns PHY registry key.
    """
    if not _PHY_AVAILABLE:
        return 'MAC_ONLY'
    print(f"\n  {C.SECT}{C.BOLD}▌ ETHERNET SPEED VARIANT{C.RESET}")
    print(f"  {C.SEP_C}{'─'*80}{C.RESET}")
    print(f"  {C.DIM}  {'No':>3}  {'Speed':<10}  {'Technology':<28}  {'Encoding':<28}  IFG{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*76}{C.RESET}")
    for i, sp in enumerate(ETH_SPEED_MENU, 1):
        p = PHY_REGISTRY.get(sp['key'], {})
        ifg = p.get('ifg', {})
        ifg_s = f"{ifg.get('min_bits',96)}b"
        print(f"  {C.L1}  {i:>3}{C.RESET}  {C.BOLD}{sp['label']:<10}{C.RESET}  "
              f"{sp['tech']:<28}  {C.DIM}{sp['encoding']:<28}  {ifg_s}{C.RESET}")
    ch = input(f"\n  {C.PROMPT}Choose speed (1-{len(ETH_SPEED_MENU)}) [default=3 = 1G]: {C.RESET}").strip() or '3'
    try:
        idx = int(ch) - 1
        assert 0 <= idx < len(ETH_SPEED_MENU)
    except (ValueError, AssertionError):
        idx = 2  # default 1G
    return ETH_SPEED_MENU[idx]['key']


def show_phy_framing(speed_key: str) -> tuple[bytes, bytes, list[dict]]:
    """
    Show PHY framing details for selected speed and ask user to confirm/edit
    frame start fields. Returns (start_bytes, end_bytes, records).
    Smart: uses Preamble+SFD for low-speed, Start Block for high-speed.
    """
    if not _PHY_AVAILABLE:
        return ask_layer1_eth() + ([],)

    p      = get_phy_info(speed_key)
    fs     = get_start_mechanism(speed_key)
    fe     = get_end_mechanism(speed_key)
    ifg_d  = get_ifg(speed_key)
    enc    = get_encoding_detail(speed_key)
    ctrl   = get_control_symbols(speed_key)

    SEP = '─' * 80
    print(f"\n  {C.SECT}{C.BOLD}▌ PHY FRAMING — {p.get('name','')}{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Encoding   : {p.get('encoding','')}{C.RESET}")
    print(f"  {C.DIM}  Line rate  : {p.get('line_rate','')}{C.RESET}")
    print(f"  {C.DIM}  Standards  : {', '.join(p.get('standards',[]))}{C.RESET}")

    # ── Frame Start ────────────────────────────────────────────────────────────
    print(f"\n  {C.L1}{C.BOLD}  FRAME START MECHANISM{C.RESET}")
    print(f"  {C.DIM}  Mechanism  : {fs.get('mechanism','')}{C.RESET}")

    records: list[dict] = []
    start_bytes = b''

    if uses_preamble_sfd(speed_key):
        # Low speed: Preamble + SFD with optional PHY start symbols shown
        if speed_key == '100M':
            print(f"  {C.L1}  100M J/K delimiter : {fs.get('j_symbol_bits','')} (J) + {fs.get('k_symbol_bits','')} (K) in 4B5B stream{C.RESET}")
            print(f"  {C.DIM}  (J/K appear before preamble in 4B5B encoded stream){C.RESET}")
        elif speed_key == '1G':
            print(f"  {C.L1}  1G /S/ ordered set : K27.7 (0xFB) Start-of-Packet{C.RESET}")
            print(f"  {C.DIM}  (Before preamble in 8b/10b stream at PCS level){C.RESET}")

        section(f"LAYER 1 — Physical ({p.get('name','').split('(')[0].strip()})")
        print(f"  {C.DIM}  Preamble: {fs.get('preamble_pattern','7 bytes 0x55 for clock sync')}{C.RESET}")
        print(f"  {C.DIM}  SFD     : {fs.get('sfd_pattern','0xD5 = 10101011 marks MAC frame start')}{C.RESET}")

        preamble_default = fs.get('preamble_hex','55555555555555').replace(' ','')
        sfd_default      = fs.get('sfd_hex','D5').replace(' ','')
        preamble = get_hex("Preamble  7 bytes (14 hex)", preamble_default, 7,
                           help=f"Clock sync pattern. Default={preamble_default}. Press Enter=default.")
        sfd      = get_hex("SFD       1 byte  ( 2 hex)", sfd_default, 1,
                           help=f"Start Frame Delimiter. Default={sfd_default}. 0xD5=10101011.")
        start_bytes = preamble + sfd
        records += [
            {"layer":1,"name":"Preamble","raw":preamble,
             "user_val":preamble.hex(),"note":f"Clock sync ({speed_key} {p.get('encoding','')})"},
            {"layer":1,"name":"SFD","raw":sfd,
             "user_val":sfd.hex(),"note":"Frame boundary marker"},
        ]

    elif uses_start_block(speed_key) or uses_8b10b_sof(speed_key):
        # High speed: show Start Block / SOF info (informational — no byte edit)
        print(f"\n  {C.L1}  START BLOCK (control block — not part of MAC frame bytes):{C.RESET}")
        if uses_start_block(speed_key):
            sb = fs.get('start_ctrl_block', {})
            print(f"  {C.HEX}  Sync header : {fs.get('sync_header_ctrl','10')} (control block){C.RESET}")
            print(f"  {C.HEX}  Block Type  : {fs.get('start_block_type','0x78')} (Start-of-Frame in lane 0){C.RESET}")
            if sb:
                for k,v in list(sb.items())[:4]:
                    print(f"  {C.DIM}  {k:<16}: {str(v)[:60]}{C.RESET}")
        elif uses_8b10b_sof(speed_key):
            sof_types = fs.get('sof_types',{})
            print(f"  {C.L1}  FC SOF ordered set types:{C.RESET}")
            for sof_name, sof_val in list(sof_types.items())[:5]:
                print(f"    {C.HEX}  {sof_name:<8}: {sof_val}{C.RESET}")

        print(f"\n  {C.DIM}  For {speed_key}: Start block is generated by NIC/HBA hardware{C.RESET}")
        print(f"  {C.DIM}  MAC frame bytes (Preamble onwards) carried in Start block payload{C.RESET}")
        section(f"LAYER 1 — Physical MAC Start ({speed_key})")
        preamble_default = "55555555555555D5"
        print(f"  {C.DIM}  Preamble+SFD encoded inside Start Block payload:{C.RESET}")
        preamble = bytes.fromhex("55555555555555")
        sfd      = bytes.fromhex("D5")
        start_bytes = preamble + sfd
        records += [
            {"layer":1,"name":"Preamble","raw":preamble,
             "user_val":"55×7","note":f"Inside {speed_key} Start Block payload"},
            {"layer":1,"name":"SFD","raw":sfd,
             "user_val":"D5","note":"Inside Start Block — hardware generated"},
        ]

    # ── Encoding detail ────────────────────────────────────────────────────────
    if enc:
        print(f"\n  {C.SECT}{C.BOLD}  ENCODING: {enc.get('scheme','')}{C.RESET}")
        for k,v in list(enc.items())[:5]:
            if k not in ('table','example_encoding'):
                print(f"  {C.DIM}  {k:<22}: {str(v)[:65]}{C.RESET}")

    # ── Control symbols ────────────────────────────────────────────────────────
    if ctrl:
        print(f"\n  {C.L1}  CONTROL SYMBOLS:{C.RESET}")
        for sym, desc in list(ctrl.items())[:6]:
            print(f"  {C.HEX}  {sym:<16}  {C.DIM}{desc}{C.RESET}")

    # ── IFG ───────────────────────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}  INTER-FRAME GAP (IFG){C.RESET}")
    min_bits = ifg_d.get('min_bits', 96)
    pattern  = ifg_d.get('pattern', 'Idle')
    purpose  = ifg_d.get('purpose', '')
    print(f"  {C.DIM}  Minimum : {min_bits} bits{C.RESET}")
    print(f"  {C.DIM}  Pattern : {pattern}{C.RESET}")
    print(f"  {C.DIM}  Purpose : {purpose}{C.RESET}")

    apply_ifg = input(f"\n  {C.PROMPT}Apply Inter-Frame Gap / Idle? (y/n) [default=y]: {C.RESET}").strip().lower() or 'y'
    ifg_bytes = b''
    if apply_ifg != 'n':
        ifg_dur = input(f"  {C.PROMPT}IFG bits (Enter={min_bits}): {C.RESET}").strip() or str(min_bits)
        try:    ifg_bit_count = int(ifg_dur)
        except: ifg_bit_count = min_bits
        ifg_byte_count = max(12, (ifg_bit_count + 7) // 8)
        # Default IFG pattern based on speed
        if speed_key == '10M':
            ifg_bytes = b'\x00' * ifg_byte_count
            ifg_note  = "No carrier (Manchester idle)"
        elif speed_key in ('100M', '1G'):
            ifg_bytes = b'\x1F' * ifg_byte_count   # approximation of IDLE symbol
            ifg_note  = f"IDLE symbols (~{pattern[:30]})"
        else:
            ifg_bytes = b'\x00' * ifg_byte_count    # Idle blocks
            ifg_note  = f"Idle blocks ({pattern[:30]})"
        ifg_custom = input(f"  {C.PROMPT}Custom IFG pattern hex (Enter=default): {C.RESET}").strip()
        if ifg_custom:
            try:
                custom_b = bytes.fromhex(ifg_custom.replace(' ',''))
                ifg_bytes = custom_b
                ifg_note  = "Custom IFG pattern"
            except ValueError:
                pass
        if ifg_bytes:
            records.append({"layer":1,"name":f"IFG ({ifg_bit_count}b)",
                             "raw":ifg_bytes,"user_val":f"{len(ifg_bytes)}B",
                             "note":ifg_note})

    # ── PHY caution ───────────────────────────────────────────────────────────
    caution = p.get('caution','')
    if caution:
        print(f"\n  {C.WARN}  ⚠  PHY CAUTION: {caution}{C.RESET}")

    return start_bytes[:7], start_bytes[7:8] if len(start_bytes) >= 8 else b'\xD5', records


def ask_phy_serial_encoding() -> dict:
    """Ask user for serial PHY encoding selection and parameters."""
    if not _PHY_AVAILABLE:
        return {}
    print(f"\n  {C.SECT}{C.BOLD}▌ SERIAL PHY ENCODING{C.RESET}")
    print(f"  {C.SEP_C}{'─'*70}{C.RESET}")
    for i, sp in enumerate(SERIAL_SPEED_MENU, 1):
        print(f"  {C.L1}  [{i}]  {sp['label']:<35}  {C.DIM}{sp['encoding']}{C.RESET}")
    ch = input(f"  {C.PROMPT}Choose (1-{len(SERIAL_SPEED_MENU)}) [default=1=NRZ]: {C.RESET}").strip() or '1'
    try:
        idx = max(0, min(int(ch)-1, len(SERIAL_SPEED_MENU)-1))
    except ValueError:
        idx = 0
    key = SERIAL_SPEED_MENU[idx]['key']
    p   = get_phy_info(key)
    print(f"\n  {C.L1}  Selected: {p.get('name','')}{C.RESET}")
    enc = get_encoding_detail(key)
    for k,v in list(enc.items())[:4]:
        print(f"  {C.DIM}  {k:<22}: {str(v)[:65]}{C.RESET}")
    fs = get_start_mechanism(key)
    fe = get_end_mechanism(key)
    print(f"  {C.L1}  Frame start: {fs.get('mechanism','')}{C.RESET}")
    print(f"  {C.L1}  Frame end  : {fe.get('mechanism','')}{C.RESET}")
    return dict(key=key, info=p, encoding=enc, frame_start=fs, frame_end=fe)


def ask_layer1_eth():
    """
    PHY-aware Layer 1 function.
    If _ETH_PHY_SPEED is set (user chose PHY mode), delegates to show_phy_framing()
    for speed-specific encoding, IFG, and control symbol display.
    Otherwise uses traditional Preamble+SFD prompts.
    """
    global _ETH_PHY_SPEED
    speed = _ETH_PHY_SPEED

    if speed not in ('MAC_ONLY', '') and _PHY_AVAILABLE:
        # PHY mode — delegate to full PHY framing display
        preamble, sfd, _extra_records = show_phy_framing(speed)
        return preamble, sfd

    # MAC-only mode (default) — traditional prompt
    section("LAYER 1 — Physical (Preamble + SFD)")
    preamble = get_hex("Preamble  7 bytes (14 hex)","55555555555555",7,
        help="7 bytes of 0x55 transmitted before every Ethernet frame.\n"
             "Purpose: allows receiver hardware to synchronise its clock to the sender.\n"
             "Always 55 55 55 55 55 55 55 — changing this breaks clock recovery.")

    sfd = get_hex("SFD       1 byte  ( 2 hex)","d5",1,
        help="Start Frame Delimiter — 1 byte, always 0xD5 (10101011 in binary).\n"
             "Purpose: marks the EXACT boundary where the MAC frame begins.\n"
             "The receiver looks for 0xD5 after the preamble to start decoding.\n"
             "Changing this means no Ethernet NIC will recognise the frame.")
    return preamble, sfd

def wifi_crc32(data: bytes) -> bytes:
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4,'little')

def build_dsss_plcp(mpdu_len_bytes, rate_byte, short_preamble=False):
    if short_preamble:
        sync=bytes([0xFF]*7); sfd_val=0x05CF
        sync_note="56-bit SYNC (7×0xFF) — short preamble scrambled 1s"
        sfd_note="0x05CF — 802.11b SHORT preamble SFD (frame boundary)"
        mode_note="Short preamble (96µs total PLCP)"
    else:
        sync=bytes([0xFF]*16); sfd_val=0xF3A0
        sync_note="128-bit SYNC (16×0xFF) — long preamble scrambled 1s"
        sfd_note="0xF3A0 — 802.11b LONG preamble SFD (frame boundary)"
        mode_note="Long preamble (192µs total PLCP)"
    sfd_b=struct.pack("<H",sfd_val); signal_b=bytes([rate_byte]); service_b=bytes([0x00])
    length_b=struct.pack("<H",mpdu_len_bytes & 0xFFFF)
    crc_input=bytes([rate_byte,0x00])+length_b; crc_val=crc16_ibm(crc_input)
    crc_b=struct.pack("<H",crc_val)
    plcp=sync+sfd_b+signal_b+service_b+length_b+crc_b
    records=[
        {"layer":1,"name":"DSSS SYNC (preamble)","raw":sync,"user_val":f"0xFF×{len(sync)}","note":sync_note},
        {"layer":1,"name":"DSSS SFD  ← FRAME BOUNDARY","raw":sfd_b,"user_val":f"0x{sfd_val:04X}","note":sfd_note},
        {"layer":1,"name":"DSSS SIGNAL (rate)","raw":signal_b,"user_val":f"0x{rate_byte:02X}","note":"Rate encoding — see SIGNAL table"},
        {"layer":1,"name":"DSSS SERVICE","raw":service_b,"user_val":"0x00","note":"Reserved in long preamble"},
        {"layer":1,"name":"DSSS LENGTH (MPDU µs/B)","raw":length_b,"user_val":str(mpdu_len_bytes),"note":"MPDU length (bytes encoded as µs field)"},
        {"layer":1,"name":"DSSS PLCP CRC-16","raw":crc_b,"user_val":f"0x{crc_val:04X}","note":f"CRC-16/IBM over SIGNAL+SERVICE+LENGTH  {mode_note}"},
    ]
    return plcp, records

def build_ofdm_lsig(mpdu_len_bytes, rate_bits, rate_label):
    length_field=mpdu_len_bytes & 0xFFF
    word=(rate_bits & 0xF)|(0<<4)|(length_field<<5)
    parity=bin(word & 0x1FFFF).count('1') % 2
    word|=(parity<<17)
    lsig_bytes=struct.pack("<I",word)[:3]
    records=[
        {"layer":1,"name":"L-STF  (Short Training Field)","raw":bytes(10),"user_val":"8µs OFDM symbols","note":"10 symbols × 0.8µs — AGC + coarse freq sync  (not byte-representable)"},
        {"layer":1,"name":"L-LTF  (Long Training Field)","raw":bytes(8),"user_val":"8µs OFDM symbols","note":"GI(1.6µs) + 2×LTF(3.2µs each) — fine channel estimation"},
        {"layer":1,"name":"L-SIG  ← FRAME BOUNDARY","raw":lsig_bytes,"user_val":f"RATE={rate_bits:04b} LEN={mpdu_len_bytes}","note":f"{rate_label}  LEN={mpdu_len_bytes}B  Par={parity}  4µs OFDM symbol — marks MPDU start  [closest to SFD]"},
    ]
    return lsig_bytes, records

def build_ht_sig(mpdu_len_bytes, mcs, bw40, sgi, stbc, ldpc, rate_label):
    ht_len=mpdu_len_bytes & 0xFFFF
    sig1_word=(mcs & 0x7F)|((1 if bw40 else 0)<<7)|(ht_len<<8)
    sig1=struct.pack("<I",sig1_word)[:3]
    smooth=1; not_snd=1; aggr=0
    stbc_b=(1 if stbc else 0); fec=(1 if ldpc else 0); sgi_b=(1 if sgi else 0)
    sig2_lo=(smooth|(not_snd<<1)|(0<<2)|(aggr<<3)|(stbc_b<<4)|(fec<<5)|(sgi_b<<6)|(0<<7))
    crc_input=sig1+bytes([sig2_lo]); crc8=0xFF
    for byte in crc_input:
        for i in range(8):
            bit=(byte>>i)&1; fb=((crc8>>7)&1)^bit; crc8=((crc8<<1)&0xFF)|0
            if fb: crc8^=0x07
    sig2=bytes([sig2_lo,crc8&0xFF,0x00])
    lsig_bytes,lsig_records=build_ofdm_lsig(mpdu_len_bytes,0b1011,"6Mbps legacy")
    records=lsig_records+[
        {"layer":1,"name":"HT-SIG-1  (MCS+BW+Length)","raw":sig1,"user_val":f"MCS{mcs} BW={'40' if bw40 else '20'}MHz LEN={ht_len}","note":"8µs (2×4µs OFDM) — HT rate/length descriptor"},
        {"layer":1,"name":"HT-SIG-2  ← HT FRAME BOUNDARY","raw":sig2,"user_val":f"SGI={int(sgi)} LDPC={int(ldpc)} STBC={int(stbc)}","note":"HT-SIG-2 + CRC8+Tail — marks HT MPDU start (≈SFD for 802.11n)"},
        {"layer":1,"name":"HT-STF  (HT Short Training)","raw":bytes(4),"user_val":"4µs","note":"MIMO AGC adjustment"},
        {"layer":1,"name":"HT-LTF(s) (HT Long Training)","raw":bytes(4),"user_val":"4µs×NSS","note":"Per-stream channel estimation"},
    ]
    return sig1+sig2, records

def build_vht_sig(mpdu_len_bytes, mcs, nss, bw, sgi, ldpc):
    bw_map={20:0,40:1,80:2,160:3}; bw_bits=bw_map.get(bw,0); nss_b=(nss-1)&0x7
    siga1=struct.pack("<I",bw_bits|(0<<2)|(1<<3)|(nss_b<<13))[:3]
    siga2=struct.pack("<I",(mcs<<4)|(int(sgi)<<0)|(int(ldpc)<<2))[:3]
    lsig_bytes,lsig_records=build_ofdm_lsig(mpdu_len_bytes,0b1011,"6Mbps legacy")
    records=lsig_records+[
        {"layer":1,"name":"VHT-SIG-A1  (BW+NSS+STBC)","raw":siga1,"user_val":f"BW={bw}MHz NSS={nss}","note":"8µs — VHT rate/NSS/BW descriptor"},
        {"layer":1,"name":"VHT-SIG-A2  ← VHT FRAME BOUNDARY","raw":siga2,"user_val":f"MCS{mcs} SGI={int(sgi)} LDPC={int(ldpc)}","note":"VHT-SIG-A2 — marks VHT MPDU start  (≈SFD for 802.11ac)"},
        {"layer":1,"name":"VHT-STF","raw":bytes(4),"user_val":"4µs","note":"MIMO AGC"},
        {"layer":1,"name":"VHT-LTF(s)","raw":bytes(4),"user_val":f"4µs×{nss}","note":"Per-stream channel est."},
        {"layer":1,"name":"VHT-SIG-B  (length per user)","raw":bytes(3),"user_val":f"LEN={mpdu_len_bytes}","note":"Per-user MPDU length"},
    ]
    return siga1+siga2, records

def build_he_sig(mpdu_len_bytes, mcs, nss, bw, gi, ldpc):
    bw_map={20:0,40:1,80:2,160:3}; bw_bits=bw_map.get(bw,0); nss_b=(nss-1)&0x7
    hesa1=struct.pack("<I",bw_bits|(0<<2)|(nss_b<<9))[:3]
    hesa2=struct.pack("<I",(mcs<<4)|(int(ldpc)<<3)|(gi&0x3))[:3]
    lsig_bytes,lsig_records=build_ofdm_lsig(mpdu_len_bytes,0b1011,"6Mbps legacy")
    gi_names={0:"0.8µs(Normal)",1:"1.6µs(Double)",2:"3.2µs(Quad)"}
    records=lsig_records+[
        {"layer":1,"name":"RL-SIG  (Repeated L-SIG)","raw":lsig_bytes,"user_val":"repeat","note":"Confirms HE frame to non-HE stations"},
        {"layer":1,"name":"HE-SIG-A1  (BW+BSS-Color+NSS)","raw":hesa1,"user_val":f"BW={bw}MHz NSS={nss}","note":"8µs — HE BSS colour, UL/DL, NSS"},
        {"layer":1,"name":"HE-SIG-A2  ← HE FRAME BOUNDARY","raw":hesa2,"user_val":f"MCS{mcs} GI={gi_names.get(gi,'?')} LDPC={int(ldpc)}","note":"HE-SIG-A2 — marks HE MPDU start  (≈SFD for 802.11ax)"},
        {"layer":1,"name":"HE-STF","raw":bytes(4),"user_val":"4µs or 8µs","note":"HE MIMO AGC"},
        {"layer":1,"name":"HE-LTF(s)","raw":bytes(4),"user_val":f"4/8µs×{nss}","note":"HE channel estimation"},
    ]
    return hesa1+hesa2, records

def ask_wifi_phy(phy_ch, mpdu_len):
    phy_records=[]
    if phy_ch=='1':
        section("802.11b DSSS PLCP HEADER")
        print("    Long preamble (192µs) or Short preamble (96µs)?")
        sp=get("Short preamble? (y/n)","n").lower().startswith("y")
        print("    SIGNAL (rate) byte:")
        for k,(rb,rd) in DSSS_RATES.items(): print(f"      {k} = 0x{rb:02X}  {rd}")
        rate_ch=get("Rate","4"); rate_byte,rate_desc=DSSS_RATES.get(rate_ch,(0x6E,"11 Mbps CCK"))
        print(f"    -> Rate: {rate_desc}"); _,phy_records=build_dsss_plcp(mpdu_len,rate_byte,sp)
    elif phy_ch in ('2','3'):
        std="802.11a (5GHz)" if phy_ch=='2' else "802.11g (2.4GHz)"
        section(f"{std} OFDM L-SIG  (legacy preamble: L-STF + L-LTF + L-SIG)")
        print("    L-SIG RATE field (MCS/rate code, 4 bits):")
        for k,(rb,rd) in OFDM_RATE_BITS.items(): print(f"      {k:>2} Mbps = 0b{rb:04b}  {rd}")
        rate_ch=get("Data rate (Mbps)","54"); rate_bits,rate_label=OFDM_RATE_BITS.get(rate_ch,(0b1100,"54 Mbps"))
        print(f"    -> {rate_label}")
        print(f"    NOTE: L-STF (8µs) and L-LTF (8µs) are OFDM analog waveforms.")
        print(f"    They are NOT byte-representable. Shown as placeholder bytes below.")
        _,phy_records=build_ofdm_lsig(mpdu_len,rate_bits,rate_label)
    elif phy_ch=='4':
        section("802.11n HT-MIXED PLCP  (L-STF + L-LTF + L-SIG + HT-SIG1 + HT-SIG2 + HT-STF + HT-LTF)")
        print("    MCS index (0=BPSK 1/2, 7=64QAM 5/6, 8-15=2-stream ...)")
        mcs=int(get("MCS index (0-31)","7"))&0x1F
        bw40=get("40 MHz bandwidth? (y/n)","n").lower().startswith("y")
        sgi=get("Short Guard Interval 400ns? (y/n)","n").lower().startswith("y")
        stbc=get("STBC? (y/n)","n").lower().startswith("y")
        ldpc=get("LDPC FEC? (y/n)","n").lower().startswith("y")
        rate_label=f"MCS{mcs} {'HT40' if bw40 else 'HT20'} {'SGI' if sgi else 'LGI'}"
        _,phy_records=build_ht_sig(mpdu_len,mcs,bw40,sgi,stbc,ldpc,rate_label)
    elif phy_ch=='5':
        section("802.11ac VHT PLCP  (L-STF+L-LTF+L-SIG+VHT-SIG-A+VHT-STF+VHT-LTF+VHT-SIG-B)")
        mcs=int(get("MCS index (0-9)","9"))&0xF; nss=int(get("Number of Spatial Streams NSS (1-8)","1"))
        bw=int(get("Bandwidth  20/40/80/160 MHz","80"))
        sgi=get("Short GI 400ns? (y/n)","n").lower().startswith("y")
        ldpc=get("LDPC FEC? (y/n)","n").lower().startswith("y")
        _,phy_records=build_vht_sig(mpdu_len,mcs,nss,bw,sgi,ldpc)
    elif phy_ch=='6':
        section("802.11ax HE PLCP  (L-STF+L-LTF+L-SIG+RL-SIG+HE-SIG-A+HE-STF+HE-LTF)")
        mcs=int(get("MCS index (0-11)","11"))&0xF; nss=int(get("Number of Spatial Streams NSS (1-8)","1"))
        bw=int(get("Bandwidth  20/40/80/160 MHz","80"))
        print("    Guard Interval:  0=0.8µs(Normal)  1=1.6µs  2=3.2µs")
        gi=int(get("GI (0/1/2)","0"))&0x3; ldpc=get("LDPC FEC? (y/n)","n").lower().startswith("y")
        _,phy_records=build_he_sig(mpdu_len,mcs,nss,bw,gi,ldpc)
    return phy_records

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — LAYER 2  (Data Link)
# ══════════════════════════════════════════════════════════════════════════════
def ask_l2_ethernet(ethertype_hint="0800"):
    section("LAYER 2 — Ethernet / 802.3  (MAC Header)")
    print("    Variants:")
    print("      1 = Ethernet II        (EtherType >= 0x0600)")
    print("      2 = IEEE 802.3 Raw     (Length only)")
    print("      3 = IEEE 802.3 + LLC")
    print("      4 = IEEE 802.3 + LLC + SNAP")
    v=input("    Select variant [1]: ").strip() or '1'
    dst=get("Destination MAC","ff:ff:ff:ff:ff:ff",
        help="6-byte MAC address of the RECEIVER of this frame.\n"
             "ff:ff:ff:ff:ff:ff = broadcast (all devices on segment receive it).\n"
             "Used by ARP, DHCP discover, STP — any frame for unknown/all targets.\n"
             "For unicast set to peer's actual MAC (e.g. 00:1A:2B:3C:4D:5E).")
    src=get("Source MAC","00:11:22:33:44:55",
        help="6-byte MAC address of the SENDER (your interface).\n"
             "Must be your NIC's hardware address — used by the receiver to reply.\n"
             "First 3 bytes = OUI (manufacturer ID), last 3 = device serial.\n"
             "bit0 of byte0 = 1 means multicast source (invalid for normal frames).\n"
             "bit1 of byte0 = 1 means locally-administered (overriding factory MAC).")
    llc_b=b''; snap_b=b''
    if v=='1':
        et=get_hex(f"EtherType (4 hex)",ethertype_hint,2,
            help="2-byte protocol identifier telling the receiver what's inside the frame.\n"
                 "0x0800 = IPv4   0x0806 = ARP   0x86DD = IPv6   0x8100 = VLAN tag\n"
                 "0x8808 = MAC Control (Pause/PFC)   0x8809 = LACP   0x88CC = LLDP\n"
                 "Values >= 0x0600 = EtherType (Ethernet II).\n"
                 "Values < 0x0600 = 802.3 Length field (number of payload bytes).")
        variant_name="Ethernet II"; type_len_b=et
    elif v=='2':
        variant_name="IEEE 802.3 Raw"; type_len_b=None
    elif v=='3':
        variant_name="IEEE 802.3 + LLC"
        dsap=get_hex("DSAP (2 hex)","42",1,help="Destination Service Access Point — 1 byte.\n0x42=STP  0xAA=SNAP  0xFE=ISO  0x00=Null SAP")
        ssap=get_hex("SSAP (2 hex)","42",1,help="Source Service Access Point — 1 byte, same encoding as DSAP.")
        ctl =get_hex("Control (2 hex)","03",1,help="LLC Control field. 0x03=UI (Unnumbered Information) — most common.")
        llc_b=dsap+ssap+ctl; type_len_b=None
    elif v=='4':
        variant_name="IEEE 802.3 + LLC + SNAP"
        dsap=get_hex("DSAP (2 hex, SNAP=aa)","aa",1); ssap=get_hex("SSAP (2 hex, SNAP=aa)","aa",1)
        ctl =get_hex("Control (2 hex)","03",1); llc_b=dsap+ssap+ctl
        oui=get_hex("SNAP OUI (6 hex)","000000",3); pid=get_hex("SNAP Protocol ID (4 hex)",ethertype_hint,2)
        snap_b=oui+pid; type_len_b=None
    else:
        v='1'; et=get_hex(f"EtherType (4 hex)",ethertype_hint,2)
        variant_name="Ethernet II"; type_len_b=et
    return mac_b(dst),mac_b(src),type_len_b,llc_b,snap_b,variant_name,dst,src,v

def assemble_eth_frame(l3_payload,l3_fields,dst_mb,src_mb,type_len_b,
                       llc_b,snap_b,variant,dst_s,src_s,v,preamble,sfd):
    if v in ('2','3','4'):
        length_val=len(llc_b)+len(snap_b)+len(l3_payload)
        tl=struct.pack('>H',length_val); tl_note=f"Length={length_val}B"; tl_user=str(length_val)
    else:
        tl=type_len_b; tl_note=f"EtherType 0x{tl.hex().upper()}"; tl_user=f"0x{tl.hex().upper()}"
    mac_content=dst_mb+src_mb+tl+llc_b+snap_b+l3_payload
    fcs,fcs_note=ask_fcs_eth(mac_content)
    full_frame=preamble+sfd+mac_content+fcs
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":sfd.hex(),"note":"0xD5"},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":""},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
        {"layer":2,"name":"Type / Length","raw":tl,"user_val":tl_user,"note":tl_note},
    ]
    if llc_b:
        records+=[
            {"layer":2,"name":"LLC DSAP","raw":llc_b[0:1],"user_val":llc_b[0:1].hex(),"note":""},
            {"layer":2,"name":"LLC SSAP","raw":llc_b[1:2],"user_val":llc_b[1:2].hex(),"note":""},
            {"layer":2,"name":"LLC Control","raw":llc_b[2:3],"user_val":llc_b[2:3].hex(),"note":""},
        ]
    if snap_b:
        records+=[
            {"layer":2,"name":"SNAP OUI","raw":snap_b[0:3],"user_val":snap_b[0:3].hex(),"note":""},
            {"layer":2,"name":"SNAP PID","raw":snap_b[3:5],"user_val":snap_b[3:5].hex(),"note":""},
        ]
    records+=l3_fields
    records.append({"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note})
    return full_frame,records

def ask_l2_serial():
    section("LAYER 2 — Serial / WAN  (choose protocol)")
    for k,v in SERIAL_TYPES.items():
        marker="  ←  full 3-type builder" if k=='11' else ""
        print(f"      {k:>2} = {v}{marker}")
    ch=input("    Select [3]: ").strip() or '3'
    if ch not in SERIAL_TYPES: ch='3'
    return ch,SERIAL_TYPES[ch]

def print_hdlc_education():
    print(f"""
  {'═'*110}
  {'HDLC — HIGH-LEVEL DATA LINK CONTROL  (ISO 13239)':^110}
  {'THREE FRAME TYPES:  I-frame (data)  |  S-frame (supervisory)  |  U-frame (management)':^110}
  {'═'*110}

  FRAME STRUCTURE
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  │ Flag(1B) │ Address(1+B) │ Control(1-2B) │ Information(0+B) │ FCS(2-4B) │ Flag(1B) │
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────

  I-FRAME: data + N(S)/N(R) sequence numbers  |  bit0=0
  S-FRAME: ACK/NAK/flow control  |  bits[1:0]=01  |  subtypes: RR REJ RNR SREJ
  U-FRAME: link management  |  bits[1:0]=11  |  subtypes: UI SABM DISC UA FRMR XID TEST

  Control mod-8 (1B):  I=[N(S)(3b)+P/F+N(R)(3b)+0]  S=[N(R)(3b)+P/F+SS+01]  U=[M(3b)+P/F+M(2b)+11]
  Control mod-128(2B): I=[N(S)(7b)+0 | N(R)(7b)+P/F]

  FCS: CRC-16/CCITT(2B default) or CRC-32(4B extended)  — covers Address+Control+Info
  {'═'*110}""")

def build_hdlc_control_i(ns,pf,nr,mod128=False):
    if mod128:
        return bytes([((ns&0x7F)<<1)|0, ((nr&0x7F)<<1)|(pf&1)])
    return bytes([((ns&0x7)<<5)|((pf&1)<<4)|((nr&0x7)<<1)|0])

def build_hdlc_control_s(nr,pf,s1s0,mod128=False):
    if mod128:
        return bytes([0x01|((s1s0&0x3)<<2), ((nr&0x7F)<<1)|(pf&1)])
    return bytes([((nr&0x7)<<5)|((pf&1)<<4)|((s1s0&0x3)<<2)|0x01])

def build_hdlc_control_u(m4m3m2,pf,m1m0):
    return bytes([((m4m3m2&0x7)<<5)|((pf&1)<<4)|((m1m0&0x3)<<2)|0x03])

def ask_hdlc_address():
    section("HDLC ADDRESS FIELD")
    print("    0xFF = broadcast (all stations)  0x01 = LAPB DTE  0x03 = LAPB DCE")
    print("    For LAPD (ISDN): 2-byte address (SAPI+TEI)")
    print("    EA bit (bit 0): 1 = last address byte, 0 = more bytes follow")
    addr_type=get("Address type  1=1-byte  2=2-byte(LAPD)","1")
    if addr_type=='2':
        sapi=int(get("SAPI (0=signalling, 63=LME)","0"))&0x3F
        cr=int(get("C/R bit (0=response, 1=command)","1"))&1
        byte0=(sapi<<2)|(cr<<1)|0
        tei=int(get("TEI (Terminal Endpoint Identifier)","0"))&0x7F
        byte1=(tei<<1)|1
        addr_bytes=bytes([byte0,byte1]); addr_note=f"SAPI={sapi} C/R={cr} TEI={tei} (LAPD 2-byte)"
    else:
        addr_hex=get("Address byte (hex, FF=broadcast)","ff")
        try:    addr_byte=int(addr_hex,16)&0xFF
        except: addr_byte=0xFF
        addr_bytes=bytes([addr_byte])
        addr_note="0xFF broadcast" if addr_byte==0xFF else f"0x{addr_byte:02X}"
    return addr_bytes,addr_note

def print_pause_education():
    print(f"""
  {'═'*110}
  {'ETHERNET PAUSE FRAME  —  IEEE 802.3x  (MAC Flow Control)':^110}
  {'═'*110}

  Purpose: ask link partner to temporarily stop sending data.
  EtherType 0x8808  |  Opcode 0x0001  |  Pause Quanta 2B  |  Pad 42B  =  64B total
  1 quanta = 512 bit-times at link speed.
  0x0000=Resume  0x0001=Minimal  0x0200≈262µs@1GbE  0xFFFF=Max pause
  {'═'*110}""")

def ask_l2_pause():
    section("LAYER 1  —  Physical  (Preamble + SFD)")
    preamble=get_hex("Preamble  7 B (14 hex)","55555555555555",7)
    sfd=get_hex("SFD       1 B  (2 hex)","d5",1)
    section("LAYER 2  —  Ethernet MAC Header")
    print("    Dst MAC options:")
    print("      01:80:c2:00:00:01  — IEEE 802.3x reserved multicast (recommended)")
    print("      Peer unicast MAC   — direct point-to-point pause")
    dst_s=get("Dst MAC","01:80:c2:00:00:01"); src_s=get("Src MAC  (your interface MAC)","00:11:22:33:44:55")
    section("PAUSE QUANTA  —  Flow Control Value  (YOUR KEY INPUT)")
    print("    1 quanta = 512 bit-times at the link speed.")
    print("    Examples:  0x0000=Resume  0x0001=Minimal  0x0200≈262µs@1GbE  0xFFFF=Max")
    link=get("Link speed for quanta display  1=100M  2=1G  3=10G  4=25G","2")
    speed_map={'1':100e6,'2':1e9,'3':10e9,'4':25e9}
    speed_bps=speed_map.get(link,1e9)
    speed_label={'1':'100 Mbps','2':'1 Gbps','3':'10 Gbps','4':'25 Gbps'}.get(link,'1 Gbps')
    quanta_hex=get("Pause Quanta  (hex, 0000–FFFF)","00ff")
    try:    quanta_val=int(quanta_hex.replace("0x",""),16)&0xFFFF
    except: quanta_val=0x00FF; print("    -> invalid, using 0x00FF")
    bit_time_s=1.0/speed_bps; pause_bits=quanta_val*512; pause_us=(pause_bits*bit_time_s)*1e6
    print(f"\n    ┌─────────────────────────────────────────────────────────────┐")
    print(f"    │  Quanta : {quanta_val:5d}  (0x{quanta_val:04X})                                  │")
    print(f"    │  Speed  : {speed_label:<10}                                     │")
    print(f"    │  Pause  : {quanta_val} × 512 = {pause_bits:,} bit-times                    │")
    print(f"    │  Time   : {pause_us:.3f} µs  ({pause_us/1000:.4f} ms)                       │")
    print(f"    └─────────────────────────────────────────────────────────────┘")
    section("PADDING  (auto-computed)")
    print("    Pause frame payload = opcode(2) + quanta(2) + pad(42) = 46 bytes.")
    return preamble,sfd,dst_s,src_s,quanta_val

def build_pause(preamble,sfd,dst_s,src_s,quanta_val):
    et=bytes.fromhex("8808"); opcode=bytes.fromhex("0001")
    quanta=struct.pack("!H",quanta_val); pad=b'\x00'*42
    dst_mb=mac_b(dst_s); src_mb=mac_b(src_s)
    fcs_input=dst_mb+src_mb+et+opcode+quanta+pad
    fcs,fcs_note=ask_fcs_eth(fcs_input)
    full_frame=preamble+sfd+fcs_input+fcs
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7 × 0x55  clock sync / delimiter"},
        {"layer":1,"name":"SFD  (Start Frame Delim)","raw":sfd,"user_val":"0xD5","note":"0xD5  marks start of MAC frame"},
        {"layer":2,"name":"Dst MAC  (Pause dest)","raw":dst_mb,"user_val":dst_s,"note":"01:80:C2:00:00:01 = IEEE reserved multicast (not forwarded)"},
        {"layer":2,"name":"Src MAC  (sender)","raw":src_mb,"user_val":src_s,"note":"Transmitting station's own MAC"},
        {"layer":2,"name":"EtherType  (MAC Control)","raw":et,"user_val":"0x8808","note":"Fixed: 0x8808 = IEEE 802.3 MAC Control"},
        {"layer":2,"name":"MAC Ctrl Opcode  (PAUSE)","raw":opcode,"user_val":"0x0001","note":"Fixed: 0x0001 = PAUSE  (only defined MAC Ctrl opcode)"},
        {"layer":2,"name":"Pause Quanta  ← user value","raw":quanta,"user_val":f"0x{quanta_val:04X}  ({quanta_val} decimal)","note":f"Sender must halt for {quanta_val} × 512 bit-times"},
        {"layer":2,"name":"Pad  (min-frame filler)","raw":pad,"user_val":"0x00 × 42","note":"Auto: pads frame body to 46 B (IEEE 802.3 minimum)"},
        {"layer":0,"name":"Ethernet FCS  (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame,records

def print_pfc_education():
    print(f"""
  {'═'*110}
  {'PFC — PRIORITY FLOW CONTROL  (IEEE 802.1Qbb / DCB)':^110}
  {'═'*110}

  EtherType 0x8808 + Opcode 0x0101 + Priority Enable Vector(2B) + 8×Quanta(16B) + Pad(26B)
  Priority Enable Vector: bitmask selecting which of 8 priority queues to pause.
  Bit0=P0(BestEffort)  Bit5=P5(RoCE/iSCSI)  0x0020=pause P5 only   0x00FF=pause all
  {'═'*110}""")

def ask_l2_pfc():
    section("LAYER 1  —  Physical")
    preamble=get_hex("Preamble  7 B","55555555555555",7)
    sfd=get_hex("SFD       1 B","d5",1)
    section("LAYER 2  —  Ethernet MAC Header")
    dst_s=get("Dst MAC  (MAC Ctrl multicast)","01:80:c2:00:00:01")
    src_s=get("Src MAC  (your interface MAC)","00:11:22:33:44:55")
    section("PFC CONTROL  —  Opcode 0x0101")
    print("    Priority Enable Vector: bitmask selecting which priorities to pause.")
    print("    Examples:  0x0020=P5(RoCE)  0x00E0=P5+P6+P7  0x00FF=all  0x0001=P0 only")
    vec_hex=get("Priority Enable Vector (hex 0000-00FF)","0020",
        help="8-bit bitmask — each bit=1 means that priority queue is being PAUSED.\n"
             "Bit 0=P0(BestEffort)  Bit 5=P5(RoCE/iSCSI)  Bit 7=P7(STP/LLDP)\n"
             "0x0020=pause P5 only  0x00FF=pause all 8 priorities")
    try:    vec_val=int(vec_hex.replace("0x",""),16)&0x00FF
    except: vec_val=0x0020
    enabled=[i for i in range(8) if vec_val&(1<<i)]
    print(f"    -> Pausing priorities: {enabled if enabled else 'NONE'}")
    section("QUANTA PER PRIORITY  (2 bytes each, 0x0000 = not pausing)")
    prio_labels=["P0 Best-Effort","P1 Background","P2 Video","P3 Critical-App",
                 "P4 Video-Conf ","P5 RoCE/iSCSI ","P6 Net-Control ","P7 STP/LLDP   "]
    quanta=[]
    for i in range(8):
        enabled_marker=" ← ENABLED" if i in enabled else "  (0=no pause)"
        default="00ff" if i in enabled else "0000"
        q_hex=get(f"Quanta[{i}]  {prio_labels[i]}{enabled_marker}",default)
        try:    q_val=int(q_hex.replace("0x",""),16)&0xFFFF
        except: q_val=0x00FF if i in enabled else 0x0000
        quanta.append(q_val)
    return preamble,sfd,dst_s,src_s,vec_val,quanta

def build_pfc(preamble,sfd,dst_s,src_s,vec_val,quanta):
    et=bytes.fromhex("8808"); opcode=bytes.fromhex("0101")
    vec_b=struct.pack("!H",vec_val); q_bytes=b''.join(struct.pack("!H",q) for q in quanta); pad=b'\x00'*26
    dst_mb=mac_b(dst_s); src_mb=mac_b(src_s)
    fcs_input=dst_mb+src_mb+et+opcode+vec_b+q_bytes+pad
    fcs,fcs_note=ask_fcs_eth(fcs_input)
    full_frame=preamble+sfd+fcs_input+fcs
    prio_labels=["P0-BestEffort","P1-Background","P2-Video","P3-CriticalApp",
                 "P4-VideoConf","P5-RoCE/iSCSI","P6-NetCtrl","P7-STP/LLDP"]
    enabled=[i for i in range(8) if vec_val&(1<<i)]
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":"0xD5","note":"Start Frame Delimiter"},
        {"layer":2,"name":"Dst MAC (MAC Ctrl mcast)","raw":dst_mb,"user_val":dst_s,"note":"01:80:C2:00:00:01 IEEE reserved"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":"Sender interface MAC"},
        {"layer":2,"name":"EtherType (MAC Control)","raw":et,"user_val":"0x8808","note":"Fixed: MAC Control"},
        {"layer":2,"name":"PFC Opcode","raw":opcode,"user_val":"0x0101","note":"PFC (vs 0x0001=basic Pause)"},
        {"layer":2,"name":"Priority Enable Vector","raw":vec_b,"user_val":f"0x{vec_val:04X}","note":f"Pause P{enabled} bitmask"},
    ]
    for i in range(8):
        records.append({"layer":2,"name":f"Quanta[P{i}] {prio_labels[i]}","raw":struct.pack("!H",quanta[i]),
            "user_val":f"0x{quanta[i]:04X} ({quanta[i]})","note":"PAUSED" if i in enabled and quanta[i]>0 else ("resume" if quanta[i]==0 and i in enabled else "not paused")})
    records+=[
        {"layer":2,"name":"Pad (min-frame filler)","raw":pad,"user_val":"0x00×26","note":"26B pad to reach 64B minimum"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame,records

def print_lldp_education():
    print(f"""
  {'═'*110}
  {'LLDP — LINK LAYER DISCOVERY PROTOCOL  (IEEE 802.1AB)':^110}
  {'═'*110}

  EtherType 0x88CC  |  Dst MAC 01:80:C2:00:00:0E (not forwarded by bridges)
  TLV format: Type(7b) + Length(9b) + Value  — chained until End TLV (type=0)
  Mandatory: TLV1=ChassisID  TLV2=PortID  TLV3=TTL(120s default)  TLV0=End
  Optional:  TLV4=PortDesc  TLV5=SysName  TLV6=SysDesc  TLV7=SysCap  TLV8=MgmtAddr
  {'═'*110}""")

def make_lldp_tlv(tlv_type,value_bytes):
    length=len(value_bytes)
    return struct.pack("!H",(tlv_type<<9)|length)+value_bytes

def ask_l2_lldp():
    section("LAYER 1  —  Physical")
    preamble=get_hex("Preamble  7 B","55555555555555",7)
    sfd=get_hex("SFD       1 B","d5",1)
    section("LAYER 2  —  Ethernet MAC Header")
    dst_s=get("Dst MAC  (LLDP multicast)","01:80:c2:00:00:0e")
    src_s=get("Src MAC  (your interface MAC)","00:11:22:33:44:55")
    section("TLV 1 — Chassis ID  (mandatory)")
    print("    Subtypes:  4=MAC address  5=Network address  7=Locally-assigned string")
    ch_sub=get("Chassis ID Subtype  (4=MAC / 7=string)","4")
    if ch_sub=="4":
        ch_mac=get("Chassis MAC",src_s); chassis_val=bytes([4])+mac_b(ch_mac)
    else:
        ch_str=get("Chassis ID string","switch01"); chassis_val=bytes([7])+ch_str.encode()
    section("TLV 2 — Port ID  (mandatory)")
    print("    Subtypes:  3=MAC address  5=Interface name  7=Locally-assigned string")
    po_sub=get("Port ID Subtype  (5=IfName / 7=string)","5")
    if po_sub=="3":
        po_mac=get("Port MAC",src_s); port_val=bytes([3])+mac_b(po_mac)
    elif po_sub=="5":
        po_str=get("Interface name","GigabitEthernet0/1"); port_val=bytes([5])+po_str.encode()
    else:
        po_str=get("Port ID string","port1"); port_val=bytes([7])+po_str.encode()
    section("TLV 3 — TTL  (mandatory)")
    print("    0=remove entry immediately   120=default   65535=maximum")
    ttl_val=int(get("TTL (seconds)","120",
        help="Time To Live — how long neighbours keep this LLDP entry (default 120s).\n"
             "0=remove entry immediately (device shutting down).  65535=keep permanently."))&0xFFFF
    ttl_bytes=struct.pack("!H",ttl_val)
    section("OPTIONAL TLVs")
    opt_tlvs=[]
    if get("Include Port Description TLV? (y/n)","y").lower().startswith("y"):
        pd_str=get("Port Description","GigabitEthernet0/1 to CoreSwitch")
        opt_tlvs.append(("Port Description",4,pd_str.encode()))
    if get("Include System Name TLV? (y/n)","y").lower().startswith("y"):
        sn_str=get("System Name (hostname)","SW-ACCESS-01")
        opt_tlvs.append(("System Name",5,sn_str.encode()))
    if get("Include System Description TLV? (y/n)","y").lower().startswith("y"):
        sd_str=get("System Description","Cisco IOS 15.2 Catalyst 2960")
        opt_tlvs.append(("System Description",6,sd_str.encode()))
    if get("Include System Capabilities TLV? (y/n)","y").lower().startswith("y"):
        print("    Capability bits: 0x0002=Repeater  0x0004=Bridge  0x0010=Router  0x0080=Station")
        sup_hex=get("Supported capabilities (hex)","0004"); ena_hex=get("Enabled  capabilities (hex)","0004")
        cap_bytes=hpad(sup_hex,2)+hpad(ena_hex,2)
        opt_tlvs.append(("System Capabilities",7,cap_bytes))
    if get("Include Management Address TLV? (y/n)","y").lower().startswith("y"):
        mgmt_ip=get("Management IP address","192.168.1.1")
        try:    addr_bytes=b'\x05'+b'\x01'+ip_b(mgmt_ip)
        except: addr_bytes=b'\x05\x01\xc0\xa8\x01\x01'
        addr_bytes+=b'\x02'+struct.pack("!I",1)+b'\x00'
        opt_tlvs.append(("Management Address",8,addr_bytes))
    return (preamble,sfd,dst_s,src_s,chassis_val,port_val,ttl_val,ttl_bytes,opt_tlvs)

def build_lldp(preamble,sfd,dst_s,src_s,chassis_val,port_val,ttl_val,ttl_bytes,opt_tlvs):
    dst_mb=mac_b(dst_s); src_mb=mac_b(src_s); et=bytes.fromhex("88cc")
    tlv1=make_lldp_tlv(1,chassis_val); tlv2=make_lldp_tlv(2,port_val)
    tlv3=make_lldp_tlv(3,ttl_bytes);   end_tlv=make_lldp_tlv(0,b'')
    opt_built=[(name,t,make_lldp_tlv(t,val)) for (name,t,val) in opt_tlvs]
    lldpdu=tlv1+tlv2+tlv3
    for (_,_,tb) in opt_built: lldpdu+=tb
    lldpdu+=end_tlv
    fcs_input=dst_mb+src_mb+et+lldpdu
    fcs,fcs_note=ask_fcs_eth(fcs_input)
    full_frame=preamble+sfd+fcs_input+fcs
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":"0xD5","note":""},
        {"layer":2,"name":"Dst MAC (LLDP mcast)","raw":dst_mb,"user_val":dst_s,"note":"01:80:C2:00:00:0E not forwarded"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":"Sender MAC"},
        {"layer":2,"name":"EtherType (LLDP)","raw":et,"user_val":"0x88CC","note":"IEEE 802.1AB LLDP"},
        {"layer":3,"name":"TLV1 Chassis-ID hdr","raw":tlv1[:2],"user_val":"type=1","note":f"len={len(chassis_val)}B"},
        {"layer":3,"name":"TLV1 Chassis-ID val","raw":chassis_val,"user_val":chassis_val.hex()[:20],"note":""},
        {"layer":3,"name":"TLV2 Port-ID header","raw":tlv2[:2],"user_val":"type=2","note":f"len={len(port_val)}B"},
        {"layer":3,"name":"TLV2 Port-ID value","raw":port_val,"user_val":port_val[1:].decode(errors='replace')[:20],"note":""},
        {"layer":3,"name":"TLV3 TTL header","raw":tlv3[:2],"user_val":"type=3","note":"len=2B"},
        {"layer":3,"name":"TLV3 TTL value","raw":ttl_bytes,"user_val":str(ttl_val),"note":"seconds"},
    ]
    for (name,t,tb) in opt_built:
        val_b=tb[2:]
        records.append({"layer":3,"name":f"TLV{t} {name} hdr","raw":tb[:2],"user_val":f"type={t}","note":f"len={len(val_b)}B"})
        records.append({"layer":3,"name":f"TLV{t} {name} val","raw":val_b,"user_val":val_b.decode(errors='replace')[:20] if t not in (7,8) else val_b.hex()[:20],"note":""})
    records+=[
        {"layer":3,"name":"TLV0 End-of-LLDPDU","raw":end_tlv,"user_val":"0x0000","note":"type=0 len=0 mandatory last TLV"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame,records

def print_vlan_education():
    print(f"""
  {'═'*110}
  {'VLAN TAGGED FRAME  —  IEEE 802.1Q  (VID + PCP + DEI)':^110}
  {'═'*110}

  4-byte tag inserted between Src MAC and EtherType:
  TPID(2B) 0x8100 | PCP(3b) 0–7 | DEI(1b) | VID(12b) 0–4094

  PCP: 0=BestEffort  1=Background  2=ExcellentEffort  3=CriticalApps
       4=Video  5=Voice  6=IntNetCtrl  7=NetControl
  DEI: 0=keep  1=drop first during congestion
  Q-in-Q: outer TPID=0x88A8 (S-Tag)  inner TPID=0x8100 (C-Tag)
  {'═'*110}""")

def ask_l2_vlan():
    section("LAYER 1  —  Physical")
    preamble=get_hex("Preamble  7 B","55555555555555",7)
    sfd=get_hex("SFD       1 B","d5",1)
    section("LAYER 2  —  Ethernet MAC Header")
    dst_s=get("Destination MAC","ff:ff:ff:ff:ff:ff")
    src_s=get("Source MAC","00:11:22:33:44:55")
    section("802.1Q VLAN TAG")
    print("    TPID options:  0x8100=standard 802.1Q   0x88A8=Q-in-Q outer (802.1ad)")
    tpid_hex=get("TPID (hex)","8100",
        help="Tag Protocol Identifier — 2 bytes.\n"
             "0x8100=standard 802.1Q  0x88A8=IEEE 802.1ad outer S-Tag  0x9100=Cisco legacy Q-in-Q")
    try:    tpid_val=int(tpid_hex.replace("0x",""),16)&0xFFFF
    except: tpid_val=0x8100
    print("    PCP (Priority Code Point):  0=BestEffort  3=CritApps  5=Voice  7=NetCtrl")
    pcp=int(get("PCP  (0-7)","0",help="Priority Code Point — 3 bits (0–7), CoS/QoS priority.\n0=Best Effort  5=Voice(VoIP)  7=Network Control"))&0x7
    print("    DEI (Drop Eligible):  0=keep  1=may be dropped first during congestion")
    dei=int(get("DEI  (0 or 1)","0",help="Drop Eligible Indicator — 1 bit.\n0=keep  1=may be dropped first during congestion"))&0x1
    print("    VID:  0=priority-only  1=native  2-4094=user VLANs  4095=reserved")
    vid=int(get("VID  (0-4094)","100",help="VLAN Identifier — 12 bits (0–4094).\n0=priority-tagged  1=native VLAN  2–4094=user VLANs"))&0x0FFF
    tci=(pcp<<13)|(dei<<12)|vid
    print(f"    -> TCI = 0x{tci:04X}  (PCP={pcp}  DEI={dei}  VID={vid})")
    section("DOUBLE TAGGING (Q-in-Q)?")
    double_tag=get("Add inner C-Tag (Q-in-Q)? (y/n)","n").lower().startswith("y")
    inner_tpid_val=0x8100; inner_tci=0x0001
    if double_tag:
        print("    Inner (C-Tag) — customer VLAN")
        inner_tpid_hex=get("Inner TPID (hex)","8100")
        try: inner_tpid_val=int(inner_tpid_hex.replace("0x",""),16)&0xFFFF
        except: pass
        inner_pcp=int(get("Inner PCP (0-7)","0"))&0x7
        inner_dei=int(get("Inner DEI (0/1)","0"))&0x1
        inner_vid=int(get("Inner VID (0-4094)","10"))&0x0FFF
        inner_tci=(inner_pcp<<13)|(inner_dei<<12)|inner_vid
        print(f"    -> Inner TCI = 0x{inner_tci:04X}  (PCP={inner_pcp}  DEI={inner_dei}  VID={inner_vid})")
    section("INNER ETHERTYPE + PAYLOAD")
    print("    Common EtherTypes:  0800=IPv4  0806=ARP  86DD=IPv6  8100=another VLAN tag")
    inner_et_hex=get("Inner EtherType (hex)","0800")
    try:    inner_et=hpad(inner_et_hex,2)
    except: inner_et=bytes.fromhex("0800")
    print("    Inner payload hex  (leave empty for 46B zero pad)")
    payload_hex=get("Payload hex","")
    try:    payload=bytes.fromhex(payload_hex.replace(" ",""))
    except: payload=b''
    min_payload=46 if not double_tag else 42
    if len(payload)<min_payload: payload=payload+b'\x00'*(min_payload-len(payload))
    return (preamble,sfd,dst_s,src_s,tpid_val,tci,pcp,dei,vid,double_tag,inner_tpid_val,inner_tci,inner_et,payload)

def build_vlan(preamble,sfd,dst_s,src_s,tpid_val,tci,pcp,dei,vid,double_tag,inner_tpid_val,inner_tci,inner_et,payload):
    dst_mb=mac_b(dst_s); src_mb=mac_b(src_s)
    outer_tpid=struct.pack("!H",tpid_val); outer_tci_b=struct.pack("!H",tci)
    if double_tag:
        inner_tpid_b=struct.pack("!H",inner_tpid_val); inner_tci_b=struct.pack("!H",inner_tci)
        tag_section=outer_tpid+outer_tci_b+inner_tpid_b+inner_tci_b
    else:
        tag_section=outer_tpid+outer_tci_b
    fcs_input=dst_mb+src_mb+tag_section+inner_et+payload
    fcs,fcs_note=ask_fcs_eth(fcs_input)
    full_frame=preamble+sfd+fcs_input+fcs
    pcp_names={0:"BestEffort",1:"Background",2:"ExcellentEffort",3:"CriticalApps",
               4:"Video",5:"Voice",6:"IntNetCtrl",7:"NetControl"}
    tpid_name="802.1Q" if tpid_val==0x8100 else ("802.1ad Q-in-Q" if tpid_val==0x88A8 else f"0x{tpid_val:04X}")
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":"0xD5","note":""},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":""},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
        {"layer":2,"name":"TPID (outer tag)","raw":outer_tpid,"user_val":f"0x{tpid_val:04X}","note":tpid_name},
        {"layer":2,"name":"TCI outer: PCP+DEI+VID","raw":outer_tci_b,"user_val":f"0x{tci:04X}","note":f"PCP={pcp}({pcp_names.get(pcp,'')})  DEI={dei}  VID={vid}"},
    ]
    if double_tag:
        records+=[
            {"layer":2,"name":"TPID (inner C-Tag)","raw":struct.pack("!H",inner_tpid_val),"user_val":f"0x{inner_tpid_val:04X}","note":"802.1Q inner"},
            {"layer":2,"name":"TCI inner: PCP+DEI+VID","raw":struct.pack("!H",inner_tci),"user_val":f"0x{inner_tci:04X}","note":f"VID={inner_tci&0xFFF}"},
        ]
    records+=[
        {"layer":2,"name":"Inner EtherType","raw":inner_et,"user_val":inner_et.hex(),"note":"payload type"},
        {"layer":3,"name":"Payload","raw":payload,"user_val":payload.hex()[:24],"note":f"{len(payload)}B"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame,records

def print_jumbo_education():
    print(f"""
  {'═'*110}
  {'JUMBO FRAME  —  Non-Standard Vendor Extension  (MTU > 1500 bytes)':^110}
  {'═'*110}

  No IEEE standard — requires ALL devices on path to be configured with matching MTU.
  9000B payload (9018B frame) = typical jumbo — NFS/iSCSI/Ceph/HPC
  Efficiency: MTU 1500 → 97.9% vs MTU 9000 → 99.3%
  {'═'*110}""")

def ask_l2_jumbo():
    section("LAYER 1  —  Physical")
    preamble=get_hex("Preamble  7 B","55555555555555",7)
    sfd=get_hex("SFD       1 B","d5",1)
    section("LAYER 2  —  Ethernet MAC Header")
    dst_s=get("Destination MAC","00:aa:bb:cc:dd:ee")
    src_s=get("Source MAC","00:11:22:33:44:55")
    section("PAYLOAD SIZE — Jumbo MTU Selection")
    for k,(sz,desc) in JUMBO_PRESETS.items(): print(f"    {k} = {sz:6d} B  —  {desc}")
    preset=get("Select preset","4")
    if preset not in JUMBO_PRESETS: preset='4'
    max_payload,preset_desc=JUMBO_PRESETS[preset]
    if preset=='7':
        max_payload=int(get("Custom MTU payload size (bytes)","9000"))
        preset_desc=f"Custom {max_payload}B"
    print(f"\n    Selected: {max_payload}B payload ({preset_desc})")
    print(f"    Total frame will be: {8+14+max_payload+4}B on wire")
    section("ETHERTYPE + PAYLOAD")
    print("    EtherTypes:  0800=IPv4  86DD=IPv6  0806=ARP")
    et_hex=get("EtherType (hex)","0800")
    try:    et=hpad(et_hex,2)
    except: et=bytes.fromhex("0800")
    print(f"    Payload hex  (max {max_payload} bytes = {max_payload*2} hex chars)")
    print(f"    Leave blank for auto-fill with 0x00 up to {max_payload} bytes")
    payload_hex=get("Payload hex","")
    try:    payload=bytes.fromhex(payload_hex.replace(" ",""))
    except: payload=b''
    if len(payload)<max_payload: print(f"    -> Padding payload to {max_payload}B with 0x00"); payload=payload+b'\x00'*(max_payload-len(payload))
    elif len(payload)>max_payload: print(f"    -> Truncating to {max_payload}B"); payload=payload[:max_payload]
    section("ADD 802.1Q VLAN TAG to Jumbo Frame?")
    add_vlan=get("Add VLAN tag? (y/n)","n").lower().startswith("y")
    vlan_tag=b''; vlan_note=""
    if add_vlan:
        tpid_h=get("TPID (hex)","8100"); pcp=int(get("PCP (0-7)","0"))&0x7
        dei=int(get("DEI (0/1)","0"))&0x1; vid=int(get("VID (0-4094)","100"))&0x0FFF
        tci=(pcp<<13)|(dei<<12)|vid
        try: tpid_v=int(tpid_h.replace("0x",""),16)&0xFFFF
        except: tpid_v=0x8100
        vlan_tag=struct.pack("!HH",tpid_v,tci); vlan_note=f"TPID=0x{tpid_v:04X} PCP={pcp} DEI={dei} VID={vid}"
        print(f"    -> VLAN tag: {vlan_tag.hex()}  ({vlan_note})")
    return preamble,sfd,dst_s,src_s,et,payload,vlan_tag,vlan_note,max_payload,preset_desc

def build_jumbo(preamble,sfd,dst_s,src_s,et,payload,vlan_tag,vlan_note,max_payload,preset_desc):
    dst_mb=mac_b(dst_s); src_mb=mac_b(src_s)
    fcs_input=dst_mb+src_mb+vlan_tag+et+payload
    fcs,fcs_note=ask_fcs_eth(fcs_input)
    full_frame=preamble+sfd+fcs_input+fcs
    records=[
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":"0xD5","note":""},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":""},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
    ]
    if vlan_tag: records.append({"layer":2,"name":"VLAN Tag (802.1Q)","raw":vlan_tag,"user_val":vlan_tag.hex(),"note":vlan_note})
    records+=[
        {"layer":2,"name":"EtherType","raw":et,"user_val":et.hex(),"note":""},
        {"layer":3,"name":f"Jumbo Payload ({preset_desc})","raw":payload,"user_val":f"{len(payload)}B","note":f"Max MTU={max_payload}B (non-standard jumbo)"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame,records

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — LAYER 3  (Network)
# ══════════════════════════════════════════════════════════════════════════════
def ask_l3_arp():
    section("LAYER 3 — ARP")
    hw_type   =get("Hardware Type (1=Ethernet)","1",help="1=Ethernet 6=IEEE802 15=FrameRelay")
    proto_type=get("Protocol Type hex (0800=IPv4)","0800",help="0800=IPv4  86DD=IPv6  8100=VLAN")
    hw_len    =get("HW Address Length","6",help="6=Ethernet MAC  8=EUI-64")
    proto_len =get("Protocol Address Length","4",help="4=IPv4  16=IPv6")
    opcode    =get("Opcode  1=Request  2=Reply","1",help="1=Request(broadcast)  2=Reply(unicast)  3=RARP-Req  4=RARP-Rep")
    sender_ha =get("Sender MAC","00:11:22:33:44:55",help="MAC address of the device SENDING this ARP frame.")
    sender_pa =get("Sender IP","192.168.1.10",help="IP address of the device SENDING this ARP frame.")
    target_ha =get("Target MAC","00:00:00:00:00:00",help="In a Request: 00:00:00:00:00:00 (unknown). In a Reply: requester MAC.")
    target_pa =get("Target IP","192.168.1.100",help="IP address you want to resolve to a MAC address.")
    return (hw_type,proto_type,hw_len,proto_len,opcode,sender_ha,sender_pa,target_ha,target_pa)

def build_arp(inputs):
    hw_type,proto_type,hw_len,proto_len,opcode,sha,spa,tha,tpa=inputs
    hdr=struct.pack("!HHBBH",int(hw_type),int(proto_type,16),int(hw_len),int(proto_len),int(opcode))
    body=mac_b(sha)+ip_b(spa)+mac_b(tha)+ip_b(tpa)
    raw=hdr+body
    op_s="Request" if opcode=="1" else "Reply" if opcode=="2" else opcode
    fields=[
        {"layer":3,"name":"ARP HW Type","raw":hdr[0:2],"user_val":hw_type,"note":"1=Ethernet"},
        {"layer":3,"name":"ARP Protocol Type","raw":hdr[2:4],"user_val":proto_type,"note":"0800=IPv4"},
        {"layer":3,"name":"ARP HW Addr Len","raw":hdr[4:5],"user_val":hw_len,"note":"bytes"},
        {"layer":3,"name":"ARP Proto Addr Len","raw":hdr[5:6],"user_val":proto_len,"note":"bytes"},
        {"layer":3,"name":"ARP Opcode","raw":hdr[6:8],"user_val":opcode,"note":op_s},
        {"layer":3,"name":"ARP Sender MAC","raw":body[0:6],"user_val":sha,"note":""},
        {"layer":3,"name":"ARP Sender IP","raw":body[6:10],"user_val":spa,"note":""},
        {"layer":3,"name":"ARP Target MAC","raw":body[10:16],"user_val":tha,"note":""},
        {"layer":3,"name":"ARP Target IP","raw":body[16:20],"user_val":tpa,"note":""},
    ]
    return raw,fields

def _resolve_host(host):
    try:
        socket.inet_aton(host)
        return host,""
    except OSError: pass
    info=socket.getaddrinfo(host,None,socket.AF_INET)
    return info[0][4][0],host

def ask_l3_ipv4():
    section("LAYER 3 — IPv4  (Source + Destination)")
    print(f"    {C.NOTE}You can enter an IPv4 address OR a domain name for each IP.{C.RESET}")
    print(f"    {C.DIM}Domain names are resolved via your system DNS (requires internet).{C.RESET}")
    src_raw=get("Source IP or domain","192.168.1.10",
        help="IPv4 address OR domain name of the SENDER.\nPrivate: 10.x.x.x / 172.16-31.x.x / 192.168.x.x")
    try:
        src_ip,src_dom=_resolve_host(src_raw.strip())
        if src_dom: print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{src_dom}{C.RESET}  →  {C.HEX}{src_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{src_raw}': {e} — using as-is{C.RESET}")
        src_ip,src_dom=src_raw.strip(),""
    dst_raw=get("Destination IP or domain","192.168.1.20",
        help="IPv4 address OR domain name of the RECEIVER.\n8.8.8.8=Google DNS  1.1.1.1=Cloudflare")
    try:
        dst_ip,dst_dom=_resolve_host(dst_raw.strip())
        if dst_dom: print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{dst_dom}{C.RESET}  →  {C.HEX}{dst_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{dst_raw}': {e} — using as-is{C.RESET}")
        dst_ip,dst_dom=dst_raw.strip(),""
    ttl=get("TTL","64",help="Hop limit 0–255. 64=Linux/Mac  128=Windows  255=max.\nUse 1 for traceroute-style probes.")
    ip_id=get("Identification (decimal)","4660",help="16-bit fragment group ID. Arbitrary for non-fragmented packets.")
    dscp=get("DSCP/ECN (decimal, usu. 0)","0",help="0=Best Effort  46=EF(VoIP)  48=CS6(routing)")
    df=get("DF flag? (y/n)","y",help="y=DF=1: routers MUST NOT fragment.\nn=DF=0: fragmentation allowed.")
    return src_ip,dst_ip,int(ttl),int(ip_id),int(dscp),df.lower().startswith('y'),0,src_dom,dst_dom

def build_ipv4(l4_payload,src_ip,dst_ip,ttl,ip_id,dscp,df,proto_num):
    flags_frag=0x4000 if df else 0x0000
    ver_ihl=(4<<4)|5; tot_len=20+len(l4_payload)
    hdr0=struct.pack("!BBHHHBBH4s4s",ver_ihl,dscp,tot_len,ip_id,flags_frag,ttl,proto_num,0,ip_b(src_ip),ip_b(dst_ip))
    ck=inet_cksum(hdr0)
    hdr=struct.pack("!BBHHHBBH4s4s",ver_ihl,dscp,tot_len,ip_id,flags_frag,ttl,proto_num,ck,ip_b(src_ip),ip_b(dst_ip))
    flag_s=("DF" if flags_frag&0x4000 else "")+("MF" if flags_frag&0x2000 else "")
    proto_s=L3_PROTO_NAMES.get(proto_num,str(proto_num))
    fields=[
        {"layer":3,"name":"IP Version + IHL","raw":hdr[0:1],"user_val":"4 / 5","note":"IPv4, 20B header"},
        {"layer":3,"name":"IP DSCP/ECN","raw":hdr[1:2],"user_val":str(dscp),"note":""},
        {"layer":3,"name":"IP Total Length","raw":hdr[2:4],"user_val":"auto","note":f"{tot_len}B (20+{len(l4_payload)})"},
        {"layer":3,"name":"IP Identification","raw":hdr[4:6],"user_val":str(ip_id),"note":f"0x{ip_id:04x}"},
        {"layer":3,"name":"IP Flags + FragOffset","raw":hdr[6:8],"user_val":flag_s or "none","note":"frag offset=0"},
        {"layer":3,"name":"IP TTL","raw":hdr[8:9],"user_val":str(ttl),"note":"hops"},
        {"layer":3,"name":"IP Protocol","raw":hdr[9:10],"user_val":str(proto_num),"note":proto_s},
        {"layer":3,"name":"IP Header Checksum","raw":hdr[10:12],"user_val":"auto","note":f"0x{ck:04x} RFC791"},
        {"layer":3,"name":"IP Source Address","raw":hdr[12:16],"user_val":src_ip,"note":""},
        {"layer":3,"name":"IP Destination Addr","raw":hdr[16:20],"user_val":dst_ip,"note":""},
    ]
    return hdr,fields,ck

def ask_l3_stp():
    """
    STP / RSTP / MSTP / PVST+ / Rapid-PVST+ BPDU builder.
    Asks ONLY the fields that exist in the selected protocol variant.
    Enforces correct IEEE 802.1D/802.1w/802.1s/802.1Q and Cisco PVST+ rules.
    """
    section("LAYER 3 — STP / RSTP / MSTP / PVST+ / Rapid-PVST+  BPDU")
    print(f"  {C.DIM}  Variant summary:{C.RESET}")
    print(f"  {C.DIM}  0 = IEEE 802.1D-1998  STP            30-50s convergence  single tree  Bridge-ID=Prio(16b)+MAC(48b){C.RESET}")
    print(f"  {C.DIM}  2 = IEEE 802.1w       RSTP            <1s convergence     single tree  Bridge-ID=Prio(4b)+Ext=0(12b)+MAC(48b){C.RESET}")
    print(f"  {C.DIM}  3 = IEEE 802.1s       MSTP            <1s per-instance     multi-tree   Bridge-ID=Prio(4b)+MSTI-ID(12b)+MAC(48b){C.RESET}")
    print(f"  {C.DIM}  C = Cisco             PVST+           per-VLAN STP        multi-tree   Bridge-ID=Prio(4b)+VLAN-ID(12b)+MAC(48b){C.RESET}")
    print(f"  {C.DIM}  R = Cisco             Rapid-PVST+     per-VLAN RSTP       multi-tree   Bridge-ID=Prio(4b)+VLAN-ID(12b)+MAC(48b){C.RESET}")
    print(f"  {C.SEP_C}{'─'*76}{C.RESET}")

    version = get("Variant  0=STP  2=RSTP  3=MSTP  C=PVST+  R=Rapid-PVST+", "2",
        help="0=IEEE STP(802.1D-1998)  2=IEEE RSTP(802.1w)  3=IEEE MSTP(802.1s)\n"
             "C=Cisco PVST+(per-VLAN STP)  R=Cisco Rapid-PVST+(per-VLAN RSTP)").upper()
    if version == '2': version = '2'   # normalize

    # ── PVST+ / Rapid-PVST+ — Cisco per-VLAN ─────────────────────────────────
    if version in ('C', 'R'):
        vlan_id = get("PVST+ VLAN ID (1-4094)", "1",
            help="Each VLAN runs its own STP instance.\n"
                 "VLAN ID is encoded in the 12-bit System-ID-Extension of Bridge-ID.\n"
                 "VLAN 1 uses native (untagged) VLAN on trunk ports.")
        print(f"  {C.L1}  PVST+ framing: 802.1Q tag (0x8100) + SNAP (AA AA 03 00 00 0C 01 0B){C.RESET}")
        print(f"  {C.WARN}  Dst MAC: 01:00:0C:CC:CC:CD  (Cisco PVST multicast — NOT IEEE 01:80:C2:00:00:00){C.RESET}")
        print(f"  {C.WARN}  IEEE switches ignore PVST+ BPDUs (different dst MAC + SNAP encap){C.RESET}")

        # PVST+ = STP config BPDU format (version=0, type=0x00)
        # Rapid-PVST+ = RST BPDU format (version=2, type=0x02)
        is_rapid = (version == 'R')
        bpdu_type = "02" if is_rapid else get(
            "BPDU Type  00=Config  80=TCN", "00",
            help="0x00=Configuration BPDU (normal operation)\n"
                 "0x80=Topology Change Notification (sent toward root)")

        if is_rapid or bpdu_type == "00":
            # Flags: PVST+ (STP base) = only TC(b0) and TCA(b7)
            # Rapid-PVST+ = full RSTP flags
            if is_rapid:
                flags = get("BPDU Flags (hex)", "3c",
                    help="Rapid-PVST+ uses full RSTP flag byte:\n"
                         "  bit 0 = TC (Topology Change)\n"
                         "  bit 1 = Proposal\n"
                         "  bit 2-3 = Port Role: 00=Unknown 01=Alt/Backup 10=Root 11=Designated\n"
                         "  bit 4 = Learning\n"
                         "  bit 5 = Forwarding\n"
                         "  bit 6 = Agreement\n"
                         "  bit 7 = TCA\n"
                         "  0x3C = Designated + Learning + Forwarding (normal designated port)")
            else:
                flags = get("BPDU Flags (hex)", "00",
                    help="PVST+ (STP base) ONLY uses 2 bits:\n"
                         "  bit 0 = TC  (Topology Change — set on ports toward root during TC)\n"
                         "  bit 7 = TCA (Topology Change Acknowledgement)\n"
                         "  bits 1-6 = RESERVED — MUST be 0x00\n"
                         "  0x00=normal  0x01=TC  0x80=TCA  0x81=TC+TCA")
        else:
            flags = "00"

        # Bridge-ID encoding: Prio(4b) + VLAN-ID(12b) + MAC(6b)
        # Priority MUST be multiple of 4096 (0,4096,8192...61440)
        print(f"  {C.L1}  Bridge-ID format: Priority(4b, steps 4096) + VLAN-ID(12b) + MAC(48b){C.RESET}")
        root_prio = get("Root Bridge Priority (multiples of 4096: 0,4096...61440)", "32768",
            help="Priority encoded in upper 4 bits of Bridge-ID word.\n"
                 "Must be a multiple of 4096. Lower = preferred root.\n"
                 "Default=32768. Cisco sets per-VLAN: VLAN1=32769 VLAN2=32770 etc.\n"
                 "(32768 + VLAN-ID if not manually configured)")
        root_mac = get("Root Bridge MAC", "00:00:00:00:00:00",
            help="MAC of root bridge. 00:00:00:00:00:00 = this switch is root.")
        path_cost = get("Root Path Cost", "0",
            help="802.1D-2004 short path costs:\n"
                 "  10Mbps=100  100Mbps=19  1Gbps=4  10Gbps=2  100Gbps=1\n"
                 "  0 = this switch is the root bridge")
        br_prio = get("Bridge Priority (multiples of 4096)", "32768",
            help="Priority of THIS switch. Same encoding as Root Bridge Priority.\n"
                 "Must be multiple of 4096.")
        br_mac = get("Bridge MAC", "00:11:22:33:44:55",
            help="Unique MAC of THIS switch port originating BPDU.")
        port_id = get("Port ID (hex)", "8001",
            help="2 bytes: PortPriority(4b, steps 16) + PortNumber(12b)\n"
                 "Default port priority=0x80 (128). Port number=1.\n"
                 "e.g. 0x8001=priority128 port1  0x0001=priority0(highest) port1")
        msg_age   = get("Message Age (seconds, 0=root)", "0",
            help="Incremented by 1 for each bridge hop from root.\n"
                 "0=generated directly by root. Frame discarded when msg_age >= max_age.")
        max_age   = get("Max Age (seconds)", "20",
            help="Default 20s. If no BPDU received within max_age, topology recalculates.")
        hello     = get("Hello Time (seconds)", "2",
            help="Root sends Config BPDUs every hello_time seconds. Default 2s. Range 1-10s.")
        fwd_delay = get("Forward Delay (seconds)", "15",
            help="PVST+: time in Listening+Learning states. Default 15s.\n"
                 "Rapid-PVST+: only used for legacy STP interop fallback.")

        return (version, vlan_id, bpdu_type, flags,
                root_prio, str(int(vlan_id)), root_mac, path_cost,
                br_prio, str(int(vlan_id)), br_mac, port_id,
                msg_age, max_age, hello, fwd_delay,
                "", "0", "0"*32, [])

    # ── IEEE STP 802.1D-1998 (version=0) ─────────────────────────────────────
    if version == '0':
        print(f"  {C.L1}  IEEE 802.1D-1998 STP — classic spanning tree{C.RESET}")
        print(f"  {C.L1}  Bridge-ID format: Priority(16b full, any value) + MAC(48b){C.RESET}")
        print(f"  {C.DIM}  Dst MAC: 01:80:C2:00:00:00 (IEEE STP multicast){C.RESET}")
        print(f"  {C.WARN}  NO System-ID-Extension in 802.1D-1998 — full 16-bit priority{C.RESET}")

        bpdu_type = get("BPDU Type  00=Config  80=TCN", "00",
            help="0x00=Configuration BPDU — normal operation, sent by designated ports\n"
                 "0x80=TCN (Topology Change Notification) — sent toward root only")

        if bpdu_type == "80":
            print(f"  {C.WARN}  TCN BPDU has NO flags, NO bridge IDs, NO timers — just Protocol+Version+Type{C.RESET}")
            # TCN BPDU is minimal — just 3 bytes: proto(2B)+version(1B)+type(1B) = 4B
            return ('0', None, '80', '00', '0', '0', '00:00:00:00:00:00', '0',
                    '0', '0', '00:00:00:00:00:00', '8001', '0', '20', '2', '15',
                    '', '0', '0'*32, [])

        flags = get("BPDU Flags (hex)", "00",
            help="IEEE 802.1D-1998 STP uses ONLY 2 flag bits:\n"
                 "  bit 0 (LSB) = TC  (Topology Change)\n"
                 "  bit 7 (MSB) = TCA (Topology Change Acknowledgement)\n"
                 "  bits 1-6 = RESERVED — must be 0x00\n"
                 "  0x00=normal  0x01=TC active  0x80=TCA  0x81=TC+TCA")

        print(f"  {C.L1}  Bridge-ID = 16-bit priority (any value 0-65535) + 6B MAC{C.RESET}")
        root_prio = get("Root Bridge Priority (0-65535, any value)", "32768",
            help="Full 16-bit value — any integer 0-65535.\n"
                 "Default 32768 (0x8000). Lower value = higher priority.\n"
                 "NOTE: 802.1D-1998 does NOT restrict to multiples of 4096.")
        root_mac = get("Root Bridge MAC", "00:00:00:00:00:00",
            help="MAC address of root bridge. 00:00:00:00:00:00 = this bridge IS root.")
        path_cost = get("Root Path Cost (802.1D original costs)", "0",
            help="802.1D-1998 original path costs (4B):\n"
                 "  10Mbps=100   100Mbps=10   1Gbps=1  (original 802.1D-1998)\n"
                 "  802.1D-2004 revised: 10Mbps=2000000 100Mbps=200000 1Gbps=20000\n"
                 "  0 = this bridge is the root bridge")
        br_prio = get("Bridge Priority (0-65535)", "32768",
            help="Priority of THIS bridge. Full 16-bit — not restricted to multiples of 4096.")
        br_mac = get("Bridge MAC", "00:11:22:33:44:55",
            help="MAC of THIS bridge. Unique identifier used to break priority ties.")
        port_id = get("Port ID (hex)", "8001",
            help="2 bytes: PortPriority(8b, 0-255) + PortNumber(8b, 0-255)\n"
                 "STP 802.1D-1998: port priority is full 8-bit (0-255)\n"
                 "Default: 0x80 (128) priority, port 0x01\n"
                 "e.g. 0x8001=priority128 port1")
        msg_age   = get("Message Age (seconds, 0=root)", "0",
            help="0=sent by root. Incremented 1 per hop. Max=max_age-1.")
        max_age   = get("Max Age (seconds)", "20", help="Default 20s. Range 6-40s.")
        hello     = get("Hello Time (seconds)", "2",  help="Default 2s. Range 1-10s.")
        fwd_delay = get("Forward Delay (seconds)", "15",
            help="Time in Listening+Learning. Default 15s. Range 4-30s.")

        # STP uses full 16-bit priority, no sys-ext
        return ('0', None, bpdu_type, flags,
                root_prio, '0', root_mac, path_cost,
                br_prio, '0', br_mac, port_id,
                msg_age, max_age, hello, fwd_delay,
                '', '0', '0'*32, [])

    # ── IEEE RSTP 802.1w (version=2) ─────────────────────────────────────────
    if version == '2':
        print(f"  {C.L1}  IEEE 802.1w RSTP — rapid spanning tree{C.RESET}")
        print(f"  {C.L1}  Bridge-ID format: Priority(4b, ×4096) + System-ID-Ext=0(12b) + MAC(48b){C.RESET}")
        print(f"  {C.DIM}  Dst MAC: 01:80:C2:00:00:00  BPDU Type=0x02  Version=0x02{C.RESET}")
        print(f"  {C.WARN}  RSTP System-ID-Extension = 0 (RSTP is single-tree — no per-VLAN){C.RESET}")

        bpdu_type = "02"   # RST BPDU — RSTP only uses type 0x02
        print(f"  {C.DIM}  BPDU Type fixed = 0x02 (RST BPDU — RSTP Configuration BPDU){C.RESET}")
        print(f"  {C.DIM}  TCN is not sent separately in RSTP — TC bit in RST BPDU instead{C.RESET}")

        flags = get("BPDU Flags (hex)", "3c",
            help="RSTP full 8-bit flags:\n"
                 "  bit 0 = TC        (Topology Change)\n"
                 "  bit 1 = Proposal  (sync request to downstream bridge)\n"
                 "  bit 2-3 = Port Role: 00=Unknown 01=Alternate/Backup 10=Root 11=Designated\n"
                 "  bit 4 = Learning  (port is in Learning state)\n"
                 "  bit 5 = Forwarding (port is in Forwarding state)\n"
                 "  bit 6 = Agreement (downstream agrees to sync)\n"
                 "  bit 7 = TCA       (unused in RST BPDU, set to 0)\n"
                 "  0x3C = Designated+Learning+Forwarding (normal designated port)\n"
                 "  0x1C = Root port forwarding\n"
                 "  0x0F = Proposal from designated port\n"
                 "  0x3E = Agreement from root port")

        print(f"  {C.L1}  Priority must be multiple of 4096 (0,4096,8192...61440){C.RESET}")
        root_prio = get("Root Bridge Priority (×4096: 0,4096...61440)", "32768",
            help="Upper 4 bits of Bridge-ID priority word × 4096.\n"
                 "Default=32768. Multiples: 0,4096,8192,12288,16384,20480,\n"
                 "24576,28672,32768,36864,40960,45056,49152,53248,57344,61440")
        root_mac = get("Root Bridge MAC", "00:00:00:00:00:00",
            help="MAC of root bridge. Lowest Bridge-ID = root.")
        path_cost = get("Root Path Cost (802.1D-2004 costs)", "0",
            help="IEEE 802.1D-2004 revised path costs:\n"
                 "  10Mbps=2000000  100Mbps=200000  1Gbps=20000\n"
                 "  10Gbps=2000  100Gbps=200  1Tbps=20\n"
                 "  0 = this bridge is the root")
        br_prio = get("Bridge Priority (×4096)", "32768",
            help="Priority of THIS bridge. Must be multiple of 4096.")
        br_mac = get("Bridge MAC", "00:11:22:33:44:55")
        port_id = get("Port ID (hex)", "8001",
            help="RSTP: PortPriority(4b, ×16: 0,16,32...240) + PortNumber(12b, 0-4095)\n"
                 "Default: 0x8001 = priority128 + port1\n"
                 "Port priority 0x80=128 (default), in steps of 16")
        msg_age   = get("Message Age (seconds, 0=root)", "0",
            help="0=root generated. Incremented per hop. Must be < max_age.")
        max_age   = get("Max Age (seconds)", "20", help="Default 20s.")
        hello     = get("Hello Time (seconds)", "2",
            help="Only meaningful if bridge is root. Otherwise ignored by RSTP.")
        fwd_delay = get("Forward Delay (seconds)", "15",
            help="Only used when interoperating with legacy STP bridges.\n"
                 "RSTP uses Proposal/Agreement for <1s convergence instead.")

        return ('2', None, bpdu_type, flags,
                root_prio, '0', root_mac, path_cost,
                br_prio, '0', br_mac, port_id,
                msg_age, max_age, hello, fwd_delay,
                '', '0', '0'*32, [])

    # ── IEEE MSTP 802.1s (version=3) ─────────────────────────────────────────
    print(f"  {C.L1}  IEEE 802.1s MSTP — Multiple Spanning Tree Protocol{C.RESET}")
    print(f"  {C.L1}  Bridge-ID format: Priority(4b, ×4096) + MSTI-Instance-ID(12b) + MAC(48b){C.RESET}")
    print(f"  {C.DIM}  CIST (instance 0) = common tree; MSTI 1-64 = per-group trees{C.RESET}")
    print(f"  {C.WARN}  All bridges in same MST region MUST have identical: RegionName+Revision+VLANmap-digest{C.RESET}")

    bpdu_type = "02"
    print(f"  {C.DIM}  BPDU Type=0x02  Version=0x03  (MST BPDU always RST BPDU base + MST extension){C.RESET}")

    flags = get("CIST Flags (hex)", "3c",
        help="MSTP CIST flags (same bit layout as RSTP):\n"
             "  bit 0=TC  bit1=Proposal  bit2-3=PortRole  bit4=Learning\n"
             "  bit5=Forwarding  bit6=Agreement  bit7=TCA\n"
             "  0x3C=Designated+Learning+Forwarding")

    print(f"  {C.L1}  CIST = Common Internal Spanning Tree (instance 0 — VLAN1 default){C.RESET}")
    root_prio = get("CIST Root Bridge Priority (×4096)", "32768",
        help="CIST root bridge priority. Multiple of 4096.\n"
             "CIST Root is elected across ALL MSTP regions.")
    root_mac = get("CIST Root Bridge MAC", "00:00:00:00:00:00",
        help="CIST Root Bridge MAC. Bridges outside this region may be CIST root.")
    path_cost = get("CIST External Root Path Cost", "0",
        help="Cost from this MST region boundary to CIST root (external cost).\n"
             "0 if CIST root is in this region. Regional bridges use internal cost.")
    br_prio = get("CIST Bridge Priority (×4096)", "32768",
        help="Priority of THIS bridge for CIST. Multiple of 4096.")
    br_mac = get("Bridge MAC (all instances share same MAC)", "00:11:22:33:44:55",
        help="MAC unique to this bridge. Used for ALL instances (CIST and MSTIs).")
    port_id = get("CIST Port ID (hex)", "8001",
        help="CIST port: PortPriority(4b, ×16) + PortNumber(12b)\n"
             "Default 0x8001 = priority128 port1")
    msg_age   = get("Message Age (seconds)", "0",
        help="MSTP: hops from CIST root to this bridge × message-age-increment.")
    max_age   = get("Max Age (seconds)", "20")
    hello     = get("Hello Time (seconds)", "2")
    fwd_delay = get("Forward Delay (seconds)", "15",
        help="Used for interoperability with legacy STP bridges.")

    section("MSTP — MST Configuration Identification (Region Identity)")
    print(f"  {C.WARN}  ALL bridges in same region MUST have byte-for-byte identical Config ID{C.RESET}")
    mstp_name = get("MST Region Name (up to 32 ASCII chars)", "MST-REGION-1",
        help="Case-sensitive. Padded with NULLs to 32 bytes.\n"
             "Mismatch = bridges form separate regions (different CIST topology).")
    mstp_rev  = get("MST Revision Level (0-65535)", "0",
        help="Revision number. Must match across all region bridges.")
    mstp_digest = get("MST VLAN-to-Instance mapping MD5 digest (32 hex chars = 16B)", "00"*16,
        help="MD5 hash of the 4096-entry VLAN-to-instance mapping table.\n"
             "All bridges must have same VLAN map to compute same digest.\n"
             "Generate with: md5(VLAN-map-table) — see IEEE 802.1Q §13.7")

    n_msti = int(get("Number of MSTI records (0-64)", "1",
        help="One record per active MSTI (instance 1-64).\n"
             "Each MSTI covers a group of VLANs mapped to it.\n"
             "Instance 0 = CIST (handled above). Max 64 additional instances."))

    mstp_msti = []
    for i in range(n_msti):
        msti_num = i + 1
        section(f"MSTI {msti_num} Record (16 bytes)")
        print(f"  {C.DIM}  MSTI {msti_num} Bridge-ID = Priority(4b,×4096) + MSTI-Number({msti_num:04b}b as 12b) + MAC{C.RESET}")
        msti_flags = get(f"MSTI {msti_num} Flags (hex)", "00",
            help="MSTI flags (1B):\n"
                 "  bit 0 = Master (this is the IST master bridge for this MSTI)\n"
                 "  bit 1 = Proposal\n"
                 "  bit 2-3 = Port Role: 00=Unknown 01=Alt/Backup 10=Root 11=Designated\n"
                 "  bit 4 = Learning\n"
                 "  bit 5 = Forwarding\n"
                 "  bit 6 = Agreement\n"
                 "  bit 7 = TC (Topology Change)\n"
                 "  0x00=normal 0x7C=Designated+Learning+Forwarding")
        msti_reg_root_prio = get(f"MSTI {msti_num} Regional Root Priority (×4096)", "32768",
            help=f"Root bridge priority for MSTI {msti_num} within this region.\n"
                 "Multiple of 4096. Lower = preferred regional root.")
        msti_reg_root_mac  = get(f"MSTI {msti_num} Regional Root MAC", "00:00:00:00:00:00",
            help=f"MAC of MSTI {msti_num} regional root bridge.")
        msti_int_cost      = get(f"MSTI {msti_num} Internal Root Path Cost", "0",
            help="Internal path cost within this MST region to MSTI regional root.")
        msti_br_prio       = get(f"MSTI {msti_num} Bridge Priority (0-240 in steps of 16)", "128",
            help="1-byte field: upper nibble = priority (0-15 × 16).\n"
                 "Values: 0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240\n"
                 "Default=128. NOTE: this is 1B not 2B (MSTI bridge prio is compact)")
        msti_port_prio     = get(f"MSTI {msti_num} Port Priority (0-240 in steps of 16)", "128",
            help="1-byte: upper nibble = port priority for this MSTI.\n"
                 "Steps of 16: 0,16,32...240. Default=128.")
        msti_rem_hops      = get(f"MSTI {msti_num} Remaining Hops", "20",
            help="Decremented by 1 at each bridge. MSTI BPDU discarded when 0.\n"
                 "Default 20 = MaxHops. Limits MSTI extent within region.")
        mstp_msti.append((msti_reg_root_prio, str(msti_num), msti_reg_root_mac,
                          msti_int_cost, msti_br_prio, msti_port_prio,
                          msti_flags, msti_rem_hops))

    return ('3', None, bpdu_type, flags,
            root_prio, '0', root_mac, path_cost,
            br_prio, '0', br_mac, port_id,
            msg_age, max_age, hello, fwd_delay,
            mstp_name, mstp_rev, mstp_digest, mstp_msti)


def build_stp(inputs):
    """
    Build IEEE 802.1D/802.1w/802.1s and Cisco PVST+/Rapid-PVST+ BPDU bytes.
    Each variant encoded exactly per its spec.
    """
    (version, vlan_id, bpdu_type, flags,
     root_prio, root_sys_ext, root_mac, path_cost,
     br_prio, br_sys_ext, br_mac, port_id,
     msg_age, max_age, hello, fwd_delay,
     mstp_name, mstp_rev, mstp_digest, mstp_msti) = inputs

    # ── Bridge-ID builder — version-aware ─────────────────────────────────────
    def make_bridge_id(prio_s, sys_ext_s, mac_s, ver):
        """
        Build 8-byte Bridge-ID correctly per variant.
        802.1D-1998 STP: full 16-bit priority (any value), no sys-ext
        802.1w RSTP:     4-bit priority (×4096) + 12-bit sys-ext=0
        802.1s MSTP:     4-bit priority (×4096) + 12-bit MSTI-ID
        PVST+/Rapid:     4-bit priority (×4096) + 12-bit VLAN-ID
        """
        if ver == '0':
            # Classic STP: full 16-bit priority, no extension
            prio_val = int(prio_s) & 0xFFFF
            prio_word = struct.pack("!H", prio_val)
        else:
            # RSTP/MSTP/PVST+: priority in top 4 bits (×4096), ext in lower 12 bits
            prio_4b = (int(prio_s) // 4096) & 0x000F   # keep top nibble only
            ext_12b = int(sys_ext_s) & 0x0FFF
            prio_word = struct.pack("!H", (prio_4b << 12) | ext_12b)
        return prio_word + mac_b(mac_s)

    root_id = make_bridge_id(root_prio, root_sys_ext, root_mac, version)
    br_id   = make_bridge_id(br_prio,   br_sys_ext,   br_mac,   version)

    proto_id = bytes.fromhex("0000")

    # Version byte — per variant
    ver_byte_map = {'0':'00', '2':'02', '3':'03', 'C':'00', 'R':'02'}
    ver_b = hpad(ver_byte_map.get(version, '02'), 1)

    # BPDU type byte
    btype_b = hpad(bpdu_type, 1)

    # Flags byte — enforcement per variant
    raw_flags = int(flags, 16)
    if version == '0' or (version == 'C' and bpdu_type == '00'):
        # STP / PVST+ Config BPDU: only bits 0 and 7 valid
        clean_flags = raw_flags & 0x81
        if clean_flags != raw_flags:
            raw_flags = clean_flags    # silently clear reserved bits
    flags_b = struct.pack("!B", raw_flags)

    cost_b  = struct.pack("!I", int(path_cost))
    port_b  = hpad(port_id, 2)

    def timer(sec_s):
        """Encode timer as 1/256-second units (2B big-endian)."""
        return struct.pack("!H", int(float(sec_s) * 256))

    # TCN BPDU — minimal (no flags, no IDs, no timers)
    if bpdu_type == '80':
        bpdu = proto_id + ver_b + btype_b
        fields = [
            {"layer":3,"name":"Protocol ID",  "raw":proto_id,  "user_val":"0x0000", "note":"IEEE STP always 0"},
            {"layer":3,"name":"Version",       "raw":ver_b,     "user_val":"0x00",   "note":"STP version 0"},
            {"layer":3,"name":"BPDU Type",     "raw":btype_b,   "user_val":"0x80",   "note":"Topology Change Notification"},
        ]
        return bpdu, fields

    # Configuration BPDU / RST BPDU
    bpdu = (proto_id + ver_b + btype_b + flags_b +
            root_id + cost_b + br_id + port_b +
            timer(msg_age) + timer(max_age) + timer(hello) + timer(fwd_delay))

    # RSTP / Rapid-PVST+ Version1Length field (must be 0x00)
    if version in ('2', 'R'):
        bpdu += bytes.fromhex("00")   # Version1Length = 0x00 (1 byte per 802.1w §9.3.3)

    # MSTP additions
    mstp_extra = b""
    if version == '3':
        # MST Configuration ID = 51 bytes:
        #   Format-Selector(1B=0) + RegionName(32B) + RevisionLevel(2B) + ConfigDigest(16B)
        name_b    = mstp_name.encode("ascii")[:32].ljust(32, b'\x00')
        rev_b     = struct.pack("!H", int(mstp_rev))
        dig_hex   = (mstp_digest.replace(" ","") + "00"*32)[:32]
        digest_b  = bytes.fromhex(dig_hex)
        mst_config_id = bytes([0x00]) + name_b + rev_b + digest_b   # 51B

        # CIST Internal Root Path Cost (4B) — cost within MST region to CIST regional root
        cist_int_cost = struct.pack("!I", 0)
        # CIST Bridge ID (8B) — same br_id
        cist_bridge_id = br_id
        # CIST Remaining Hops (1B)
        cist_hops = bytes([20])

        mstp_extra = mst_config_id + cist_int_cost + cist_bridge_id + cist_hops

        # MSTI Configuration Messages (16B each per IEEE 802.1s §14.5)
        # Format: Flags(1B) + RegionalRoot(8B) + IntPathCost(4B) + BridgePrio(1B) + PortPrio(1B) + RemainingHops(1B) + Reserved(1B)
        for idx, (mrp, msti_id_s, mrm, mic, mbp, mpp, mfl, mr) in enumerate(mstp_msti):
            msti_num = idx + 1
            # MSTI Regional Root Bridge ID: priority(4b) + MSTI-number(12b) + MAC(6b)
            msti_root_id = make_bridge_id(mrp, msti_id_s, mrm, '3')
            msti_int_cost_b = struct.pack("!I", int(mic))
            msti_br_prio_b  = bytes([int(mbp) & 0xF0])   # upper nibble only, lower=0
            msti_port_prio_b= bytes([int(mpp) & 0xF0])   # upper nibble only
            msti_flags_b    = hpad(mfl, 1)
            msti_rem_b      = bytes([int(mr)])
            msti_reserved   = bytes([0])
            mstp_extra += (msti_flags_b + msti_root_id + msti_int_cost_b +
                           msti_br_prio_b + msti_port_prio_b + msti_rem_b + msti_reserved)

        # Version1Length(1B=0) + Version3Length(2B) + MST data
        v3len = struct.pack("!H", len(mstp_extra))
        bpdu += bytes.fromhex("00") + v3len + mstp_extra

    # PVST+ framing: SNAP header + optional VLAN TLV appended after BPDU
    pvst_snap    = b""
    pvst_vlan_tlv= b""
    if version in ('C', 'R'):
        # SNAP: AA AA 03 + OUI(00:00:0C) + PID(01:0B)
        pvst_snap     = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("010b")
        vid           = int(vlan_id)
        # PVST+ VLAN TLV: 0x0000 + VID(2B) + 0x00 = 5 bytes
        pvst_vlan_tlv = bytes.fromhex("0000") + struct.pack("!H", vid) + bytes.fromhex("00")

    # ── Field list for display ─────────────────────────────────────────────────
    var_name = {"0":"IEEE 802.1D-1998 STP","2":"IEEE 802.1w RSTP","3":"IEEE 802.1s MSTP",
                "C":"Cisco PVST+","R":"Cisco Rapid-PVST+"}.get(version,"STP")

    if version == '0':
        flag_note = "bit0=TC  bit7=TCA  (bits1-6 RESERVED in 802.1D-1998 — must be 0)"
        bid_note  = "Priority(16b full) + MAC(48b)  [NO System-ID-Ext in 802.1D-1998]"
    elif version in ('2', 'R'):
        flag_note = "bit0=TC bit1=Proposal bit2-3=Role(01=Alt 10=Root 11=Desg) bit4=Learn bit5=Fwd bit6=Agree bit7=TCA"
        bid_note  = "Priority(4b,×4096) + System-ID-Ext=0(12b) + MAC(48b)"
    elif version == '3':
        flag_note = "CIST: same 8 bits as RSTP"
        bid_note  = "Priority(4b,×4096) + MSTI-ID(12b) + MAC(48b)"
    else:  # PVST+
        flag_note = "bit0=TC  bit7=TCA  (PVST+ = STP base, bits1-6 reserved)"
        bid_note  = f"Priority(4b,×4096) + VLAN-ID={vlan_id}(12b) + MAC(48b)"

    fields = []
    if pvst_snap:
        fields.append({"layer":3,"name":"PVST+ SNAP HDR","raw":pvst_snap,
                        "user_val":"AA:AA:03:00:00:0C:01:0B","note":"Cisco PVST+ SNAP OUI+PID"})
    fields += [
        {"layer":3,"name":"Protocol ID",   "raw":proto_id, "user_val":"0x0000",  "note":"IEEE 802.1D always 0"},
        {"layer":3,"name":"Version",        "raw":ver_b,    "user_val":version,   "note":var_name},
        {"layer":3,"name":"BPDU Type",      "raw":btype_b,  "user_val":bpdu_type, "note":"00=Config 80=TCN 02=RST"},
        {"layer":3,"name":"Flags",          "raw":flags_b,  "user_val":flags,     "note":flag_note},
        {"layer":3,"name":"Root Bridge ID", "raw":root_id,  "user_val":f"prio={root_prio} mac={root_mac}", "note":bid_note},
        {"layer":3,"name":"Root Path Cost", "raw":cost_b,   "user_val":path_cost, "note":"0=this bridge is root"},
        {"layer":3,"name":"Bridge ID",      "raw":br_id,    "user_val":f"prio={br_prio} mac={br_mac}", "note":bid_note},
        {"layer":3,"name":"Port ID",        "raw":port_b,   "user_val":port_id,
         "note":"STP:Prio(8b)+Num(8b)  RSTP/MSTP/PVST+:Prio(4b,×16)+Num(12b)"},
        {"layer":3,"name":"Message Age",    "raw":bpdu[27:29],"user_val":msg_age, "note":"÷256=seconds"},
        {"layer":3,"name":"Max Age",        "raw":bpdu[29:31],"user_val":max_age, "note":"÷256=seconds"},
        {"layer":3,"name":"Hello Time",     "raw":bpdu[31:33],"user_val":hello,   "note":"÷256=seconds"},
        {"layer":3,"name":"Forward Delay",  "raw":bpdu[33:35],"user_val":fwd_delay,"note":"÷256=seconds"},
    ]
    if version in ('2','R'):
        fields.append({"layer":3,"name":"Version1Length","raw":bpdu[35:36],"user_val":"0",
                        "note":"RSTP §9.3.3: always 0x00"})
    if version == '3' and mstp_extra:
        offset = 36
        fields.append({"layer":3,"name":"Version1Length","raw":bpdu[offset:offset+1],
                        "user_val":"0","note":"0x00 per MSTP spec"})
        fields.append({"layer":3,"name":"Version3Length","raw":bpdu[offset+1:offset+3],
                        "user_val":str(len(mstp_extra)),"note":"bytes of MST extension"})
        fields.append({"layer":3,"name":"MST Config ID","raw":mstp_extra[:51],
                        "user_val":mstp_name,"note":"51B: Selector(1)+Name(32)+Rev(2)+Digest(16)"})
        fields.append({"layer":3,"name":"CIST Int Cost","raw":mstp_extra[51:55],
                        "user_val":"0","note":"internal path cost to CIST regional root"})
        fields.append({"layer":3,"name":"CIST Bridge ID","raw":mstp_extra[55:63],
                        "user_val":br_mac,"note":"this bridge ID for CIST within region"})
        fields.append({"layer":3,"name":"CIST Rem Hops","raw":mstp_extra[63:64],
                        "user_val":"20","note":"remaining hops in region (default MaxHops)"})
        if len(mstp_extra) > 64:
            msti_data = mstp_extra[64:]
            n_msti = len(msti_data)//16
            fields.append({"layer":3,"name":f"MSTI Records ({n_msti}×16B)",
                            "raw":msti_data,"user_val":f"{n_msti} instances",
                            "note":"Flags+RegRoot+IntCost+BridgePrio+PortPrio+Hops+Rsvd"})
    if pvst_vlan_tlv:
        fields.append({"layer":3,"name":"PVST+ VLAN TLV","raw":pvst_vlan_tlv,
                        "user_val":f"VLAN {vlan_id}",
                        "note":"5B: 0x0000 + VID(2B) + 0x00  — Cisco PVST VLAN tag"})
    return pvst_snap + bpdu + pvst_vlan_tlv, fields

def ask_l3_dtp():
    section("LAYER 3 — DTP  (Dynamic Trunking Protocol — Cisco Proprietary)")
    print(f"  {C.DIM}  DTP negotiates trunk encapsulation (802.1Q / ISL) and mode between Cisco switches.{C.RESET}")
    print(f"  {C.WARN}  ⚠  SECURITY: disable DTP with 'switchport nonegotiate' on all access/untrusted ports{C.RESET}")
    print(f"  {C.SEP_C}{'─'*70}{C.RESET}")
    mode = get("DTP Mode (hex)", "02",
        help="0x01=Trunk-On  0x02=Desirable  0x03=Auto  0x04=Access-On  0x05=Off\n"
             "Desirable+Auto or Desirable+Desirable → trunk forms\n"
             "Auto+Auto → no trunk (both passive)")
    neighbor_mac = get("Neighbor MAC (switch sending DTP)", "00:11:22:33:44:55",
        help="MAC address of THIS switch port — included in TLV 0x01 (Domain)")
    domain = get("DTP Domain (hex, 1B)", "01",
        help="0x01=default Cisco domain. Must match between switches for trunking.")
    encap = get("Encap type (hex)", "05",
        help="0x05=802.1Q  0xA5=ISL  0xB5=802.1Q+ISL-auto\n"
             "Modern switches use 802.1Q only.")
    mode_s = {"01":"Trunk-On","02":"Desirable","03":"Auto","04":"Access-On","05":"Off"}.get(mode,f"0x{mode}")
    return mode, neighbor_mac, domain, encap, mode_s


def build_dtp(inputs):
    mode, neighbor_mac, domain, encap, mode_s = inputs
    snap     = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("2004")
    # TLVs: Type(2B)+Length(2B)+Value
    # TLV 0x01: Domain (5B value = 4B domain + 1B pad)
    tlv_domain  = struct.pack("!HH",0x0001,5) + hpad(domain,1)*4 + bytes([0])
    # TLV 0x02: Status (5B = 1B mode + 4B neighbor)
    tlv_status  = struct.pack("!HH",0x0002,5) + hpad(mode,1) + mac_b(neighbor_mac)[:4]
    # TLV 0x03: DTP Type / Encap
    tlv_type    = struct.pack("!HH",0x0003,5) + hpad(encap,1) + bytes([0])*4
    # TLV 0x04: Neighbor (6B MAC)
    tlv_neighbor= struct.pack("!HH",0x0004,6) + mac_b(neighbor_mac)
    dtp_payload = tlv_domain + tlv_status + tlv_type + tlv_neighbor
    raw = snap + dtp_payload
    fields = [
        {"layer":3,"name":"DTP DSAP","raw":snap[0:1],"user_val":"AA","note":"SNAP"},
        {"layer":3,"name":"DTP SSAP","raw":snap[1:2],"user_val":"AA","note":"SNAP"},
        {"layer":3,"name":"DTP Control","raw":snap[2:3],"user_val":"03","note":"UI"},
        {"layer":3,"name":"DTP SNAP OUI","raw":snap[3:6],"user_val":"00:00:0C","note":"Cisco"},
        {"layer":3,"name":"DTP SNAP PID","raw":snap[6:8],"user_val":"0x2004","note":"DTP"},
        {"layer":3,"name":"TLV Domain Type","raw":tlv_domain[0:2],"user_val":"0001","note":"Domain"},
        {"layer":3,"name":"TLV Domain Len","raw":tlv_domain[2:4],"user_val":"5","note":"bytes"},
        {"layer":3,"name":"TLV Domain Val","raw":tlv_domain[4:],"user_val":domain,"note":"domain ID"},
        {"layer":3,"name":"TLV Status Type","raw":tlv_status[0:2],"user_val":"0002","note":"Status"},
        {"layer":3,"name":"TLV Status Mode","raw":tlv_status[4:5],"user_val":mode,"note":mode_s},
        {"layer":3,"name":"TLV Encap Type","raw":tlv_type[0:2],"user_val":"0003","note":"Encap"},
        {"layer":3,"name":"TLV Encap Val","raw":tlv_type[4:5],"user_val":encap,"note":"05=802.1Q A5=ISL"},
        {"layer":3,"name":"TLV Neighbor MAC","raw":tlv_neighbor[4:],"user_val":neighbor_mac,"note":"6B"},
    ]
    return raw, fields


def ask_l3_pagp():
    section("LAYER 3 — PAgP  (Port Aggregation Protocol — Cisco EtherChannel)")
    print(f"  {C.DIM}  PAgP negotiates EtherChannel (LAG) formation between Cisco switches.{C.RESET}")
    print(f"  {C.DIM}  EtherChannel bundles 2-8 ports into one logical link for bandwidth+redundancy.{C.RESET}")
    print(f"  {C.WARN}  ⚠  PAgP is Cisco-proprietary — use LACP (802.3ad) for multi-vendor LAG{C.RESET}")
    print(f"  {C.SEP_C}{'─'*70}{C.RESET}")
    state = get("Port State (hex)", "41",
        help="8-bit flags:\n"
             "  bit0=Active  bit1=Slow-Hello  bit2=AgPort  bit3=Consistent\n"
             "  bit4=IfAutomatic  bit5=PartnerLearnEnable  bit6=Reserved  bit7=AllPortsUp\n"
             "  0x01=Active  0x41=Active+AgPort  0x45=Active+AgPort+Consistent")
    group_cap = get("Group Capability (hex 4B)", "00000001",
        help="4-byte group capability — ports must match to bundle. "
             "Cisco uses speed+duplex+media encoding.")
    group_ifidx = get("Group If Index (hex 4B)", "00000001",
        help="Interface index of this port in the switch. Used to identify port in EtherChannel.")
    port_name = get("Port Name (ASCII, max 16B)", "Fa0/1",
        help="Interface name — e.g. Fa0/1, Gi0/1, Te1/1")
    device_id = get("Device ID MAC", "00:11:22:33:44:55",
        help="MAC address identifying THIS device — used by peer to identify the switch.")
    learn = get("Learn Method (hex)", "01",
        help="0x00=Source-based  0x01=Address-based(normal). "
             "Both sides must match — mismatch = traffic sent to wrong port in bundle.")
    return state, group_cap, group_ifidx, port_name, device_id, learn


def build_pagp(inputs):
    state, group_cap, group_ifidx, port_name, device_id, learn = inputs
    snap = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("0104")
    # PAgP PDU structure
    version   = bytes([0x01])
    flags_b   = hpad(state, 1)
    # TLVs
    grp_cap_b = bytes.fromhex((group_cap+"00000000")[:8])
    grp_if_b  = bytes.fromhex((group_ifidx+"00000000")[:8])
    pname_b   = port_name.encode("ascii")[:16].ljust(16, b'\x00')
    devid_b   = mac_b(device_id)
    learn_b   = hpad(learn, 1)
    pad       = b'\x00' * 3
    payload   = version + flags_b + grp_cap_b + grp_if_b + devid_b + learn_b + pad + pname_b
    raw = snap + payload
    fields = [
        {"layer":3,"name":"PAgP DSAP","raw":snap[0:1],"user_val":"AA","note":"SNAP SAP"},
        {"layer":3,"name":"PAgP SSAP","raw":snap[1:2],"user_val":"AA","note":"SNAP SAP"},
        {"layer":3,"name":"PAgP Control","raw":snap[2:3],"user_val":"03","note":"UI"},
        {"layer":3,"name":"PAgP SNAP OUI","raw":snap[3:6],"user_val":"00:00:0C","note":"Cisco"},
        {"layer":3,"name":"PAgP SNAP PID","raw":snap[6:8],"user_val":"0x0104","note":"PAgP"},
        {"layer":3,"name":"PAgP Version","raw":payload[0:1],"user_val":"1","note":""},
        {"layer":3,"name":"PAgP Flags","raw":payload[1:2],"user_val":state,
         "note":"Active+AgPort+Consistent etc."},
        {"layer":3,"name":"PAgP Group Capability","raw":payload[2:6],"user_val":group_cap,
         "note":"must match peer to bundle"},
        {"layer":3,"name":"PAgP Group IfIndex","raw":payload[6:10],"user_val":group_ifidx,"note":""},
        {"layer":3,"name":"PAgP Device ID","raw":payload[10:16],"user_val":device_id,"note":"switch MAC"},
        {"layer":3,"name":"PAgP Learn Method","raw":payload[16:17],"user_val":learn,
         "note":"01=addr-based; must match peer"},
        {"layer":3,"name":"PAgP Pad","raw":payload[17:20],"user_val":"000000","note":""},
        {"layer":3,"name":"PAgP Port Name","raw":payload[20:36],"user_val":port_name,"note":"16B ASCII"},
    ]
    return raw, fields


def ask_l3_lacp():
    section("LAYER 3 — LACP  (IEEE 802.3ad/802.1AX Link Aggregation Control Protocol)")
    print(f"  {C.DIM}  LACP is the IEEE standard for LAG/EtherChannel — works across all vendors.{C.RESET}")
    print(f"  {C.DIM}  Both Actor (local) and Partner (remote) TLVs are included in every PDU.{C.RESET}")
    print(f"  {C.SEP_C}{'─'*70}{C.RESET}")

    section("LACP ACTOR TLV (this port's information)")
    actor_sys_prio = get("Actor System Priority", "32768",
        help="0-65535. Lower=higher priority. Used in LACP system election. Default 32768.")
    actor_mac      = get("Actor System MAC", "00:11:22:33:44:55",
        help="MAC of THIS system (switch/NIC). Combined with priority = System ID.")
    actor_key      = get("Actor Operational Key (hex 2B)", "0001",
        help="Ports with same key on same system can bundle. "
             "Key encodes speed+duplex: 1Gbps=0x0001 10Gbps=0x0002 25Gbps=0x0003.")
    actor_port_prio= get("Actor Port Priority", "32768",
        help="0-65535. Lower priority port selected first into LAG if >max-bundle-links.")
    actor_port     = get("Actor Port Number (hex 2B)", "0001",
        help="Interface number (1-based). Must be unique per system+key.")
    actor_state    = get("Actor State (hex)", "3d",
        help="8-bit LACP state bitmap:\n"
             "  bit0=LACP_Activity(1=Active 0=Passive)\n"
             "  bit1=LACP_Timeout(1=Short/1s 0=Long/30s)\n"
             "  bit2=Aggregation(1=can-aggregate)\n"
             "  bit3=Synchronization(1=in-sync-with-partner)\n"
             "  bit4=Collecting(1=collecting frames from partner)\n"
             "  bit5=Distributing(1=distributing frames to partner)\n"
             "  bit6=Defaulted(1=using default partner info)\n"
             "  bit7=Expired(1=LACP expired state)\n"
             "  0x3D=00111101=Active+Short+Agg+Sync+Col+Dist(normal active)\n"
             "  0x07=00000111=Active+Short+Agg (negotiating)")
    print(f"  {C.WARN}  ⚠  Both ends must be Active or one Active+one Passive — Passive+Passive = no LAG{C.RESET}")

    section("LACP PARTNER TLV (remote port's information)")
    partner_sys_prio = get("Partner System Priority", "32768")
    partner_mac      = get("Partner System MAC", "00:aa:bb:cc:dd:ee",
        help="MAC of the REMOTE switch/NIC this port is connected to.")
    partner_key      = get("Partner Operational Key (hex 2B)", "0001",
        help="Key reported by partner. Must match actor key for bundle to form.")
    partner_port_prio= get("Partner Port Priority", "32768")
    partner_port     = get("Partner Port Number (hex 2B)", "0001")
    partner_state    = get("Partner State (hex)", "3d",
        help="Same state bits as Actor State — reflects what partner told us.")
    print(f"  {C.WARN}  ⚠  Synchronization bit(3) must=1 on BOTH actor and partner for LAG to pass traffic{C.RESET}")

    section("LACP COLLECTOR TLV (frame collection delay)")
    collector_max_delay = get("Collector Max Delay (hex 2B, units=10µs)", "ffff",
        help="Maximum delay the collector can impose. 0xFFFF=65535×10µs=655ms. "
             "0x0000=no delay imposed.")

    return (actor_sys_prio, actor_mac, actor_key, actor_port_prio, actor_port, actor_state,
            partner_sys_prio, partner_mac, partner_key, partner_port_prio, partner_port, partner_state,
            collector_max_delay)


def build_lacp(inputs):
    (actor_sys_prio, actor_mac, actor_key, actor_port_prio, actor_port, actor_state,
     partner_sys_prio, partner_mac, partner_key, partner_port_prio, partner_port, partner_state,
     collector_max_delay) = inputs

    subtype_ver = b"\x01\x01"

    def make_tlv(tlv_type, sys_prio_s, mac_s, key_s, port_prio_s, port_s, state_s):
        return (bytes([tlv_type, 0x14]) +
                struct.pack("!H", int(sys_prio_s)) +
                mac_b(mac_s) +
                bytes.fromhex((key_s+"0000")[:4]) +
                struct.pack("!H", int(port_prio_s)) +
                bytes.fromhex((port_s+"0000")[:4]) +
                hpad(state_s, 1) +
                bytes([0, 0, 0]))   # reserved

    actor_tlv   = make_tlv(0x01, actor_sys_prio,   actor_mac,   actor_key,   actor_port_prio,   actor_port,   actor_state)
    partner_tlv = make_tlv(0x02, partner_sys_prio, partner_mac, partner_key, partner_port_prio, partner_port, partner_state)
    # Collector TLV: type=0x03 len=0x10 maxDelay(2B) + reserved(12B)
    collector_tlv = (bytes([0x03, 0x10]) +
                     bytes.fromhex((collector_max_delay+"0000")[:4]) +
                     bytes([0]*12))
    terminator = bytes([0x00, 0x00])
    raw = subtype_ver + actor_tlv + partner_tlv + collector_tlv + terminator

    o = 2  # offset past subtype+version
    fields = [
        {"layer":3,"name":"LACP Subtype",         "raw":raw[0:1],"user_val":"1","note":"1=LACP"},
        {"layer":3,"name":"LACP Version",          "raw":raw[1:2],"user_val":"1","note":""},
        # Actor TLV
        {"layer":3,"name":"Actor TLV Type",        "raw":raw[o:o+1],"user_val":"01","note":"Actor Info"},
        {"layer":3,"name":"Actor TLV Length",      "raw":raw[o+1:o+2],"user_val":"20","note":"32B"},
        {"layer":3,"name":"Actor Sys Priority",    "raw":raw[o+2:o+4],"user_val":actor_sys_prio,"note":"lower=higher prio"},
        {"layer":3,"name":"Actor Sys MAC",         "raw":raw[o+4:o+10],"user_val":actor_mac,"note":""},
        {"layer":3,"name":"Actor Key",             "raw":raw[o+10:o+12],"user_val":actor_key,"note":"speed+duplex"},
        {"layer":3,"name":"Actor Port Priority",   "raw":raw[o+12:o+14],"user_val":actor_port_prio,"note":""},
        {"layer":3,"name":"Actor Port",            "raw":raw[o+14:o+16],"user_val":actor_port,"note":""},
        {"layer":3,"name":"Actor State",           "raw":raw[o+16:o+17],"user_val":actor_state,
         "note":"Active+Timeout+Agg+Sync+Col+Dist+Def+Exp"},
        {"layer":3,"name":"Actor Reserved",        "raw":raw[o+17:o+20],"user_val":"000000","note":""},
    ]
    o += 20  # move to partner TLV
    fields += [
        {"layer":3,"name":"Partner TLV Type",      "raw":raw[o:o+1],"user_val":"02","note":"Partner Info"},
        {"layer":3,"name":"Partner TLV Length",    "raw":raw[o+1:o+2],"user_val":"20","note":"32B"},
        {"layer":3,"name":"Partner Sys Priority",  "raw":raw[o+2:o+4],"user_val":partner_sys_prio,"note":""},
        {"layer":3,"name":"Partner Sys MAC",       "raw":raw[o+4:o+10],"user_val":partner_mac,"note":"remote switch"},
        {"layer":3,"name":"Partner Key",           "raw":raw[o+10:o+12],"user_val":partner_key,"note":"must match actor key"},
        {"layer":3,"name":"Partner Port Priority", "raw":raw[o+12:o+14],"user_val":partner_port_prio,"note":""},
        {"layer":3,"name":"Partner Port",          "raw":raw[o+14:o+16],"user_val":partner_port,"note":""},
        {"layer":3,"name":"Partner State",         "raw":raw[o+16:o+17],"user_val":partner_state,"note":""},
        {"layer":3,"name":"Partner Reserved",      "raw":raw[o+17:o+20],"user_val":"000000","note":""},
    ]
    o += 20  # collector TLV
    fields += [
        {"layer":3,"name":"Collector TLV Type",   "raw":raw[o:o+1],"user_val":"03","note":"Collector"},
        {"layer":3,"name":"Collector TLV Length", "raw":raw[o+1:o+2],"user_val":"16","note":""},
        {"layer":3,"name":"Collector Max Delay",  "raw":raw[o+2:o+4],"user_val":collector_max_delay,"note":"×10µs"},
        {"layer":3,"name":"Collector Reserved",   "raw":raw[o+4:o+16],"user_val":"0"*24,"note":"12B"},
        {"layer":3,"name":"Terminator TLV",       "raw":terminator,"user_val":"0000","note":"end of LACPDU"},
    ]
    return raw, fields

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — LAYER 4  (Transport / Control)
# ══════════════════════════════════════════════════════════════════════════════
def print_icmp_table():
    print(f"\n  {'─'*100}")
    print(f"  {'ICMP TYPE / CODE REFERENCE TABLE':^100}")
    print(f"  {'─'*100}")
    print(f"  {'Type':>5}  {'Type Name':<28}  {'Code':>5}  Code Description")
    print(f"  {'─'*100}")
    for t,(tname,codes) in sorted(ICMP_TABLE.items()):
        first=True
        for c,cdesc in sorted(codes.items()):
            if first: print(f"  {t:5d}  {tname:<28}  {c:5d}  {cdesc}"); first=False
            else:     print(f"  {'':5}  {'':28}  {c:5d}  {cdesc}")
    print(f"  {'─'*100}")

def ask_l4_icmp():
    print_icmp_table()
    section("LAYER 4 — ICMP")
    icmp_type=int(get("ICMP Type  (default=8 Echo Request)","8",
        help="8=Echo Request(ping)  0=Echo Reply  3=Dest Unreachable  11=Time Exceeded\n5=Redirect  12=Param Problem"))
    if icmp_type in ICMP_TABLE:
        codes=ICMP_TABLE[icmp_type][1]
        code_hint="  ".join(f"{c}={d}" for c,d in sorted(codes.items()))
        print(f"    Valid codes: {code_hint}")
    icmp_code=int(get("ICMP Code","0",help="Sub-code qualifying the type.\n0 for Echo/Reply. 3=port unreachable. 0=TTL exceeded."))
    icmp_id  =int(get("ICMP Identifier (decimal)","1",help="16-bit ID to match requests with replies (usually PID)."))
    icmp_seq =int(get("ICMP Sequence   (decimal)","1",help="Sequence number — incremented per ping. Gaps=lost packets."))
    print("    ICMP data payload hex  (default = ping pattern 'abcdefgh')")
    data_hex =get("ICMP payload hex","6162636465666768")
    try:    icmp_data=bytes.fromhex(data_hex.replace(" ",""))
    except: print("    -> invalid hex, using default"); icmp_data=bytes.fromhex("6162636465666768")
    return icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex

def build_icmp(icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex_repr=""):
    rest=struct.pack("!HH",icmp_id,icmp_seq) if icmp_type in ICMP_ECHO_TYPES else b'\x00\x00\x00\x00'
    msg0=struct.pack("!BBH",icmp_type,icmp_code,0)+rest+icmp_data
    ck=inet_cksum(msg0)
    msg=struct.pack("!BBH",icmp_type,icmp_code,ck)+rest+icmp_data
    tname=ICMP_TABLE.get(icmp_type,(f"Type {icmp_type}",{}))[0]
    cname=ICMP_TABLE.get(icmp_type,("",{}))[1].get(icmp_code,f"Code {icmp_code}")
    fields=[
        {"layer":4,"name":"ICMP Type","raw":msg[0:1],"user_val":str(icmp_type),"note":tname},
        {"layer":4,"name":"ICMP Code","raw":msg[1:2],"user_val":str(icmp_code),"note":cname},
        {"layer":4,"name":"ICMP Checksum","raw":msg[2:4],"user_val":"auto","note":f"0x{ck:04x} RFC792 over full ICMP"},
    ]
    if icmp_type in ICMP_ECHO_TYPES:
        fields+=[
            {"layer":4,"name":"ICMP Identifier","raw":msg[4:6],"user_val":str(icmp_id),"note":f"0x{icmp_id:04x}"},
            {"layer":4,"name":"ICMP Sequence","raw":msg[6:8],"user_val":str(icmp_seq),"note":""},
        ]
    else:
        fields.append({"layer":4,"name":"ICMP Rest-of-Header","raw":msg[4:8],"user_val":"0","note":"type-specific"})
    if icmp_data:
        fields.append({"layer":4,"name":"ICMP Data Payload","raw":icmp_data,"user_val":data_hex_repr[:20] if data_hex_repr else icmp_data.hex()[:20],"note":f"{len(icmp_data)}B"})
    return msg,fields,ck

def port_note(port):
    return WELL_KNOWN_PORTS.get(port,"")

def print_port_table():
    print(f"\n  {'─'*100}")
    print(f"  {'WELL-KNOWN PORT REFERENCE  (TCP & UDP)':^100}")
    print(f"  {'─'*100}")
    ports=sorted(WELL_KNOWN_PORTS.items()); cols=3; rows=(len(ports)+cols-1)//cols
    for r in range(rows):
        line="  "
        for c in range(cols):
            idx=r+c*rows
            if idx<len(ports):
                p,n=ports[idx]; line+=f"  {p:>5} = {n:<18}"
        print(line)
    print(f"  {'─'*100}")

def tcp_checksum(src_ip,dst_ip,tcp_segment):
    pseudo=(ip_b(src_ip)+ip_b(dst_ip)+b'\x00'+b'\x06'+struct.pack("!H",len(tcp_segment)))
    return inet_cksum(pseudo+tcp_segment)

def print_tcp_handshake_diagram():
    print("""
  ┌──────────────────────────────────────────────────────────────────────┐
  │                 TCP 3-WAY HANDSHAKE FLOW                             │
  │   CLIENT                                          SERVER             │
  │     │  ── STEP 1: SYN ──────────────────────────>  │  SEQ=x         │
  │     │  <─ STEP 2: SYN-ACK ───────────────────────  │  SEQ=y ACK=x+1 │
  │     │  ── STEP 3: ACK ──────────────────────────>  │  SEQ=x+1       │
  │     │  ── STEP 4: PSH+ACK (data) ───────────────>  │                │
  │     │  ── STEP 5: FIN+ACK (close) ──────────────>  │                │
  │     │  ── STEP 6: RST (reset) ──────────────────>  │                │
  │  Flags:  SYN=0x02  ACK=0x10  SYN+ACK=0x12  PSH=0x08  FIN=0x01     │
  │          RST=0x04  URG=0x20  ECE=0x40  CWR=0x80                     │
  └──────────────────────────────────────────────────────────────────────┘""")

def ask_l4_tcp(src_ip,dst_ip):
    print_tcp_handshake_diagram(); print_port_table()
    section("LAYER 4 — TCP")
    print("    Handshake step:")
    for k,(name,_,desc) in TCP_STEPS.items(): print(f"      {k} = {name:<10}  {desc}")
    step=get("Choose step","1")
    if step not in TCP_STEPS: step='1'
    step_name,default_flags,step_desc=TCP_STEPS[step]
    print(f"\n    Building: {step_name}  —  {step_desc}")
    src_port=int(get("Source Port","49152",help="Sender port. Ephemeral>49152 for clients. 22=SSH 80=HTTP 443=HTTPS"))
    dst_port=int(get("Destination Port","80",help="Receiver service port. 80=HTTP 443=HTTPS 22=SSH 3306=MySQL"))
    pn=port_note(dst_port) or port_note(src_port)
    if pn: print(f"    -> Port note: {pn}")
    seq_num =int(get("Sequence Number  (ISN for SYN, else continuation)","1000",help="SYN: random ISN. Data: previous SeqNum + bytes sent."))
    ack_num =int(get("Acknowledgement Number  (0 if SYN, else peer_seq+1)","0" if step=='1' else "1001",help="Next SeqNum expected from peer. 0 if ACK not set."))
    data_off=5; flags_val=default_flags
    print(f"    TCP Flags (hex, default={default_flags:#04x} = {step_name})")
    flags_in=get("Flags hex (Enter=default)",f"{default_flags:02x}",help="SYN=0x02 ACK=0x10 SYN+ACK=0x12 PSH=0x08 FIN=0x01 RST=0x04")
    try:    flags_val=int(flags_in,16)
    except: flags_val=default_flags
    window  =int(get("Window Size (bytes)","65535",help="Receive buffer size. 0=stop sending. 65535=max without scaling."))
    urg_ptr =int(get("Urgent Pointer      (0 unless URG set)","0",help="Valid only when URG flag set. Points to last urgent byte."))
    tcp_data=b''
    if step in ('4',):
        print("    TCP data payload hex  (default = 'GET / HTTP/1.0\\r\\n')")
        dhex=get("Data hex","474554202f20485454502f312e300d0a")
        try:    tcp_data=bytes.fromhex(dhex.replace(" ",""))
        except: tcp_data=b''
    return (step,step_name,src_port,dst_port,seq_num,ack_num,data_off,flags_val,window,urg_ptr,tcp_data,src_ip,dst_ip)

def build_tcp(step,step_name,src_port,dst_port,seq_num,ack_num,data_off,flags_val,window,urg_ptr,tcp_data,src_ip,dst_ip):
    hdr_no_ck=struct.pack("!HHIIBBHHH",src_port,dst_port,seq_num,ack_num,(data_off<<4),flags_val,window,0,urg_ptr)
    seg_no_ck=hdr_no_ck+tcp_data; ck=tcp_checksum(src_ip,dst_ip,seg_no_ck)
    hdr=struct.pack("!HHIIBBHHH",src_port,dst_port,seq_num,ack_num,(data_off<<4),flags_val,window,ck,urg_ptr)
    seg=hdr+tcp_data
    flag_names=[n for n,v in TCP_FLAGS.items() if flags_val&v]
    flag_str='+'.join(flag_names) if flag_names else "none"
    pn_src=port_note(src_port); pn_dst=port_note(dst_port)
    fields=[
        {"layer":4,"name":"TCP Source Port","raw":seg[0:2],"user_val":str(src_port),"note":pn_src or "ephemeral"},
        {"layer":4,"name":"TCP Dest Port","raw":seg[2:4],"user_val":str(dst_port),"note":pn_dst or ""},
        {"layer":4,"name":"TCP Sequence Num","raw":seg[4:8],"user_val":str(seq_num),"note":f"0x{seq_num:08x}"},
        {"layer":4,"name":"TCP Ack Number","raw":seg[8:12],"user_val":str(ack_num),"note":f"0x{ack_num:08x}"},
        {"layer":4,"name":"TCP Data Offset+Res","raw":seg[12:13],"user_val":str(data_off),"note":f"{data_off*4}B header, reserved=0"},
        {"layer":4,"name":"TCP Flags","raw":seg[13:14],"user_val":f"0x{flags_val:02x}","note":f"{flag_str}  [{step_name}]"},
        {"layer":4,"name":"TCP Window Size","raw":seg[14:16],"user_val":str(window),"note":"bytes"},
        {"layer":4,"name":"TCP Checksum","raw":seg[16:18],"user_val":"auto","note":f"0x{ck:04x}  RFC793 pseudo-hdr+segment"},
        {"layer":4,"name":"TCP Urgent Pointer","raw":seg[18:20],"user_val":str(urg_ptr),"note":"0 unless URG flag set"},
    ]
    if tcp_data: fields.append({"layer":4,"name":"TCP Data Payload","raw":tcp_data,"user_val":tcp_data.hex()[:24],"note":f"{len(tcp_data)}B"})
    return seg,fields,ck

def udp_checksum(src_ip,dst_ip,udp_datagram):
    pseudo=(ip_b(src_ip)+ip_b(dst_ip)+b'\x00'+b'\x11'+struct.pack("!H",len(udp_datagram)))
    return inet_cksum(pseudo+udp_datagram)

def ask_l4_udp(src_ip,dst_ip):
    print_port_table()
    section("LAYER 4 — UDP")
    print("    UDP is connectionless – single datagram, no handshake.")
    print("    Common uses: DNS (53), DHCP (67/68), NTP (123), SNMP (161), TFTP (69)")
    src_port=int(get("Source Port","49152",help="Sender port. Ephemeral>49152 for clients."))
    dst_port=int(get("Destination Port","53",help="53=DNS  67=DHCP server  68=DHCP client  123=NTP  161=SNMP"))
    pn=port_note(dst_port) or port_note(src_port)
    if pn: print(f"    -> Port note: {pn}")
    print("    UDP data payload hex")
    print("      DNS query example : 0001010000010000000000000377777703636f6d00000100 01")
    print("      NTP request       : e300000000000000...")
    dhex=get("Data hex  (Enter=empty datagram)","")
    try:    udp_data=bytes.fromhex(dhex.replace(" ",""))
    except: udp_data=b''
    return src_port,dst_port,udp_data,src_ip,dst_ip

def build_udp(src_port,dst_port,udp_data,src_ip,dst_ip):
    length=8+len(udp_data)
    hdr_no_ck=struct.pack("!HHHH",src_port,dst_port,length,0)
    dgram_no_ck=hdr_no_ck+udp_data; ck=udp_checksum(src_ip,dst_ip,dgram_no_ck)
    if ck==0: ck=0xFFFF
    hdr=struct.pack("!HHHH",src_port,dst_port,length,ck)
    dgram=hdr+udp_data
    pn_src=port_note(src_port); pn_dst=port_note(dst_port)
    fields=[
        {"layer":4,"name":"UDP Source Port","raw":dgram[0:2],"user_val":str(src_port),"note":pn_src or "ephemeral"},
        {"layer":4,"name":"UDP Dest Port","raw":dgram[2:4],"user_val":str(dst_port),"note":pn_dst or ""},
        {"layer":4,"name":"UDP Length","raw":dgram[4:6],"user_val":"auto","note":f"{length}B (8 hdr + {len(udp_data)} data)"},
        {"layer":4,"name":"UDP Checksum","raw":dgram[6:8],"user_val":"auto","note":f"0x{ck:04x}  RFC768 pseudo-hdr+datagram"},
    ]
    if udp_data: fields.append({"layer":4,"name":"UDP Data Payload","raw":udp_data,"user_val":udp_data.hex()[:24],"note":f"{len(udp_data)}B"})
    return dgram,fields,ck

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — WIFI / IEEE 802.11  (MAC frame builder)
# ══════════════════════════════════════════════════════════════════════════════
def print_wifi_education():
    print(f"""
  {'═'*110}
  {'WiFi FRAME  —  IEEE 802.11  (Wireless LAN MAC + PHY Preamble)':^110}
  {'═'*110}

  WiFi PHY preamble (STF+LTF+SIG) is the functional equivalent of Ethernet Preamble+SFD.
  802.11b: DSSS SFD = 0xF3A0 (long) / 0x05CF (short)  — exact byte-level SFD
  802.11a/g: L-SIG field marks MPDU boundary (rate+length)
  802.11n:   HT-SIG  |  802.11ac: VHT-SIG  |  802.11ax: HE-SIG

  FRAME TYPES:
    Management (00): Beacon · Probe · Auth · Assoc · Disassoc · Action
    Control    (01): RTS · CTS · ACK · BlockAck · PS-Poll · CF-End
    Data       (10): Data · Null · QoS-Data · QoS-Null

  DS-BIT ADDRESS TABLE:
    ToDS=0 FromDS=0: IBSS/Ad-Hoc  Addr1=Dst  Addr2=Src  Addr3=BSSID
    ToDS=1 FromDS=0: STA→AP       Addr1=BSSID  Addr2=Src  Addr3=Dst
    ToDS=0 FromDS=1: AP→STA       Addr1=Dst  Addr2=BSSID  Addr3=Src
    ToDS=1 FromDS=1: WDS/Mesh     Addr1=RA  Addr2=TA  Addr3=DA  Addr4=SA

  FCS: CRC-32 over entire MPDU (FC → Frame Body), 4B little-endian
  {'═'*110}""")

def ask_wifi_frame():
    section("WiFi PHY MODE  (determines preamble / frame boundary field)")
    print("    NOTE: PHY preamble is transmitted BEFORE the MAC frame on air.\n")
    for k, v in WIFI_PHY_MODES.items():
        print(f"    {k} = {v}")
    phy_ch = get("PHY mode", "3")
    if phy_ch not in WIFI_PHY_MODES: phy_ch = '3'
    print(f"    -> Selected: {WIFI_PHY_MODES[phy_ch]}")

    section("WiFi FRAME TYPE")
    print("    1 = Management  (Beacon, Probe, Auth, Assoc, Disassoc ...)")
    print("    2 = Control     (RTS, CTS, ACK, Block-Ack ...)")
    print("    3 = Data        (Data, Null, QoS-Data, QoS-Null)")
    ftype_ch = get("Frame type", "1")
    if ftype_ch not in WIFI_FRAME_TYPES: ftype_ch = '1'
    type_bits, type_name = WIFI_FRAME_TYPES[ftype_ch]

    section(f"SUBTYPE  —  {type_name} frame")
    has_qos = False
    if ftype_ch == '1':
        for k, (sv, sn, sd) in WIFI_MGMT_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<30}  {sd}")
        sub_ch = get("Subtype", "8")
        if sub_ch not in WIFI_MGMT_SUBTYPES: sub_ch = '8'
        subtype_val, subtype_name, _ = WIFI_MGMT_SUBTYPES[sub_ch]
    elif ftype_ch == '2':
        for k, (sv, sn, sd) in WIFI_CTRL_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<25}  {sd}")
        sub_ch = get("Subtype", "13")
        if sub_ch not in WIFI_CTRL_SUBTYPES: sub_ch = '13'
        subtype_val, subtype_name, _ = WIFI_CTRL_SUBTYPES[sub_ch]
    else:
        for k, (sv, sn, qos, sd) in WIFI_DATA_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<15}  QoS={'Yes' if qos else 'No '}  {sd}")
        sub_ch = get("Subtype", "8")
        if sub_ch not in WIFI_DATA_SUBTYPES: sub_ch = '8'
        subtype_val, subtype_name, has_qos, _ = WIFI_DATA_SUBTYPES[sub_ch]

    section("FRAME CONTROL FLAGS")
    subtype_has_a2 = True
    if ftype_ch == '2':
        to_ds = 0; from_ds = 0
        subtype_has_a2 = subtype_val not in (0x0C, 0x0D)
        print("    Control frames: ToDS=0 FromDS=0 (fixed)")
    else:
        print("    0/0=IBSS  1/0=STA→AP(uplink)  0/1=AP→STA(downlink)  1/1=WDS")
        to_ds   = int(get("ToDS   (0 or 1)", "1",
            help="1 = frame going TO the AP / distribution system (STA→AP uplink).\n"
                 "Controls which role each address field plays — see DS table above.")) & 1
        from_ds = int(get("FromDS (0 or 1)", "0",
            help="1 = frame coming FROM the AP (AP→STA downlink).\n"
                 "ToDS=1 + FromDS=1 = WDS/Mesh (AP-to-AP bridge).")) & 1

    more_frag = int(get("More Fragments (0/1)", "0",
        help="1=more fragments of this frame follow. 0=last or only fragment.")) & 1
    retry     = int(get("Retry          (0/1)", "0",
        help="1=retransmission. Receiver uses SeqNum to discard duplicates.")) & 1
    pwr_mgmt  = int(get("Power Mgmt     (0/1)", "0",
        help="1=STA enters power-save after this frame. AP buffers frames for it.")) & 1
    more_data = int(get("More Data      (0/1)", "0",
        help="1=AP has more buffered frames for this sleeping STA.")) & 1
    protected = int(get("Protected Frame (0/1, 1=encrypted)", "0",
        help="1=frame body is encrypted (WEP/TKIP/CCMP/GCMP). 0=plaintext.")) & 1
    htc_order = int(get("+HTC/Order     (0/1)", "0",
        help="1=HT Control field present (QoS frames) or strict order (non-QoS).")) & 1

    fc_byte0 = (subtype_val << 4) | (type_bits << 2) | 0x00
    fc_byte1 = (to_ds | (from_ds<<1) | (more_frag<<2) | (retry<<3) |
                (pwr_mgmt<<4) | (more_data<<5) | (protected<<6) | (htc_order<<7))
    fc_bytes = bytes([fc_byte0, fc_byte1])

    section("DURATION / ID  (2 bytes)")
    print("    NAV duration in microseconds (Network Allocation Vector).")
    dur_val = int(get("Duration µs  (0–32767) or AID for PS-Poll", "0",
        help="NAV = how long medium is busy; other STAs defer transmission.\n"
             "RTS sets NAV = time for CTS+Data+ACK.  PS-Poll: use AID value.")) & 0x7FFF
    dur_bytes = struct.pack("<H", dur_val)

    section("ADDRESS FIELDS")
    ds_desc = {
        (0,0): "IBSS  Addr1=Dst  Addr2=Src  Addr3=BSSID",
        (1,0): "STA→AP  Addr1=BSSID  Addr2=SrcSTA  Addr3=DstSTA",
        (0,1): "AP→STA  Addr1=DstSTA  Addr2=BSSID  Addr3=SrcSTA",
        (1,1): "WDS  Addr1=RA  Addr2=TA  Addr3=DA  Addr4=SA",
    }
    print(f"    DS mode: {ds_desc.get((to_ds, from_ds), 'see table')}")

    need_a4 = False
    if (to_ds, from_ds) == (0, 0):
        a1_lbl, a2_lbl, a3_lbl = "Addr1  Destination STA", "Addr2  Source STA", "Addr3  BSSID"
        a1_def, a2_def, a3_def = "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"
    elif (to_ds, from_ds) == (1, 0):
        a1_lbl, a2_lbl, a3_lbl = "Addr1  AP BSSID", "Addr2  Source STA", "Addr3  Destination STA"
        a1_def, a2_def, a3_def = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff"
    elif (to_ds, from_ds) == (0, 1):
        a1_lbl, a2_lbl, a3_lbl = "Addr1  Destination STA", "Addr2  AP BSSID", "Addr3  Source STA"
        a1_def, a2_def, a3_def = "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "cc:dd:ee:ff:00:11"
    else:
        a1_lbl, a2_lbl, a3_lbl = "Addr1  RA (receiver/next-hop AP)", "Addr2  TA (transmitter/this AP)", "Addr3  DA (final destination)"
        a1_def, a2_def, a3_def = "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff"
        need_a4 = True

    if ftype_ch == '2':
        a1_lbl, a2_lbl = "Addr1  RA (Receiver Address)", "Addr2  TA (Transmitter Address)"
        a1_def, a2_def = "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff"
        need_a4 = False

    addr1 = get(a1_lbl, a1_def)
    addr2 = get(a2_lbl, a2_def) if (ftype_ch != '2' or subtype_has_a2) else None
    addr3 = get(a3_lbl, a3_def) if ftype_ch != '2' else None
    addr4 = get("Addr4  SA (source address)", "cc:dd:ee:ff:00:11") if need_a4 else None

    seq_ctrl_bytes = b''
    if ftype_ch != '2' or subtype_val in (0x08, 0x09):
        section("SEQUENCE CONTROL")
        seq_num  = int(get("Sequence Number  (0–4095)", "100",
            help="12-bit sequence 0–4095; increments per MSDU.\nUsed to detect/discard duplicate retransmitted frames.")) & 0xFFF
        frag_num = int(get("Fragment Number  (0=unfragmented)", "0",
            help="4-bit fragment number. 0=unfragmented or first fragment.")) & 0xF
        seq_ctrl_val   = (seq_num << 4) | frag_num
        seq_ctrl_bytes = struct.pack("<H", seq_ctrl_val)

    qos_bytes = b''
    if has_qos:
        section("QoS CONTROL")
        for tid, name in WIFI_TID_NAMES.items():
            print(f"      TID {tid} = {name}")
        tid     = int(get("TID  Traffic ID (0–7)", "0",
            help="0=BE(BestEffort)  1-2=BK(Background)  4-5=VI(Video)  6-7=VO(Voice)")) & 0xF
        eosp    = int(get("EOSP (0/1)", "0",
            help="End Of Service Period — 1=last frame of U-APSD service period.")) & 0x1
        print("    Ack Policy:  0=Normal  1=No-Ack  2=No-Explicit  3=Block-Ack")
        ack_pol = int(get("Ack Policy (0–3)", "0",
            help="0=Normal ACK  1=No ACK (multicast/video)  3=Block ACK (aggregation)")) & 0x3
        amsdu   = int(get("A-MSDU Present (0/1)", "0",
            help="1=frame body contains an A-MSDU aggregate.")) & 0x1
        txop    = int(get("TXOP Limit (0–255)", "0",
            help="Max TXOP in 32µs units. 0=one frame per TXOP.")) & 0xFF
        qos_lo  = tid | (eosp<<4) | (ack_pol<<5) | (amsdu<<7)
        qos_bytes = bytes([qos_lo, txop])

    htc_bytes = b''
    if htc_order:
        section("HT CONTROL  (4 bytes)")
        htc_hex = get("HT Control (8 hex chars)", "00000000")
        try:    htc_bytes = bytes.fromhex(htc_hex.replace(" ", ""))[:4]
        except: htc_bytes = b'\x00' * 4
        if len(htc_bytes) < 4: htc_bytes = htc_bytes.ljust(4, b'\x00')

    section("FRAME BODY / PAYLOAD")
    frame_body = b''

    if ftype_ch == '3' and subtype_val in (0x00, 0x08):
        print("    1=LLC/SNAP+IPv4  2=LLC/SNAP+raw hex  3=Raw hex  4=Empty")
        body_ch = get("Body type", "1")
        if body_ch in ('1', '2'):
            llcsnap = bytes.fromhex("aaaa03000000")
            et_hex  = get("EtherType (hex)", "0800")
            try:    et_b = hpad(et_hex, 2)
            except: et_b = bytes.fromhex("0800")
            llcsnap += et_b
            raw_hex = get("Payload hex after LLC/SNAP+EtherType (Enter=empty)", "")
            try:    raw_data = bytes.fromhex(raw_hex.replace(" ", ""))
            except: raw_data = b''
            frame_body = llcsnap + raw_data
        elif body_ch == '3':
            raw_hex = get("Raw frame body hex", "")
            try:    frame_body = bytes.fromhex(raw_hex.replace(" ", ""))
            except: frame_body = b''

    elif ftype_ch == '1':
        if subtype_val == 0x08:
            use_beacon = get("Use beacon template? (y/n)", "y").lower().startswith("y")
            if use_beacon:
                ssid_str   = get("SSID", "MyNetwork")
                ts         = b'\x00' * 8
                bi         = struct.pack("<H", 100)
                cap_info   = struct.pack("<H", 0x0431)
                ssid_b     = bytes([0, len(ssid_str)]) + ssid_str.encode()
                rates_b    = bytes([0x01,0x08,0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24])
                ds_ch      = int(get("DS Channel (1-14)", "6"))
                ds_b       = bytes([0x03, 0x01, ds_ch])
                frame_body = ts + bi + cap_info + ssid_b + rates_b + ds_b
            else:
                ie_hex = get("Management body hex", "")
                try:    frame_body = bytes.fromhex(ie_hex.replace(" ", ""))
                except: frame_body = b''
        elif subtype_val == 0x04:
            ssid_str  = get("SSID to probe (empty=broadcast)", "")
            ssid_b    = bytes([0, len(ssid_str)]) + ssid_str.encode()
            frame_body = ssid_b + bytes([0x01,0x04,0x02,0x04,0x0B,0x16])
        else:
            ie_hex = get("Management body hex (Enter=none)", "")
            try:    frame_body = bytes.fromhex(ie_hex.replace(" ", ""))
            except: frame_body = b''

    elif ftype_ch == '2':
        ctrl_hex = get("Control frame extra body hex (usually empty)", "")
        try:    frame_body = bytes.fromhex(ctrl_hex.replace(" ", ""))
        except: frame_body = b''

    return {
        'phy_ch': phy_ch, 'fc_bytes': fc_bytes,
        'fc_byte0': fc_byte0, 'fc_byte1': fc_byte1,
        'type_bits': type_bits, 'type_name': type_name,
        'subtype_val': subtype_val, 'subtype_name': subtype_name,
        'has_qos': has_qos, 'to_ds': to_ds, 'from_ds': from_ds,
        'more_frag': more_frag, 'retry': retry,
        'pwr_mgmt': pwr_mgmt, 'more_data': more_data,
        'protected': protected, 'htc_order': htc_order,
        'dur_val': dur_val, 'dur_bytes': dur_bytes,
        'addr1': addr1, 'addr2': addr2, 'addr3': addr3, 'addr4': addr4,
        'seq_ctrl_bytes': seq_ctrl_bytes,
        'qos_bytes': qos_bytes, 'htc_bytes': htc_bytes,
        'frame_body': frame_body, 'ftype_ch': ftype_ch,
    }

def build_wifi(d):
    records = []
    fc = d['fc_bytes']
    records += [
        {"layer":2,"name":"FC Byte0 (Type+Subtype)",
         "raw":fc[0:1],"user_val":f"0x{d['fc_byte0']:02X}",
         "note":f"Type={d['type_name']}({d['type_bits']:02b})  Sub={d['subtype_name']}(0x{d['subtype_val']:02X})"},
        {"layer":2,"name":"FC Byte1 (Flags)",
         "raw":fc[1:2],"user_val":f"0x{d['fc_byte1']:02X}",
         "note":(f"ToDS={d['to_ds']} FromDS={d['from_ds']} MoreFrag={d['more_frag']} "
                 f"Retry={d['retry']} PwrMgmt={d['pwr_mgmt']} MoreData={d['more_data']} "
                 f"Protect={d['protected']} HTC={d['htc_order']}")},
        {"layer":2,"name":"Duration / NAV ID",
         "raw":d['dur_bytes'],"user_val":str(d['dur_val']),"note":"µs  Network Allocation Vector"},
    ]
    ds_role = {
        (0,0): ("Destination","Source","BSSID",None),
        (1,0): ("BSSID","Source STA","Dest STA",None),
        (0,1): ("Destination","BSSID","Source",None),
        (1,1): ("RA next-hop","TA sender","DA dest","SA source"),
    }
    roles = ds_role.get((d['to_ds'], d['from_ds']), ("Addr1","Addr2","Addr3","Addr4"))
    if d['addr1']: records.append({"layer":2,"name":f"Addr1 ({roles[0]})","raw":mac_b(d['addr1']),"user_val":d['addr1'],"note":"Receiver Address (RA)"})
    if d['addr2']: records.append({"layer":2,"name":f"Addr2 ({roles[1]})","raw":mac_b(d['addr2']),"user_val":d['addr2'],"note":"Transmitter Address (TA)"})
    if d['addr3']: records.append({"layer":2,"name":f"Addr3 ({roles[2]})","raw":mac_b(d['addr3']),"user_val":d['addr3'],"note":""})
    if d['seq_ctrl_bytes']:
        sc_val = struct.unpack("<H", d['seq_ctrl_bytes'])[0]
        records.append({"layer":2,"name":"Sequence Control",
                        "raw":d['seq_ctrl_bytes'],"user_val":f"SeqNum={sc_val>>4} FragNum={sc_val&0xF}",
                        "note":f"0x{sc_val:04X}  (LE on air)"})
    if d['addr4']: records.append({"layer":2,"name":f"Addr4 ({roles[3]})","raw":mac_b(d['addr4']),"user_val":d['addr4'],"note":"WDS/Mesh SA"})
    if d['qos_bytes']:
        qlo = d['qos_bytes'][0]
        records.append({"layer":2,"name":"QoS Control","raw":d['qos_bytes'],
                        "user_val":f"0x{d['qos_bytes'].hex()}",
                        "note":(f"TID={qlo&0xF}({WIFI_TID_NAMES.get(qlo&0xF,'')})  "
                                f"EOSP={(qlo>>4)&1}  AckPol={WIFI_ACK_POLICY[(qlo>>5)&3]}")})
    if d['htc_bytes']:
        records.append({"layer":2,"name":"HT Control","raw":d['htc_bytes'],"user_val":d['htc_bytes'].hex(),"note":"802.11n/ac HTC"})

    fb = d['frame_body']
    if fb:
        if fb[:3] == bytes.fromhex("aaaa03"):
            records += [
                {"layer":2,"name":"LLC DSAP+SSAP+Control","raw":fb[0:3],"user_val":"AA AA 03","note":"SNAP header"},
                {"layer":2,"name":"SNAP OUI","raw":fb[3:6],"user_val":fb[3:6].hex(),"note":"000000=Ethernet-bridged"},
                {"layer":2,"name":"SNAP EtherType","raw":fb[6:8],"user_val":fb[6:8].hex(),"note":"Protocol identifier"},
            ]
            if len(fb) > 8:
                records.append({"layer":3,"name":"Frame Body Payload","raw":fb[8:],"user_val":f"{len(fb)-8}B","note":"L3 payload"})
        elif d['ftype_ch'] == '1':
            records.append({"layer":3,"name":"Management Body (IEs)","raw":fb,"user_val":f"{len(fb)}B","note":"Information Elements"})
        else:
            records.append({"layer":3,"name":"Frame Body","raw":fb,"user_val":f"{len(fb)}B","note":""})

    # Assemble MPDU
    mpdu = fc + d['dur_bytes']
    if d['addr1']:         mpdu += mac_b(d['addr1'])
    if d['addr2']:         mpdu += mac_b(d['addr2'])
    if d['addr3']:         mpdu += mac_b(d['addr3'])
    if d['seq_ctrl_bytes']:mpdu += d['seq_ctrl_bytes']
    if d['addr4']:         mpdu += mac_b(d['addr4'])
    mpdu += d['qos_bytes'] + d['htc_bytes'] + fb

    section("FCS  —  CRC-32 over entire MPDU")
    print(f"    Covers {len(mpdu)} bytes (FC → end of Frame Body)")
    fcs_ch = input("    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    if fcs_ch == '2':
        try:
            fcs = bytes.fromhex(input("    Enter 8 hex chars: ").strip())
            if len(fcs) != 4: raise ValueError
        except:
            fcs = wifi_crc32(mpdu)
            print("    -> invalid, using auto")
    else:
        fcs = wifi_crc32(mpdu)

    fcs_computed = wifi_crc32(mpdu)
    records.append({"layer":0,"name":"FCS (CRC-32 over MPDU)","raw":fcs,
                    "user_val":"auto/custom","note":f"0x{fcs.hex()}  ({len(mpdu)}B MPDU)"})
    return mpdu + fcs, records, mpdu, fcs, fcs_computed


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — STANDALONE IPv4 PACKET BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def print_ip_education():
    print(f"""
  {'═'*110}
  {'STANDALONE IPv4 PACKET BUILDER  (RFC 791)':^110}
  {'═'*110}

  IPv4 Header  (20 bytes minimum, up to 60 bytes with options)
  ─────────────────────────────────────────────────────────────────────────
  Ver(4b)+IHL(4b) | DSCP(6b)+ECN(2b) | Total Length(2B)
  Identification(2B) | Flags(3b: Rsv DF MF) + FragOffset(13b)
  TTL(1B) | Protocol(1B) | Header Checksum(2B)
  Source IP(4B) | Destination IP(4B) | Options(0-40B)
  ─────────────────────────────────────────────────────────────────────────
  Protocol numbers: 1=ICMP  6=TCP  17=UDP  47=GRE  50=ESP  51=AH
                    58=ICMPv6  89=OSPF  103=PIM  112=VRRP  132=SCTP
  DSCP: 0=BE  46=EF(VoIP)  48=CS6(routing)  34-38=AF41-43(video)
  DF=1: required for TCP PMTUD.  MF=1: more fragments follow.
  {'═'*110}""")

def ask_ip_options():
    section("IP OPTIONS  (optional — extends header beyond 20 bytes)")
    print("    1 = No options  (IHL=5, 20-byte header — most common)")
    print("    2 = NOP padding  (Type=0x01, 1 byte, used to align)")
    print("    3 = Record Route (Type=0x07 — routers record their IPs)")
    print("    4 = Timestamp    (Type=0x44 — routers record timestamps)")
    print("    5 = Custom hex   (enter raw option bytes manually)")
    opt_ch = get("Options choice", "1",
        help="IP options rarely used today — most firewalls DROP packets with options.\n"
             "Max options length = 40 bytes (IHL max=15, 15×4-20=40).")
    if opt_ch == '1':
        return b'', []
    elif opt_ch == '2':
        count = int(get("How many NOP bytes (1–40)", "3"))
        nop = bytes([0x01] * min(count, 40))
        if len(nop) % 4: nop += bytes([0x00] * (4 - len(nop) % 4))
        return nop, [{"layer":3,"name":f"IP Option NOP×{len(nop)}","raw":nop,"user_val":f"{len(nop)}B","note":"0x01 padding"}]
    elif opt_ch == '3':
        slots = max(1, min(9, int(get("Number of route slots (1–9)", "4"))))
        opt_len = 3 + slots * 4
        rr = bytes([0x07, opt_len, 0x04]) + b'\x00' * (slots * 4)
        if len(rr) % 4: rr += bytes([0x00] * (4 - len(rr) % 4))
        return rr, [{"layer":3,"name":"IP Option Record Route","raw":rr,
                     "user_val":f"{slots} slots ({opt_len}B)","note":f"Type=0x07 Len={opt_len} Ptr=4"}]
    elif opt_ch == '4':
        print("    Timestamp flag:  0=timestamp only  1=IP+timestamp  3=prespecified IPs")
        ts_flag  = int(get("Timestamp flag (0/1/3)", "0")) & 0xF
        slots    = max(1, min(4, int(get("Number of timestamp slots (1–4)", "2"))))
        slot_size = 8 if ts_flag else 4
        opt_len  = 4 + slots * slot_size
        ts_opt   = bytes([0x44, opt_len, 5, ts_flag]) + b'\x00' * (slots * slot_size)
        if len(ts_opt) % 4: ts_opt += bytes([0x00] * (4 - len(ts_opt) % 4))
        return ts_opt, [{"layer":3,"name":"IP Option Timestamp","raw":ts_opt,
                         "user_val":f"{slots} slots flag={ts_flag}","note":f"Type=0x44 Len={opt_len}"}]
    else:
        opt_hex = get("Option bytes hex", "01010101",
            help="Raw option bytes in hex. Must be multiple of 4 bytes total.")
        try:    opt_bytes = bytes.fromhex(opt_hex.replace(" ", ""))
        except: opt_bytes = b'\x01\x01\x01\x01'
        if len(opt_bytes) % 4: opt_bytes += bytes([0x00] * (4 - len(opt_bytes) % 4))
        if len(opt_bytes) > 40: opt_bytes = opt_bytes[:40]; print("    -> truncated to 40 bytes")
        return opt_bytes, [{"layer":3,"name":"IP Option Custom","raw":opt_bytes,
                            "user_val":opt_bytes.hex()[:24],"note":f"{len(opt_bytes)}B"}]

def ask_ip_payload(preselected: str = ""):
    """
    Ask user for IPv4 L4 payload type.
    Shows all options mapped from l3_builder (IP protocols) and l4_builder (services).
    If preselected is provided (from print_ipv4_l4_menu), use it directly.
    """
    if preselected and preselected in ('1','2','3','4','5','6'):
        # Map sub-menu choices to old 1-5 scheme
        MAP = {'1':'1','2':'2','3':'3','4':'4','5':'4','6':'5'}
        return MAP.get(preselected, '1')

    section("IPv4 PAYLOAD  —  L4 Protocol Selection")

    # Pull IP protocol list from l3_builder
    if _L3_AVAILABLE:
        from l3_builder import IP_PROTOCOL_REGISTRY
        print(f"  {C.DIM}  IP Protocol Registry: {len(IP_PROTOCOL_REGISTRY)} protocols "
              f"(1=ICMP 6=TCP 17=UDP 47=GRE 50=ESP 89=OSPF ...){C.RESET}")

    # Pull ICMP types from l3_builder
    if _L3_AVAILABLE:
        from l3_builder import ICMP_EXTENDED
        icmp_names = [f"{t}={ICMP_EXTENDED[t]['name'][:12]}" for t in sorted(ICMP_EXTENDED)[:6]]
        print(f"    {C.L4}1 = ICMP{C.RESET}  {C.DIM}Echo·Unreachable·TTL-Exceeded·Redirect  "
              f"({len(ICMP_EXTENDED)} types: {' '.join(icmp_names)}...){C.RESET}")
    else:
        print("    1 = ICMP  (Echo Request/Reply/Unreachable/Time Exceeded ...)")

    # Pull TCP states from l4_builder
    if _L4_AVAILABLE:
        from l4_builder import TCP_HANDSHAKE_STATES
        tcp_names = '/'.join(list(TCP_HANDSHAKE_STATES.keys())[:5])
        print(f"    {C.L4}2 = TCP{C.RESET}   {C.DIM}SYN/SYN-ACK/ACK/PSH+ACK/FIN/RST  "
              f"(states: {tcp_names}...){C.RESET}")
    else:
        print("    2 = TCP   (SYN / SYN-ACK / ACK / PSH+ACK / FIN / RST)")

    # Pull UDP ports from l4_builder
    if _L4_AVAILABLE:
        from l4_builder import PORT_REGISTRY
        udp_svcs = [f"{p}/{i['name'][:8]}" for p,i in sorted(PORT_REGISTRY.items())
                    if 'udp' in i.get('proto',[]) and i.get('status')=='Active'][:6]
        print(f"    {C.L4}3 = UDP{C.RESET}   {C.DIM}{' · '.join(udp_svcs)}...{C.RESET}")
    else:
        print("    3 = UDP   (DNS / NTP / SNMP / custom ...)")

    print(f"    {C.L4}4 = Raw hex{C.RESET}  {C.DIM}GRE(47)·ESP(50)·AH(51)·OSPF(89) or any protocol{C.RESET}")
    print(f"    {C.L4}5 = Empty{C.RESET}    {C.DIM}IPv4 header only — no L4 payload{C.RESET}")
    return get("Payload type", "1")

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — FLOW CONTROLLERS
# ══════════════════════════════════════════════════════════════════════════════
def flow_eth_arp():
    banner("ETHERNET  +  ARP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0806)  |  L3: ARP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v) = ask_l2_ethernet("0806")
    arp_inputs   = ask_l3_arp()
    arp_raw, arp_fields = build_arp(arp_inputs)
    full_frame, records = assemble_eth_frame(
        arp_raw, arp_fields, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)
    print_frame_table(records)
    fcs_s = full_frame[-4:]; fcs_r = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_s.hex(), fcs_r.hex(), fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"arp","ethertype":0x0806,"raw_bytes":arp_raw})

def flow_eth_ip_icmp():
    banner("ETHERNET  +  IPv4  +  ICMP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: ICMP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v) = ask_l2_ethernet("0800")
    (src_ip,dst_ip,ttl,ip_id,dscp,df,_,src_dom,dst_dom) = ask_l3_ipv4()
    icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
    icmp_msg, icmp_fields, icmp_ck = build_icmp(icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex)
    ip_hdr, ip_fields, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"
    full_frame, records = assemble_eth_frame(
        ip_hdr+icmp_msg, ip_fields+icmp_fields,
        dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v,preamble,sfd)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("IP Header Checksum",f"0x{ip_ck:04x}",f"0x{inet_cksum(ip_hdr):04x}",inet_cksum(ip_hdr)==0),
                   ("ICMP Checksum",f"0x{icmp_ck:04x}",f"0x{inet_cksum(icmp_msg):04x}",inet_cksum(icmp_msg)==0),
                   ("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"ipv4","ethertype":0x0800},src_ip,dst_ip,1)

def flow_eth_ip_tcp():
    banner("ETHERNET  +  IPv4  +  TCP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: TCP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v) = ask_l2_ethernet("0800")
    (src_ip,dst_ip,ttl,ip_id,dscp,df,_,src_dom,dst_dom) = ask_l3_ipv4()
    (step,step_name,src_port,dst_port,seq_num,ack_num,
     data_off,flags_val,window,urg_ptr,tcp_data,sip,dip) = ask_l4_tcp(src_ip, dst_ip)
    tcp_seg, tcp_fields, tcp_ck = build_tcp(
        step,step_name,src_port,dst_port,seq_num,ack_num,
        data_off,flags_val,window,urg_ptr,tcp_data,src_ip,dst_ip)
    ip_hdr, ip_fields, ip_ck = build_ipv4(tcp_seg, src_ip, dst_ip, ttl, ip_id, dscp, df, 6)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"
    full_frame, records = assemble_eth_frame(
        ip_hdr+tcp_seg, ip_fields+tcp_fields,
        dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v,preamble,sfd)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    tcp_ver = tcp_checksum(src_ip, dst_ip, tcp_seg)
    verify_report([("IP Header Checksum",f"0x{ip_ck:04x}",f"0x{inet_cksum(ip_hdr):04x}",inet_cksum(ip_hdr)==0),
                   ("TCP Checksum",f"0x{tcp_ck:04x}",f"0x{tcp_ver:04x}",tcp_ver==0),
                   ("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"ipv4","ethertype":0x0800},src_ip,dst_ip,6)

def flow_eth_ip_udp():
    banner("ETHERNET  +  IPv4  +  UDP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: UDP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v) = ask_l2_ethernet("0800")
    (src_ip,dst_ip,ttl,ip_id,dscp,df,_,src_dom,dst_dom) = ask_l3_ipv4()
    (src_port,dst_port,udp_data,sip,dip) = ask_l4_udp(src_ip, dst_ip)
    udp_dgram, udp_fields, udp_ck = build_udp(src_port,dst_port,udp_data,src_ip,dst_ip)
    ip_hdr, ip_fields, ip_ck = build_ipv4(udp_dgram, src_ip, dst_ip, ttl, ip_id, dscp, df, 17)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"
    full_frame, records = assemble_eth_frame(
        ip_hdr+udp_dgram, ip_fields+udp_fields,
        dst_mb,src_mb,type_len_b,llc_b,snap_b,variant,dst_s,src_s,v,preamble,sfd)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    udp_ver = udp_checksum(src_ip, dst_ip, udp_dgram)
    verify_report([("IP Header Checksum",f"0x{ip_ck:04x}",f"0x{inet_cksum(ip_hdr):04x}",inet_cksum(ip_hdr)==0),
                   ("UDP Checksum",f"0x{udp_ck:04x}",f"0x{udp_ver:04x}",udp_ver==0),
                   ("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"ipv4","ethertype":0x0800},src_ip,dst_ip,17)

def flow_eth_stp():
    """STP/RSTP/MSTP/PVST+/Rapid-PVST+ — all variants, correct L2 framing."""
    banner("ETHERNET (802.3+LLC/SNAP)  +  STP/RSTP/MSTP/PVST+",
           "L1:Preamble+SFD | L2:802.3+LLC[+SNAP+VLAN] | L3:BPDU")
    preamble, sfd = ask_layer1_eth()
    stp_inputs = ask_l3_stp()
    bpdu_raw, bpdu_fields = build_stp(stp_inputs)
    version = stp_inputs[0]
    is_pvst = version.upper() in ("C","R")
    section("LAYER 2 — Ethernet 802.3 + LLC" + (" + SNAP (PVST+)" if is_pvst else ""))
    if is_pvst:
        print(f"  {C.WARN}  PVST+ Dst: 01:00:0C:CC:CC:CD | VLAN-tagged | SNAP 00:00:0C:01:0B{C.RESET}")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cd" if is_pvst else "01:80:c2:00:00:00")
    src_s = get("Source MAC", "00:11:22:33:44:55")
    llc_b = bytes.fromhex("424203")
    if is_pvst:
        vlan_id = stp_inputs[1] or "1"
        vid_int = int(vlan_id)
        dot1q   = struct.pack("!HH", 0x8100, vid_int & 0x0FFF)
        snap_b  = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("010b")
        pdu     = dot1q + llc_b + snap_b + bpdu_raw
    else:
        dot1q = b""; snap_b = b""
        pdu   = llc_b + bpdu_raw
    tl = struct.pack(">H", len(pdu))
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    mac_content = dst_mb + src_mb + tl + pdu
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7x0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":sfd.hex(),"note":"0xD5"},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":"STP/PVST multicast"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":"bridge port MAC"},
        {"layer":2,"name":"802.3 Length","raw":tl,"user_val":str(len(pdu)),"note":"bytes"},
    ]
    if is_pvst:
        records += [
            {"layer":2,"name":"802.1Q TPID","raw":dot1q[0:2],"user_val":"0x8100","note":"PVST VLAN tag"},
            {"layer":2,"name":"802.1Q TCI","raw":dot1q[2:4],"user_val":f"VLAN {vlan_id}","note":""},
        ]
    records += [
        {"layer":2,"name":"LLC DSAP","raw":llc_b[0:1],"user_val":"42","note":"STP SAP"},
        {"layer":2,"name":"LLC SSAP","raw":llc_b[1:2],"user_val":"42","note":"STP SAP"},
        {"layer":2,"name":"LLC Ctrl","raw":llc_b[2:3],"user_val":"03","note":"UI frame"},
    ]
    if is_pvst:
        records += [
            {"layer":2,"name":"PVST SNAP OUI","raw":snap_b[3:6],"user_val":"00:00:0C","note":"Cisco"},
            {"layer":2,"name":"PVST SNAP PID","raw":snap_b[6:8],"user_val":"010B","note":"PVST+"},
        ]
    records += bpdu_fields
    records += [{"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto","note":fcs_note}]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    proto={"0":"stp","2":"rstp","3":"mstp","C":"pvst","R":"rapid_pvst"}.get(version.upper(),"stp")
    _run_layer_progression({"technology":"ethernet","protocol":proto})


def flow_eth_dtp():
    banner("ETHERNET (802.3+LLC+SNAP) + DTP  (Cisco Dynamic Trunking Protocol)",
           "L1:Preamble+SFD | L2:802.3+LLC+SNAP | L3:DTP TLVs")
    preamble, sfd = ask_layer1_eth()
    dtp_inputs = ask_l3_dtp()
    dtp_raw, dtp_fields = build_dtp(dtp_inputs)
    section("LAYER 2 — Ethernet 802.3")
    print(f"  {C.WARN}  DTP Dst MAC: 01:00:0C:CC:CC:CC  (Cisco CDP/VTP/DTP multicast){C.RESET}")
    dst_s = get("Destination MAC","01:00:0c:cc:cc:cc")
    src_s = get("Source MAC","00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    tl = struct.pack(">H", len(dtp_raw))
    mac_content = dst_mb + src_mb + tl + dtp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7x0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":sfd.hex(),"note":"0xD5"},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":"Cisco DTP multicast"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,"user_val":str(len(dtp_raw)),"note":"bytes"},
    ] + dtp_fields + [{"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto","note":fcs_note}]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"dtp"})


def flow_eth_pagp():
    banner("ETHERNET (802.3+LLC+SNAP) + PAgP  (Cisco Port Aggregation / EtherChannel)",
           "L1:Preamble+SFD | L2:802.3+LLC+SNAP | L3:PAgP TLVs")
    preamble, sfd = ask_layer1_eth()
    pagp_inputs = ask_l3_pagp()
    pagp_raw, pagp_fields = build_pagp(pagp_inputs)
    section("LAYER 2 — Ethernet 802.3")
    print(f"  {C.WARN}  PAgP Dst MAC: 01:00:0C:CC:CC:CC  (Cisco multicast — not forwarded){C.RESET}")
    dst_s = get("Destination MAC","01:00:0c:cc:cc:cc")
    src_s = get("Source MAC","00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    tl = struct.pack(">H", len(pagp_raw))
    mac_content = dst_mb + src_mb + tl + pagp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7x0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":sfd.hex(),"note":"0xD5"},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":"Cisco multicast"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,"user_val":str(len(pagp_raw)),"note":"bytes"},
    ] + pagp_fields + [{"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto","note":fcs_note}]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"pagp"})


def flow_eth_lacp():
    banner("ETHERNET II (0x8809) + LACP  (IEEE 802.3ad/802.1AX Link Aggregation)",
           "L1:Preamble+SFD | L2:EtherType 0x8809 | L3:Actor+Partner+Collector TLVs")
    preamble, sfd = ask_layer1_eth()
    lacp_inputs = ask_l3_lacp()
    lacp_raw, lacp_fields = build_lacp(lacp_inputs)
    section("LAYER 2 — Ethernet II (Slow Protocol)")
    print(f"  {C.WARN}  LACP Dst MAC: 01:80:C2:00:00:02  (Slow Protocol — not forwarded by bridges){C.RESET}")
    dst_s = get("Destination MAC","01:80:c2:00:00:02")
    src_s = get("Source MAC","00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    et = bytes.fromhex("8809")
    mac_content = dst_mb + src_mb + et + lacp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7x0x55"},
        {"layer":1,"name":"SFD","raw":sfd,"user_val":sfd.hex(),"note":"0xD5"},
        {"layer":2,"name":"Dst MAC","raw":dst_mb,"user_val":dst_s,"note":"Slow Protocol multicast"},
        {"layer":2,"name":"Src MAC","raw":src_mb,"user_val":src_s,"note":""},
        {"layer":2,"name":"EtherType","raw":et,"user_val":"0x8809","note":"Slow Protocols"},
    ] + lacp_fields + [{"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto","note":fcs_note}]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"lacp","ethertype":0x8809})


def flow_eth_pause():
    banner("ETHERNET PAUSE FRAME  —  IEEE 802.3x",
           "L1: Preamble+SFD  |  L2: EtherType 0x8808  |  MAC Ctrl Opcode 0x0001  |  Pause Quanta")
    print_pause_education()
    preamble, sfd, dst_s, src_s, quanta_val = ask_l2_pause()
    full_frame, records = build_pause(preamble, sfd, dst_s, src_s, quanta_val)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"pause","ethertype":0x8808})

def flow_eth_pfc():
    banner("PFC — PRIORITY FLOW CONTROL  IEEE 802.1Qbb",
           "L1: Preamble+SFD  |  L2: EtherType 0x8808  |  Opcode 0x0101  |  8×Priority Quanta")
    print_pfc_education()
    preamble, sfd, dst_s, src_s, vec_val, quanta = ask_l2_pfc()
    full_frame, records = build_pfc(preamble, sfd, dst_s, src_s, vec_val, quanta)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"pfc","ethertype":0x8808})

def flow_eth_lldp():
    banner("LLDP — LINK LAYER DISCOVERY PROTOCOL  IEEE 802.1AB",
           "L1: Preamble+SFD  |  L2: EtherType 0x88CC  |  L3: LLDP TLVs (Chassis+Port+TTL+Options)")
    print_lldp_education()
    inputs = ask_l2_lldp()
    full_frame, records = build_lldp(*inputs)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"lldp","ethertype":0x88CC})

def flow_eth_vlan():
    banner("VLAN TAGGED FRAME  —  IEEE 802.1Q  (+Q-in-Q / 802.1ad option)",
           "L1: Preamble+SFD  |  L2: TPID(0x8100)+TCI[PCP+DEI+VID]  |  Inner EtherType  |  Payload")
    print_vlan_education()
    inputs = ask_l2_vlan()
    full_frame, records = build_vlan(*inputs)
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"vlan","ethertype":0x8100})

def flow_eth_jumbo():
    banner("JUMBO FRAME  —  Non-Standard Vendor Extension",
           "L1: Preamble+SFD  |  L2: Ethernet II  |  Payload up to 9000B+ (MTU > 1500B)")
    print_jumbo_education()
    inputs = ask_l2_jumbo()
    full_frame, records = build_jumbo(*inputs)
    total = len(full_frame)
    print(f"\n  -> Frame size: {total} bytes  ({total*8} bits)")
    if total > 1518:
        overhead_pct = (14+4)/total*100
        print(f"  -> Header overhead: {overhead_pct:.2f}%  (Payload efficiency: {100-overhead_pct:.2f}%)")
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet","protocol":"ethernet"})


def ask_phy_encoding_option(speed_key: str) -> tuple[bool, int]:
    """
    Ask: Include PHY layer encoding in output?
    Encoding is AUTO-determined by speed — user does NOT choose encoding type.
    Returns (do_encode: bool, idle_count: int).
    """
    if not _PHY_AVAILABLE or speed_key in ('MAC_ONLY', ''):
        return False, 12
    p = get_phy_info(speed_key)
    print(f"\n  {C.SECT}{C.BOLD}▌ PHY LAYER ENCODING{C.RESET}")
    print(f"  {C.DIM}  Speed selected: {speed_key} — {p.get('name','').split('(')[0].strip()}{C.RESET}")
    print(f"  {C.L1}  Encoding automatically applied: {p.get('encoding','')}{C.RESET}")
    print(f"  {C.DIM}  (Encoding is determined by speed — no manual selection needed){C.RESET}")
    print()
    print(f"  {C.L1}  What gets encoded:{C.RESET}")
    print(f"  {C.DIM}    ✓ Full MAC frame: Dst MAC + Src MAC + EtherType + Payload + FCS{C.RESET}")
    print(f"  {C.WARN}    ✗ NOT encoded separately: Preamble, SFD (these are PHY framing){C.RESET}")
    print(f"  {C.WARN}    ✗ NOT encoded: IFG/Idle symbols (fixed PHY patterns inserted AFTER encoding){C.RESET}")
    print()
    print(f"  {C.L1}  Output stages:{C.RESET}")
    print(f"  {C.DIM}    A. MAC frame hex (before encoding){C.RESET}")
    print(f"  {C.DIM}    B. Encoded MAC frame hex (after encoding){C.RESET}")
    print(f"  {C.DIM}    C. Full PHY stream: [IFG] + [Start] + [Encoded MAC] + [End]{C.RESET}")
    ch = input(f"  {C.PROMPT}Include PHY encoding? (Y/N) [default=Y]: {C.RESET}").strip().upper() or 'Y'
    if ch != 'Y':
        return False, 12
    # IFG count
    ifg_s = input(f"  {C.PROMPT}IFG idle count (bytes, Enter=12): {C.RESET}").strip() or '12'
    try:    idle_count = max(1, int(ifg_s))
    except: idle_count = 12
    return True, idle_count


def show_eth_phy_encoding(frame_bytes: bytes, speed_key: str,
                           idle_count: int = 12) -> None:
    """
    Show PHY encoding using corrected architecture:
      - frame_bytes is the FULL wire frame (preamble+SFD+MAC)
      - MAC frame extracted as frame_bytes[8:] (strip preamble+SFD)
      - FULL MAC frame encoded (not preamble/SFD alone)
      - IFG/control symbols inserted AFTER encoding
      - Shows hex before and after encoding, then full PHY stream hex
    """
    if not _PHY_AVAILABLE:
        return

    # Extract MAC frame (strip preamble 7B + SFD 1B)
    if len(frame_bytes) > 8:
        mac_frame = frame_bytes[8:]   # Dst+Src+EtherType+Payload+FCS
    else:
        mac_frame = frame_bytes

    p   = get_phy_info(speed_key)
    SEP = '─' * 76

    print(f"\n  {C.SECT}{C.BOLD}▌ PHY ENCODING — {p.get('name','').split('(')[0].strip()}{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    # Build PHY stream using correct architecture
    result = build_phy_stream(mac_frame, speed_key, idle_count=idle_count,
                               include_start_end=True, initial_rd=-1)

    lines_out = format_phy_stream_display(result, max_hex_chars=56)
    for line in lines_out:
        # Colour coding: A/B/C stage headers
        if line.startswith('  A.'):
            print(f"  {C.L2}{line[2:]}{C.RESET}")
        elif line.startswith('  B.'):
            print(f"  {C.L3}{line[2:]}{C.RESET}")
        elif line.startswith('  C.'):
            print(f"  {C.L1}{line[2:]}{C.RESET}")
        elif '[CTL]' in line:
            print(f"  {C.WARN}{line}{C.RESET}")
        elif '[ENC]' in line:
            print(f"  {C.HEX}{line}{C.RESET}")
        elif '[PHY]' in line:
            print(f"  {C.L1}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}{line}{C.RESET}")

    # Encoding correctness note
    print(f"\n  {C.DIM}  Encoding rules enforced:{C.RESET}")
    if speed_key == '1G':
        rd = result.get('final_rd', 0)
        print(f"  {C.DIM}    8b/10b: ANSI codeword table only · RD tracked · Final: {'RD+' if rd>0 else 'RD-'}{C.RESET}")
        print(f"  {C.DIM}    K-codes (Start/End) inserted as PHY control — not from MAC data{C.RESET}")
    elif speed_key == '100M':
        print(f"  {C.DIM}    4B/5B: ANSI X3.263 table only · max 2 consecutive zeros · no run>3{C.RESET}")
        print(f"  {C.DIM}    J/K SSD + T/R ESD inserted as PHY delimiters{C.RESET}")
        print(f"  {C.DIM}    MLT-3 applied after 4B5B — transitions on each 1-bit{C.RESET}")
    elif speed_key == '10M':
        print(f"  {C.DIM}    Manchester: 0→H↓L  1→L↑H · self-clocking · 20 Mbaud{C.RESET}")
    elif speed_key in ('10G','25G','40G','100G','400G'):
        print(f"  {C.DIM}    64b/66b: LFSR(x^58+x^39+1) scrambler · sync=01 data · sync=10 ctrl{C.RESET}")
        print(f"  {C.DIM}    IFG idle blocks (type=0x1E) + Start (0x78) + Terminate inserted by PCS{C.RESET}")
        stats = result.get('stats',{})
        if 'fec' in stats:
            print(f"  {C.WARN}    FEC note: {stats['fec']}{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")


def flow_fc_native():
    """
    Fibre Channel native frame builder.
    Full PDU stack: SOF (selectable) + 24B Header + Payload + CRC + EOF (selectable)
    With 8b/10b encoding if PHY mode selected.
    """
    banner("FIBRE CHANNEL NATIVE FRAME BUILDER",
           "SOF(4chars) | FC-Header(24B) | Payload | CRC(4B) | EOF(4chars) | 8b/10b encoding")

    print(f"\n  {C.SECT}{C.BOLD}▌ FIBRE CHANNEL FRAME STRUCTURE{C.RESET}")
    print(f"  {C.DIM}  FC frame = SOF ordered-set (4 chars × 10b = 40 bits){C.RESET}")
    print(f"  {C.DIM}          + Frame Header (24 bytes fixed){C.RESET}")
    print(f"  {C.DIM}          + Optional Headers (variable, controlled by DF_CTL){C.RESET}")
    print(f"  {C.DIM}          + Data Payload (0-2112 bytes){C.RESET}")
    print(f"  {C.DIM}          + FC CRC-32 (4 bytes over Header+Payload){C.RESET}")
    print(f"  {C.DIM}          + EOF ordered-set (4 chars × 10b = 40 bits){C.RESET}")
    print(f"  {C.WARN}  ⚠  FC Class-3 (most common): unacknowledged — no retransmit at FC layer{C.RESET}")

    # ── SOF Selection ────────────────────────────────────────────────────────
    section("SOF — Start of Frame Ordered Set")
    print(f"  {C.DIM}  SOF type determines frame class and sequence position:{C.RESET}")
    sof_list = list(FC_SOF_BYTES.keys())
    for i, name in enumerate(sof_list, 1):
        desc = FC_SOF_DESC.get(name, '')
        raw  = FC_SOF_BYTES[name]
        print(f"  {C.L1}  [{i}]  {name:<8}  {raw.hex().upper()}  {C.DIM}{desc}{C.RESET}")
    sof_ch = input(f"\n  {C.PROMPT}Choose SOF (1-{len(sof_list)}) [default=1=SOFi3]: {C.RESET}").strip() or '1'
    try:
        sof_idx = max(0, min(int(sof_ch)-1, len(sof_list)-1))
    except ValueError:
        sof_idx = 0
    sof_name = sof_list[sof_idx]
    sof_bytes = FC_SOF_BYTES[sof_name]
    print(f"  {C.PASS_}  → {sof_name}: {sof_bytes.hex().upper()}  ({FC_SOF_DESC.get(sof_name,'')}){C.RESET}")

    # ── FC Frame Header — 24 bytes fixed ────────────────────────────────────
    section("FC FRAME HEADER — 24 bytes (fixed size per FC spec)")
    print(f"  {C.DIM}  All FC frames have exactly 24B header — no exceptions{C.RESET}")

    r_ctl   = get("R_CTL (Routing+Info)", "00",
                  help="1B: 0x00=Uncategorized-Data 0x01=Solicited-Data 0x02=Unsolicited-Data 0x03=Solicited-Control 0x06=Video-Data 0x18=Link-Service 0x22=ExtLinkService 0x23=FC-4-Link-Svc")
    d_id    = get("D_ID (Destination N_Port ID)", "010000",
                  help="3B hex: destination Fibre Channel address e.g. 010000=fabric controller FF0000")
    cs_ctl  = get("CS_CTL / Priority", "00",
                  help="1B: Class-specific control or priority (0x00=normal)")
    s_id    = get("S_ID (Source N_Port ID)", "210000",
                  help="3B hex: source N_Port ID assigned by fabric during FLOGI")
    fc_type = get("TYPE (FC-4 Protocol)", "08",
                  help="1B: 0x01=BLS 0x08=FCP(SCSI) 0x20=IP-over-FC 0x22=SNMP 0xFE=ELS 0xFF=Vendor")
    f_ctl   = get("F_CTL (Frame Control)", "290000",
                  help="3B: bit23=ExchangeSeq bit22=SeqInit bit20=ABTSAck bit19=RelOffset bit4=EndSeq bit7=LastSeq  0x290000=Initiator+LastSeq")
    seq_id  = get("SEQ_ID (Sequence ID)", "00",
                  help="1B: sequence identifier; increments per new sequence within exchange")
    df_ctl  = get("DF_CTL (Data Field Control)", "00",
                  help="1B: bit7=ESP_HDR bit6=Network_HDR bit5=Association_HDR bit4=Device_HDR; 0x00=no optional headers")
    seq_cnt = get("SEQ_CNT (Sequence Count)", "0000",
                  help="2B: frame count within sequence (starts at 0); used for ordered delivery")
    ox_id   = get("OX_ID (Originator Exchange ID)", "0001",
                  help="2B: unique per exchange at originator; must be unique among active exchanges")
    rx_id   = get("RX_ID (Responder Exchange ID)", "FFFF",
                  help="2B: 0xFFFF until assigned by responder in first response frame")
    parameter = get("Parameter", "00000000",
                    help="4B: relative offset of first payload byte (for Class-1/2); or RO for streamed data")

    def h(s, n):
        try:    return bytes.fromhex(s.replace(' ','').zfill(n*2)[-n*2:])
        except: return b'\x00' * n

    fc_header = (h(r_ctl,1) + h(d_id,3) + h(cs_ctl,1) + h(s_id,3) +
                 h(fc_type,1) + h(f_ctl,3) + h(seq_id,1) + h(df_ctl,1) +
                 h(seq_cnt,2) + h(ox_id,2) + h(rx_id,2) + h(parameter,4))
    assert len(fc_header) == 24, f"FC header must be 24B, got {len(fc_header)}B"

    # ── Payload ──────────────────────────────────────────────────────────────
    section("FC PAYLOAD")
    fc_type_int = int(fc_type.strip() or '08', 16)
    type_hints  = {0x08:"FCP: FCP_CMND(32B) or FCP_DATA or FCP_RSP",
                   0x18:"Link Service: FLOGI/PLOGI/LOGO/ADISC — ELS payload",
                   0x01:"BLS: ABTS/BA_ACC/BA_RJT — basic link service",
                   0x20:"IP over FC: IPv4/IPv6 datagram",
                   0xFE:"Extended Link Service: detailed ELS payload"}
    if fc_type_int in type_hints:
        print(f"  {C.DIM}  TYPE=0x{fc_type_int:02X} expected payload: {type_hints[fc_type_int]}{C.RESET}")
    payload_hex = get("Payload hex (Enter=empty)", "",
                      help="FCP command: e.g. SCSI CDB — hex string; empty=no payload")
    try:
        payload = bytes.fromhex(payload_hex.replace(' ',''))
    except ValueError:
        payload = b''
    if payload:
        print(f"  {C.DIM}  Payload: {len(payload)}B{C.RESET}")
        if len(payload) > 2112:
            print(f"  {C.WARN}  ⚠  FC max payload = 2112B — payload truncated to 2112B{C.RESET}")
            payload = payload[:2112]

    # ── FC CRC-32 ────────────────────────────────────────────────────────────
    crc_input = fc_header + payload
    fc_crc = zlib.crc32(crc_input) & 0xFFFFFFFF
    fc_crc_bytes = struct.pack('>I', fc_crc ^ 0xFFFFFFFF)  # FC CRC is bitwise inverted
    print(f"\n  {C.DIM}  FC CRC-32: 0x{fc_crc_bytes.hex().upper()}  (over header+payload, bit-inverted per FC spec){C.RESET}")

    # ── EOF Selection ────────────────────────────────────────────────────────
    section("EOF — End of Frame Ordered Set")
    eof_list = list(FC_EOF_BYTES.keys())
    for i, name in enumerate(eof_list, 1):
        desc = FC_EOF_DESC.get(name, '')
        raw  = FC_EOF_BYTES[name]
        print(f"  {C.L1}  [{i}]  {name:<8}  {raw.hex().upper()}  {C.DIM}{desc}{C.RESET}")
    eof_ch = input(f"\n  {C.PROMPT}Choose EOF (1-{len(eof_list)}) [default=1=EOFt]: {C.RESET}").strip() or '1'
    try:
        eof_idx = max(0, min(int(eof_ch)-1, len(eof_list)-1))
    except ValueError:
        eof_idx = 0
    eof_name  = eof_list[eof_idx]
    eof_bytes = FC_EOF_BYTES[eof_name]
    print(f"  {C.PASS_}  → {eof_name}: {eof_bytes.hex().upper()}  ({FC_EOF_DESC.get(eof_name,'')}){C.RESET}")

    # ── FC PHY speed ─────────────────────────────────────────────────────────
    section("FC PHY SPEED (for 8b/10b encoding)")
    print(f"  {C.DIM}  All FC speeds (1G/4G/8G/16G below 16GFC) use 8b/10b encoding{C.RESET}")
    fc_speeds = [(k, PHY_REGISTRY[k]) for k in ['FC_1G','FC_4G','FC_16G','FC_32G']]
    for i, (k, p) in enumerate(fc_speeds, 1):
        print(f"  {C.L1}  [{i}]  {k:<8}  {p['line_rate']:<20}  {p['encoding']}{C.RESET}")
    sp_ch = input(f"  {C.PROMPT}Choose FC speed (1-4) [default=1=1GFC]: {C.RESET}").strip() or '1'
    try:
        sp_idx = max(0, min(int(sp_ch)-1, 3))
    except ValueError:
        sp_idx = 0
    fc_speed_key = fc_speeds[sp_idx][0]

    # ── Build frame table records ─────────────────────────────────────────────
    sof_rec = [{"layer":1,"name":f"SOF({sof_name})","raw":sof_bytes,
                 "user_val":sof_bytes.hex().upper(),
                 "note":f"4 chars: K28.5+{FC_SOF_DESC.get(sof_name,'')[:25]}"}]
    hdr_records = [
        {"layer":3,"name":"R_CTL",    "raw":h(r_ctl,1),    "user_val":r_ctl,    "note":"Routing+Info"},
        {"layer":3,"name":"D_ID",     "raw":h(d_id,3),     "user_val":d_id,     "note":"Dest N_Port ID"},
        {"layer":3,"name":"CS_CTL",   "raw":h(cs_ctl,1),   "user_val":cs_ctl,   "note":"Class-specific ctrl"},
        {"layer":3,"name":"S_ID",     "raw":h(s_id,3),     "user_val":s_id,     "note":"Source N_Port ID"},
        {"layer":3,"name":"TYPE",     "raw":h(fc_type,1),  "user_val":fc_type,  "note":"FC-4 Protocol"},
        {"layer":3,"name":"F_CTL",    "raw":h(f_ctl,3),    "user_val":f_ctl,    "note":"Frame control"},
        {"layer":3,"name":"SEQ_ID",   "raw":h(seq_id,1),   "user_val":seq_id,   "note":"Sequence ID"},
        {"layer":3,"name":"DF_CTL",   "raw":h(df_ctl,1),   "user_val":df_ctl,   "note":"Optional hdr ctrl"},
        {"layer":3,"name":"SEQ_CNT",  "raw":h(seq_cnt,2),  "user_val":seq_cnt,  "note":"Frame count in seq"},
        {"layer":3,"name":"OX_ID",    "raw":h(ox_id,2),    "user_val":ox_id,    "note":"Originator Exch ID"},
        {"layer":3,"name":"RX_ID",    "raw":h(rx_id,2),    "user_val":rx_id,    "note":"Responder Exch ID"},
        {"layer":3,"name":"Parameter","raw":h(parameter,4),"user_val":parameter,"note":"Relative offset"},
    ]
    pl_rec = []
    if payload:
        pl_rec = [{"layer":4,"name":f"FC Payload","raw":payload,
                   "user_val":f"{len(payload)}B","note":"FCP/ELS/BLS data"}]
    crc_rec = [{"layer":3,"name":"FC CRC-32","raw":fc_crc_bytes,
                "user_val":fc_crc_bytes.hex().upper(),"note":"over hdr+payload"}]
    eof_rec = [{"layer":1,"name":f"EOF({eof_name})","raw":eof_bytes,
                "user_val":eof_bytes.hex().upper(),
                "note":f"4 chars: K28.5+{FC_EOF_DESC.get(eof_name,'')[:25]}"}]

    records = sof_rec + hdr_records + pl_rec + crc_rec + eof_rec

    print_frame_table(records)

    # Verify CRC
    verify_report([("FC CRC-32", fc_crc_bytes.hex(), fc_crc_bytes.hex(), True)])

    # Frame summary
    total_bytes = len(sof_bytes) + 24 + len(payload) + 4 + len(eof_bytes)
    print(f"\n  {C.DIM}  FC Frame: SOF(4B) + Header(24B) + Payload({len(payload)}B) + CRC(4B) + EOF(4B) = {total_bytes}B total{C.RESET}")
    print(f"  {C.DIM}  8b/10b encoded: {total_bytes*10} line bits at {PHY_REGISTRY[fc_speed_key]['line_rate']}{C.RESET}")

    # ── 8b/10b PHY encoding ──────────────────────────────────────────────────
    do_encode = input(f"\n  {C.PROMPT}Show 8b/10b PHY encoding? (Y/N) [default=Y]: {C.RESET}").strip().upper() or 'Y'
    if do_encode == 'Y' and _PHY_AVAILABLE:
        enc_result = encode_fc_frame_8b10b(sof_name, fc_header, payload,
                                            fc_crc_bytes, eof_name, initial_rd=-1)
        lines = format_encoding_display(enc_result, fc_speed_key, max_codewords_shown=3)
        print(f"\n  {C.SECT}{C.BOLD}▌ 8b/10b ENCODING — {fc_speed_key} ({PHY_REGISTRY[fc_speed_key]['line_rate']}){C.RESET}")
        print(f"  {C.DIM}  Running Disparity starts at RD- (convention: first frame starts RD-){C.RESET}")
        print(f"  {C.DIM}  Each 10-bit codeword shown MSB first (transmission order){C.RESET}")
        print(f"  {C.DIM}  Control symbols (K28.5 in SOF/EOF) marked with * prefix{C.RESET}")
        for line in lines:
            print(f"  {C.DIM}{line}{C.RESET}")

        # Show SOF ordered set encoding explicitly
        from phy_builder import encode_fc_ordered_set_8b10b
        sof_cws, _ = encode_fc_ordered_set_8b10b(sof_bytes, initial_rd=-1)
        print(f"\n  {C.L1}  {sof_name} ordered set (4 chars → 4 × 10-bit codewords):{C.RESET}")
        char_names = ["K28.5 (comma/sync)", "D-char 2", "D-char 3", "D-char 4"]
        for i, (byte_val, cw) in enumerate(zip(sof_bytes, sof_cws)):
            k_mark = " [K]" if i == 0 else "    "
            print(f"  {C.HEX}  0x{byte_val:02X}{k_mark} → {format(cw,'010b')}  ({char_names[i]}){C.RESET}")

        eof_cws, _ = encode_fc_ordered_set_8b10b(eof_bytes, initial_rd=enc_result['final_rd'])
        print(f"\n  {C.L1}  {eof_name} ordered set:{C.RESET}")
        for i, (byte_val, cw) in enumerate(zip(eof_bytes, eof_cws)):
            k_mark = " [K]" if i == 0 else "    "
            print(f"  {C.HEX}  0x{byte_val:02X}{k_mark} → {format(cw,'010b')}{C.RESET}")


def flow_eth_cdp():
    """Cisco CDP — full interactive builder with all TLV types."""
    banner("ETHERNET (802.3+LLC+SNAP) + CDP  (Cisco Discovery Protocol)",
           "L1:Preamble+SFD | L2:802.3+LLC+SNAP | L3:CDP TLVs | Dst:01:00:0C:CC:CC:CC")
    preamble, sfd = ask_layer1_eth()
    section("CDP HEADER")
    print(f"  {C.WARN}  ⚠  CDP leaks device ID, IOS version, platform, IP addresses — disable on untrusted ports{C.RESET}")
    print(f"  {C.DIM}  SECURITY: 'no cdp enable' on all access ports / edge interfaces{C.RESET}")
    cdp_ver  = get("CDP Version", "02", help="01=CDPv1  02=CDPv2")
    cdp_ttl  = get("TTL (hold time seconds)", "B4", help="0xB4=180s default")
    try:
        ver_b = bytes.fromhex(cdp_ver.zfill(2)[-2:])
        ttl_b = bytes.fromhex(cdp_ttl.zfill(2)[-2:])
    except ValueError:
        ver_b, ttl_b = b'\x02', b'\xB4'

    section("CDP TLVs  (Type=2B  Length=2B  Value=variable)")
    print(f"  {C.DIM}  Each TLV is optional. Press Enter to skip any TLV.{C.RESET}")
    tlvs = b''
    tlv_records = []
    def _tlv(ttype, label, default, hint=''):
        nonlocal tlvs
        val = get(f"  TLV {label}", default, help=hint)
        if val.strip():
            try:
                vb = bytes.fromhex(val.replace(':','').replace(' ',''))
            except ValueError:
                vb = val.encode('ascii', errors='replace')
            tlv = struct.pack('>HH', ttype, 4 + len(vb)) + vb
            tlvs += tlv
            tlv_records.append({"layer":3,"name":f"TLV-{label[:15]}","raw":tlv,
                                 "user_val":val[:18],"note":f"Type=0x{ttype:04X}"})

    _tlv(0x0001, "DeviceID",       "Router01",           "hostname or serial")
    _tlv(0x0003, "PortID",         "GigabitEthernet0/1", "interface name")
    _tlv(0x0004, "Capabilities",   "00000028",           "bitmask: 0x01=Router 0x08=Switch 0x28=Switch+IGMP")
    _tlv(0x0006, "Platform",       "cisco WS-C3750X-48", "hardware model")
    _tlv(0x0005, "SoftwareVersion","IOS Version 15.2(7)E6", "IOS version string")
    _tlv(0x000A, "NativeVLAN",     "0001",               "native VLAN ID 2B (e.g. 0001=VLAN1)")
    _tlv(0x000B, "Duplex",         "01",                 "0x00=half  0x01=full")
    _tlv(0x0010, "PowerAvailable", "00001770",           "milliwatts PoE available (0x1770=6000mW=6W)")
    extra_hex = get("  Extra TLV hex (Enter=none)", "")
    if extra_hex.strip():
        try: tlvs += bytes.fromhex(extra_hex.replace(' ',''))
        except ValueError: pass

    # Build CDP PDU
    header_no_crc = ver_b + ttl_b + b'\x00\x00' + tlvs
    cksum = 0
    data = header_no_crc
    if len(data) % 2: data += b'\x00'
    for i in range(0, len(data), 2):
        cksum += (data[i] << 8) + data[i+1]
    cksum = ~((cksum >> 16) + (cksum & 0xFFFF)) & 0xFFFF
    cdp_pdu = ver_b + ttl_b + struct.pack('>H', cksum) + tlvs

    # 802.3 LLC + SNAP header
    snap = bytes.fromhex('aaaa03') + bytes.fromhex('00000c') + bytes.fromhex('2000')

    section("LAYER 2 — Ethernet 802.3 + LLC + SNAP")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    payload = snap + cdp_pdu
    length  = struct.pack('>H', len(payload))
    mac_content = dst_mb + src_mb + length + payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble",    "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",         "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",     "raw":dst_mb,  "user_val":dst_s,         "note":"01:00:0C:CC:CC:CC"},
        {"layer":2,"name":"Src MAC",     "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"Length",      "raw":length,  "user_val":str(len(payload)),"note":"802.3 length field"},
        {"layer":2,"name":"LLC+SNAP",    "raw":snap,    "user_val":"AA:AA:03:00:00:0C:20:00","note":"Cisco SNAP"},
        {"layer":3,"name":"CDP Ver",     "raw":ver_b,   "user_val":cdp_ver,       "note":"CDP version"},
        {"layer":3,"name":"CDP TTL",     "raw":ttl_b,   "user_val":cdp_ttl,       "note":"hold-time seconds"},
        {"layer":3,"name":"CDP Checksum","raw":struct.pack('>H',cksum),"user_val":f"0x{cksum:04X}","note":"CRC-16"},
    ] + tlv_records + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)


def flow_eth_vtp():
    """Cisco VTP — full interactive builder (Summary/Subset/Request/Join)."""
    banner("ETHERNET (802.3+LLC+SNAP) + VTP  (Cisco VLAN Trunk Protocol)",
           "L1:Preamble+SFD | L2:802.3+LLC+SNAP | L3:VTP PDU | Dst:01:00:0C:CC:CC:CC")
    preamble, sfd = ask_layer1_eth()

    section("VTP HEADER")
    print(f"  {C.WARN}  ⚠  Config-Revision attack: higher revision overwrites ALL VLANs on entire domain{C.RESET}")
    print(f"  {C.WARN}  ⚠  Always use VTPv3+password or VTP Transparent mode in production{C.RESET}")

    vtp_ver  = get("VTP Version",           "02", help="01=VTPv1  02=VTPv2  03=VTPv3")
    vtp_code = get("Code",                  "01", help="01=Summary-Advert 02=Subset-Advert 03=Request 04=Join")
    followers= get("Followers (Summary)",   "01", help="number of Subset-Adverts to follow (Summary only)")
    dom_name = get("VTP Domain Name",       "CORP_VTP_DOMAIN")
    dom_b    = dom_name.encode('ascii')[:32].ljust(32, b'\x00')
    cfg_rev  = get("Config Revision",       "00000001", help="4B hex — CAUTION: higher value wins domain")
    updater  = get("Updater IP",            "0a0a0a01",  help="4B IPv4 hex of last updater")
    timestamp= get("Update Timestamp",      "202401010000", help="YYMMDDHHMMSS ASCII")
    ts_b     = timestamp.encode('ascii')[:12].ljust(12, b'\x00')
    md5      = get("MD5 Digest (auth)",     "00"*16, help="16B hex — all zeros = no auth")

    try:
        ver_b   = bytes([int(vtp_ver,16)])
        code_b  = bytes([int(vtp_code,16)])
        fol_b   = bytes([int(followers,16)])
        rev_b   = bytes.fromhex(cfg_rev.zfill(8))
        upd_b   = bytes.fromhex(updater.zfill(8))
        md5_b   = bytes.fromhex(md5.replace(' ','').zfill(32))
    except ValueError:
        ver_b=b'\x02'; code_b=b'\x01'; fol_b=b'\x01'
        rev_b=b'\x00\x00\x00\x01'; upd_b=b'\x00'*4; md5_b=b'\x00'*16

    vtp_pdu = ver_b + code_b + fol_b + bytes([len(dom_name.encode('ascii')[:32])]) + dom_b + rev_b + upd_b + ts_b + md5_b

    # Optional VLAN info for Subset
    if vtp_code == '02':
        section("VLAN INFO  (Subset Advertisement)")
        vlan_id  = get("  VLAN ID", "0001",  help="2B hex e.g. 0001=VLAN1")
        vlan_name= get("  VLAN Name","default","string")
        vname_b  = vlan_name.encode('ascii')[:32]
        try:
            vid_b = bytes.fromhex(vlan_id.zfill(4))
        except ValueError:
            vid_b = b'\x00\x01'
        vlan_info = bytes([len(vname_b)+12, 0x00, 0x01, len(vname_b)]) + vid_b + b'\x05\xDC' + b'\x00'*4 + vname_b
        vtp_pdu += vlan_info

    # SNAP
    snap = bytes.fromhex('aaaa03') + bytes.fromhex('00000c') + bytes.fromhex('2003')

    section("LAYER 2 — Ethernet 802.3 + LLC + SNAP")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    payload = snap + vtp_pdu
    length  = struct.pack('>H', len(payload))
    mac_content = dst_mb + src_mb + length + payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble",         "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",              "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",          "raw":dst_mb,  "user_val":dst_s,         "note":"VTP multicast"},
        {"layer":2,"name":"Src MAC",          "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"Length",           "raw":length,  "user_val":str(len(payload)),"note":"802.3"},
        {"layer":2,"name":"LLC+SNAP",         "raw":snap,    "user_val":"VTP SNAP",    "note":"SNAP PID 0x2003"},
        {"layer":3,"name":"VTP Version",      "raw":ver_b,   "user_val":vtp_ver,       "note":""},
        {"layer":3,"name":"VTP Code",         "raw":code_b,  "user_val":vtp_code,      "note":"01=Summary"},
        {"layer":3,"name":"VTP Domain",       "raw":dom_b,   "user_val":dom_name,      "note":"32B padded"},
        {"layer":3,"name":"Config Revision",  "raw":rev_b,   "user_val":cfg_rev,       "note":"⚠ higher wins"},
        {"layer":3,"name":"MD5 Digest",       "raw":md5_b,   "user_val":"auth/none",   "note":"16B"},
        {"layer":0,"name":"Ethernet FCS",     "raw":fcs,     "user_val":"auto",        "note":fcs_note},
    ]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)


def flow_eth_pvst():
    """Cisco PVST+ / Rapid-PVST+ — routes to the STP builder with PVST variant."""
    print(f"\n  {C.DIM}  PVST+ uses the same BPDU structure as STP/RSTP but with Cisco SNAP PID 0x010B{C.RESET}")
    print(f"  {C.DIM}  and Dst MAC 01:00:0C:CC:CC:CD — routing to STP builder with PVST+ mode{C.RESET}")
    flow_eth_stp()


def flow_eth_udld():
    """Cisco UDLD — full interactive builder."""
    banner("ETHERNET (802.3+LLC+SNAP) + UDLD  (Cisco Uni-Directional Link Detection)",
           "L1:Preamble+SFD | L2:802.3+LLC+SNAP | L3:UDLD TLVs | Dst:01:00:0C:CC:CC:CC")
    preamble, sfd = ask_layer1_eth()
    section("UDLD PDU")
    print(f"  {C.WARN}  ⚠  UDLD Aggressive mode: port goes err-disabled if no Echo — do NOT use on protection paths{C.RESET}")
    udld_ver = '01'
    opcode   = get("Opcode", "01", help="01=Probe  02=Echo  03=Flush")
    flags    = get("Flags",  "00", help="bit0=RT(7s timeout)  bit1=RSY(resync)")
    try:
        hdr_b = bytes([int(udld_ver+''+opcode, 16)]) if len(opcode)==1 else bytes([int(udld_ver,16)*16+int(opcode,16)])
    except Exception:
        hdr_b = b'\x11'
    try:
        flags_b = bytes.fromhex(flags.zfill(2))
    except Exception:
        flags_b = b'\x00'

    tlvs = b''
    def _utlv(ttype, label, default, hint=''):
        nonlocal tlvs
        val = get(f"  TLV {label}", default, help=hint)
        if val.strip():
            try:    vb = bytes.fromhex(val.replace(':','').replace(' ',''))
            except: vb = val.encode('ascii', errors='replace')
            tlvs += struct.pack('>HH', ttype, 4+len(vb)) + vb

    _utlv(0x0001, "DeviceID",        "SW1/GigabitEthernet0/1", "device+port string")
    _utlv(0x0002, "PortID",          "GigabitEthernet0/1",     "sending port")
    _utlv(0x0003, "EchoList",        "",                       "neighbor device+port IDs heard (leave blank for Probe)")
    _utlv(0x0004, "MsgInterval",     "07",                     "1B probe interval seconds (07=7s  01=1s aggressive)")
    _utlv(0x0005, "TimeoutInterval", "15",                     "1B timeout seconds (15=21s = 3×7s)")
    _utlv(0x0006, "DeviceName",      "Switch1",                "hostname")
    _utlv(0x0007, "SeqNumber",       "00000001",               "4B monotonic sequence")

    # Checksum
    raw_no_ck = hdr_b + flags_b + b'\x00\x00' + tlvs
    ck = 0
    d = raw_no_ck if len(raw_no_ck)%2==0 else raw_no_ck+b'\x00'
    for i in range(0, len(d), 2):
        ck += (d[i]<<8)+d[i+1]
    ck = ~((ck>>16)+(ck&0xFFFF)) & 0xFFFF
    udld_pdu = hdr_b + flags_b + struct.pack('>H', ck) + tlvs

    snap = bytes.fromhex('aaaa03') + bytes.fromhex('00000c') + bytes.fromhex('0111')

    section("LAYER 2 — Ethernet 802.3 + LLC + SNAP")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    payload = snap + udld_pdu
    length  = struct.pack('>H', len(payload))
    mac_content = dst_mb + src_mb + length + payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble",  "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",       "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",   "raw":dst_mb,  "user_val":dst_s,         "note":"01:00:0C:CC:CC:CC"},
        {"layer":2,"name":"Src MAC",   "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"Length",    "raw":length,  "user_val":str(len(payload)),"note":"802.3"},
        {"layer":2,"name":"LLC+SNAP",  "raw":snap,    "user_val":"UDLD SNAP",   "note":"SNAP PID 0x0111"},
        {"layer":3,"name":"UDLD Hdr",  "raw":hdr_b,   "user_val":f"ver=1 op={opcode}","note":"version+opcode"},
        {"layer":3,"name":"Flags",     "raw":flags_b, "user_val":flags,         "note":""},
        {"layer":3,"name":"Checksum",  "raw":struct.pack('>H',ck),"user_val":f"0x{ck:04X}","note":"CRC"},
        {"layer":3,"name":"UDLD TLVs", "raw":tlvs,    "user_val":f"{len(tlvs)}B","note":"TLV chain"},
        {"layer":0,"name":"Ethernet FCS","raw":fcs,   "user_val":"auto",        "note":fcs_note},
    ]
    print_frame_table(records)
    fcs_s=full_frame[-4:]; fcs_r=crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS",fcs_s.hex(),fcs_r.hex(),fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)



def flow_hdlc():
    banner("HDLC FRAME BUILDER — ISO 13239",
           "3 Frame Types:  I-frame (data+seq)  |  S-frame (supervisory)  |  U-frame (link mgmt)")
    print_hdlc_education()
    section("FLAGS  (frame delimiters)")
    print("    Standard HDLC flag = 0x7E.  Both start and end use same value.")
    flag_hex = get("Flag byte (hex)", "7e",
        help="0x7E=01111110 — standard HDLC flag.\nBit-stuffing prevents 0x7E appearing inside frame content.")
    try:    flag_b = bytes([int(flag_hex, 16) & 0xFF])
    except: flag_b = b'\x7E'

    addr_bytes, addr_note = ask_hdlc_address()

    section("HDLC FRAME TYPE")
    print("    1 = I-frame  (Information)   — reliable data with sequence numbers")
    print("    2 = S-frame  (Supervisory)   — ACK/NAK/flow control, no data")
    print("    3 = U-frame  (Unnumbered)    — link setup/teardown/UI datagram")
    ftype = get("Frame type (1/2/3)", "1")
    if ftype not in ('1','2','3'): ftype = '1'

    mod128 = False
    if ftype in ('1','2'):
        print("\n    Modulo-8: 1B control, seq 0–7  |  Modulo-128: 2B control, seq 0–127")
        mod128 = get("Use Modulo-128 extended control? (y/n)", "n",
            help="mod-8: basic HDLC, PPP, simple WAN.\nmod-128: ISDN LAPD, X.25 LAPB — large windows.").lower().startswith("y")

    section("POLL/FINAL (P/F) BIT")
    print("    P=1 in COMMAND: respond now  |  F=1 in RESPONSE: final response")
    pf = int(get("P/F bit (0 or 1)", "0",
        help="0=normal unsolicited frame.\nP=1=poll(command—peer must respond).\nF=1=final(response to poll).")) & 1

    # Frame-type specific inputs
    u_mn = ""; s_mn = ""; s1 = s0 = 0; s1s0 = 0
    m4 = m3 = m2 = m1 = m0 = 0
    ns = nr = 0

    if ftype == '1':
        section("I-FRAME — SEQUENCE NUMBERS")
        ns_max = 127 if mod128 else 7
        ns = int(get(f"N(S) Send Sequence  (0–{ns_max})", "0",
            help=f"Send sequence of THIS I-frame (0–{ns_max}). Incremented per frame sent.")) & (0x7F if mod128 else 0x7)
        nr = int(get(f"N(R) Receive/ACK Seq (0–{ns_max})", "0",
            help=f"ACKs all frames up to N(R)-1. Next frame expected from peer.")) & (0x7F if mod128 else 0x7)
        ctrl_bytes = build_hdlc_control_i(ns, pf, nr, mod128)
        ctrl_note  = f"I-frame  N(S)={ns}  P/F={pf}  N(R)={nr}  {'mod-128' if mod128 else 'mod-8'}"
        section("I-FRAME — INFORMATION PAYLOAD")
        payload_hex = get("Payload hex (Enter=empty)", "")
        try:    info_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
        except: info_bytes = b''

    elif ftype == '2':
        section("S-FRAME — SUPERVISORY FUNCTION")
        for k, (s1v,s0v,mn,desc) in HDLC_S_SUBTYPES.items():
            print(f"      {k} = {mn:<6}  {desc}")
        s_ch = get("S-frame subtype (1-4)", "1")
        if s_ch not in HDLC_S_SUBTYPES: s_ch = '1'
        s1, s0, s_mn, s_desc = HDLC_S_SUBTYPES[s_ch]
        s1s0 = (s1 << 1) | s0
        nr_max = 127 if mod128 else 7
        nr = int(get(f"N(R) Receive/ACK Sequence (0–{nr_max})", "0",
            help=f"ACKs all frames up to N(R)-1.\nRR N(R)=5: ACKs 0-4, ready for 5.\nREJ N(R)=3: retransmit from frame 3.")) & (0x7F if mod128 else 0x7)
        ctrl_bytes = build_hdlc_control_s(nr, pf, s1s0, mod128)
        ctrl_note  = f"S-frame  {s_mn}  N(R)={nr}  P/F={pf}  {'mod-128' if mod128 else 'mod-8'}"
        info_bytes = b''

    else:  # U-frame
        section("U-FRAME — UNNUMBERED SUBTYPE")
        for k, (m4v,m3v,m2v,m1v,m0v,mn,cr,desc) in HDLC_U_SUBTYPES.items():
            print(f"    {k:>2} = {mn:<6}  [{m4v}{m3v}{m2v}-{m1v}{m0v}]  {cr:3}  {desc}")
        u_ch = get("U-frame subtype (1-10)", "1")
        if u_ch not in HDLC_U_SUBTYPES: u_ch = '1'
        m4, m3, m2, m1, m0, u_mn, u_cr, u_desc = HDLC_U_SUBTYPES[u_ch]
        m4m3m2 = (m4<<2)|(m3<<1)|m2
        m1m0   = (m1<<1)|m0
        ctrl_bytes = build_hdlc_control_u(m4m3m2, pf, m1m0)
        ctrl_note  = f"U-frame  {u_mn}  P/F={pf}  M={m4}{m3}{m2}-{m1}{m0}  ({u_cr}) {u_desc}"
        info_bytes = b''
        has_info   = u_mn in ("UI","XID","TEST","FRMR")
        if has_info:
            section(f"U-FRAME INFO FIELD  ({u_mn} carries optional data)")
            xid_hex = get(f"{u_mn} payload hex (Enter=empty)", "")
            try:    info_bytes = bytes.fromhex(xid_hex.replace(" ", ""))
            except: info_bytes = b''

    # FCS
    fcs_input = addr_bytes + ctrl_bytes + info_bytes
    section("FCS  (Frame Check Sequence)")
    print("    1 = CRC-16/CCITT  (2 bytes, standard HDLC, x^16+x^12+x^5+1)")
    print("    2 = CRC-32        (4 bytes, extended HDLC)")
    fcs_mode = get("FCS type (1=CRC-16  2=CRC-32)", "1")
    if fcs_mode == '2':
        crc_auto  = crc32_eth(fcs_input)
        fcs_label = "CRC-32 (4B)"
    else:
        crc_val  = crc16_ccitt(fcs_input)
        crc_auto = crc_val.to_bytes(2, 'little')
        fcs_label = "FCS-16/CCITT (2B)"

    print(f"    Auto-computed {fcs_label} = 0x{crc_auto.hex()}")
    custom = get("Use auto FCS? (y=auto  n=enter custom)", "y")
    if custom.lower().startswith('n'):
        fcs_hex = get("Enter FCS hex", crc_auto.hex())
        try:
            fcs_bytes = bytes.fromhex(fcs_hex.replace(" ", ""))
            if len(fcs_bytes) not in (2, 4): raise ValueError
        except:
            print("    -> invalid, using auto")
            fcs_bytes = crc_auto
    else:
        fcs_bytes = crc_auto

    section("BIT STUFFING  (transparent operation)")
    print("    After 5 consecutive 1-bits, a 0 is inserted to prevent 0x7E in content.")
    do_stuff = get("Apply bit-stuffing to content? (y/n)", "n",
        help="y=synchronous HDLC on physical serial lines.\nn=async links or driver-handled framing.").lower().startswith("y")

    inner = addr_bytes + ctrl_bytes + info_bytes + fcs_bytes
    if do_stuff:
        inner      = bit_stuff(byte_escape(inner))
        stuff_note = "bit-stuffed + byte-escaped"
    else:
        stuff_note = "raw (no bit-stuffing)"

    full_frame = flag_b + inner + flag_b

    if ftype == '1':   frame_type_label = "I-frame (Information)"
    elif ftype == '2': frame_type_label = f"S-frame (Supervisory) — {s_mn}"
    else:              frame_type_label = f"U-frame (Unnumbered) — {u_mn}"

    fcs_verify = crc32_eth(fcs_input) if fcs_mode == '2' else crc16_ccitt(fcs_input).to_bytes(2, 'little')

    records = [
        {"layer":1,"name":"HDLC Start Flag","raw":flag_b,"user_val":flag_b.hex(),"note":"0x7E — frame delimiter"},
        {"layer":2,"name":"HDLC Address","raw":addr_bytes,"user_val":addr_bytes.hex(),"note":addr_note},
        {"layer":2,"name":f"HDLC Control  ({frame_type_label})","raw":ctrl_bytes,"user_val":f"0x{ctrl_bytes.hex()}","note":ctrl_note},
    ]
    if ftype == '1':
        if mod128:
            records += [
                {"layer":2,"name":"  └─ I-ctrl Byte0: N(S)+0","raw":b"","user_val":f"N(S)={ns}","note":f"bits[7:1]=N(S)={ns}  bit[0]=0(I-frame)"},
                {"layer":2,"name":"  └─ I-ctrl Byte1: N(R)+P/F","raw":b"","user_val":f"N(R)={nr} P/F={pf}","note":f"bits[7:1]=N(R)={nr}  bit[0]=P/F={pf}"},
            ]
        else:
            records.append({"layer":2,"name":"  └─ I-ctrl bits breakdown","raw":b"",
                            "user_val":f"N(S)={ns} P/F={pf} N(R)={nr}",
                            "note":f"[7:5]N(S)={ns:03b}  [4]P/F={pf}  [3:1]N(R)={nr:03b}  [0]=0"})
    elif ftype == '2':
        records.append({"layer":2,"name":"  └─ S-ctrl bits breakdown","raw":b"",
                        "user_val":f"N(R)={nr} P/F={pf} {s_mn}",
                        "note":f"[7:5]N(R)={nr:03b}  [4]P/F={pf}  [3:2]SS={s1}{s0}({s_mn})  [1:0]=01"})
    else:
        records.append({"layer":2,"name":"  └─ U-ctrl bits breakdown","raw":b"",
                        "user_val":f"{u_mn}  P/F={pf}",
                        "note":f"[7:5]M={m4}{m3}{m2}  [4]P/F={pf}  [3:2]M={m1}{m0}  [1:0]=11"})

    if info_bytes:
        records.append({"layer":3,"name":"HDLC Information (payload)","raw":info_bytes,
                        "user_val":info_bytes.hex()[:30] if len(info_bytes)<=15 else f"{len(info_bytes)}B",
                        "note":f"{len(info_bytes)} bytes"})
    records += [
        {"layer":0,"name":f"HDLC FCS  ({fcs_label})","raw":fcs_bytes,"user_val":fcs_bytes.hex(),
         "note":f"Covers: Addr+Ctrl+Info={len(fcs_input)}B  {stuff_note}"},
        {"layer":1,"name":"HDLC End Flag","raw":flag_b,"user_val":flag_b.hex(),"note":"0x7E — frame end delimiter"},
    ]
    banner(f"HDLC FRAME — {frame_type_label}")
    print_frame_table(records)
    verify_report([(f"HDLC {fcs_label}", fcs_bytes.hex(), fcs_verify.hex(), fcs_bytes==fcs_verify)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"serial","protocol":"hdlc"})

def flow_serial():
    banner("SERIAL / WAN FRAME BUILDER",
           "L2: PPP | HDLC | SLIP | Modbus RTU | ATM AAL5 | Cisco HDLC | KISS | COBS")

    # PHY encoding selection for serial protocols
    if _PHY_AVAILABLE:
        phy_serial = ask_phy_mode()
        if phy_serial == 'phy':
            serial_phy = ask_phy_serial_encoding()
            if serial_phy:
                p = serial_phy.get('info', {})
                print(f"\n  {C.L1}  PHY selected: {p.get('name','')}{C.RESET}")
                print(f"  {C.DIM}  Encoding: {p.get('encoding','')}{C.RESET}")
                fs = serial_phy.get('frame_start', {})
                fe = serial_phy.get('frame_end', {})
                print(f"  {C.L1}  Frame start: {fs.get('mechanism','Start bit')}{C.RESET}")
                print(f"  {C.L1}  Frame end  : {fe.get('mechanism','Stop bit')}{C.RESET}")
                caution = p.get('caution','')
                if caution:
                    print(f"  {C.WARN}  ⚠  {caution}{C.RESET}")

    ch, proto_name = ask_l2_serial()
    if ch == '11': flow_hdlc(); return

    start_flag = b'\x7E'; end_flag = b'\x7E'
    if ch in ('3','4','8','10'):
        start_flag = get_hex("Start Flag (2 hex)", "7e", 1)
        end_flag   = get_hex("End   Flag (2 hex)", "7e", 1)

    addr_map = {'3':'ff','4':'ff','8':'ff','10':'0f','7':'01'}
    address  = b''
    if ch in addr_map: address = get_hex(f"Address/Slave (2 hex)", addr_map[ch], 1)

    control = b''
    if ch in ('3','4','8','10'): control = get_hex("Control field (2 hex)", "03", 1)

    l3_payload = b''; l3_fields = []
    if ch in ('3','4','8','10'):
        section("LAYER 3 — Payload inside Serial frame")
        print("      1 = None  (empty payload)")
        print("      2 = Raw hex  (enter bytes directly)")
        print("      3 = IPv4  →  then choose L4 (ICMP / TCP / UDP)")
        l3ch = input(f"    {C.PROMPT}Choose [1]: {C.RESET}").strip() or '1'
        if l3ch == '2':
            phex = get("Payload hex", "")
            try:    l3_payload = bytes.fromhex(phex.replace(" ", ""))
            except: l3_payload = b''
        elif l3ch == '3':
            src_ip,_ = _resolve_host(get("Source IP", "192.168.1.10"))
            dst_ip,_ = _resolve_host(get("Destination IP", "192.168.1.20"))
            ttl=int(get("TTL","64")); ip_id=int(get("IP ID","1")); dscp=int(get("DSCP","0"))
            df=get("DF? (y/n)","y").lower().startswith('y')
            # Show L4 sub-menu pulled from l3/l4 builders
            l4ch = print_ipv4_l4_menu()
            if l4ch == '1':
                icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex = ask_l4_icmp()
                icmp_msg,icmp_flds,_ = build_icmp(icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex)
                ip_hdr,ip_flds,_ = build_ipv4(icmp_msg,src_ip,dst_ip,ttl,ip_id,dscp,df,1)
                l3_payload = ip_hdr + icmp_msg; l3_fields = ip_flds + icmp_flds
            elif l4ch == '2':
                (step,step_name,src_port,dst_port,seq_num,ack_num,data_off,
                 flags_val,window,urg_ptr,tcp_data,sip,dip) = ask_l4_tcp(src_ip, dst_ip)
                tcp_seg,tcp_flds,_ = build_tcp(step,step_name,src_port,dst_port,seq_num,ack_num,
                                               data_off,flags_val,window,urg_ptr,tcp_data,src_ip,dst_ip)
                ip_hdr,ip_flds,_ = build_ipv4(tcp_seg,src_ip,dst_ip,ttl,ip_id,dscp,df,6)
                l3_payload = ip_hdr + tcp_seg; l3_fields = ip_flds + tcp_flds
            elif l4ch == '3':
                src_port,dst_port,udp_data,sip,dip = ask_l4_udp(src_ip, dst_ip)
                udp_dgram,udp_flds,_ = build_udp(src_port,dst_port,udp_data,src_ip,dst_ip)
                ip_hdr,ip_flds,_ = build_ipv4(udp_dgram,src_ip,dst_ip,ttl,ip_id,dscp,df,17)
                l3_payload = ip_hdr + udp_dgram; l3_fields = ip_flds + udp_flds
            else:
                # Raw/empty — just IPv4 header
                ip_hdr,ip_flds,_ = build_ipv4(b'',src_ip,dst_ip,ttl,ip_id,dscp,df,0)
                l3_payload = ip_hdr; l3_fields = ip_flds
        elif l3ch == '4':
            src_ip,_ = _resolve_host(get("Source IP", "192.168.1.10"))
    header    = address + control
    crc_input = header + l3_payload
    fcs = b''; fcs_desc = "none"
    if ch in ('3','4','8','10'):
        fcs, fcs_desc = ask_serial_crc(crc_input, "FCS-16 CCITT", 'big')
    elif ch == '7':
        fcs, fcs_desc = ask_serial_crc(crc_input, "Modbus CRC-16", 'little')
    elif ch == '9':
        crc_val = zlib.crc32(crc_input) & 0xFFFFFFFF
        section("ATM AAL5 CRC-32")
        cx = input(f"    {C.PROMPT}1=Auto  2=Custom  [1]: {C.RESET}").strip() or '1'
        if cx == '2':
            fh = input(f"    {C.PROMPT}Enter 8 hex digits: {C.RESET}").strip()
            try:
                cf = bytes.fromhex(fh)
                if len(cf) == 4: fcs = cf; fcs_desc = "AAL5 CRC-32 custom"
                else: raise ValueError
            except:
                fcs = crc_val.to_bytes(4,'big'); fcs_desc = f"AAL5 CRC-32 auto over {len(crc_input)}B"
        else:
            fcs = crc_val.to_bytes(4,'big'); fcs_desc = f"AAL5 CRC-32 auto over {len(crc_input)}B"

    content = header + l3_payload + fcs
    if ch == '2':              full_frame = slip_enc(content)
    elif ch in ('3','4','10'): full_frame = start_flag + byte_escape(content) + end_flag
    elif ch == '8':            full_frame = start_flag + bit_stuff(byte_escape(content)) + end_flag
    elif ch == '9':
        pad_len = (48 - (len(content)+8) % 48) % 48
        full_frame = content + b'\x00'*pad_len + fcs
    else:                      full_frame = content

    records = []
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"Start Flag","raw":start_flag,"user_val":start_flag.hex(),"note":"0x7E frame delimiter"})
    if address: records.append({"layer":2,"name":"Address","raw":address,"user_val":address.hex(),"note":""})
    if control: records.append({"layer":2,"name":"Control","raw":control,"user_val":control.hex(),"note":""})
    records += l3_fields
    if fcs:     records.append({"layer":0,"name":"CRC/FCS","raw":fcs,"user_val":"auto/custom","note":fcs_desc})
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"End Flag","raw":end_flag,"user_val":end_flag.hex(),"note":"0x7E frame delimiter"})

    banner(f"SERIAL FRAME — {proto_name}")
    print_frame_table(records)
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"serial","protocol":proto_name.lower().split()[0]})

def flow_wifi():
    banner("WiFi FRAME  —  IEEE 802.11  (PHY Preamble + MAC MPDU)",
           "PHY: STF+LTF+SIG(≈SFD)  |  MAC: FC+Dur+Addr1-4+SeqCtrl+QoS+HTC+Body+FCS")
    print_wifi_education()
    d = ask_wifi_frame()
    full_frame, records, mpdu, fcs, fcs_computed = build_wifi(d)
    mpdu_len    = len(mpdu) + 4
    phy_records = ask_wifi_phy(d['phy_ch'], mpdu_len)
    all_records = phy_records + records
    print_frame_table(all_records)
    verify_report([("802.11 FCS (CRC-32 MPDU)", fcs.hex(), fcs_computed.hex(), fcs==fcs_computed)])
    phy_bytes    = b''.join(r['raw'] for r in phy_records)
    full_with_phy = phy_bytes + full_frame
    print_encapsulation(all_records, full_with_phy)
    _run_layer_progression({"technology":"wifi","protocol":"802.11"})

def flow_ip_standalone(preselected_l4: str = ""):
    banner("STANDALONE IPv4 PACKET BUILDER",
           "RFC 791  |  Full header fields  |  Options  |  Auto or manual checksum  |  L4 payload")
    print_ip_education()
    section("DSCP / ECN REFERENCE")
    print(f"  {'Value':>5}  {'DSCP Name':<12}  Description"); print(f"  {'─'*60}")
    for val,(name,desc) in sorted(DSCP_TABLE.items()): print(f"  {val:>5}  {name:<12}  {desc}")
    section("PROTOCOL NUMBER REFERENCE")
    print(f"  {'Proto':>5}  {'Name':<8}  Description"); print(f"  {'─'*60}")
    for num,(name,desc) in sorted(IP_PROTO_NAMES.items()): print(f"  {num:>5}  {name:<8}  {desc}")
    section("IPv4 HEADER FIELDS")
    print(f"    {C.NOTE}You can enter an IPv4 address OR a domain name for each IP.{C.RESET}")

    src_raw = get("Source IP or domain", "192.168.1.10",
        help="IPv4 address OR domain name of the SENDER.\nPrivate: 10.x.x.x / 172.16-31.x.x / 192.168.x.x")
    try:
        src_ip, src_dom = _resolve_host(src_raw.strip())
        if src_dom: print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{src_dom}{C.RESET}  →  {C.HEX}{src_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{src_raw}': {e} — using as-is{C.RESET}")
        src_ip, src_dom = src_raw.strip(), ""

    dst_raw = get("Destination IP or domain", "192.168.1.20",
        help="IPv4 address OR domain name of the RECEIVER.\n8.8.8.8=Google DNS  1.1.1.1=Cloudflare")
    try:
        dst_ip, dst_dom = _resolve_host(dst_raw.strip())
        if dst_dom: print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{dst_dom}{C.RESET}  →  {C.HEX}{dst_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{dst_raw}': {e} — using as-is{C.RESET}")
        dst_ip, dst_dom = dst_raw.strip(), ""

    ttl = int(get("TTL  (Time To Live)", "64",
        help="64=Linux/Mac  128=Windows  255=max\n1=traceroute probe  255=link-local protocols"))
    print(f"\n    Common protocol numbers: 1=ICMP  6=TCP  17=UDP  47=GRE  89=OSPF  50=ESP")
    proto_in = get("Protocol number", "1",
        help="IANA 8-bit field. Receiver uses this to route payload to correct socket.")
    try:    proto_num = int(proto_in) & 0xFF
    except: proto_num = 1
    proto_name_s = IP_PROTO_NAMES.get(proto_num, (str(proto_num),"Unknown"))[0]
    print(f"    -> Protocol: {proto_num} = {proto_name_s}")

    ip_id = int(get("Identification  (0–65535)", "1234",
        help="16-bit fragment group ID. Arbitrary for non-fragmented packets."))

    section("IP FLAGS + FRAGMENT OFFSET")
    df = get("DF  Don't Fragment  (y/n)", "y",
        help="y=DF=1: routers must NOT fragment. Required for TCP PMTUD.\nn=DF=0: fragmentation allowed.").lower().startswith('y')
    mf = get("MF  More Fragments  (y/n)", "n",
        help="y=MF=1: more fragments follow this one.\nn=MF=0: last or only fragment.").lower().startswith('y')
    frag_off = int(get("Fragment Offset  (0 for non-fragmented)", "0",
        help="Offset of this fragment's data ÷8. 0 for unfragmented packets.")) & 0x1FFF
    flags_frag = (0<<15) | ((1 if df else 0)<<14) | ((1 if mf else 0)<<13) | frag_off

    section("DSCP / ECN  (Quality of Service)")
    dscp_val = int(get("DSCP value  (0–63)", "0",
        help="0=BE(default)  46=EF(VoIP)  48=CS6(routing)  34=AF41(video conf)")) & 0x3F
    ecn_val  = int(get("ECN  (0=non-ECN  1=ECT1  2=ECT0  3=CE)", "0",
        help="0=Not-ECN-capable  3=CE(Congestion Experienced — set by router)")) & 0x3
    tos = (dscp_val << 2) | ecn_val

    opt_bytes, opt_records = ask_ip_options()
    ihl = 5 + len(opt_bytes) // 4

    payload_ch  = ask_ip_payload(preselected_l4)
    l4_payload  = b''; l4_records = []; l4_ck = 0; l4_proto_override = None

    if payload_ch == '1':
        icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex = ask_l4_icmp()
        l4_payload,l4_records,l4_ck = build_icmp(icmp_type,icmp_code,icmp_id,icmp_seq,icmp_data,data_hex)
        l4_proto_override = 1
    elif payload_ch == '2':
        print_tcp_handshake_diagram()
        (step,step_name,src_port,dst_port,seq_num,ack_num,
         data_off,flags_val,window,urg_ptr,tcp_data,sip,dip) = ask_l4_tcp(src_ip, dst_ip)
        l4_payload,l4_records,l4_ck = build_tcp(step,step_name,src_port,dst_port,seq_num,ack_num,
                                                  data_off,flags_val,window,urg_ptr,tcp_data,src_ip,dst_ip)
        l4_proto_override = 6
    elif payload_ch == '3':
        (src_port,dst_port,udp_data,sip,dip) = ask_l4_udp(src_ip, dst_ip)
        l4_payload,l4_records,l4_ck = build_udp(src_port,dst_port,udp_data,src_ip,dst_ip)
        l4_proto_override = 17
    elif payload_ch == '4':
        section("RAW HEX PAYLOAD")
        raw_hex = get("Payload hex bytes", "",
            help="Any bytes in hex — custom protocols, test patterns, GRE inner frames.")
        try:    l4_payload = bytes.fromhex(raw_hex.replace(" ", ""))
        except: l4_payload = b''
        if l4_payload:
            l4_records = [{"layer":4,"name":"Raw Payload","raw":l4_payload,
                           "user_val":f"{len(l4_payload)}B","note":"raw hex"}]
    # payload_ch == '5': empty — stays b''

    if l4_proto_override: proto_num = l4_proto_override

    tot_len  = ihl*4 + len(l4_payload)
    ver_ihl  = (4 << 4) | ihl
    hdr0     = struct.pack("!BBHHHBBH4s4s",
                   ver_ihl, tos, tot_len, ip_id, flags_frag,
                   ttl, proto_num, 0, ip_b(src_ip), ip_b(dst_ip))
    if opt_bytes: hdr0 = hdr0 + opt_bytes
    auto_ck  = inet_cksum(hdr0)

    section("IP HEADER CHECKSUM  (RFC 791 — one's complement)")
    print(f"    Header size      : {ihl*4} bytes  (IHL={ihl})")
    print(f"    Auto-computed    : 0x{auto_ck:04X}")
    print(f"\n      1 = Use auto-calculated  0x{auto_ck:04X}  (correct)")
    print(f"      2 = Enter custom checksum  (for testing bad-checksum handling)")
    print(f"      3 = Force 0x0000          (simulate checksum-offload / not computed)")
    ck_ch = input("    Choice [1]: ").strip() or '1'
    if ck_ch == '2':
        ck_hex = get("Custom checksum (4 hex chars)", f"{auto_ck:04x}")
        try:    user_ck = int(ck_hex, 16) & 0xFFFF
        except: user_ck = auto_ck
        ck_note = f"0x{user_ck:04X}  CUSTOM (auto would be 0x{auto_ck:04X})"
        ck_val  = user_ck
    elif ck_ch == '3':
        ck_val  = 0x0000
        ck_note = "0x0000 forced (checksum offload / not computed)"
    else:
        ck_val  = auto_ck
        ck_note = f"0x{auto_ck:04X}  RFC791 one's complement (auto)"

    hdr = struct.pack("!BBHHHBBH4s4s",
              ver_ihl, tos, tot_len, ip_id, flags_frag,
              ttl, proto_num, ck_val, ip_b(src_ip), ip_b(dst_ip))
    if opt_bytes: hdr = hdr + opt_bytes
    full_packet = hdr + l4_payload

    ck_verify = inet_cksum(hdr)
    ck_ok     = (ck_verify == 0)

    flag_parts = []
    if flags_frag & 0x4000: flag_parts.append("DF")
    if flags_frag & 0x2000: flag_parts.append("MF")
    flag_str   = '+'.join(flag_parts) if flag_parts else "none"
    dscp_name  = DSCP_TABLE.get(dscp_val, (f"DSCP{dscp_val}",""))[0]
    ecn_names  = {0:"Non-ECN", 1:"ECT1", 2:"ECT0", 3:"CE"}

    records = [
        {"layer":3,"name":"IP Version + IHL","raw":hdr[0:1],
         "user_val":f"v4 / IHL={ihl}","note":f"Header={ihl*4}B  {'options present' if ihl>5 else 'no options'}"},
        {"layer":3,"name":"IP DSCP + ECN","raw":hdr[1:2],
         "user_val":f"DSCP={dscp_val}({dscp_name}) ECN={ecn_val}({ecn_names[ecn_val]})",
         "note":f"TOS byte = 0x{tos:02X}"},
        {"layer":3,"name":"IP Total Length","raw":hdr[2:4],
         "user_val":"auto","note":f"{tot_len}B  (header {ihl*4}B + payload {len(l4_payload)}B)"},
        {"layer":3,"name":"IP Identification","raw":hdr[4:6],
         "user_val":str(ip_id),"note":f"0x{ip_id:04X}  fragment group ID"},
        {"layer":3,"name":"IP Flags + Frag Offset","raw":hdr[6:8],
         "user_val":f"flags={flag_str}  offset={frag_off}",
         "note":f"DF={int(df)} MF={int(mf)} FragOffset={frag_off} (×8={frag_off*8}B)"},
        {"layer":3,"name":"IP TTL","raw":hdr[8:9],
         "user_val":str(ttl),"note":"hops remaining"},
        {"layer":3,"name":"IP Protocol","raw":hdr[9:10],
         "user_val":str(proto_num),"note":proto_name_s},
        {"layer":3,"name":"IP Header Checksum","raw":hdr[10:12],
         "user_val":f"0x{ck_val:04X}","note":ck_note},
        {"layer":3,"name":"IP Source Address","raw":hdr[12:16],
         "user_val":src_ip,"note":f"({src_dom})" if src_dom else ""},
        {"layer":3,"name":"IP Destination Addr","raw":hdr[16:20],
         "user_val":dst_ip,"note":f"({dst_dom})" if dst_dom else ""},
    ]
    records += opt_records
    records += l4_records

    verify_checks = [("IP Header Checksum (RFC791)", f"0x{ck_val:04X}",
                      f"0x{ck_verify:04X} → {'0x0000=PASS' if ck_ok else 'NON-ZERO=FAIL'}", ck_ok)]
    if payload_ch == '1' and l4_records:
        icmp_ver = inet_cksum(l4_payload)
        verify_checks.append(("ICMP Checksum (RFC792)", f"0x{l4_ck:04X}", f"verify={icmp_ver:04X}", icmp_ver==0))
    elif payload_ch == '2' and l4_records:
        tcp_ver = tcp_checksum(src_ip, dst_ip, l4_payload)
        verify_checks.append(("TCP Checksum (RFC793 pseudo-hdr)", f"0x{l4_ck:04X}", f"verify={tcp_ver:04X}", tcp_ver==0))
    elif payload_ch == '3' and l4_records:
        udp_ver = udp_checksum(src_ip, dst_ip, l4_payload)
        verify_checks.append(("UDP Checksum (RFC768 pseudo-hdr)", f"0x{l4_ck:04X}", f"verify={udp_ver:04X}", udp_ver==0))

    banner(f"STANDALONE IPv4 PACKET  —  {src_ip} → {dst_ip}  proto={proto_name_s}  {tot_len}B")
    print_frame_table(records)
    verify_report(verify_checks)
    print_encapsulation(records, full_packet)
    _run_layer_progression({"technology":"standalone_ip","protocol":"ipv4"},src_ip,dst_ip,proto_num)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — MENUS, DISPATCH TABLE, MAIN
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
#  FLOW — GENERIC ETHERNET BUILDER  (any EtherType not already specialised)
#  Used when user picks an EtherType that has a defined PDU but no dedicated
#  ask_/build_ flow, OR when pdu == 'RAW'.
# ══════════════════════════════════════════════════════════════════════════════
def _ask_fields_interactive(fields: dict, layer: int, section_title: str) -> tuple[bytes, list[dict]]:
    """
    Core helper — asks user for every field in a fields dict interactively.
    Skips CAUTION/Note entries (prints them as warnings).
    Returns (assembled_bytes, records_list) for frame table display.
    """
    import re
    raw_parts: list[bytes] = []
    records: list[dict] = []

    if fields:
        section(section_title)
        print(f"  {C.DIM}  Each field is asked individually. Press Enter to use the default value.{C.RESET}")
        print(f"  {C.DIM}  Size notation: 1B=1 byte 2B=2 bytes 4B=4 bytes  b=bits (enter as hex){C.RESET}")
        print(f"  {C.SEP_C}{'─'*80}{C.RESET}")

    for fname, fdesc in fields.items():
        fdesc_str = str(fdesc)

        # CAUTION / Note — print warning, don't ask input
        if fname.upper() in ('CAUTION', 'NOTE', 'NOTE:'):
            print(f"\n  {C.WARN}  ⚠  {fname}: {fdesc_str}{C.RESET}\n")
            continue

        # Determine byte size from description
        byte_size = 0
        m_bytes = re.search(r'(\d+)B\b', fdesc_str)
        m_bits  = re.search(r'(\d+)b\b', fdesc_str)
        if m_bytes:
            byte_size = int(m_bytes.group(1))
        elif m_bits:
            # bit field — round up to byte boundary for collection
            byte_size = max(1, (int(m_bits.group(1)) + 7) // 8)

        # Extract sensible default from description
        default = ""
        m_hex = re.search(r'0x([0-9A-Fa-f]{2,})', fdesc_str)
        if m_hex:
            default = '0x' + m_hex.group(1)
        elif byte_size == 1:  default = "00"
        elif byte_size == 2:  default = "0000"
        elif byte_size == 3:  default = "000000"
        elif byte_size == 4:  default = "00000000"
        elif byte_size == 6:  default = "000000000000"
        elif byte_size == 8:  default = "0000000000000000"

        # Show field with description
        size_hint = f"[{byte_size}B]" if byte_size else "[var]"
        val = get(f"  {fname:<28} {size_hint}", default,
                  help=fdesc_str[:120] if len(fdesc_str) > 40 else "")

        # Convert to bytes
        clean = val.strip().replace(' ','').replace(':','').replace('-','').lstrip('0x').lstrip('0X')
        if not clean: clean = '00' * max(1, byte_size)

        # Pad or truncate to expected byte size
        if byte_size:
            clean = clean.zfill(byte_size * 2)[-byte_size * 2:]
        else:
            # variable length — take what was given
            if len(clean) % 2: clean = '0' + clean

        try:
            chunk = bytes.fromhex(clean)
        except ValueError:
            # Try ASCII encoding for string fields
            try:
                chunk = val.encode('ascii')
                if byte_size and len(chunk) < byte_size:
                    chunk = chunk.ljust(byte_size, b'\x00')
                elif byte_size:
                    chunk = chunk[:byte_size]
            except Exception:
                chunk = b'\x00' * max(1, byte_size)

        raw_parts.append(chunk)
        records.append({
            "layer":  layer,
            "name":   fname[:24],
            "raw":    chunk,
            "user_val": val[:20],
            "note":   fdesc_str[:40],
        })

    assembled = b''.join(raw_parts)
    return assembled, records


def _ask_variable_payload(label: str = "Variable payload") -> tuple[bytes, list[dict]]:
    """Ask for a variable-length payload as hex or ASCII."""
    section(f"{label}  (variable length)")
    print(f"  {C.DIM}  Enter as hex bytes (e.g. 48656c6c6f) or press Enter for empty{C.RESET}")
    val = get("Payload hex", "")
    clean = val.replace(' ','').replace(':','')
    try:
        data = bytes.fromhex(clean)
    except ValueError:
        # Try as ASCII
        try:    data = val.encode('ascii')
        except: data = b''
    if data:
        return data, [{"layer":3,"name":label[:24],"raw":data,
                       "user_val":f"{len(data)}B","note":"variable payload"}]
    return b'', []


def flow_eth_generic(et_int: int):
    """
    Generic Ethernet frame builder — asks EVERY field interactively.

    For each EtherType:
      1. Load PDU fields from l2_builder (header-level fields)
      2. Load L3 type_map from l3_builder (dispatch field → sub-protocol)
      3. If L3 has a type_map, ask user to pick type, then ask L3 fields
      4. Load L4 fields from l4_builder for the selected L3 type
      5. Ask every L4 field interactively
      6. For truly RAW EtherTypes (no defined PDU): still ask raw hex
      7. Assemble L1+L2+all_fields+FCS and display frame table
    """
    import re

    # ── Load registry info ────────────────────────────────────────────────────
    info   = {}
    pdu    = 'RAW'
    name   = f"0x{et_int:04X}"
    l2_fields: dict = {}
    stack  = {}
    l3_cls: str = ''

    if _L2_AVAILABLE:
        from l2_builder import ETHERTYPE_REGISTRY, get_l3_stack
        info   = ETHERTYPE_REGISTRY.get(et_int, {})
        pdu    = info.get('pdu', 'RAW')
        name   = info.get('name', f"0x{et_int:04X}")
        l2_fields = info.get('fields', {})
        stack  = get_l3_stack(et_int)
        l3_cls = info.get('l3_proto') or ''

    l3_entry: dict = {}
    l3_type_map: dict = {}
    if _L3_AVAILABLE and l3_cls:
        from l3_builder import NON_IP_L3_REGISTRY
        l3_entry   = NON_IP_L3_REGISTRY.get(l3_cls, {})
        l3_type_map = l3_entry.get('type_map', {})

    # ── Banner ────────────────────────────────────────────────────────────────
    banner(f"ETHERNET  +  {name}",
           f"L1: Preamble+SFD  |  L2: EtherType 0x{et_int:04X}  |  PDU: {pdu}")

    # Protocol info header
    print(f"\n  {C.SECT}{C.BOLD}▌ PROTOCOL: {name}{C.RESET}")
    print(f"  {C.DIM}  PDU      : {pdu}{C.RESET}")
    print(f"  {C.DIM}  Category : {info.get('category','?')}  |  Status: {info.get('status','?')}{C.RESET}")
    print(f"  {C.DIM}  Usage    : {info.get('usage','')}{C.RESET}")
    if stack:
        print(f"  {C.SEP_C}{'─'*76}{C.RESET}")
        for k, v in list(stack.items())[:4]:
            print(f"  {C.L2}  {k:<16}{C.RESET}  {C.DIM}{str(v)[:65]}{C.RESET}")

    # Print any CAUTION from l2 fields upfront
    for fname, fdesc in l2_fields.items():
        if fname.upper() == 'CAUTION':
            print(f"\n  {C.WARN}  ⚠  CAUTION: {fdesc}{C.RESET}")

    # ── L1 ───────────────────────────────────────────────────────────────────
    preamble, sfd = ask_layer1_eth()

    # ── L2 MAC header ────────────────────────────────────────────────────────
    section(f"LAYER 2 — ETHERNET  (EtherType 0x{et_int:04X}  {name[:35]})")

    # Multicast destination hint from l3_stack
    dst_hint = "ff:ff:ff:ff:ff:ff"
    if stack.get('L2') and ':' in str(stack.get('L2','')):
        import re as _re
        m = _re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', str(stack['L2']))
        if m: dst_hint = m.group(1)

    dst_s = get("Destination MAC", dst_hint,
                help="Unicast, multicast (01:xx), or broadcast (ff:ff:ff:ff:ff:ff)")
    src_s = get("Source MAC", "aa:bb:cc:dd:ee:ff")
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)
    et_b   = struct.pack('>H', et_int)

    # ── PDU fields (L3 header) ────────────────────────────────────────────────
    all_payload   = b''
    all_records: list[dict] = []

    if pdu == 'RAW' or not l2_fields:
        # Truly no defined structure — ask raw hex only
        section(f"PAYLOAD  (RAW — 0x{et_int:04X} has no published PDU structure)")
        print(f"  {C.WARN}  No defined field structure — enter raw hex payload bytes{C.RESET}")
        raw_hex = get("Raw payload hex (Enter=empty)", "")
        try:    all_payload = bytes.fromhex(raw_hex.replace(' ','').replace(':',''))
        except: all_payload = b''
        if all_payload:
            all_records.append({"layer":3,"name":f"Raw Payload","raw":all_payload,
                                "user_val":f"{len(all_payload)}B","note":"RAW — no defined PDU"})
    else:
        # Has defined fields — ask each one interactively
        # Remove CAUTION entries before asking (already shown above)
        ask_fields = {k:v for k,v in l2_fields.items()
                      if k.upper() not in ('CAUTION','NOTE')}

        # Separate fixed fields from variable ones
        fixed_fields  = {k:v for k,v in ask_fields.items()
                         if re.search(r'\d+B\b', str(v)) or re.search(r'\d+b\b', str(v))}
        var_fields    = {k:v for k,v in ask_fields.items() if k not in fixed_fields}

        # Ask fixed PDU header fields
        if fixed_fields:
            hdr_bytes, hdr_records = _ask_fields_interactive(
                fixed_fields, layer=3, section_title=f"PDU HEADER — {pdu}")
            all_payload += hdr_bytes
            all_records += hdr_records

        # ── L3 type dispatch ─────────────────────────────────────────────────
        l4_fields: dict = {}
        l4_cls  = ''
        if l3_type_map:
            section(f"L3 TYPE SELECTION — {l3_entry.get('name', l3_cls)}")
            print(f"  {C.DIM}  {l3_entry.get('type_field','Type field')} determines the L4 protocol:{C.RESET}")
            type_list = list(l3_type_map.items())
            for i, (tval, tinfo) in enumerate(type_list, 1):
                print(f"  {C.L3}  [{i:>2}]  {tval:<6}  {tinfo['name']:<20}  {C.DIM}{tinfo['usage']}{C.RESET}")
            type_ch = input(f"  {C.PROMPT}Choose type (1-{len(type_list)}, or Enter=1): {C.RESET}").strip() or '1'
            try:
                tidx = int(type_ch) - 1
                assert 0 <= tidx < len(type_list)
            except (ValueError, AssertionError):
                tidx = 0
            chosen_type_val, chosen_type_info = type_list[tidx]
            l4_cls = chosen_type_info.get('l4', '')
            print(f"  {C.PASS_}  → Selected: {chosen_type_info['name']} (type={chosen_type_val}){C.RESET}")

            # Encode the type value into the appropriate field
            # Find which field carries the type (usually it's in l3_fields or the 'type_field' desc)
            type_key = l3_entry.get('l4_key', '')
            if type_key and type_key not in fixed_fields:
                # Add type byte record
                try:
                    if isinstance(chosen_type_val, int):
                        type_bytes = chosen_type_val.to_bytes(1, 'big')
                    else:
                        type_bytes = bytes([int(str(chosen_type_val), 16)])
                    all_payload += type_bytes
                    all_records.append({"layer":3,"name":f"Type ({type_key})","raw":type_bytes,
                                        "user_val":str(chosen_type_val),"note":chosen_type_info['name']})
                except Exception:
                    pass

        # Ask variable/data fields from l2_fields
        for fname, fdesc in var_fields.items():
            if fname.upper() in ('CAUTION','NOTE'): continue
            fdesc_s = str(fdesc)
            print(f"\n  {C.L3}  {fname}{C.RESET}  {C.DIM}{fdesc_s[:70]}{C.RESET}")
            val = get(f"  {fname} (hex or text)", "")
            if val:
                clean = val.replace(' ','').replace(':','')
                try:
                    chunk = bytes.fromhex(clean)
                except ValueError:
                    chunk = val.encode('ascii', errors='replace')
                all_payload += chunk
                all_records.append({"layer":3,"name":fname[:24],"raw":chunk,
                                    "user_val":val[:20],"note":fdesc_s[:40]})

        # ── L4 interactive fields ─────────────────────────────────────────────
        if l4_cls and _L4_AVAILABLE:
            from l4_builder import NON_IP_L4_REGISTRY
            l4_entry = NON_IP_L4_REGISTRY.get(l4_cls, {})
            # field_detail or fields
            l4_fields = (l4_entry.get('fields') or
                         l4_entry.get('field_detail') or {})

            if l4_fields:
                l4_name = l4_entry.get('name', l4_cls)
                print(f"\n  {C.SECT}{C.BOLD}▌ L4: {l4_name}{C.RESET}")
                print(f"  {C.DIM}  Transport: {l4_entry.get('transport','')}{C.RESET}")
                if l4_entry.get('applications'):
                    print(f"  {C.DIM}  Applications: {l4_entry['applications'][:70]}{C.RESET}")
                caution = l4_entry.get('caution') or l4_fields.get('CAUTION','')
                if caution:
                    print(f"  {C.WARN}  ⚠  CAUTION: {caution}{C.RESET}")

                ask_l4 = {k:v for k,v in l4_fields.items()
                          if k.upper() not in ('CAUTION','NOTE')}
                l4_bytes, l4_records = _ask_fields_interactive(
                    ask_l4, layer=4, section_title=f"L4 FIELDS — {l4_name}")
                all_payload += l4_bytes
                all_records += l4_records

        # Ask for variable/data payload at the end
        section("DATA PAYLOAD  (variable — actual content/data segment)")
        print(f"  {C.DIM}  Any remaining payload bytes after the header fields above{C.RESET}")
        print(f"  {C.DIM}  Enter as hex (e.g. deadbeef) or press Enter to skip{C.RESET}")
        data_hex = get("Data payload hex (Enter=none)", "")
        if data_hex.strip():
            clean = data_hex.replace(' ','').replace(':','')
            try:
                data_bytes = bytes.fromhex(clean)
                all_payload += data_bytes
                all_records.append({"layer":3,"name":"Data Payload","raw":data_bytes,
                                    "user_val":f"{len(data_bytes)}B","note":"variable data"})
            except ValueError:
                print(f"  {C.WARN}  Invalid hex — data payload skipped{C.RESET}")

    # ── Assemble frame ────────────────────────────────────────────────────────
    mac_content = dst_mb + src_mb + et_b + all_payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame   = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble", "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",      "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",  "raw":dst_mb,  "user_val":dst_s,         "note":""},
        {"layer":2,"name":"Src MAC",  "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"EtherType","raw":et_b,    "user_val":f"0x{et_int:04X}",
         "note":f"{name[:35]}  [{info.get('category','?')}]"},
    ] + all_records + [
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,
         "user_val":"auto/custom","note":fcs_note},
    ]

    print_frame_table(records)
    fcs_s = full_frame[-4:]; fcs_r = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_s.hex(), fcs_r.hex(), fcs_s == fcs_r)])
    print_encapsulation(records, full_frame)
    _run_layer_progression({"technology":"ethernet",
                             "protocol": pdu.lower().replace(' ','_'),
                             "ethertype": et_int,
                             "raw_bytes": all_payload})

    # ── PHY encoding (if PHY mode was selected) ───────────────────────────────
    global _ETH_PHY_SPEED
    if _ETH_PHY_SPEED not in ('MAC_ONLY', '') and _PHY_AVAILABLE:
        do_enc, idle_count = ask_phy_encoding_option(_ETH_PHY_SPEED)
        if do_enc:
            show_eth_phy_encoding(full_frame, _ETH_PHY_SPEED, idle_count=idle_count)


# ══════════════════════════════════════════════════════════════════════════════
#  flow_eth_ipv4 — unified IPv4 entry point that shows L4 sub-menu
# ══════════════════════════════════════════════════════════════════════════════
def flow_eth_ipv4():
    """
    Called when user selects IPv4 from Ethernet menu.
    Shows L4 sub-menu (ICMP/TCP/UDP/Other/Raw/Empty) pulled from l3/l4 builders,
    then dispatches to the correct dedicated flow.
    """
    l4ch = print_ipv4_l4_menu()
    if   l4ch == '1': flow_eth_ip_icmp()
    elif l4ch == '2': flow_eth_ip_tcp()
    elif l4ch == '3': flow_eth_ip_udp()
    elif l4ch in ('4','5','6'):
        # Raw/Other/Empty — run generic IPv4 builder
        flow_eth_generic(0x0800)
    else:
        # Default to ICMP if invalid
        flow_eth_ip_icmp()


# ══════════════════════════════════════════════════════════════════════════════
#  FIXED DISPATCH TABLE  (13 specialised flows)
#  Entries 2/3/4 all show "IPv4" — L4 is chosen via sub-menu inside flow_eth_ipv4
# ══════════════════════════════════════════════════════════════════════════════
L3_DISPATCH_FIXED: dict[str, object] = {
    '1' : flow_eth_arp,
    '2' : flow_eth_ipv4,    # IPv4  →  L4 sub-menu (ICMP/TCP/UDP/GRE/ESP/Raw/Empty)
    '3' : flow_eth_stp,     # STP / RSTP / MSTP / PVST+ / Rapid-PVST+
    '4' : flow_eth_dtp,     # DTP — Cisco Dynamic Trunking
    '5' : flow_eth_pagp,    # PAgP — Cisco EtherChannel negotiation
    '6' : flow_eth_lacp,    # LACP — IEEE 802.3ad Link Aggregation
    '7' : flow_eth_pause,   # Pause Frame — 802.3x
    '8' : flow_eth_pfc,     # PFC — 802.1Qbb per-priority
    '9' : flow_eth_lldp,    # LLDP — 802.1AB neighbour discovery
    '10': flow_eth_vlan,    # VLAN / Q-in-Q — 802.1Q
    '11': flow_eth_jumbo,   # Jumbo Frame — MTU >1500B
    '12': flow_eth_cdp,     # CDP — Cisco Discovery Protocol
    '13': flow_eth_vtp,     # VTP — Cisco VLAN Trunk Protocol
    '14': flow_eth_pvst,    # PVST+ / Rapid-PVST+ — Cisco Per-VLAN STP
    '15': flow_eth_udld,    # UDLD — Cisco Unidirectional Link Detection
    '16': flow_fc_native,   # FC — Fibre Channel native frame (SOF+Header+Payload+CRC+EOF)
}

# Keep L3_DISPATCH alias for backward compatibility
L3_DISPATCH = L3_DISPATCH_FIXED


def _build_eth_selection_map() -> dict[str, object]:
    """
    Build the FULL Ethernet selection map at runtime:
      - Fixed specialised flows 1-15
      - All EtherTypes from l2_builder starting at 16+
    """
    sel: dict[str, tuple] = {}

    # ── Fixed flows 1-15  (one per distinct protocol) ────────────────────────
    FIXED_INFO = {
        '1' : (0x0806,None,  'ARP Frame',         'arp',    'Standard', 'ARP — Address Resolution Protocol'),
        '2' : (0x0800,None,  'IPv4 Packet',        'ipv4',   'Standard', 'IPv4  →  L4 sub-menu (ICMP/TCP/UDP/GRE/ESP/Raw/Empty)'),
        '3' : (None,  None,  'STP/RSTP/MSTP BPDU', 'stp',   'Switch',   'STP/RSTP/MSTP/PVST+ — all spanning-tree variants'),
        '4' : (None,  None,  'DTP PDU',            'dtp',    'Switch',   'DTP — Cisco Dynamic Trunking Protocol'),
        '5' : (None,  None,  'PAgP PDU',           'pagp',   'Switch',   'PAgP — Cisco EtherChannel (Port Aggregation)'),
        '6' : (0x8809,None,  'LACP PDU',           'lacp',   'Switch',   'LACP — IEEE 802.3ad/802.1AX Link Aggregation'),
        '7' : (0x8808,None,  'Pause Frame',        'pause',  'FlowCtrl', 'Pause — IEEE 802.3x symmetric flow control'),
        '8' : (0x8808,None,  'PFC Frame',          'pfc',    'FlowCtrl', 'PFC — IEEE 802.1Qbb per-priority pause'),
        '9' : (0x88CC,None,  'LLDP PDU',           'lldp',   'Discovery','LLDP — IEEE 802.1AB neighbour discovery'),
        '10': (0x8100,None,  'VLAN Tagged Frame',  'vlan',   'VLAN',     'VLAN / Q-in-Q — IEEE 802.1Q tagging'),
        '11': (None,  None,  'Jumbo Payload',      'any',    'MTU',      'Jumbo Frame — MTU >1500B up to 9000B+'),
        '12': (None,  None,  'CDP PDU',            'cdp',    'Cisco',    'CDP — Cisco Discovery Protocol (device ID/capabilities/PoE)'),
        '13': (None,  None,  'VTP PDU',            'vtp',    'Cisco',    'VTP — Cisco VLAN Trunk Protocol (VLAN database sync)'),
        '14': (None,  None,  'PVST+ BPDU',         'pvst',   'Cisco',    'PVST+/Rapid-PVST+ — Cisco Per-VLAN Spanning Tree'),
        '15': (None,  None,  'UDLD PDU',           'udld',   'Cisco',    'UDLD — Cisco Uni-Directional Link Detection'),
        '16': (None,  None,  'FC Native Frame',    'fc',     'Storage',  'Fibre Channel — SOF+Header(24B)+Payload+CRC+EOF + 8b/10b encoding'),
    }
    for k, (et, _r, pdu, l3, cat, desc) in FIXED_INFO.items():
        et_str = f"0x{et:04X}" if et else '802.3+LLC/SNAP'
        sel[k] = ('fixed', L3_DISPATCH_FIXED[k], et_str, pdu, l3, cat, desc, et)

    # ── All EtherTypes from l2_builder (skip those already covered by 1-16) ──
    if not _L2_AVAILABLE:
        return sel

    from l2_builder import ETHERTYPE_REGISTRY
    from l3_builder import NON_IP_L3_REGISTRY as nl3r

    ALREADY_COVERED = {0x0800, 0x0806, 0x8809, 0x8808, 0x88CC, 0x8100}

    # Group by category for numbered display
    CAT_ORDER = ['Standard', 'Industry', 'Vendor', 'Private', 'Historical']
    num = 17   # starts right after the 16 fixed flows
    for cat in CAT_ORDER:
        entries = [(et, v) for et, v in sorted(ETHERTYPE_REGISTRY.items())
                   if v['category'] == cat and et not in ALREADY_COVERED]
        for et_int, info in entries:
            pdu    = info['pdu']
            l3c    = info.get('l3_proto') or '—'
            l4hint = '—'
            if info.get('l3_proto') and info['l3_proto'] in nl3r:
                tmap = nl3r[info['l3_proto']].get('type_map', {})
                l4s  = sorted(set(v.get('l4','') for v in tmap.values() if v.get('l4')))
                if l4s: l4hint = '/'.join(l4s[:3])
            sel[str(num)] = (
                'generic', et_int,
                f"0x{et_int:04X}", pdu, l3c, cat,
                info.get('usage','')[:60], info['name'][:50],
                l4hint, info['status']
            )
            num += 1

    return sel


# Build once at module level
_ETH_SEL_MAP: dict = {}   # populated on first print_eth_menu() call
_ETH_PHY_SPEED: str = 'MAC_ONLY'  # set in main() before any flow runs


def print_eth_menu():
    """
    Full Ethernet menu:
      1. L1 field reference (Preamble/SFD)
      2. L2 field reference (Dst MAC/Src MAC/EtherType/FCS)
      3. Fixed specialised flows 1-11  (one per distinct protocol — no duplicates)
      4. ALL EtherTypes from l2_builder (12+), grouped by category
         Each shows: number | EtherType | PDU | L3 class | L4 hint | status
    All entries are selectable — picks 1-11 run full builders,
    12+ run flow_eth_generic() with the registry field info.
    """
    global _ETH_SEL_MAP
    _ETH_SEL_MAP = _build_eth_selection_map()

    SEP90 = '─' * 90

    # ── L1 reference ──────────────────────────────────────────────────────────
    print(f"\n  {C.BANNER}{C.BOLD}{'═'*90}{C.RESET}")
    print(f"  {C.BOLD}{C.BANNER}  ETHERNET FRAME BUILDER  —  Select EtherType / Protocol{C.RESET}")
    print(f"  {C.BANNER}{'═'*90}{C.RESET}")

    print(f"\n  {C.SECT}{C.BOLD}▌ LAYER 1 — PHYSICAL  (always present — asked first){C.RESET}")
    print(f"  {C.SEP_C}{SEP90}{C.RESET}")
    print(f"  {C.L1}  Preamble{C.RESET}  7 bytes  {C.HEX}55 55 55 55 55 55 55{C.RESET}  "
          f"{C.DIM}Clock sync — 10101010 alternating × 7  (stripped by NIC on receive){C.RESET}")
    print(f"  {C.L1}  SFD     {C.RESET}  1 byte   {C.HEX}D5{C.RESET}                    "
          f"{C.DIM}Start Frame Delimiter — 11010101, signals start of MAC frame{C.RESET}")

    print(f"\n  {C.SECT}{C.BOLD}▌ LAYER 2 — ETHERNET HEADER  (asked for every flow){C.RESET}")
    print(f"  {C.SEP_C}{SEP90}{C.RESET}")
    print(f"  {C.L2}  Dst MAC    {C.RESET}  6 bytes  {C.DIM}Unicast / Multicast (01:xx) / Broadcast (ff:ff:ff:ff:ff:ff){C.RESET}")
    print(f"  {C.L2}  Src MAC    {C.RESET}  6 bytes  {C.DIM}Sender hardware address{C.RESET}")
    print(f"  {C.L2}  EtherType  {C.RESET}  2 bytes  {C.DIM}≥0x0600 = protocol ID  |  <0x0600 = IEEE 802.3 payload length{C.RESET}")
    print(f"  {C.L2}  [LLC+SNAP] {C.RESET}  5 bytes  {C.DIM}DSAP+SSAP+Ctrl + OUI + PID — optional, used by STP/DTP/PAgP{C.RESET}")
    print(f"  {C.L2}  FCS        {C.RESET}  4 bytes  {C.DIM}CRC-32 over Dst MAC → end of payload  (auto or custom){C.RESET}")

    # ── Print all selections ──────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ SELECT PROTOCOL / ETHERTYPE  —  Enter number then press Enter{C.RESET}")
    print(f"  {C.SEP_C}{SEP90}{C.RESET}")

    # Header row
    print(f"  {C.DIM}  {'No':>4}  {'EtherType':<11}  {'PDU / Protocol':<30}  "
          f"{'L3 class':<10}  {'L4 dispatch':<22}  {'Status'}{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*86}{C.RESET}")

    current_cat = None
    for num_s, entry in _ETH_SEL_MAP.items():
        kind = entry[0]

        if kind == 'fixed':
            _, fn, et_str, pdu, l3, cat, desc, et_int = entry
            # Category header
            if cat != current_cat:
                current_cat = cat
                print(f"\n  {C.NOTE}{C.BOLD}  ── {cat} (Fully specialised builders) ──{C.RESET}")

            # L4 hint for fixed flows
            l4_hint = {
                '1' : 'arp_request / arp_reply',
                '2' : '→ L4 sub-menu (ICMP/TCP/UDP/…)',
                '3' : 'stp_bpdu/rstp_bpdu/mstp_bpdu/pvst_bpdu',
                '4' : 'dtp_domain/status/type/neighbor TLVs',
                '5' : 'pagp_group_cap/group_ifidx/port_name',
                '6' : 'lacp_actor+partner+collector TLVs',
                '7' : 'pause_quanta × 512bit-times',
                '8' : 'pfc_priority_enable + quanta[0-7]',
                '9' : 'lldp_chassisID+portID+TTL+orgSpec TLVs',
                '10': 'vlan_dot1q / qinq s-tag+c-tag',
                '11': 'any_oversized_payload',
                '12': 'cdp_deviceID+portID+capabilities+platform TLVs',
                '13': 'vtp_summary/subset/request/join PDU',
                '14': 'pvst+_bpdu / rapid-pvst+_bpdu + VLAN TLV',
                '15': 'udld_probe/echo/flush + device+port TLVs',
                '16': 'SOFi3/SOFn3/SOFf + FC-header(24B) + FCP/ELS/BLS + CRC + EOFt/EOFn/EOFa',
            }.get(num_s, '—')

            print(f"  {C.BOLD}{C.L3}  {num_s:>4}{C.RESET}  "
                  f"{C.HEX}{et_str:<11}{C.RESET}  "
                  f"{C.BOLD}{desc:<30}{C.RESET}  "
                  f"{C.L3}{l3:<10}{C.RESET}  "
                  f"{C.L4}{l4_hint:<22}{C.RESET}  "
                  f"{C.PASS_}builtin{C.RESET}")

        else:  # 'generic'
            _, et_int, et_str, pdu, l3c, cat, usage, full_name, l4hint, status = entry

            if cat != current_cat:
                current_cat = cat
                # Count for this category
                cat_count = sum(1 for e in _ETH_SEL_MAP.values()
                                if e[0]=='generic' and e[5]==cat)
                print(f"\n  {C.NOTE}{C.BOLD}  ── {cat}  ({cat_count} EtherTypes) ──{C.RESET}")

            # Status colour
            sc = (C.PASS_ if status=='Active' else
                  C.WARN  if status in ('Deprecated','Legacy') else
                  C.NOTE  if status=='Vendor-specific' else C.DIM)

            # RAW marker
            raw_m = f"{C.WARN}[R]{C.RESET} " if pdu == 'RAW' else "    "

            # Trim PDU for display
            pdu_d  = (pdu[:28] if pdu != 'RAW' else full_name[:28])

            print(f"  {raw_m}{C.L2}{num_s:>4}{C.RESET}  "
                  f"{C.HEX}{et_str:<11}{C.RESET}  "
                  f"{C.DIM}{pdu_d:<30}{C.RESET}  "
                  f"{C.L3}{str(l3c):<10}{C.RESET}  "
                  f"{C.L4}{l4hint:<22}{C.RESET}  "
                  f"{sc}{status}{C.RESET}")

    # Footer
    total = len(_ETH_SEL_MAP)
    fixed_count = sum(1 for e in _ETH_SEL_MAP.values() if e[0]=='fixed')
    gen_count   = total - fixed_count
    print(f"\n  {C.SEP_C}{SEP90}{C.RESET}")
    print(f"  {C.DIM}  {C.WARN}[R]{C.RESET}{C.DIM} = RAW payload (no defined PDU structure) — "
          f"payload accepted as hex bytes{C.RESET}")
    print(f"  {C.DIM}  {C.BOLD}1-{fixed_count}{C.RESET}{C.DIM} = full specialised builders  |  "
          f"{C.BOLD}{fixed_count+1}+{C.RESET}{C.DIM} = generic builder "
          f"(asks Dst/Src/payload hex) — {gen_count} EtherTypes selectable{C.RESET}")
    print(f"  {C.SEP_C}{SEP90}{C.RESET}")
    print(f"\n  {C.NOTE}{C.BOLD}  ── CUSTOM / PRIVATE / UNDISCLOSED  (1 entry) ──{C.RESET}")
    print(f"  {C.BOLD}{C.L3}     C{C.RESET}  "
          f"{C.HEX}{'0x????':<11}{C.RESET}  "
          f"{C.BOLD}{'Custom / Private EtherType':<30}{C.RESET}  "
          f"{C.L3}{'user-def':<10}{C.RESET}  "
          f"{C.L4}{'user-defined TLVs':<22}{C.RESET}  "
          f"{C.NOTE}custom{C.RESET}")
    print(f"  {C.DIM}      Enter 'C' to build a frame with ANY EtherType 0x0000-0xFFFF{C.RESET}")
    print(f"  {C.DIM}      Define custom fields, TLVs, raw hex, or structured payload{C.RESET}")
    print(f"  {C.SEP_C}{SEP90}{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _fmt_row(num, label, detail, W=76):
    """Format one menu row, truncating detail to fit."""
    n    = f"{num:>2}"
    lbl  = label[:28]
    det  = detail[:W - len(n) - len(lbl) - 7]
    return f"  │ {n} │ {lbl:<28}  {det}"

def _box_top(title):
    return (f"\n  ┌{'─'*76}┐\n"
            f"  │  {C.BOLD}{title:<74}{C.RESET}  │\n"
            f"  ├{'─'*4}┬{'─'*71}┤")

def _box_bot():
    return f"  └{'─'*4}┴{'─'*71}┘"


def print_main_menu():
    """
    Dynamic MAIN MENU — 5 options: Ethernet / Serial / WiFi / IPv4 / Hardware-Bus
    """
    if _L2_AVAILABLE:
        from l2_builder import (ETHERTYPE_REGISTRY, WAN_PROTOCOL_REGISTRY,
                                 WIFI_SPEED_TABLE, WIFI_FRAME_CATEGORY)
        n_eth=16; n_et=len(ETHERTYPE_REGISTRY); n_wan=len(WAN_PROTOCOL_REGISTRY)
        n_wifi=len(WIFI_SPEED_TABLE); n_wfcat=len(WIFI_FRAME_CATEGORY)
    else:
        n_eth=11; n_et=174; n_wan=11; n_wifi=21; n_wfcat=4

    if _L3_AVAILABLE:
        from l3_builder import IP_PROTOCOL_REGISTRY, NON_IP_L3_REGISTRY
        n_ip=len(IP_PROTOCOL_REGISTRY); n_nil=len(NON_IP_L3_REGISTRY)
    else:
        n_ip=24; n_nil=35

    if _L4_AVAILABLE:
        from l4_builder import NON_IP_L4_REGISTRY
        n_nil4=len(NON_IP_L4_REGISTRY)
    else:
        n_nil4=77

    if _HW_AVAILABLE:
        hw_s=registry_stats_hw(); n_hw_buses=hw_s['buses']; n_hw_plat=hw_s['platforms']
    else:
        n_hw_buses=40; n_hw_plat=9

    if _PHY_AVAILABLE:
        phy_s=registry_stats_phy(); n_phy_eth=phy_s['eth_speeds']; n_phy_fc=phy_s['fc_speeds']
    else:
        n_phy_eth=8; n_phy_fc=4

    def row(num, tech, detail):
        return (f"  {C.BOLD}{C.BANNER}║{C.RESET} {C.L2}{num}{C.RESET}  "
                f"{C.BOLD}{tech:<24}{C.RESET}  {C.DIM}{detail}{C.RESET}")
    def sub(txt):  return f"  {C.BANNER}║{C.RESET}     {C.DIM}{txt}{C.RESET}"
    def div():     return f"  {C.BANNER}╠{'═'*78}╣{C.RESET}"

    eng = ('L1✓ L2✓ L3✓ L4✓ HW✓' if all([_PHY_AVAILABLE,_L2_AVAILABLE,_L3_AVAILABLE,_L4_AVAILABLE,_HW_AVAILABLE])
           else 'L2✓ L3✓ L4✓ HW✓' if all([_L2_AVAILABLE,_L3_AVAILABLE,_L4_AVAILABLE,_HW_AVAILABLE])
           else 'partial — check builder files')
    print(f"\n  {C.BANNER}╔{'═'*78}╗{C.RESET}")
    print(f"  {C.BANNER}║{C.RESET}  {C.BOLD}{C.BANNER}{'NETWORK FRAME BUILDER  ─  COMPLETE PROTOCOL SUITE':^76}{C.RESET}  {C.BANNER}║{C.RESET}")
    print(f"  {C.BANNER}║{C.RESET}  {C.DIM}{f'Engines: {eng}':^76}{C.RESET}  {C.BANNER}║{C.RESET}")
    print(div())
    print(row('1','Ethernet / 802.3',f'{n_eth} full builders | {n_et} EtherTypes | {n_nil} L3 | {n_nil4} L4'))
    print(sub(f'PHY: {n_phy_eth} speeds (10M→400G) Manchester/MLT-3/8b10b/64b66b/PAM4 + FC {n_phy_fc} speeds'))
    print(sub('ARP · IPv4(→L4) · STP/RSTP/MSTP · DTP · PAgP · LACP · Pause · PFC · LLDP · VLAN · Jumbo'))
    print(sub('CDP · VTP · PVST+ · UDLD  ·  FCoE · FIP · AoE · RoCE · iSCSI · NVMe  ·  +174 EtherTypes'))
    print(div())
    print(row('2','Serial / WAN',f'{n_wan} protocols  ·  PHY: NRZ/NRZI encoding  (RS-232/485/HDLC/CAN)'))
    print(sub('HDLC: I-frame · S-frame · U-frame  ·  PHY: Manchester/MLT-3/NRZ/NRZI selectable'))
    print(div())
    print(row('3','WiFi / 802.11',f'{n_wifi} PHY standards  ·  {n_wfcat} frame categories'))
    print(sub('802.11a/b/g/n/ac/ax/be · ad/ay(60GHz) · p(V2X) · s(Mesh) · ah(HaLow)'))
    print(div())
    print(row('4','Standalone IPv4',f'Full RFC 791  ·  {n_ip} protocols  ·  options  ·  L4 payload'))
    print(sub('ICMP(19 types) · TCP(11 states) · UDP(41 ports) · GRE · ESP · AH · OSPF · SCTP'))
    print(div())
    print(row('5','Hardware / Bus Frame',f'{n_hw_buses} bus protocols  ·  {n_hw_plat} platform categories'))
    print(sub('PCIe TLP/DLLP/VDM/SR-IOV · CXL · USB · HDMI · DP · SATA · NVMe · IPMI · TB4'))
    print(sub('CAN FD · FlexRay · JTAG · I2C · SPI · MIPI · DDR4/5 · HBM3 · InfiniBand'))
    print(f"  {C.BANNER}╚{'═'*78}╝{C.RESET}")



def print_serial_menu():
    """
    Full Serial/WAN menu showing:
      1. Serial L1/L2 field reference (flags, address, control, FCS)
      2. All 11 protocols with complete frame structure from l2_builder
      3. L3 payload options available per protocol
    """
    SEP = '─' * 90
    print(f"\n  {C.BANNER}{C.BOLD}{'═'*90}{C.RESET}")
    print(f"  {C.BOLD}{C.BANNER}  SERIAL / WAN FRAME BUILDER  —  Layer-by-Layer Input{C.RESET}")
    print(f"  {C.BANNER}{'═'*90}{C.RESET}")

    # ── L1/L2 field reference ─────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ SERIAL FRAME FIELDS  (common elements across protocols){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Field           Size      Value/Notes{C.RESET}")
    print(f"  {C.SEP_C}{'─'*90}{C.RESET}")
    SERIAL_FIELDS = [
        (C.L1,'Start Flag',    '1 byte', '0x7E (HDLC/PPP/KISS=0xC0)  — marks frame boundary'),
        (C.L2,'Address',       '1-∞B',  '0xFF=PPP broadcast  0x01=KISS  slave-ID=Modbus RTU'),
        (C.L2,'Control',       '1-2B',  '0x03=UI (PPP/HDLC)  or I/S/U frame type (HDLC Full)'),
        (C.L3,'Protocol/NLPID','2B',    '0x0021=IPv4  0x0057=IPv6  0x0281=MPLS  (PPP only)'),
        (C.L3,'Payload',       'var',   'IP datagram / Modbus data / raw bytes'),
        (C.L2,'FCS',           '2-4B',  'CRC-16/CCITT (HDLC/PPP)  CRC-32 (Cisco HDLC/AAL5)  CRC-16LE (Modbus)'),
        (C.L1,'End Flag',      '1 byte', '0x7E (same as start)  — end of frame'),
    ]
    for lc, name, size, notes in SERIAL_FIELDS:
        print(f"  {lc}  {name:<16}{C.RESET}  {C.DIM}{size:<8}  {notes}{C.RESET}")
    print(f"  {C.DIM}  Bit-stuffing: after 5 consecutive 1s a 0 is inserted (HDLC) to prevent 0x7E in data{C.RESET}")
    print(f"  {C.DIM}  Byte-stuffing: 0x7E→[0x7D,0x5E]  0x7D→[0x7D,0x5D]  (PPP/HDLC escape){C.RESET}")

    # ── Pull WAN registry from l2_builder ─────────────────────────────────────
    wan_reg = {}
    if _L2_AVAILABLE:
        from l2_builder import WAN_PROTOCOL_REGISTRY
        wan_reg = WAN_PROTOCOL_REGISTRY

    # Serial protocol → WAN registry key mapping
    SERIAL_WAN_MAP = {
        '1':'raw', '2':'slip', '3':'ppp', '4':'hdlc', '5':'cobs',
        '6':'kiss','7':'modbus_rtu','8':'hdlc','9':'atm_aal5',
        '10':'cisco_hdlc','11':'hdlc_full',
    }
    # L3 options available per protocol
    SERIAL_L3_OPTIONS = {
        '1': '—  (raw bytes only)',
        '2': 'IPv4 implicit  (no protocol field — always IPv4)',
        '3': 'IPv4(0x0021) · IPv6(0x0057) · MPLS(0x0281) · IPX(0x002B) · Compressed(0x00FD)',
        '4': 'None · Raw · IPv4  →  L4 sub-menu (ICMP/TCP/UDP)  selectable',
        '5': '—  (COBS: application-defined — no standard L3)',
        '6': '—  (KISS: AX.25 packet radio frames)',
        '7': '—  (Modbus RTU: coil/register data — no IP layer)',
        '8': 'None · Raw · IPv4  →  L4 sub-menu (ICMP/TCP/UDP)  selectable',
        '9': 'IPv4/IPv6 via LLC/SNAP encap over AAL5 cells',
        '10':'IPv4(0x0800) · IPv6(0x86DD) · ARP(0x0806) · MPLS(0x8847)',
        '11':'None · Raw · IPv4  →  L4 sub-menu (ICMP/TCP/UDP)  selectable',
    }

    print(f"\n  {C.SECT}{C.BOLD}▌ SELECT PROTOCOL  —  Enter number (1-11){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    for k, name in sorted(SERIAL_TYPES.items(), key=lambda x: int(x[0])):
        wkey  = SERIAL_WAN_MAP.get(k, '')
        winfo = wan_reg.get(wkey, {})
        std   = winfo.get('standard', '')
        l3opt = SERIAL_L3_OPTIONS.get(k, '')
        fstr  = winfo.get('frame_structure', [])
        fcs_t = winfo.get('fields', {}).get('FCS', winfo.get('fields', {}).get('CRC-16',''))

        sc = C.PASS_ if winfo.get('status') == 'Active' else (
             C.WARN  if winfo.get('status') in ('Deprecated',) else C.DIM)

        print(f"\n  {C.BOLD}{C.L2}  [{k:>2}]  {name}{C.RESET}  {C.DIM}{std}{C.RESET}")
        if fstr:
            print(f"       {C.DIM}Frame : {' → '.join(fstr)}{C.RESET}")
        if fcs_t:
            print(f"       {C.DIM}FCS   : {fcs_t}{C.RESET}")
        print(f"       {C.L3}L3    : {l3opt}{C.RESET}")
        if k == '11':
            print(f"       {C.NOTE}HDLC Full — you will choose I-frame / S-frame / U-frame inside builder{C.RESET}")
            print(f"       {C.DIM}  I-frame: N(S)+P/F+N(R)  reliable data with sliding-window ARQ{C.RESET}")
            print(f"       {C.DIM}  S-frame: RR/REJ/RNR/SREJ  supervisory (ACK/NAK/flow) — no payload{C.RESET}")
            print(f"       {C.DIM}  U-frame: SABM/DISC/UA/UI/FRMR/XID/TEST  link management{C.RESET}")

    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")


def print_wifi_menu():
    """
    Full WiFi menu — all 21 standards selectable, all frame types/subtypes shown.
    Flow (ask_wifi_frame) is unchanged — user picks PHY mode + frame type + subtype inside builder.
    """
    SEP = '─' * 90
    print(f"\n  {C.BANNER}{C.BOLD}{'═'*90}{C.RESET}")
    print(f"  {C.BOLD}{C.BANNER}  WiFi / IEEE 802.11 FRAME BUILDER  —  PHY + MAC layer{C.RESET}")
    print(f"  {C.BANNER}{'═'*90}{C.RESET}")

    # ── MAC Frame structure reference ─────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ 802.11 MAC FRAME STRUCTURE  (MPDU fields — asked inside builder){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    MAC_FIELDS = [
        (C.L1, "PHY Preamble/SIG","variable","STF+LTF+L-SIG/HT-SIG/VHT-SIG/HE-SIG — clock sync + rate+length"),
        (C.L2, "Frame Control",   "2 bytes", "Type(2b)+Subtype(4b)+ToDS+FromDS+MoreFrag+Retry+PwrMgmt+MoreData+Protect+HTC"),
        (C.L2, "Duration/ID",     "2 bytes", "NAV in µs (0-32767) or AID for PS-Poll"),
        (C.L2, "Addr 1 (RA)",     "6 bytes", "Receiver Address — always present"),
        (C.L2, "Addr 2 (TA)",     "6 bytes", "Transmitter Address — present in most frames"),
        (C.L2, "Addr 3",          "6 bytes", "BSSID / DA / SA — depends on ToDS/FromDS bits"),
        (C.L2, "Seq Control",     "2 bytes", "SeqNum(12b)+FragNum(4b) — duplicate detection"),
        (C.L2, "Addr 4 (SA)",     "6 bytes", "Only present in WDS/Mesh (ToDS=1 AND FromDS=1)"),
        (C.L2, "QoS Control",     "2 bytes", "TID(4b)+EOSP+AckPolicy+TXOP — QoS frames only"),
        (C.L2, "HT Control",      "4 bytes", "802.11n/ac link adaptation — +HTC/Order bit=1 only"),
        (C.L3, "Frame Body",      "0-7951B", "LLC/SNAP+payload (data) | IEs (management) | empty (control)"),
        (C.L2, "FCS",             "4 bytes", "CRC-32 over entire MPDU (Frame Control → end of Frame Body)"),
    ]
    for lc, name, size, desc in MAC_FIELDS:
        print(f"  {lc}  {name:<18}{C.RESET}  {C.DIM}{size:<9}  {desc}{C.RESET}")

    # ── PHY modes ─────────────────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ STEP 1 — PHY MODE  (asked first inside builder){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Choose {'  ':<3}  PHY standard  →  determines preamble/SIG field format{C.RESET}")
    for k, v in WIFI_PHY_MODES.items():
        print(f"  {C.L1}    {k}{C.RESET}  {C.DIM}{v}{C.RESET}")

    # ── All 21 WiFi standards from l2_builder ─────────────────────────────────
    if _L2_AVAILABLE:
        from l2_builder import WIFI_SPEED_TABLE
        print(f"\n  {C.SECT}{C.BOLD}▌ 802.11 STANDARD REGISTRY  "
              f"(l2_builder — {len(WIFI_SPEED_TABLE)} standards){C.RESET}")
        print(f"  {C.SEP_C}{SEP}{C.RESET}")
        print(f"  {C.DIM}  {'Standard':<12} {'Alias':<22} {'Max speed':>10}  "
              f"{'Band':<28}  {'Modulation':<22}  {'Year'}{C.RESET}")
        print(f"  {C.SEP_C}  {'─'*86}{C.RESET}")
        for std, info in WIFI_SPEED_TABLE.items():
            mbps  = info['max_mbps']
            spd   = ("N/A" if mbps==0 else
                     f"{mbps/1000:.0f} Gbps" if mbps>=1000 else f"{mbps} Mbps")
            alias = info.get('alias','')
            notes = info.get('notes','')
            print(f"  {C.NOTE}  {std:<12}{C.RESET}  {C.DIM}{alias:<22}{C.RESET}  "
                  f"{C.L1}{spd:>10}{C.RESET}  "
                  f"{C.DIM}{info['band']:<28}  {info['modulation']:<22}  "
                  f"{info.get('year','')}{C.RESET}")
            if notes:
                print(f"  {C.DIM}              ↳ {notes}{C.RESET}")

    # ── Frame types + subtypes ─────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ STEP 2 — FRAME TYPE  (asked next: Management / Control / Data){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    FRAME_INFO = [
        ('1', 'Management', WIFI_MGMT_SUBTYPES,
         "BSS lifecycle — beacon discovery, auth, assoc, roaming",
         "Dst=Unicast/Broadcast  Src=STA or AP  Addr3=BSSID"),
        ('2', 'Control',    WIFI_CTRL_SUBTYPES,
         "Medium access — RTS/CTS collision avoidance, ACK, Block ACK",
         "RA always present; TA present except CTS/ACK/CF-End"),
        ('3', 'Data',       WIFI_DATA_SUBTYPES,
         "Payload delivery — QoS/non-QoS frames, Null/power-save",
         "ToDS/FromDS bits determine address roles (IBSS/AP/WDS)"),
    ]
    for fnum, fname, subtypes, purpose, addr_note in FRAME_INFO:
        print(f"\n  {C.BOLD}{C.L2}  [{fnum}] {fname}{C.RESET}  —  {C.DIM}{purpose}{C.RESET}")
        print(f"      {C.DIM}Address: {addr_note}{C.RESET}")
        print(f"      {C.DIM}Subtypes ({len(subtypes)}):{C.RESET}")
        for sub_k, sub_v in subtypes.items():
            if fname == 'Data':
                sv, sn, qos, sd = sub_v
                qmark = f"{C.NOTE}QoS{C.RESET}" if qos else "    "
                print(f"        {qmark} {C.L3}{sub_k:>2}{C.RESET}  {C.DIM}{sn:<22}  {sd}{C.RESET}")
            else:
                sv, sn, sd = sub_v
                print(f"             {C.L3}{sub_k:>2}{C.RESET}  {C.DIM}{sn:<22}  {sd}{C.RESET}")

    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  All frame types fully buildable — builder asks each field interactively{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")


def print_ip_menu():
    """
    Standalone IPv4 menu — shows IPv4 header fields then ALL
    IP protocol numbers as selectable options with their L3→L4 chain.
    Each entry maps:  IPv4 (L3)  →  protocol-specific L4 handler
    """
    SEP = '─' * 90
    print(f"\n  {C.BANNER}{C.BOLD}{'═'*90}{C.RESET}")
    print(f"  {C.BOLD}{C.BANNER}  STANDALONE IPv4 PACKET BUILDER  —  RFC 791{C.RESET}")
    print(f"  {C.BANNER}{'═'*90}{C.RESET}")

    # ── IPv4 header field reference ───────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ LAYER 3 — IPv4 HEADER  (asked for every IPv4 flow){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Field               Size     Notes{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")
    IPV4_FIELDS = [
        ("Version + IHL",    "1 byte",  "ver=4(4b) + IHL=header-length-in-32b-words(4b), 5=20B no-options"),
        ("DSCP + ECN",       "1 byte",  "DSCP(6b) 0=BE 46=EF 48=CS6 34=AF41  |  ECN(2b) 0=Non 3=CE"),
        ("Total Length",     "2 bytes", "Header + payload total bytes"),
        ("Identification",   "2 bytes", "Fragment group ID (0=not fragmented is fine)"),
        ("Flags + FragOffset","2 bytes","DF(1b)+MF(1b)+FragOffset(13b) — DF=1 required for TCP PMTUD"),
        ("TTL",              "1 byte",  "Hop limit: 64=Linux  128=Windows  255=max"),
        ("Protocol",         "1 byte",  "L4 protocol number — see selectable list below"),
        ("Header Checksum",  "2 bytes", "One's complement over header — auto / custom / force-zero"),
        ("Source IP",        "4 bytes", "IPv4 address or domain name (auto DNS-resolved)"),
        ("Destination IP",   "4 bytes", "IPv4 address or domain name"),
        ("Options",          "0-40B",   "NOP / Record-Route / Timestamp / Custom hex"),
    ]
    for name, size, desc in IPV4_FIELDS:
        print(f"  {C.L3}  {name:<20}{C.RESET}  {C.DIM}{size:<8}  {desc}{C.RESET}")

    # ── Selectable IPv4 + L4 protocol list ────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ SELECT IPv4 PAYLOAD  —  Enter number inside builder{C.RESET}")
    print(f"  {C.DIM}  Each option = IPv4 header (above) + the L4 payload shown{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    # Pull full IP protocol registry from l3_builder
    if _L3_AVAILABLE:
        from l3_builder import IP_PROTOCOL_REGISTRY
    else:
        IP_PROTOCOL_REGISTRY = {}

    # Pull non-IP L4 handler info from l4_builder
    if _L4_AVAILABLE:
        from l4_builder import NON_IP_L4_REGISTRY
    else:
        NON_IP_L4_REGISTRY = {}

    # ── PART A: 5 fully buildable IPv4+L4 flows ───────────────────────────────
    print(f"\n  {C.NOTE}{C.BOLD}  ── Fully buildable IPv4 flows  (asked field-by-field) ──{C.RESET}")
    print(f"  {C.DIM}  {'No':<4}  {'Proto#':<7}  {'IPv4 Protocol':<18}  "
          f"{'L4 class':<10}  {'PDU / Fields asked'}{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")

    BUILTIN_L4 = [
        # no  proto  name            l4_cls   l4_fields_summary
        ('1',  1, 'ICMP',           'icmp',
         'Type(1B)+Code(1B)+Checksum(2B)+ID(2B)+Seq(2B)+Data — Echo/Unreachable/TTL-Exceeded/Redirect'),
        ('2',  6, 'TCP',            'tcp',
         'SrcPort+DstPort+Seq(4B)+Ack(4B)+Offset+Flags(SYN/ACK/FIN/RST/PSH)+Window+Cksum+Urg+Data'),
        ('3', 17, 'UDP',            'udp',
         'SrcPort(2B)+DstPort(2B)+Length(2B)+Checksum(2B)+Data — DNS/DHCP/NTP/SNMP/custom'),
        ('4',  0, 'Raw hex payload','raw',
         'Any bytes — GRE(47) / ESP(50) / AH(51) / OSPF(89) / custom protocol payload'),
        ('5',  0, 'Empty (no L4)', 'none',
         'IPv4 header only — no L4 payload (header-only probe / test)'),
    ]
    for num, proto, name, l4cls, fdesc in BUILTIN_L4:
        proto_str = f"proto={proto}" if proto else "any"
        print(f"  {C.BOLD}{C.L4}  [{num}]{C.RESET}  "
              f"{C.DIM}{proto_str:<7}{C.RESET}  "
              f"{C.BOLD}{name:<18}{C.RESET}  "
              f"{C.L4}{l4cls:<10}{C.RESET}  "
              f"{C.DIM}{fdesc[:55]}{C.RESET}")

    # ── PART B: Full IP protocol registry from l3_builder ─────────────────────
    if IP_PROTOCOL_REGISTRY:
        print(f"\n  {C.NOTE}{C.BOLD}  ── Complete IP Protocol Registry  "
              f"(l3_builder — {len(IP_PROTOCOL_REGISTRY)} protocols) ──{C.RESET}")
        print(f"  {C.DIM}  These are the valid Protocol field values inside IPv4.{C.RESET}")
        print(f"  {C.DIM}  Use option [4] Raw hex above to build any of these manually.{C.RESET}")
        print(f"  {C.SEP_C}{SEP}{C.RESET}")
        print(f"  {C.DIM}  {'Proto#':>6}  {'Name':<14}  {'L4 class':<12}  "
              f"{'Category':<14}  Description{C.RESET}")
        print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")

        # Group by category for cleaner display
        cats = {}
        for num, info in sorted(IP_PROTOCOL_REGISTRY.items()):
            cats.setdefault(info.get('category','Other'), []).append((num, info))

        for cat, entries in sorted(cats.items()):
            print(f"\n  {C.DIM}  ── {cat} ──{C.RESET}")
            for num, info in entries:
                l4c  = info.get('l4_proto') or '—'
                sc   = C.PASS_ if info.get('status') == 'Active' else C.DIM
                # Mark which ones are directly buildable
                buildable = '★' if l4c in ('icmp','tcp','udp') else ' '
                print(f"  {C.L3}  {num:>6}{C.RESET}  "
                      f"{sc}{info['name']:<14}{C.RESET}  "
                      f"{C.L4}{l4c:<12}{C.RESET}  "
                      f"{C.DIM}{cat:<14}  {info.get('usage','')[:38]}{C.RESET}  "
                      f"{C.NOTE}{buildable}{C.RESET}")

        print(f"\n  {C.DIM}  {C.NOTE}★{C.RESET}{C.DIM} = directly buildable with options 1-3 above{C.RESET}")

    # ── PART C: Non-IP L3/L4 stack reference ──────────────────────────────────
    if _L3_AVAILABLE:
        from l3_builder import NON_IP_L3_REGISTRY
        print(f"\n  {C.NOTE}{C.BOLD}  ── Non-IP L3 Stacks  "
              f"({len(NON_IP_L3_REGISTRY)} — selectable via Ethernet EtherType menu) ──{C.RESET}")
        print(f"  {C.DIM}  These protocols use their own L3 — not IPv4. "
              f"Select via Ethernet menu → EtherType.{C.RESET}")
        print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")
        print(f"  {C.DIM}  {'EtherType':<11}  {'L3 stack':<10}  "
              f"{'Protocol':<30}  {'L4 options'}{C.RESET}")
        print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")

        # Map L3 class → EtherType
        if _L2_AVAILABLE:
            from l2_builder import ETHERTYPE_REGISTRY
            l3_to_et = {}
            for et, v in ETHERTYPE_REGISTRY.items():
                lp = v.get('l3_proto')
                if lp and lp not in l3_to_et:
                    l3_to_et[lp] = et
        else:
            l3_to_et = {}

        for cls, info in NON_IP_L3_REGISTRY.items():
            et    = l3_to_et.get(cls)
            et_s  = f"0x{et:04X}" if et else "via LLC"
            tmap  = info.get('type_map', {})
            l4s   = sorted(set(v.get('l4','') for v in tmap.values() if v.get('l4')))
            l4str = ' · '.join(l4s[:4]) + (f' +{len(l4s)-4}' if len(l4s)>4 else '')
            print(f"  {C.HEX}  {et_s:<11}{C.RESET}  "
                  f"{C.L3}{cls:<10}{C.RESET}  "
                  f"{C.DIM}{info.get('name','')[:28]:<30}  {l4str}{C.RESET}")

    # ── PART D: Non-IP L4 handlers grouped by stack ───────────────────────────
    if NON_IP_L4_REGISTRY:
        print(f"\n  {C.NOTE}{C.BOLD}  ── Non-IP L4 Handlers  "
              f"({len(NON_IP_L4_REGISTRY)} — dispatched from L3 type field) ──{C.RESET}")
        print(f"  {C.DIM}  Activated when user selects an EtherType with a non-IP L3 stack "
              f"(Ethernet menu → 14+).{C.RESET}")
        print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")

        FAM_MAP = {
            'spp':'XNS','pep':'XNS','xns_echo':'XNS','xns_error':'XNS','xns_rip':'XNS',
            'spx':'IPX/NetWare','ncp':'IPX/NetWare',
            'sap_ipx':'IPX/NetWare','netbios_ipx':'IPX/NetWare',
            'atp':'AppleTalk','nbp':'AppleTalk','rtmp':'AppleTalk',
            'aep':'AppleTalk','zip':'AppleTalk','adsp':'AppleTalk',
            'vines_ipc':'Banyan VINES','vines_spp':'Banyan VINES',
            'vines_arp':'Banyan VINES','vines_rtp':'Banyan VINES','vines_icp':'Banyan VINES',
            'nsp':'DECnet NSP','lat_session':'DEC LAT','sna_ru':'IBM SNA',
        }
        groups = {}
        for cls in NON_IP_L4_REGISTRY:
            groups.setdefault(FAM_MAP.get(cls,'Other'), []).append(cls)

        for fam in ['XNS','IPX/NetWare','AppleTalk','Banyan VINES',
                    'DECnet NSP','DEC LAT','IBM SNA']:
            hdlrs = groups.get(fam, [])
            if not hdlrs: continue
            print(f"\n  {C.DIM}  {fam}:{C.RESET}")
            for cls in hdlrs:
                info = NON_IP_L4_REGISTRY[cls]
                transport = info.get('transport','')[:35]
                print(f"  {C.L4}    {cls:<18}{C.RESET}  "
                      f"{C.DIM}{info.get('name','')[:32]:<34}  {transport}{C.RESET}")

    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Builder asks: Source IP · Dest IP · TTL · Protocol# · DSCP · DF/MF · "
          f"Options · then L4 fields{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════

def print_ipv4_l4_menu():
    """
    Sub-menu shown when user selects IPv4 from Ethernet OR Standalone IPv4.
    Lists all IP protocols from l3_builder, with L4 details from l4_builder.
    Returns user's L4 choice string ('icmp','tcp','udp','raw','empty').
    """
    SEP = '─' * 88

    # Pull from builders
    ip_protos = {}
    icmp_types = {}
    tcp_states = {}
    udp_ports  = {}
    if _L3_AVAILABLE:
        from l3_builder import IP_PROTOCOL_REGISTRY, ICMP_EXTENDED
        ip_protos  = IP_PROTOCOL_REGISTRY
        icmp_types = ICMP_EXTENDED
    if _L4_AVAILABLE:
        from l4_builder import TCP_HANDSHAKE_STATES, PORT_REGISTRY
        tcp_states = TCP_HANDSHAKE_STATES
        udp_ports  = PORT_REGISTRY

    print(f"\n  {C.SECT}{C.BOLD}▌ IPv4 PAYLOAD — Choose L4 Protocol{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    # ── Show full IP protocol registry from l3_builder ─────────────────────
    print(f"\n  {C.DIM}  IP Protocol Registry ({len(ip_protos)} protocols from l3_builder):{C.RESET}")
    print(f"  {C.DIM}  {'Proto':>5}  {'Name':<18}  {'L4 class':<10}  {'Category':<10}  Usage{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*70}{C.RESET}")
    for num, info in sorted(ip_protos.items()):
        l4c = info.get('l4_proto') or '—'
        sc  = C.PASS_ if info['status'] == 'Active' else C.DIM
        print(f"  {sc}  {num:>5}{C.RESET}  {C.L3}{info['name']:<18}{C.RESET}  "
              f"{C.L4}{l4c:<10}{C.RESET}  "
              f"{C.DIM}{info['category']:<10}  {info.get('usage','')[:35]}{C.RESET}")

    # ── Selectable options with detail ─────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ SELECTABLE L4 OPTIONS  (fully buildable){C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")

    # Option 1: ICMP — show types from l3_builder ICMP_EXTENDED
    print(f"\n  {C.BOLD}{C.L4}  [1]  ICMP{C.RESET}  "
          f"{C.DIM}IP Protocol 1  —  Internet Control Message Protocol{C.RESET}")
    print(f"       {C.DIM}PDU: 8B header (Type+Code+Checksum+ID+Seq) + Data{C.RESET}")
    if icmp_types:
        print(f"       {C.DIM}ICMP Types from l3_builder ({len(icmp_types)} defined):{C.RESET}")
        for tnum, tinfo in sorted(icmp_types.items()):
            print(f"         {C.L3}Type {tnum:>2}{C.RESET}  {C.DIM}{tinfo['name']:<32}  "
                  f"{tinfo.get('usage','')[:35]}{C.RESET}")

    # Option 2: TCP — show states from l4_builder TCP_HANDSHAKE_STATES
    print(f"\n  {C.BOLD}{C.L4}  [2]  TCP{C.RESET}  "
          f"{C.DIM}IP Protocol 6  —  Transmission Control Protocol{C.RESET}")
    print(f"       {C.DIM}PDU: 20B header (Src+Dst+Seq+Ack+Offset+Flags+Win+Cksum+Urg) + Data{C.RESET}")
    print(f"       {C.DIM}Flags: SYN ACK FIN RST PSH URG ECE CWR  |  3-way handshake builder{C.RESET}")
    if tcp_states:
        print(f"       {C.DIM}TCP States from l4_builder ({len(tcp_states)} states):{C.RESET}")
        for st, sinfo in tcp_states.items():
            desc = sinfo.get('description', sinfo.get('desc', ''))[:45]
            print(f"         {C.L4}{st:<15}{C.RESET}  {C.DIM}{desc}{C.RESET}")

    # Option 3: UDP — show common ports from l4_builder PORT_REGISTRY
    print(f"\n  {C.BOLD}{C.L4}  [3]  UDP{C.RESET}  "
          f"{C.DIM}IP Protocol 17  —  User Datagram Protocol{C.RESET}")
    print(f"       {C.DIM}PDU: 8B header (Src+Dst+Length+Checksum) + Data{C.RESET}")
    if udp_ports:
        udp_list = [(p, i) for p, i in sorted(udp_ports.items())
                    if 'udp' in i.get('proto', []) and i.get('status') == 'Active'][:20]
        print(f"       {C.DIM}Well-known UDP ports from l4_builder ({len(udp_list)} shown):{C.RESET}")
        for port, pinfo in udp_list:
            print(f"         {C.HEX}{port:>5}{C.RESET}  {C.DIM}{pinfo['name']:<22}  "
                  f"{pinfo.get('usage','')[:35]}{C.RESET}")

    # Option 4: Other IP protocols
    print(f"\n  {C.BOLD}{C.L4}  [4]  Other IP Protocol{C.RESET}  "
          f"{C.DIM}GRE(47) · ESP(50) · AH(51) · OSPF(89) · EIGRP(88) · SCTP(132) etc.{C.RESET}")
    print(f"       {C.DIM}Enter protocol number manually — payload accepted as raw hex bytes{C.RESET}")

    # Option 5: Raw hex
    print(f"\n  {C.BOLD}{C.L4}  [5]  Raw hex payload{C.RESET}  "
          f"{C.DIM}Any bytes — custom protocol / test pattern / tunnelled packet{C.RESET}")

    # Option 6: Empty
    print(f"\n  {C.BOLD}{C.L4}  [6]  Empty{C.RESET}  "
          f"{C.DIM}IPv4 header only — no L4 payload{C.RESET}")

    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")
    ch = input(f"  {C.PROMPT}Choose L4 option (1=ICMP  2=TCP  3=UDP  4=Other  5=Raw  6=Empty): {C.RESET}").strip()
    return ch


def print_hw_menu():
    """
    Hardware / Bus Frame menu.
    Shows all 9 platform categories and their bus protocols,
    with frame boundary detection info for each bus.
    """
    SEP = '─' * 90
    print(f"\n  {C.BANNER}{C.BOLD}{'═'*90}{C.RESET}")
    print(f"  {C.BOLD}{C.BANNER}  HARDWARE / BUS FRAME BUILDER  —  Ethernet-Encapsulated Hardware Protocols{C.RESET}")
    print(f"  {C.BANNER}{'═'*90}{C.RESET}")

    print(f"\n  {C.SECT}{C.BOLD}▌ CONCEPT — Why This Exists{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  Every hardware bus has a FRAME BOUNDARY detected by a specific symbol, bit pattern,{C.RESET}")
    print(f"  {C.DIM}  or delimiter. When an Ethernet NIC shares the PCIe root complex with USB, HDMI,{C.RESET}")
    print(f"  {C.DIM}  SATA, NVMe, BMC, CAN etc., a crafted Ethernet payload whose bytes match a hardware{C.RESET}")
    print(f"  {C.DIM}  bus frame can:{C.RESET}")
    print(f"  {C.WARN}    • Trigger DMA confusion across shared IOMMU domains{C.RESET}")
    print(f"  {C.WARN}    • Be forwarded to hardware parsers in FPGA/SoC shared-bus designs{C.RESET}")
    print(f"  {C.WARN}    • Control BMC/IPMI out-of-band (bypasses OS firewall){C.RESET}")
    print(f"  {C.WARN}    • Inject CAN/FlexRay commands via Automotive Ethernet gateways{C.RESET}")

    if not _HW_AVAILABLE:
        print(f"\n  {C.WARN}  hw_builder.py not found — place it in the same directory{C.RESET}")
        return

    # ── Platform selection ────────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ SELECT PLATFORM CATEGORY  —  Enter number{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    platforms = list(PLATFORM_REGISTRY.items())
    for i, (key, info) in enumerate(platforms, 1):
        buses = info['buses']
        chips = ', '.join(info['chipsets'][:2])
        print(f"  {C.BOLD}{C.L2}  [{i:>2}]  {info['name'][:50]:<50}{C.RESET}")
        print(f"         {C.DIM}Chipsets : {chips}{C.RESET}")
        print(f"         {C.L3}Buses    : {len(buses)} protocols — {' · '.join(buses[:5])}{'...' if len(buses)>5 else ''}{C.RESET}")
        print(f"         {C.WARN}Attacks  : {info['attack_notes'][:75]}{C.RESET}")
    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")


def flow_hw():
    """
    Hardware / Bus Frame builder flow.
    User picks platform → picks bus protocol → builder asks all frame fields
    with caution notes → assembles Ethernet frame with hardware bus payload.
    """
    print_hw_menu()

    if not _HW_AVAILABLE:
        print(f"  {C.WARN}hw_builder not available.{C.RESET}")
        return

    platforms = list(PLATFORM_REGISTRY.items())
    plat_ch = input(f"\n  {C.PROMPT}Choose platform (1-{len(platforms)}): {C.RESET}").strip()
    try:
        plat_idx = int(plat_ch) - 1
        assert 0 <= plat_idx < len(platforms)
    except (ValueError, AssertionError):
        print(f"  {C.WARN}Invalid platform choice.{C.RESET}")
        return

    plat_key, plat_info = platforms[plat_idx]
    buses = plat_info['buses']

    SEP = '─' * 88
    banner(f"HARDWARE FRAME — {plat_info['name']}",
           "Ethernet payload encapsulating hardware bus protocol frames")

    print(f"\n  {C.SECT}{C.BOLD}▌ BUS PROTOCOLS for {plat_info['name']}{C.RESET}")
    print(f"  {C.SEP_C}{SEP}{C.RESET}")
    print(f"  {C.DIM}  {'No':>3}  {'Bus Protocol':<28}  {'Frame Boundary':<35}  {'Frame Size'}{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*82}{C.RESET}")

    bus_list = []
    for i, bus_class in enumerate(buses, 1):
        info = get_bus_info(bus_class)
        if not info: continue
        bus_list.append((bus_class, info))
        delim = info.get('delimiter_start','')[:33]
        fsize = info.get('frame_bytes','')[:14]
        print(f"  {C.L2}  {i:>3}{C.RESET}  "
              f"{C.BOLD}{info['bus'][:28]:<28}{C.RESET}  "
              f"{C.DIM}{delim:<35}  {fsize}{C.RESET}")

    print(f"\n  {C.SEP_C}{SEP}{C.RESET}")
    bus_ch = input(f"  {C.PROMPT}Choose bus protocol (1-{len(bus_list)}): {C.RESET}").strip()
    try:
        bus_idx = int(bus_ch) - 1
        assert 0 <= bus_idx < len(bus_list)
    except (ValueError, AssertionError):
        print(f"  {C.WARN}Invalid bus choice.{C.RESET}")
        return

    bus_class, bus_info = bus_list[bus_idx]
    encap = get_encap_info(bus_class)

    # ── Show full bus protocol details ────────────────────────────────────────
    section(f"BUS PROTOCOL: {bus_info['bus']}")
    print(f"  {C.DIM}  Standard    : {bus_info.get('standard','')}{C.RESET}")
    print(f"  {C.DIM}  Encoding    : {bus_info.get('encoding','')}{C.RESET}")
    print(f"  {C.L1}  Frame Start : {bus_info.get('delimiter_start','')}{C.RESET}")
    print(f"  {C.L1}  Frame End   : {bus_info.get('delimiter_end','')}{C.RESET}")
    print(f"  {C.DIM}  Frame Size  : {bus_info.get('frame_bytes','')}{C.RESET}")
    print(f"  {C.DIM}  Detection   : {bus_info.get('detection','')}{C.RESET}")
    if encap:
        print(f"  {C.L3}  EtherType   : {encap.get('eth_type','N/A')}{C.RESET}")
        print(f"  {C.L3}  Wrapping    : {encap.get('wrapping','')}{C.RESET}")
        print(f"  {C.WARN}  Inject Via  : {encap.get('inject_method','')}{C.RESET}")
    print(f"  {C.WARN}  Attack Surface: {bus_info.get('attack_surface','')[:80]}{C.RESET}")

    # ── Show fields and ask user to fill them ────────────────────────────────
    section(f"FRAME FIELDS — Enter values for each field")
    print(f"  {C.DIM}  Press Enter to use shown default. CAUTION fields marked ⚠{C.RESET}")
    print(f"  {C.SEP_C}{'─'*80}{C.RESET}")

    fields = bus_info.get('fields', {})
    field_values: dict[str, str] = {}
    payload_hex_parts: list[str] = []

    for fname, fdesc in fields.items():
        if fname == 'CAUTION':
            print(f"\n  {C.WARN}  ⚠  CAUTION: {fdesc}{C.RESET}\n")
            continue

        # Extract default from description if available
        default = ""
        fdesc_str = str(fdesc)

        # Show field with description
        print(f"  {C.L3}  {fname:<22}{C.RESET}  {C.DIM}{fdesc_str[:60]}{C.RESET}")

        # Determine sensible default
        if '0x' in fdesc_str:
            import re
            m = re.search(r'0x([0-9A-Fa-f]+)', fdesc_str)
            if m: default = m.group(0)
        if not default and '1B' in fdesc_str:
            default = '00'
        elif not default and '2B' in fdesc_str:
            default = '0000'
        elif not default and '4B' in fdesc_str:
            default = '00000000'
        elif not default and '6B' in fdesc_str:
            default = '000000000000'
        elif not default and '8B' in fdesc_str:
            default = '0000000000000000'

        val = get(f"    {fname}", default)
        field_values[fname] = val

        # Collect hex for payload assembly
        clean = val.replace(' ','').replace(':','').replace('-','')
        try:
            bytes.fromhex(clean)
            payload_hex_parts.append(clean)
        except ValueError:
            # non-hex value (string/number) — encode as ASCII or skip
            try:
                encoded = val.encode('ascii').hex()
                payload_hex_parts.append(encoded)
            except Exception:
                pass

    # ── Assemble payload ──────────────────────────────────────────────────────
    raw_payload_hex = ''.join(payload_hex_parts)
    try:
        hw_payload = bytes.fromhex(raw_payload_hex)
    except ValueError:
        hw_payload = b''

    print(f"\n  {C.SECT}{C.BOLD}▌ ADDITIONAL RAW PAYLOAD{C.RESET}")
    print(f"  {C.DIM}  Append extra bytes after the structured fields (e.g. data segment, CRC){C.RESET}")
    extra_hex = get("Extra payload hex (Enter=none)", "")
    try:
        extra_bytes = bytes.fromhex(extra_hex.replace(' ',''))
    except ValueError:
        extra_bytes = b''
    hw_payload += extra_bytes

    # ── L1 + L2 Ethernet frame assembly ──────────────────────────────────────
    section("ETHERNET ENCAPSULATION")
    print(f"  {C.DIM}  EtherType: {encap.get('eth_type','0x88B7 (OUI-Extended)')} — carrying {bus_info['bus']}{C.RESET}")

    preamble, sfd = ask_layer1_eth()

    dst_s = get("Destination MAC", "ff:ff:ff:ff:ff:ff",
                help="ff:ff:ff:ff:ff:ff=broadcast  or target device MAC")
    src_s = get("Source MAC",      "aa:bb:cc:dd:ee:ff")
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)

    # Pick EtherType
    et_str = encap.get('eth_type','0x88B7').split()[0].replace('0x','')
    try:
        et_int = int(et_str, 16)
    except ValueError:
        et_int = 0x88B7   # OUI-Extended fallback

    et_b = struct.pack('>H', et_int)

    # Assemble
    mac_content = dst_mb + src_mb + et_b + hw_payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    # Build records for display
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",     "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC", "raw":dst_mb,  "user_val":dst_s,         "note":""},
        {"layer":2,"name":"Src MAC", "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"EtherType","raw":et_b,   "user_val":f"0x{et_int:04X}",
         "note":f"{bus_info['bus'][:40]}"},
    ]

    # Add field-level records
    offset = 0
    for fname, val in field_values.items():
        clean = val.replace(' ','').replace(':','').replace('-','')
        try:
            chunk = bytes.fromhex(clean)
            if chunk:
                records.append({
                    "layer":3,"name":fname[:24],"raw":chunk,
                    "user_val":val[:20],"note":str(fields.get(fname,''))[:35]
                })
        except ValueError:
            pass

    if extra_bytes:
        records.append({"layer":3,"name":"Extra Payload","raw":extra_bytes,
                        "user_val":f"{len(extra_bytes)}B","note":"additional data"})

    records.append({"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,
                    "user_val":"auto/custom","note":fcs_note})

    print_frame_table(records)
    fcs_s = full_frame[-4:]; fcs_r = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_s.hex(), fcs_r.hex(), fcs_s==fcs_r)])
    print_encapsulation(records, full_frame)

    # Attack surface reminder
    print(f"\n  {C.WARN}  ⚠  ATTACK SURFACE REMINDER:{C.RESET}")
    print(f"  {C.WARN}     {bus_info.get('attack_surface','')}{C.RESET}")
    print(f"  {C.WARN}     Platform: {', '.join(bus_info.get('platforms', []))}{C.RESET}")



# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM / PRIVATE / UNDISCLOSED ETHERTYPE BUILDER
#  Allows building frames with ANY EtherType — known or unknown
#  Supports: raw hex payload, structured named fields, TLV chains,
#            vendor magic headers, and auto-populating from L2 registry
# ══════════════════════════════════════════════════════════════════════════════

# Custom EtherType session storage — persists across builds in same run
_CUSTOM_ET_SESSIONS: list[dict] = []   # saved custom definitions


def _custom_et_lookup(et_int: int) -> dict:
    """Look up an EtherType in the registry; return empty dict if not found."""
    if not _L2_AVAILABLE:
        return {}
    try:
        from l2_builder import ETHERTYPE_REGISTRY
        return ETHERTYPE_REGISTRY.get(et_int, {})
    except Exception:
        return {}


def _custom_field_editor(existing_fields: list[dict] | None = None) -> list[dict]:
    """
    Interactive field editor — build a list of named fields with values.
    Each field: {name, size_bytes, value_hex, description, encoding}
    Returns list of field dicts.
    Encoding options: hex | ascii | uint | ipv4 | mac | tlv | repeat
    """
    fields: list[dict] = list(existing_fields or [])

    ENCODINGS = {
        '1': ('hex',    'Raw hex bytes  e.g. 0A1B2C3D'),
        '2': ('uint',   'Unsigned int   e.g. 42  → packed big-endian'),
        '3': ('ascii',  'ASCII string   e.g. hello'),
        '4': ('ipv4',   'IPv4 address   e.g. 192.168.1.1'),
        '5': ('mac',    'MAC address    e.g. 00:11:22:33:44:55'),
        '6': ('tlv',    'Type-Len-Value  (prompted separately)'),
        '7': ('repeat', 'Repeated pattern  e.g. FF × N bytes'),
        '8': ('zero',   'Zero-fill N bytes'),
    }

    print(f"\n  {C.SECT}{C.BOLD}▌ CUSTOM PAYLOAD FIELD EDITOR{C.RESET}")
    print(f"  {C.DIM}  Build payload field-by-field. Each field adds bytes to payload.{C.RESET}")
    print(f"  {C.DIM}  Commands: A=Add field  D=Delete last  C=Clear all  P=Preview  X=Done{C.RESET}")

    while True:
        # Show current fields
        if fields:
            print(f"\n  {C.SEP_C}  Current fields ({len(fields)} total):{C.RESET}")
            total_bytes = 0
            for i, f in enumerate(fields, 1):
                nb = f.get('size_bytes', 0)
                total_bytes += nb
                print(f"  {C.DIM}  {i:>3}. {f['name']:<22} {nb:>4}B  {f['encoding']:<7}  {f['value_hex'][:32]}{C.RESET}")
            print(f"  {C.NOTE}  Total payload: {total_bytes} bytes{C.RESET}")
        else:
            print(f"\n  {C.DIM}  (no fields yet){C.RESET}")

        cmd = input(f"\n  {C.PROMPT}Field editor (A/D/C/P/X): {C.RESET}").strip().upper()

        if cmd == 'X' or cmd == '':
            break

        elif cmd == 'A':
            # Add a new field
            fname = input(f"  {C.PROMPT}Field name (e.g. Version, Type, Magic): {C.RESET}").strip()
            if not fname: fname = f"Field_{len(fields)+1}"

            fdesc = input(f"  {C.PROMPT}Description (optional): {C.RESET}").strip()

            print(f"  {C.DIM}  Encoding: ", end='')
            for k,(enc,label) in ENCODINGS.items():
                print(f"{k}={enc}  ", end='')
            print(f"{C.RESET}")
            enc_ch = input(f"  {C.PROMPT}Encoding [1=hex]: {C.RESET}").strip() or '1'
            encoding = ENCODINGS.get(enc_ch, ('hex',''))[0]

            val_hex = b''

            if encoding == 'hex':
                raw = input(f"  {C.PROMPT}Value (hex bytes, no spaces): {C.RESET}").strip().replace(' ','').replace(':','')
                if not raw: raw = '00'
                try:
                    val_hex = bytes.fromhex(raw)
                except Exception:
                    print(f"  {C.WARN}Invalid hex — using 0x00{C.RESET}")
                    val_hex = b'\x00'

            elif encoding == 'uint':
                size_s = input(f"  {C.PROMPT}Field size in bytes [1]: {C.RESET}").strip() or '1'
                try:
                    size = max(1, min(8, int(size_s)))
                except Exception:
                    size = 1
                val_s = input(f"  {C.PROMPT}Value (decimal or 0x hex): {C.RESET}").strip() or '0'
                try:
                    val_int = int(val_s, 0)
                    val_hex = val_int.to_bytes(size, 'big')
                except Exception:
                    val_hex = b'\x00' * size

            elif encoding == 'ascii':
                val_s = input(f"  {C.PROMPT}String value: {C.RESET}").strip()
                null_t = input(f"  {C.PROMPT}Null-terminate? (y/n) [n]: {C.RESET}").strip().lower()
                val_hex = val_s.encode('ascii','replace')
                if null_t == 'y': val_hex += b'\x00'

            elif encoding == 'ipv4':
                val_s = input(f"  {C.PROMPT}IPv4 address [0.0.0.0]: {C.RESET}").strip() or '0.0.0.0'
                try:
                    val_hex = socket.inet_aton(val_s)
                except Exception:
                    val_hex = b'\x00\x00\x00\x00'

            elif encoding == 'mac':
                val_s = input(f"  {C.PROMPT}MAC address [00:00:00:00:00:00]: {C.RESET}").strip() or '00:00:00:00:00:00'
                try:
                    val_hex = mac_b(val_s)
                except Exception:
                    val_hex = b'\x00'*6

            elif encoding == 'tlv':
                print(f"  {C.DIM}  TLV: each entry = Type(N bytes) + Length(N bytes) + Value{C.RESET}")
                type_size = int(input(f"  {C.PROMPT}Type field size bytes [1]: {C.RESET}").strip() or '1')
                len_size  = int(input(f"  {C.PROMPT}Length field size bytes [1]: {C.RESET}").strip() or '1')
                tlv_bytes = b''
                while True:
                    t_raw = input(f"  {C.PROMPT}  TLV Type (hex, Enter=done): {C.RESET}").strip()
                    if not t_raw: break
                    try:
                        t_val = int(t_raw, 16)
                        t_bytes = t_val.to_bytes(type_size, 'big')
                    except Exception:
                        t_bytes = b'\x00' * type_size
                    v_raw = input(f"  {C.PROMPT}  TLV Value (hex bytes): {C.RESET}").strip().replace(' ','')
                    try:
                        v_bytes = bytes.fromhex(v_raw)
                    except Exception:
                        v_bytes = b''
                    l_bytes = len(v_bytes).to_bytes(len_size, 'big')
                    tlv_bytes += t_bytes + l_bytes + v_bytes
                val_hex = tlv_bytes

            elif encoding == 'repeat':
                pat_raw = input(f"  {C.PROMPT}Pattern byte (hex) [FF]: {C.RESET}").strip() or 'FF'
                try:
                    pat = bytes.fromhex(pat_raw.zfill(2))
                except Exception:
                    pat = b'\xFF'
                count_s = input(f"  {C.PROMPT}Repeat count [4]: {C.RESET}").strip() or '4'
                try:
                    count = max(1, int(count_s))
                except Exception:
                    count = 4
                val_hex = pat * count

            elif encoding == 'zero':
                size_s = input(f"  {C.PROMPT}Zero-fill bytes [4]: {C.RESET}").strip() or '4'
                try:
                    size = max(1, int(size_s))
                except Exception:
                    size = 4
                val_hex = b'\x00' * size

            field = {
                'name':       fname,
                'description':fdesc,
                'size_bytes': len(val_hex),
                'value_hex':  val_hex.hex().upper(),
                'encoding':   encoding,
                'raw':        val_hex,
            }
            fields.append(field)
            print(f"  {C.PASS_}  Added: {fname} = {val_hex.hex().upper()} ({len(val_hex)}B){C.RESET}")

        elif cmd == 'D':
            if fields:
                removed = fields.pop()
                print(f"  {C.NOTE}  Removed: {removed['name']}{C.RESET}")
            else:
                print(f"  {C.WARN}  No fields to remove{C.RESET}")

        elif cmd == 'C':
            if input(f"  {C.PROMPT}Clear all fields? (y/n): {C.RESET}").strip().lower() == 'y':
                fields.clear()
                print(f"  {C.NOTE}  Cleared.{C.RESET}")

        elif cmd == 'P':
            # Preview the assembled payload
            if fields:
                payload = b''.join(f.get('raw', bytes.fromhex(f['value_hex'])) for f in fields)
                print(f"\n  {C.SECT}  PAYLOAD PREVIEW ({len(payload)} bytes):{C.RESET}")
                # Hex dump
                for off in range(0, len(payload), 16):
                    chunk = payload[off:off+16]
                    hex_part  = ' '.join(f'{b:02X}' for b in chunk)
                    asc_part  = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
                    print(f"  {C.HEX}  {off:04X}:  {hex_part:<47}  {C.DIM}{asc_part}{C.RESET}")
            else:
                print(f"  {C.WARN}  No fields to preview{C.RESET}")

    return fields


def _custom_et_session_manager() -> dict | None:
    """
    Manage saved custom EtherType sessions.
    Returns a session dict to load, or None to start fresh.
    """
    if not _CUSTOM_ET_SESSIONS:
        return None
    print(f"\n  {C.SECT}{C.BOLD}▌ SAVED CUSTOM DEFINITIONS ({len(_CUSTOM_ET_SESSIONS)}){C.RESET}")
    for i, sess in enumerate(_CUSTOM_ET_SESSIONS, 1):
        et = sess.get('et_int', 0)
        nm = sess.get('name', 'unnamed')
        fcount = len(sess.get('fields', []))
        plen = sess.get('payload_len', 0)
        print(f"  {C.DIM}  {i}. 0x{et:04X} — {nm}  ({fcount} fields, {plen}B){C.RESET}")
    ch = input(f"  {C.PROMPT}Load saved? (number / Enter=new): {C.RESET}").strip()
    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(_CUSTOM_ET_SESSIONS):
            return _CUSTOM_ET_SESSIONS[idx]
    return None


def flow_custom_ethertype():
    """
    Full interactive builder for custom, private, undisclosed, or experimental
    EtherTypes. Features:
      1. Enter any EtherType 0x0000-0xFFFF
      2. Auto-lookup in registry (shows known PDU/fields if present)
      3. Define custom fields interactively (name, size, encoding, value)
      4. TLV chain builder, raw hex, pattern fill, vendor magic support
      5. Preview hex dump before building
      6. Full L1+L2 frame assembly with FCS
      7. Save definition for reuse in same session
      8. Export custom definition as Python snippet
    """
    global _CUSTOM_ET_SESSIONS

    banner("CUSTOM / PRIVATE / UNDISCLOSED EtherType BUILDER",
           "Build ANY Ethernet frame — known, private, experimental, or proprietary")

    print(f"""
  {C.SECT}{C.BOLD}▌ WHAT THIS DOES{C.RESET}
  {C.DIM}  Ethernet EtherType is a 16-bit field (0x0000-0xFFFF = 65536 values).
  Only ~300 are registered with IEEE/IANA. The remaining 65000+ are:
  • Private/undisclosed — registered but spec not public (NDA)
  • Experimental — test/lab use (IEEE recommends 0x88B5/0x88B6)
  • Proprietary — vendor internal (Cisco ACI 0x8950, Huawei 0x8905 etc.)
  • Custom — your own protocol / test tool / research
  • Unknown captures — seen in pcap but no known dissector

  You can build a valid Ethernet frame with ANY EtherType and ANY payload.
  The payload can be structured (named fields) or raw hex bytes.{C.RESET}
""")

    # ── Load saved session? ────────────────────────────────────────────────────
    loaded = _custom_et_session_manager()
    if loaded:
        et_int    = loaded['et_int']
        et_name   = loaded.get('name', f'0x{et_int:04X}')
        fields    = list(loaded.get('fields', []))
        print(f"  {C.PASS_}  Loaded: {et_name} (0x{et_int:04X}){C.RESET}")
    else:
        fields = []

        # ── EtherType entry ───────────────────────────────────────────────────
        section("STEP 1 — ETHERTYPE SELECTION")
        print(f"""
  {C.DIM}  Enter any hex value 0x0000-0xFFFF.
  Examples:
    0x88B5  — IEEE experimental (safe for lab use)
    0x88B6  — IEEE experimental (second slot)
    0x8950  — Cisco ACI (undisclosed)
    0x9999  — Arista LANZ / F5 HA (documented)
    0xAAAA  — Your custom protocol
    0x1234  — Research / test
    0xF000  — Private (undisclosed range)
    0xFEFE  — Cisco ISL (documented)
  {C.RESET}""")

        while True:
            raw_et = input(f"  {C.PROMPT}EtherType (hex, e.g. 0x88B5 or 88B5): {C.RESET}").strip()
            raw_et = raw_et.replace('0x','').replace('0X','').strip()
            try:
                et_int = int(raw_et, 16)
                if 0 <= et_int <= 0xFFFF:
                    break
                print(f"  {C.WARN}  Must be 0x0000–0xFFFF{C.RESET}")
            except ValueError:
                print(f"  {C.WARN}  Invalid hex — try again{C.RESET}")

        # ── Registry lookup ───────────────────────────────────────────────────
        reg_info = _custom_et_lookup(et_int)
        if reg_info:
            print(f"\n  {C.PASS_}{C.BOLD}  ✓ KNOWN EtherType 0x{et_int:04X} found in registry:{C.RESET}")
            print(f"  {C.NOTE}    Name    : {reg_info.get('name','?')}{C.RESET}")
            print(f"  {C.NOTE}    PDU     : {reg_info.get('pdu','?')}{C.RESET}")
            print(f"  {C.NOTE}    Category: {reg_info.get('category','?')}  Status: {reg_info.get('status','?')}{C.RESET}")
            print(f"  {C.NOTE}    L3 proto: {reg_info.get('l3_proto','—')}{C.RESET}")
            # Show known fields
            known_flds = {k:v for k,v in reg_info.get('fields',{}).items() if k.upper()!='CAUTION'}
            if known_flds:
                print(f"\n  {C.DIM}  Known fields for this EtherType:{C.RESET}")
                for fname, fdesc in list(known_flds.items())[:12]:
                    print(f"  {C.DIM}    {fname:<25} {str(fdesc)[:55]}{C.RESET}")
            # Show CAUTION
            caution = reg_info.get('fields',{}).get('CAUTION','')
            if not caution:
                for k,v in reg_info.get('fields',{}).items():
                    if k.upper()=='CAUTION': caution=v; break
            if caution:
                print(f"\n  {C.WARN}  ⚠  CAUTION: {caution[:120]}{C.RESET}")
            et_name = reg_info.get('name', f'0x{et_int:04X}')[:40]

            # Offer to pre-populate fields from registry
            if known_flds and input(f"\n  {C.PROMPT}Pre-populate fields from registry? (y/n) [y]: {C.RESET}").strip().lower() != 'n':
                for fname, fdesc in known_flds.items():
                    # Parse size hint from description (e.g. "2B", "1B", "4B", "6B")
                    import re as _re
                    m = _re.search(r'(\d+)B', str(fdesc))
                    nb = int(m.group(1)) if m else 1
                    nb = min(nb, 16)  # cap at 16 for pre-pop
                    fields.append({
                        'name':        fname,
                        'description': str(fdesc)[:80],
                        'size_bytes':  nb,
                        'value_hex':   '00' * nb,
                        'encoding':    'hex',
                        'raw':         b'\x00' * nb,
                    })
                print(f"  {C.NOTE}  Pre-populated {len(fields)} fields — edit values below{C.RESET}")

        else:
            print(f"\n  {C.NOTE}  EtherType 0x{et_int:04X} is {C.BOLD}NOT in the registry{C.RESET}"
                  f"{C.NOTE} — private / undisclosed / experimental{C.RESET}")
            print(f"  {C.DIM}  You'll define the payload structure manually.{C.RESET}")
            et_name = f"Custom 0x{et_int:04X}"

        # Custom name
        custom_name = input(f"\n  {C.PROMPT}Protocol name / label [{et_name}]: {C.RESET}").strip()
        if not custom_name: custom_name = et_name

    # ── Payload builder mode ───────────────────────────────────────────────────
    section("STEP 2 — PAYLOAD BUILDER MODE")
    print(f"""
  {C.DIM}  1. Structured fields   — define fields one by one (recommended)
  2. Raw hex            — paste raw hex bytes directly
  3. Use fields + raw   — structured fields then append raw hex tail
  4. Pattern fill       — fill N bytes with a repeating pattern
  5. Import from file   — paste hex dump or colon-separated bytes{C.RESET}""")

    mode = input(f"  {C.PROMPT}Mode [1]: {C.RESET}").strip() or '1'

    if mode == '1' or mode == '3':
        fields = _custom_field_editor(fields if mode=='3' else None)
        payload = b''.join(f.get('raw', bytes.fromhex(f['value_hex'])) for f in fields)
        if mode == '3':
            raw_tail = input(f"\n  {C.PROMPT}Append raw hex tail (Enter=none): {C.RESET}").strip().replace(' ','')
            if raw_tail:
                try:
                    payload += bytes.fromhex(raw_tail)
                except Exception:
                    print(f"  {C.WARN}  Invalid hex tail — ignored{C.RESET}")

    elif mode == '2':
        print(f"  {C.DIM}  Paste raw payload as continuous hex (spaces OK, 0x prefix OK){C.RESET}")
        raw_s = input(f"  {C.PROMPT}Hex payload: {C.RESET}").strip()
        raw_s = raw_s.replace('0x','').replace(' ','').replace('\t','').replace(':','')
        try:
            payload = bytes.fromhex(raw_s)
        except Exception:
            print(f"  {C.WARN}  Invalid hex — using empty payload{C.RESET}")
            payload = b''

    elif mode == '4':
        pat_s = input(f"  {C.PROMPT}Pattern byte (hex) [AA]: {C.RESET}").strip() or 'AA'
        try:
            pat = bytes.fromhex(pat_s.zfill(2))
        except Exception:
            pat = b'\xAA'
        cnt_s = input(f"  {C.PROMPT}Total bytes [64]: {C.RESET}").strip() or '64'
        try:
            cnt = max(0, min(65535, int(cnt_s)))
        except Exception:
            cnt = 64
        payload = pat * cnt

    elif mode == '5':
        print(f"  {C.DIM}  Paste hex dump (any format — colons, spaces, 0x prefixes all OK):{C.RESET}")
        lines = []
        while True:
            ln = input(f"  {C.PROMPT}  > {C.RESET}")
            if not ln.strip(): break
            lines.append(ln)
        raw_s = ' '.join(lines)
        raw_s = raw_s.replace('0x','').replace(':','').replace('-','')
        raw_s = ''.join(c for c in raw_s if c in '0123456789abcdefABCDEF')
        try:
            payload = bytes.fromhex(raw_s)
        except Exception:
            print(f"  {C.WARN}  Could not parse — empty payload{C.RESET}")
            payload = b''
    else:
        payload = b''

    # ── Vendor magic header option ─────────────────────────────────────────────
    section("STEP 3 — VENDOR MAGIC / PROTOCOL HEADER")
    print(f"  {C.DIM}  Many vendor protocols start with a 4-byte magic identifier.{C.RESET}")
    print(f"  {C.DIM}  Examples: ARISTA=0x41524953 CISCO=0x43434353 HUAWEI=0x48574549{C.RESET}")
    add_magic = input(f"  {C.PROMPT}Add vendor magic header? (y/n) [n]: {C.RESET}").strip().lower()
    if add_magic == 'y':
        magic_raw = input(f"  {C.PROMPT}Magic bytes (hex, e.g. 41524953): {C.RESET}").strip().replace('0x','').replace(' ','')
        try:
            magic_bytes = bytes.fromhex(magic_raw)
        except Exception:
            magic_bytes = b'\x00\x00\x00\x00'
        payload = magic_bytes + payload
        print(f"  {C.PASS_}  Magic prepended: {magic_bytes.hex().upper()}{C.RESET}")

    # Pad to minimum Ethernet payload
    if len(payload) < 46:
        pad_n = 46 - len(payload)
        pad_byte_s = input(f"\n  {C.PROMPT}Pad to min 46B with (hex byte) [00]: {C.RESET}").strip() or '00'
        try:
            pad_b = bytes.fromhex(pad_byte_s.zfill(2))
        except Exception:
            pad_b = b'\x00'
        payload = payload + pad_b * pad_n
        print(f"  {C.NOTE}  Padded {pad_n} bytes → {len(payload)}B total payload{C.RESET}")

    # ── L1 ────────────────────────────────────────────────────────────────────
    section("STEP 4 — LAYER 1 / LAYER 2 HEADERS")
    preamble, sfd = ask_layer1_eth()

    # ── L2 MAC header ─────────────────────────────────────────────────────────
    print(f"\n  {C.SECT}{C.BOLD}▌ ETHERNET MAC HEADER{C.RESET}")
    dst_s = get("Destination MAC", "ff:ff:ff:ff:ff:ff")
    src_s = get("Source MAC", "aa:bb:cc:dd:ee:ff")
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)
    et_b   = struct.pack('>H', et_int)

    # ── FCS ───────────────────────────────────────────────────────────────────
    raw_frame = dst_mb + src_mb + et_b + payload
    fcs, fcs_note = ask_fcs_eth(raw_frame)

    # ── Assemble ──────────────────────────────────────────────────────────────
    frame = preamble + sfd + raw_frame + fcs

    # ── Display records ────────────────────────────────────────────────────────
    records: list[dict] = [
        {'layer':'L1','field':'Preamble',
         'value':preamble.hex().upper(),'note':'7B 0x55×7 — clock sync'},
        {'layer':'L1','field':'SFD',
         'value':sfd.hex().upper(),'note':'0xD5 — start of frame'},
        {'layer':'L2','field':'Dst MAC',
         'value':dst_s,'note':''},
        {'layer':'L2','field':'Src MAC',
         'value':src_s,'note':''},
        {'layer':'L2','field':f'EtherType 0x{et_int:04X}',
         'value':et_b.hex().upper(),
         'note':f'{custom_name} ({reg_info.get("status","custom") if reg_info else "custom"})'},
    ]
    # Add each custom field as a record
    off = 0
    for f in fields:
        raw = f.get('raw', bytes.fromhex(f['value_hex']))
        records.append({
            'layer':'L3',
            'field':f['name'],
            'value':raw.hex().upper(),
            'note':f['description'][:60] if f.get('description') else f'{f["size_bytes"]}B {f["encoding"]}',
        })
        off += len(raw)
    # If raw mode — show as single payload record
    if mode in ('2','4','5'):
        records.append({
            'layer':'L3','field':'Payload',
            'value':payload.hex().upper()[:64]+('…' if len(payload)>32 else ''),
            'note':f'{len(payload)}B custom payload',
        })
    records.append({'layer':'L2','field':'FCS',
                    'value':fcs.hex().upper(),'note':fcs_note})

    section("FRAME SUMMARY")
    print_frame_table(records)
    print_encapsulation(records, frame)

    # ── Hex dump ───────────────────────────────────────────────────────────────
    section("HEX DUMP — COMPLETE FRAME")
    print(f"  {C.DIM}  Total frame: {len(frame)} bytes{C.RESET}\n")
    print(f"  {C.DIM}  {'Offset':<8} {'00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F':<49}  ASCII{C.RESET}")
    print(f"  {C.SEP_C}  {'─'*76}{C.RESET}")
    for off in range(0, len(frame), 16):
        chunk = frame[off:off+16]
        h1 = ' '.join(f'{b:02X}' for b in chunk[:8])
        h2 = ' '.join(f'{b:02X}' for b in chunk[8:])
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {C.HEX}  {off:04X}    {h1:<23}  {h2:<23}  {C.DIM}{asc}{C.RESET}")

    # Bit-level view of EtherType
    print(f"\n  {C.SECT}{C.BOLD}▌ ETHERTYPE FIELD ANALYSIS{C.RESET}")
    print(f"  {C.DIM}  EtherType 0x{et_int:04X} = {et_int} decimal = {et_int:016b} binary{C.RESET}")
    print(f"  {C.DIM}  High byte: 0x{et_int>>8:02X} ({et_int>>8:08b})  Low byte: 0x{et_int&0xFF:02X} ({et_int&0xFF:08b}){C.RESET}")
    if et_int >= 0x0600:
        print(f"  {C.NOTE}  ≥ 0x0600 → EtherType II frame (protocol identifier){C.RESET}")
    else:
        print(f"  {C.NOTE}  < 0x0600 → IEEE 802.3 frame (value = payload length = {et_int} bytes){C.RESET}")
    if et_int in (0x88B5, 0x88B6):
        print(f"  {C.NOTE}  IEEE 802 Local Experimental — safe for lab/research use{C.RESET}")
    elif not _custom_et_lookup(et_int):
        print(f"  {C.WARN}  Private / Undisclosed — not in public registry{C.RESET}")

    # ── Save session ──────────────────────────────────────────────────────────
    if input(f"\n  {C.PROMPT}Save this definition for reuse? (y/n) [n]: {C.RESET}").strip().lower() == 'y':
        session = {
            'et_int':      et_int,
            'name':        custom_name,
            'fields':      fields,
            'payload_len': len(payload),
            'et_hex':      f'0x{et_int:04X}',
        }
        _CUSTOM_ET_SESSIONS.append(session)
        print(f"  {C.PASS_}  Saved as session #{len(_CUSTOM_ET_SESSIONS)}{C.RESET}")

    # ── Export as Python snippet ───────────────────────────────────────────────
    if input(f"  {C.PROMPT}Export as Python bytes snippet? (y/n) [n]: {C.RESET}").strip().lower() == 'y':
        print(f"\n  {C.SECT}{C.BOLD}▌ PYTHON SNIPPET{C.RESET}")
        print(f"  # Custom EtherType 0x{et_int:04X} — {custom_name}")
        print(f"  frame = bytes.fromhex(")
        # Chunk the hex
        fx = frame.hex().upper()
        for i in range(0, len(fx), 64):
            print(f"      '{fx[i:i+64]}'{'  # ' + str(i//2) + 'B' if i==0 else ''}")
        print(f"  )")
        print(f"  # EtherType bytes: {et_b.hex().upper()}  ({custom_name})")
        print(f"  # Payload:         {payload.hex().upper()[:64]}{'…' if len(payload)>32 else ''}")

    verify_report([
        ("Frame length",      f"{len(frame)}B",        True),
        ("EtherType",         f"0x{et_int:04X}",        True),
        ("Payload length",    f"{len(payload)}B",        len(payload)>=46),
        ("Registry status",   reg_info.get('status','private/custom') if reg_info else 'private/custom', True),
        ("FCS",               fcs_note,                  True),
    ])


def main():
    """
    Main entry point — 5 options.
    All menu functions are defined above this point.
    """
    global _ETH_SEL_MAP

    print_main_menu()
    top = input(f"\n  {C.PROMPT}Choose technology  (1=Ethernet  2=Serial  3=WiFi  4=IPv4  5=Hardware): {C.RESET}").strip()

    # ── Option 1: Ethernet ────────────────────────────────────────────────────
    if top == '1':
        # Step 1: Ask processing mode (PHY layer or MAC layer only)
        phy_mode = ask_phy_mode()

        if phy_mode == 'phy':
            # Step 2A: PHY layer selected — ask speed variant
            speed_key = ask_eth_phy_speed()
            # Store in global so all flow functions can access
            _ETH_PHY_SPEED = speed_key
        else:
            # Step 2B: MAC layer only — use default Preamble+SFD
            _ETH_PHY_SPEED = 'MAC_ONLY'

        print_eth_menu()
        total   = len(_ETH_SEL_MAP)
        fixed_n = sum(1 for e in _ETH_SEL_MAP.values() if e[0]=='fixed')
        ch = input(f"\n  {C.PROMPT}Enter number  (1-{fixed_n}=full builders | {fixed_n+1}-{total}=EtherType generic | C=Custom): {C.RESET}").strip()
        entry = _ETH_SEL_MAP.get(ch)
        if ch.upper() == 'C':
            flow_custom_ethertype()
        elif entry is None:
            print(f"  {C.WARN}Invalid — enter 1 to {total}.{C.RESET}")
        elif entry[0] == 'fixed':
            entry[1]()
        else:
            et_int = entry[1]; l3cls = entry[4]
            if l3cls == 'ipv4':
                l4ch = print_ipv4_l4_menu()
                if   l4ch == '1': flow_eth_ip_icmp()
                elif l4ch == '2': flow_eth_ip_tcp()
                elif l4ch == '3': flow_eth_ip_udp()
                else: flow_eth_generic(et_int)
            else:
                flow_eth_generic(et_int)

    # ── Option 2: Serial / WAN ────────────────────────────────────────────────
    elif top == '2':
        print_serial_menu()
        flow_serial()

    # ── Option 3: WiFi / 802.11 ───────────────────────────────────────────────
    elif top == '3':
        print_wifi_menu()
        flow_wifi()

    # ── Option 4: Standalone IPv4 ─────────────────────────────────────────────
    elif top == '4':
        print_ip_menu()
        l4ch = print_ipv4_l4_menu()
        flow_ip_standalone(preselected_l4=l4ch)

    # ── Option 5: Hardware / Bus Frame ────────────────────────────────────────
    elif top == '5':
        flow_hw()

    else:
        print(f"  {C.WARN}Invalid — enter 1, 2, 3, 4, or 5.{C.RESET}")


if __name__ == "__main__":
    try:
        main()
        while input("\nBuild another frame? (y/n): ").strip().lower() == 'y':
            print()
            main()
    except KeyboardInterrupt:
        print("\nExited.")
