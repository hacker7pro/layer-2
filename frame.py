"""
Network Frame Builder  —  Complete Protocol Suite
==================================================
Layer flow:  L1-PHY → L2-DL → L3-NET → L4-CTRL → TRAILER

Technologies
────────────
 1  Ethernet/802.3 : ARP · IPv4+ICMP/TCP/UDP · STP/RSTP · DTP · PAgP · LACP
                     Pause(802.3x) · PFC(802.1Qbb) · LLDP(802.1AB)
                     VLAN(802.1Q+QinQ) · Jumbo
 2  Serial/WAN     : Raw · SLIP · PPP · Modbus RTU · ATM AAL5 · Cisco HDLC
                     KISS · COBS · HDLC+BitStuff
                     HDLC Full (I-frame · S-frame · U-frame)
 3  WiFi/802.11    : Mgmt(Beacon/Probe/Auth/Assoc/Action)
                     Ctrl(RTS/CTS/ACK/BlockAck/PSPoll)
                     Data(Data/Null/QoS-Data/QoS-Null)
                     PHY: DSSS(b) · OFDM(a/g) · HT(n) · VHT(ac) · HE(ax)
 4  Standalone IPv4: Full header · Options(NOP/RR/TS/custom)
                     Checksum: auto/custom/force-zero
                     L4: ICMP · TCP · UDP · Raw · Empty

Output per build
────────────────
  Field table  ·  Encapsulation diagram  ·  Annotated hex dump
  Final hex (no gaps)  ·  Checksum verification (PASS/FAIL)
  Every prompt: ┆ what the field does  ┆ valid values  ┆ effect of wrong value
"""
import struct, zlib, socket, os, sys

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — CONSTANTS  (widths, tags, lookup tables, menus)
# ══════════════════════════════════════════════════════════════════════════════
W   = 118
SEP = "═" * W
DIV = "─" * W
HDR = "─" * W

# ── ANSI colour palette ───────────────────────────────────────────────────────
# Auto-detect terminal support; fall back gracefully if no colour
_USE_COLOR = sys.stdout.isatty() or os.environ.get('FORCE_COLOR')

class C:
    """ANSI colour codes.  All empty strings when colour is disabled."""
    if _USE_COLOR:
        RESET  = "\033[0m"
        BOLD   = "\033[1m"
        DIM    = "\033[2m"
        ITALIC = "\033[3m"
        UL     = "\033[4m"

        # Layer colours
        L1     = "\033[38;5;220m"   # gold        — Physical
        L2     = "\033[38;5;75m"    # sky blue    — Data Link
        L3     = "\033[38;5;118m"   # lime green  — Network
        L4     = "\033[38;5;213m"   # pink/violet — Transport
        TRAIL  = "\033[38;5;203m"   # coral/red   — Trailer / FCS

        # UI colours
        BANNER = "\033[38;5;39m"    # bright cyan     — banners
        SECT   = "\033[38;5;178m"   # amber           — section headers
        HELP   = "\033[38;5;245m"   # grey            — help text (┆ lines)
        PROMPT = "\033[38;5;252m"   # near-white      — prompts
        HEX    = "\033[38;5;159m"   # pale cyan       — hex values
        NOTE   = "\033[38;5;186m"   # pale yellow     — notes/annotations
        PASS_  = "\033[1;38;5;46m"  # bright green    — PASS ✓
        FAIL_  = "\033[1;38;5;196m" # bright red      — FAIL ✗
        WARN   = "\033[38;5;214m"   # orange          — warnings
        TAG1   = "\033[38;5;220m"   # L1 gold
        TAG2   = "\033[38;5;75m"    # L2 blue
        TAG3   = "\033[38;5;118m"   # L3 green
        TAG4   = "\033[38;5;213m"   # L4 pink
        TAG0   = "\033[38;5;203m"   # Trailer coral
        BOX    = "\033[38;5;240m"   # dark grey       — box drawing
        SEP_C  = "\033[38;5;25m"    # dark blue       — separator lines
        OFFSET = "\033[38;5;243m"   # mid grey        — byte offsets
        SIZE   = "\033[38;5;180m"   # tan             — size fields
        ASCII_ = "\033[38;5;188m"   # light grey      — ASCII column
    else:
        RESET=BOLD=DIM=ITALIC=UL=""
        L1=L2=L3=L4=TRAIL=""
        BANNER=SECT=HELP=PROMPT=""
        HEX=NOTE=PASS_=FAIL_=WARN=""
        TAG1=TAG2=TAG3=TAG4=TAG0=""
        BOX=SEP_C=OFFSET=SIZE=ASCII_=""

# Colour for each layer tag
_TAG_COLOR = {1: C.TAG1, 2: C.TAG2, 3: C.TAG3, 4: C.TAG4, 0: C.TAG0}
_LAYER_COLOR = {1: C.L1, 2: C.L2, 3: C.L3, 4: C.L4, 0: C.TRAIL}

LAYER_TAG = {
    1: "[L1-PHY ]",
    2: "[L2-DL  ]",
    3: "[L3-NET ]",
    4: "[L4-CTRL]",
    0: "[TRAILER]",
}

def ctag(layer):
    """Return coloured LAYER_TAG string."""
    raw = LAYER_TAG.get(layer, "        ")
    col = _TAG_COLOR.get(layer, "")
    return f"{col}{raw}{C.RESET}"


# ──────────────────────────────────────────────────────────────────────────────
#  Protocol lookup tables
# ──────────────────────────────────────────────────────────────────────────────
L3_PROTO_NAMES = {1:"ICMP", 6:"TCP", 17:"UDP", 41:"IPv6", 89:"OSPF", 47:"GRE"}
ICMP_TABLE = {
    0:  ("Echo Reply",              {0:"Echo reply"}),
    3:  ("Destination Unreachable", {
            0:"Net unreachable",         1:"Host unreachable",
            2:"Protocol unreachable",    3:"Port unreachable",
            4:"Fragmentation needed/DF", 5:"Source route failed",
            6:"Dest network unknown",    7:"Dest host unknown",
            9:"Net admin prohibited",   10:"Host admin prohibited",
           13:"Comm admin prohibited"}),
    4:  ("Source Quench",           {0:"Source quench (deprecated)"}),
    5:  ("Redirect",                {0:"Redirect network",1:"Redirect host",
                                     2:"Redirect TOS+net",3:"Redirect TOS+host"}),
    8:  ("Echo Request",            {0:"Echo request"}),
    9:  ("Router Advertisement",    {0:"Normal advertisement"}),
   10:  ("Router Solicitation",     {0:"Router solicitation"}),
   11:  ("Time Exceeded",           {0:"TTL exceeded in transit",
                                     1:"Fragment reassembly exceeded"}),
   12:  ("Parameter Problem",       {0:"Pointer error",1:"Missing option",2:"Bad length"}),
   13:  ("Timestamp Request",       {0:"Timestamp request"}),
   14:  ("Timestamp Reply",         {0:"Timestamp reply"}),
   17:  ("Address Mask Request",    {0:"Address mask request"}),
   18:  ("Address Mask Reply",      {0:"Address mask reply"}),
   30:  ("Traceroute",              {0:"Information (deprecated)"}),
}
ICMP_ECHO_TYPES = {0, 8, 13, 14, 17, 18}
WELL_KNOWN_PORTS = {
    20: "FTP-Data",     21: "FTP-Control",  22: "SSH",
    23: "Telnet",       25: "SMTP",         53: "DNS",
    67: "DHCP-Server",  68: "DHCP-Client",  69: "TFTP",
    80: "HTTP",         110:"POP3",         119:"NNTP",
    123:"NTP",          143:"IMAP",         161:"SNMP",
    162:"SNMP-Trap",    179:"BGP",          194:"IRC",
    389:"LDAP",         443:"HTTPS",        445:"SMB",
    514:"Syslog",       520:"RIP",          587:"SMTP-TLS",
    636:"LDAPS",        993:"IMAPS",        995:"POP3S",
   1194:"OpenVPN",     1433:"MSSQL",       1521:"Oracle",
   3306:"MySQL",       3389:"RDP",         5060:"SIP",
   5432:"PostgreSQL",  5900:"VNC",         6379:"Redis",
   8080:"HTTP-Alt",    8443:"HTTPS-Alt",   9200:"Elasticsearch",
   27017:"MongoDB",
}
TCP_FLAGS = {
    'FIN':0x01, 'SYN':0x02, 'RST':0x04,
    'PSH':0x08, 'ACK':0x10, 'URG':0x20,
    'ECE':0x40, 'CWR':0x80,
}
TCP_STEPS = {
    '1': ("SYN",     0x02, "Client → Server  (open connection request)"),
    '2': ("SYN-ACK", 0x12, "Server → Client  (acknowledge + own SYN)"),
    '3': ("ACK",     0x10, "Client → Server  (acknowledge server SYN)"),
    '4': ("PSH+ACK", 0x18, "Data segment with push flag"),
    '5': ("FIN+ACK", 0x11, "Initiating graceful close"),
    '6': ("RST",     0x04, "Abrupt connection reset"),
}
UDP_COMMON = {
    ('53','53'):   "DNS Query/Response",
    ('67','68'):   "DHCP",
    ('123','123'): "NTP",
    ('161','162'): "SNMP",
    ('514','514'): "Syslog",
    ('520','520'): "RIP",
    ('69','69'):   "TFTP",
    ('5060','5060'):"SIP",
}
HDLC_U_SUBTYPES = {
    # key: (M4,M3,M2,M1,M0, mnemonic, C/R, description)
    '1' : (0,0,0,0,0, "UI",    "C/R", "Unnumbered Information — datagram (no ACK)"),
    '2' : (0,1,1,0,0, "SABM",  "C",   "Set Async Balanced Mode — initiate connection (mod-8)"),
    '3' : (0,1,1,0,1, "SABME", "C",   "SABM Extended — initiate connection (mod-128)"),
    '4' : (0,1,0,0,0, "DISC",  "C",   "Disconnect — request to terminate link"),
    '5' : (0,0,0,1,1, "DM",    "R",   "Disconnect Mode — link not established"),
    '6' : (0,0,1,0,1, "UA",    "R",   "Unnumbered Acknowledgment — accept SABM/DISC"),
    '7' : (1,0,0,0,1, "FRMR",  "R",   "Frame Reject — invalid frame received"),
    '8' : (1,1,0,0,0, "XID",   "C/R", "Exchange Identification — parameter negotiation"),
    '9' : (1,1,1,0,0, "TEST",  "C/R", "Test — link integrity test"),
    '10': (0,0,1,0,0, "UP",    "C",   "Unnumbered Poll — poll without sequence numbers"),
}
HDLC_S_SUBTYPES = {
    '1': (0,0, "RR",   "Receive Ready    — ACK, ready for more"),
    '2': (0,1, "REJ",  "Reject           — go-back-N, retransmit from N(R)"),
    '3': (1,0, "RNR",  "Receive Not Ready— busy, stop sending"),
    '4': (1,1, "SREJ", "Selective Reject — retransmit only frame N(R)"),
}
JUMBO_PRESETS = {
    '1': (1500,  "Standard Ethernet (baseline)"),
    '2': (1600,  "Baby Giant  (MPLS +1 label)"),
    '3': (4470,  "FDDI over Ethernet bridging"),
    '4': (9000,  "Typical Jumbo (NFS/iSCSI/Ceph/HPC)"),
    '5': (9216,  "Extended Jumbo (storage switches)"),
    '6': (16110, "Super Jumbo (InfiniBand bridging)"),
    '7': (0,     "Custom"),
}
WIFI_FRAME_TYPES = {
    '1': (0b00, "Management"),
    '2': (0b01, "Control"),
    '3': (0b10, "Data"),
}
WIFI_MGMT_SUBTYPES = {
    '0' : (0x00, "Association Request",    "STA→AP  join BSS"),
    '1' : (0x01, "Association Response",   "AP→STA  grant/deny join"),
    '2' : (0x02, "Reassociation Request",  "STA→AP  roaming"),
    '3' : (0x03, "Reassociation Response", "AP→STA  roam reply"),
    '4' : (0x04, "Probe Request",          "STA→all scan for APs"),
    '5' : (0x05, "Probe Response",         "AP→STA  scan reply"),
    '8' : (0x08, "Beacon",                 "AP→all  periodic BSS announce"),
    '10': (0x0A, "Disassociation",         "either  end association"),
    '11': (0x0B, "Authentication",         "either  auth exchange"),
    '12': (0x0C, "Deauthentication",       "either  end auth"),
    '13': (0x0D, "Action",                 "either  BA/RM/spectrum action"),
}
WIFI_CTRL_SUBTYPES = {
    '8' : (0x08, "Block Ack Request", "Request aggregated ACK"),
    '9' : (0x09, "Block Ack",        "Aggregated ACK bitmap"),
    '10': (0x0A, "PS-Poll",          "Power-save poll for buffered data"),
    '11': (0x0B, "RTS",              "Request To Send (CSMA/CA)"),
    '12': (0x0C, "CTS",              "Clear To Send (RTS response)"),
    '13': (0x0D, "ACK",              "Acknowledge received frame"),
    '14': (0x0E, "CF-End",           "End contention-free period"),
}
WIFI_DATA_SUBTYPES = {
    '0' : (0x00, "Data",     False, "Basic data, no QoS field"),
    '4' : (0x04, "Null",     False, "No payload, power-mgmt signal"),
    '8' : (0x08, "QoS Data", True,  "Data + QoS Control (WMM/WME)"),
    '12': (0x0C, "QoS Null", True,  "No payload + QoS, power-mgmt"),
}
WIFI_ACK_POLICY = {0:"Normal ACK", 1:"No ACK", 2:"No Explicit ACK", 3:"Block ACK"}
WIFI_TID_NAMES  = {
    0:"BE(Best Effort)", 1:"BK(Background)", 2:"BK(Background)",
    3:"BE(Best Effort)", 4:"VI(Video)",       5:"VI(Video)",
    6:"VO(Voice)",       7:"VO(Voice)",
}
WIFI_PHY_MODES = {
    '1': "802.11b  DSSS/CCK  (2.4 GHz, 1/2/5.5/11 Mbps)",
    '2': "802.11a  OFDM      (5 GHz,   6–54 Mbps)",
    '3': "802.11g  ERP-OFDM  (2.4 GHz, 6–54 Mbps)",
    '4': "802.11n  HT-Mixed  (2.4/5 GHz, up to 600 Mbps)",
    '5': "802.11ac VHT       (5 GHz,   up to 6.9 Gbps)",
    '6': "802.11ax HE        (2.4/5/6 GHz, up to 9.6 Gbps)",
    '7': "No PHY preamble   (MAC MPDU only — as seen in Wireshark pcap)",
}
DSSS_RATES = {
    '1': (0x0A, "1 Mbps  DBPSK"),
    '2': (0x14, "2 Mbps  DQPSK"),
    '3': (0x37, "5.5 Mbps CCK"),
    '4': (0x6E, "11 Mbps CCK"),
}
OFDM_RATE_BITS = {
    '6' : (0b1011, "6 Mbps  BPSK  R=1/2"),
    '9' : (0b1111, "9 Mbps  BPSK  R=3/4"),
    '12': (0b1010, "12 Mbps QPSK  R=1/2"),
    '18': (0b1110, "18 Mbps QPSK  R=3/4"),
    '24': (0b1001, "24 Mbps 16-QAM R=1/2"),
    '36': (0b1101, "36 Mbps 16-QAM R=3/4"),
    '48': (0b1000, "48 Mbps 64-QAM R=2/3"),
    '54': (0b1100, "54 Mbps 64-QAM R=3/4"),
}
IP_PROTO_NAMES = {
    0:  ("HOPOPT",  "IPv6 Hop-by-Hop Options"),
    1:  ("ICMP",    "Internet Control Message Protocol"),
    2:  ("IGMP",    "Internet Group Management Protocol"),
    4:  ("IP-IP",   "IP-in-IP Encapsulation"),
    6:  ("TCP",     "Transmission Control Protocol"),
    17: ("UDP",     "User Datagram Protocol"),
    41: ("IPv6",    "IPv6 Encapsulation"),
    47: ("GRE",     "Generic Routing Encapsulation"),
    50: ("ESP",     "Encapsulating Security Payload"),
    51: ("AH",      "Authentication Header"),
    58: ("ICMPv6",  "ICMP for IPv6"),
    89: ("OSPF",    "Open Shortest Path First"),
    103:("PIM",     "Protocol Independent Multicast"),
    112:("VRRP",    "Virtual Router Redundancy Protocol"),
    132:("SCTP",    "Stream Control Transmission Protocol"),
}
DSCP_TABLE = {
    0:  ("CS0 / BE",  "Best Effort — default"),
    8:  ("CS1",       "Scavenger / low-priority"),
    10: ("AF11",      "Assured Forwarding low drop"),
    12: ("AF12",      "Assured Forwarding med drop"),
    14: ("AF13",      "Assured Forwarding high drop"),
    16: ("CS2",       "OAM"),
    18: ("AF21",      "AF class 2 low drop"),
    20: ("AF22",      "AF class 2 med drop"),
    22: ("AF23",      "AF class 2 high drop"),
    24: ("CS3",       "Broadcast video"),
    26: ("AF31",      "AF class 3 low drop"),
    28: ("AF32",      "AF class 3 med drop"),
    30: ("AF33",      "AF class 3 high drop"),
    32: ("CS4",       "Real-time interactive"),
    34: ("AF41",      "AF class 4 low drop"),
    36: ("AF42",      "AF class 4 med drop"),
    38: ("AF43",      "AF class 4 high drop"),
    40: ("CS5",       "Signalling"),
    46: ("EF",        "Expedited Forwarding — VoIP"),
    48: ("CS6",       "Network control (routing)"),
    56: ("CS7",       "Reserved"),
}
SERIAL_TYPES = {
    '1' : "Raw",
    '2' : "SLIP",
    '3' : "PPP",
    '4' : "HDLC (basic — address+control+payload+FCS-16)",
    '5' : "COBS (placeholder)",
    '6' : "KISS",
    '7' : "Modbus RTU",
    '8' : "HDLC + Bit-Stuffing",
    '9' : "ATM AAL5",
    '10': "Cisco HDLC",
    '11': "HDLC Full (I-frame / S-frame / U-frame — all 3 types)",
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — CORE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  Input helpers
# ──────────────────────────────────────────────────────────────────────────────
def get(prompt, default="", help=""):
    """Simple prompted input with default. Optional help shown before prompt."""
    if help:
        for line in help.strip().split("\n"):
            print(f"      {C.HELP}┆ {line}{C.RESET}")
    val = input(f"    {C.PROMPT}{prompt}{C.RESET} [{C.NOTE}{default}{C.RESET}]: ").strip()
    return val if val else default

def get_hex(prompt, default_hex, byte_len=None, help=""):
    """Prompt for hex bytes, validate length. Optional help shown before prompt."""
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

# ──────────────────────────────────────────────────────────────────────────────
#  Address and byte converters
# ──────────────────────────────────────────────────────────────────────────────
def mac_b(s):
    c = s.replace(":","").replace("-","").replace(" ","").upper()
    if len(c) != 12: raise ValueError(f"bad MAC: {s!r}")
    return bytes.fromhex(c)
def mac_s(b): return ':'.join(f'{x:02x}' for x in b)
def ip_b(s): return socket.inet_aton(s)
def hpad(s, n):
    c = s.lower().replace("0x","").replace(" ","")
    if len(c) % 2: c = "0"+c
    b = bytes.fromhex(c)
    if len(b) > n: b = b[-n:]
    elif len(b) < n: b = b'\x00'*(n-len(b)) + b
    return b

# ──────────────────────────────────────────────────────────────────────────────
#  Checksum / CRC engines
# ──────────────────────────────────────────────────────────────────────────────
def crc32_eth(data):
    """Ethernet FCS: CRC-32 stored little-endian."""
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF
def crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM used in DSSS PLCP header."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8005
            else:
                crc >>= 1
    return crc
def inet_cksum(data):
    """RFC 1071 one's-complement checksum."""
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

# ──────────────────────────────────────────────────────────────────────────────
#  Serial framing helpers
# ──────────────────────────────────────────────────────────────────────────────
def byte_escape(data):
    out = bytearray()
    for b in data:
        if b == 0x7E: out += b'\x7D\x5E'
        elif b == 0x7D: out += b'\x7D\x5D'
        else: out.append(b)
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
        if b==0xC0: out+=b'\xDB\xDC'
        elif b==0xDB: out+=b'\xDB\xDD'
        else: out.append(b)
    return bytes(out+b'\xC0')

# ──────────────────────────────────────────────────────────────────────────────
#  Display / output engine
# ──────────────────────────────────────────────────────────────────────────────
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

    hdr = (f"  {C.DIM}{'Byte':>6}  "
           f"{'Layer':<11}  "
           f"{'Field Name':<28}  "
           f"{'Size':>8}  "
           f"{'Hex Value':<30}  "
           f"{'User Input / Note'}{C.RESET}")
    print(hdr)
    print(dash)

    offset = 0
    prev_layer = None
    for r in records:
        lay  = r['layer']
        name = r['name']
        raw  = r['raw']
        note = r.get('note', '')
        uval = r.get('user_val', '')
        lc   = _LAYER_COLOR.get(lay, "")

        if lay != prev_layer and prev_layer is not None:
            print(f"  {dot}")
        prev_layer = lay

        sz = len(raw)

        # zero-length = annotation-only row
        if sz == 0:
            annotation = uval if uval else note
            if uval and note and uval != note:
                annotation = f"{uval}  ({note})"
            print(f"  {'':10}  {ctag(lay)}  "
                  f"  {C.DIM}{name:<28}{C.RESET}  "
                  f"{'':>8}   {'':30}  "
                  f"  {C.NOTE}{annotation}{C.RESET}")
            continue

        hexs = ' '.join(f'{b:02x}' for b in raw)
        if len(hexs) > 29: hexs = hexs[:27] + '..'

        annotation = uval if uval else note
        if uval and note and uval != note:
            annotation = f"{uval}  ({note})"

        print(f"  {C.OFFSET}{offset:5d}-{offset+sz-1:<4d}{C.RESET}  "
              f"{ctag(lay)}  "
              f"  {lc}{name:<28}{C.RESET}  "
              f"{C.SIZE}{sz:3d}B/{sz*8:4d}b{C.RESET}  "
              f"  {C.HEX}{hexs:<30}{C.RESET}  "
              f"  {C.NOTE}{annotation}{C.RESET}")
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
    for (s, e, lay, name) in layer_spans:
        if lay not in layer_groups:
            layer_groups[lay] = [s, e, name]
        else:
            layer_groups[lay][1] = e

    LAYER_LABELS = {
        1: "LAYER 1  Physical  (Preamble + SFD / Flags)",
        2: "LAYER 2  Data Link  (MAC / Serial header)",
        3: "LAYER 3  Network   (IP / ARP / BPDU / DTP / PAgP / LACP)",
        4: "LAYER 4  Transport (TCP / UDP / ICMP)",
        0: "TRAILER  (FCS / CRC)",
    }

    def proto_names(layer):
        seen = []
        for r in records:
            if r['layer'] == layer:
                n = r['name'].split()[0]
                if n not in seen: seen.append(n)
        return ' | '.join(seen[:4])

    bar = f"{C.BANNER}{SEP}{C.RESET}"
    print(f"\n{bar}")
    print(f"  {C.BOLD}{C.BANNER}{'FRAME ENCAPSULATION  —  STRUCTURE DIAGRAM':^{W-2}}{C.RESET}")
    print(bar)
    print()

    sorted_layers = sorted(layer_groups.keys(), key=lambda x: (x if x != 0 else 99))
    indent_map = {1:0, 2:2, 3:4, 4:6, 0:0}

    for lay in sorted_layers:
        s, e, _ = layer_groups[lay]
        lc    = _LAYER_COLOR.get(lay, "")
        ind   = ' ' * indent_map.get(lay, 0)
        width = W2 - indent_map.get(lay, 0) - 2
        label = LAYER_LABELS.get(lay, f"Layer {lay}")
        proto = proto_names(lay)
        bytes_count = e - s + 1

        bc = f"{C.BOX}"  # box colour
        rc = C.RESET

        print(f"  {ind}{bc}╔{'═'*width}╗{rc}")
        content = f"  {label}"
        print(f"  {ind}{bc}║{rc}{lc}{C.BOLD}{content:<{width}}{rc}{bc}║{rc}")
        if proto:
            pcontent = f"  Protocols: {proto}"
            print(f"  {ind}{bc}║{rc}{C.DIM}{pcontent:<{width}}{rc}{bc}║{rc}")
        bcontent = f"  Bytes {s}–{e}  ({bytes_count} bytes / {bytes_count*8} bits)"
        print(f"  {ind}{bc}║{rc}{C.OFFSET}{bcontent:<{width}}{rc}{bc}║{rc}")

        fnames = [r['name'] for r in records if r['layer'] == lay]
        line_buf = "  Fields: "
        field_lines = []
        for fn in fnames:
            candidate = line_buf + fn + "  "
            if len(candidate) > width - 2:
                field_lines.append(line_buf.rstrip())
                line_buf = "          " + fn + "  "
            else:
                line_buf = candidate
        if line_buf.strip():
            field_lines.append(line_buf.rstrip())
        for fl in field_lines:
            print(f"  {ind}{bc}║{rc}{C.DIM}{fl:<{width}}{rc}{bc}║{rc}")

        layer_bytes = frame[s:e+1]
        hex_preview = ' '.join(f'{b:02x}' for b in layer_bytes[:24])
        if len(layer_bytes) > 24: hex_preview += ' ..'
        hcontent = f"  Hex: {hex_preview}"
        print(f"  {ind}{bc}║{rc}{C.HEX}{hcontent:<{width}}{rc}{bc}║{rc}")
        print(f"  {ind}{bc}╚{'═'*width}╝{rc}")
        print()

    # Nesting summary
    dash = f"{C.SEP_C}{'─'*W2}{C.RESET}"
    print(f"  {dash}")
    print(f"  {C.BOLD}ENCAPSULATION SUMMARY  (outermost → innermost){C.RESET}")
    print(f"  {dash}")

    nesting = []
    for lay in sorted(layer_groups.keys()):
        if lay == 0: continue
        lc = _LAYER_COLOR.get(lay, "")
        proto = proto_names(lay)
        nesting.append(f"{lc}L{lay}({proto}){C.RESET}")
    arrow = f"  {C.BOX}──encapsulates──>{C.RESET}  "
    nesting_str = arrow.join(nesting)
    if 0 in layer_groups:
        s, e, _ = layer_groups[0]
        nesting_str += f"  {C.BOX}──trailer──>{C.RESET}  {C.TRAIL}FCS/CRC({e-s+1}B){C.RESET}"
    print(f"  {nesting_str}")
    print()

    for lay in sorted(layer_groups.keys(), key=lambda x: x if x != 0 else 99):
        s, e, _ = layer_groups[lay]
        lc    = _LAYER_COLOR.get(lay, "")
        lname = LAYER_LABELS.get(lay, f"Layer {lay}")
        print(f"    {lc}{lname:<55}{C.RESET}  "
              f"{C.SIZE}{e-s+1:4d} bytes  /  {(e-s+1)*8:5d} bits{C.RESET}  "
              f"{C.OFFSET}[byte {s}–{e}]{C.RESET}")

    print(f"  {dash}")
    print(f"  {C.BOLD}{'TOTAL FRAME':<55}  {total_bytes:4d} bytes  /  {total_bytes*8:5d} bits{C.RESET}")
    print(f"  {dash}")

    # Annotated hex dump
    LAYER_ABBR = {1:'PHY', 2:'DL ', 3:'NET', 4:'TRP', 0:'TRL'}
    byte_layer = {}
    for (s, e, lay, _) in layer_spans:
        for b in range(s, e+1):
            byte_layer[b] = lay

    print()
    print(f"  {dash}")
    print(f"  {C.BOLD}{'ANNOTATED HEX DUMP  (16 bytes per row)':^{W2}}{C.RESET}")
    print(f"  {dash}")
    print(f"  {C.DIM}{'Offset':>6}  {'Hex (16 bytes per row)':<48}  {'ASCII':<16}  Layer annotation{C.RESET}")
    print(f"  {dash}")

    for row_start in range(0, total_bytes, 16):
        row_bytes = frame[row_start:row_start+16]

        # Build coloured hex — each byte gets its layer colour
        hex_parts = []
        for i, byte_val in enumerate(row_bytes):
            bidx = row_start + i
            lc   = _LAYER_COLOR.get(byte_layer.get(bidx, -1), "")
            hex_parts.append(f"{lc}{byte_val:02x}{C.RESET}")
        hex_part = ' '.join(hex_parts)
        # pad to fixed width (48 visible chars = 16 bytes × 3 - 1 space)
        # we need to account for ANSI escape codes not counting as width
        visible_hex = ' '.join(f'{b:02x}' for b in row_bytes)
        pad = ' ' * (48 - len(visible_hex))

        asc_chars = []
        for i, byte_val in enumerate(row_bytes):
            bidx = row_start + i
            lc   = _LAYER_COLOR.get(byte_layer.get(bidx, -1), "")
            ch   = chr(byte_val) if 32 <= byte_val < 127 else '.'
            asc_chars.append(f"{lc}{ch}{C.RESET}")
        asc_part = ''.join(asc_chars)
        visible_asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row_bytes)
        asc_pad = ' ' * (16 - len(visible_asc))

        # Layer annotation
        layers_in_row = []
        for bidx in range(row_start, row_start + len(row_bytes)):
            lay = byte_layer.get(bidx, -1)
            if not layers_in_row or layers_in_row[-1][0] != lay:
                layers_in_row.append([lay, bidx, bidx])
            else:
                layers_in_row[-1][2] = bidx

        ann_parts = []
        for (lay, bs, be) in layers_in_row:
            lc   = _LAYER_COLOR.get(lay, "")
            abbr = LAYER_ABBR.get(lay, '???')
            ann_parts.append(f"{lc}{abbr}[{bs}-{be}]{C.RESET}")
        annotation = '  '.join(ann_parts)

        print(f"  {C.OFFSET}{row_start:6d}{C.RESET}  {hex_part}{pad}  {asc_part}{asc_pad}  {annotation}")

    print(f"  {dash}")

    # Final hex
    print()
    print(f"  {dash}")
    print(f"  {C.BOLD}{'FINAL HEX  (continuous, no gaps)':^{W2}}{C.RESET}")
    print(f"  {dash}")
    hex_str = ''.join(f'{b:02x}' for b in frame)
    # Print with layer-coloured groups
    offset_map = {}
    for (s, e, lay, _) in layer_spans:
        for b in range(s, e+1):
            offset_map[b] = lay
    # Build coloured hex string in 64-char rows
    coloured_hex = []
    prev_lay = None
    for bidx, b in enumerate(frame):
        lay = offset_map.get(bidx, -1)
        lc  = _LAYER_COLOR.get(lay, "")
        if lay != prev_lay:
            if prev_lay is not None:
                coloured_hex.append(C.RESET)
            coloured_hex.append(lc)
            prev_lay = lay
        coloured_hex.append(f'{b:02x}')
    if prev_lay is not None:
        coloured_hex.append(C.RESET)
    coloured_hex_str = ''.join(coloured_hex)

    # Print in rows of 64 visible hex chars (32 bytes)
    row_len = 64
    for i in range(0, len(hex_str), row_len):
        # Extract the coloured portion for this row
        # Simpler: recolour per row
        row_hex = []
        for bidx in range(i//2, min(i//2 + 32, len(frame))):
            lay = offset_map.get(bidx, -1)
            lc  = _LAYER_COLOR.get(lay, "")
            row_hex.append(f"{lc}{frame[bidx]:02x}{C.RESET}")
        print(f"  {''.join(row_hex)}")

    print(f"  {dash}")
    print(f"  {C.BOLD}Total bytes : {total_bytes}{C.RESET}")
    print(f"  {C.BOLD}Total bits  : {total_bytes * 8}{C.RESET}")
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
            if len(fcs) == 4: return fcs, "custom"
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
            if len(fcs) == len(fcs_auto): return fcs, f"{crc_type} custom"
        except: pass
        print(f"    {C.WARN}-> invalid, using auto{C.RESET}")
    return fcs_auto, f"{crc_type} auto over {len(crc_input_bytes)}B"

def verify_report(checks):
    dash = f"{C.SEP_C}{'─'*80}{C.RESET}"
    print(f"\n  {dash}")
    print(f"  {C.BOLD}CHECKSUM / CRC VERIFICATION{C.RESET}")
    print(f"  {dash}")
    for name, stored, result, passed in checks:
        if passed:
            status = f"{C.PASS_}PASS ✓{C.RESET}"
        else:
            status = f"{C.FAIL_}FAIL ✗{C.RESET}"
        print(f"  {C.DIM}{name:<30}{C.RESET}  "
              f"stored={C.HEX}{stored}{C.RESET}   "
              f"verify={C.HEX}{result}{C.RESET}   {status}")
    print(f"  {dash}")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — LAYER 1  (Physical)
# ══════════════════════════════════════════════════════════════════════════════
def ask_layer1_eth():
    """Preamble + SFD for Ethernet."""
    section("LAYER 1 — Physical (Preamble + SFD)")
    preamble = get_hex("Preamble  7 bytes (14 hex)", "55555555555555", 7,
        help="7 bytes of 0x55 transmitted before every Ethernet frame.\n"
             "Purpose: allows receiver hardware to synchronise its clock to the sender.\n"
             "Always 55 55 55 55 55 55 55 — changing this breaks clock recovery.")
    sfd = get_hex("SFD       1 byte  ( 2 hex)", "d5", 1,
        help="Start Frame Delimiter — 1 byte, always 0xD5 (10101011 in binary).\n"
             "Purpose: marks the EXACT boundary where the MAC frame begins.\n"
             "The receiver looks for 0xD5 after the preamble to start decoding.\n"
             "Changing this means no Ethernet NIC will recognise the frame.")
    return preamble, sfd

# ──────────────────────────────────────────────────────────────────────────────
#  WiFi PHY preamble builders
# ──────────────────────────────────────────────────────────────────────────────
def wifi_crc32(data: bytes) -> bytes:
    """802.11 FCS = CRC-32 same polynomial as Ethernet, little-endian."""
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
def build_dsss_plcp(mpdu_len_bytes, rate_byte, short_preamble=False):
    """
    Build 802.11b DSSS PLCP preamble.
    Returns (plcp_bytes, records).
    Long preamble:  SYNC(128b=16B) + SFD(2B) + SIGNAL(1B) + SERVICE(1B) + LENGTH(2B) + CRC(2B) = 24B
    Short preamble: SYNC(56b=7B)  + SFD(2B) + SIGNAL(1B) + SERVICE(1B) + LENGTH(2B) + CRC(2B) = 15B
    LENGTH field = MPDU duration in µs.
    """
    if short_preamble:
        sync    = bytes([0xFF] * 7)
        sfd_val = 0x05CF
        sync_note = "56-bit SYNC (7×0xFF) — short preamble scrambled 1s"
        sfd_note  = "0x05CF — 802.11b SHORT preamble SFD (frame boundary)"
        mode_note = "Short preamble (96µs total PLCP)"
    else:
        sync    = bytes([0xFF] * 16)
        sfd_val = 0xF3A0
        sync_note = "128-bit SYNC (16×0xFF) — long preamble scrambled 1s"
        sfd_note  = "0xF3A0 — 802.11b LONG preamble SFD (frame boundary)"
        mode_note = "Long preamble (192µs total PLCP)"

    sfd_b    = struct.pack("<H", sfd_val)
    signal_b = bytes([rate_byte])
    service_b= bytes([0x00])
    # LENGTH = MPDU duration in µs at the signalled rate
    # For simplicity, store MPDU byte length directly (standard uses µs but
    # most implementations interpret length bytes at the signalled rate)
    length_b = struct.pack("<H", mpdu_len_bytes & 0xFFFF)
    crc_input = bytes([rate_byte, 0x00]) + length_b
    crc_val  = crc16_ibm(crc_input)
    crc_b    = struct.pack("<H", crc_val)

    plcp = sync + sfd_b + signal_b + service_b + length_b + crc_b
    records = [
        {"layer":1, "name":"DSSS SYNC (preamble)",
         "raw": sync,     "user_val": f"0xFF×{len(sync)}",
         "note": sync_note},
        {"layer":1, "name":"DSSS SFD  ← FRAME BOUNDARY",
         "raw": sfd_b,    "user_val": f"0x{sfd_val:04X}",
         "note": sfd_note},
        {"layer":1, "name":"DSSS SIGNAL (rate)",
         "raw": signal_b, "user_val": f"0x{rate_byte:02X}",
         "note": f"Rate encoding — see SIGNAL table"},
        {"layer":1, "name":"DSSS SERVICE",
         "raw": service_b,"user_val": "0x00",
         "note": "Reserved in long preamble"},
        {"layer":1, "name":"DSSS LENGTH (MPDU µs/B)",
         "raw": length_b, "user_val": str(mpdu_len_bytes),
         "note": "MPDU length (bytes encoded as µs field)"},
        {"layer":1, "name":"DSSS PLCP CRC-16",
         "raw": crc_b,    "user_val": f"0x{crc_val:04X}",
         "note": f"CRC-16/IBM over SIGNAL+SERVICE+LENGTH  {mode_note}"},
    ]
    return plcp, records
def build_ofdm_lsig(mpdu_len_bytes, rate_bits, rate_label):
    """
    Build 802.11a/g L-SIG field (3 bytes / 24 bits).
    Bits [3:0]=RATE  [4]=Reserved  [16:5]=LENGTH  [17]=Parity  [23:18]=Tail
    Returned as 3 bytes (raw bit-packed, transmitted LSB-first in OFDM symbol).
    """
    length_field = mpdu_len_bytes & 0xFFF
    word = (rate_bits & 0xF) | (0 << 4) | (length_field << 5)
    # parity over bits 0..16
    parity = bin(word & 0x1FFFF).count('1') % 2
    word |= (parity << 17)
    # tail bits [23:18] = 000000 (already 0)
    lsig_bytes = struct.pack("<I", word)[:3]
    records = [
        {"layer":1, "name":"L-STF  (Short Training Field)",
         "raw": bytes(10), "user_val": "8µs OFDM symbols",
         "note": "10 symbols × 0.8µs — AGC + coarse freq sync  (not byte-representable)"},
        {"layer":1, "name":"L-LTF  (Long Training Field)",
         "raw": bytes(8),  "user_val": "8µs OFDM symbols",
         "note": "GI(1.6µs) + 2×LTF(3.2µs each) — fine channel estimation"},
        {"layer":1, "name":"L-SIG  ← FRAME BOUNDARY",
         "raw": lsig_bytes,"user_val": f"RATE={rate_bits:04b} LEN={mpdu_len_bytes}",
         "note": (f"{rate_label}  LEN={mpdu_len_bytes}B  Par={parity}  "
                  f"4µs OFDM symbol — marks MPDU start  [closest to SFD]")},
    ]
    return lsig_bytes, records  # we return only L-SIG bytes (STF/LTF are analog)
def build_ht_sig(mpdu_len_bytes, mcs, bw40, sgi, stbc, ldpc, rate_label):
    """
    Build 802.11n HT-SIG (2 × 24-bit fields = 6 bytes).
    HT-SIG1: MCS(7b)+BW(1b)+HT-LEN(16b)
    HT-SIG2: Smoothing+NotSounding+Reserved+Aggregation+STBC+FEC+SGI+NumExtSS+CRC+Tail
    """
    ht_len = mpdu_len_bytes & 0xFFFF
    sig1_word = (mcs & 0x7F) | ((1 if bw40 else 0) << 7) | (ht_len << 8)
    sig1 = struct.pack("<I", sig1_word)[:3]

    smooth=1; not_snd=1; aggr=0
    stbc_b=(1 if stbc else 0); fec=(1 if ldpc else 0); sgi_b=(1 if sgi else 0)
    sig2_lo = (smooth | (not_snd<<1) | (0<<2) | (aggr<<3) |
               (stbc_b<<4) | (fec<<5) | (sgi_b<<6) | (0<<7))
    crc_input = sig1 + bytes([sig2_lo])
    crc8 = 0xFF
    for byte in crc_input:
        for i in range(8):
            bit = (byte >> i) & 1
            fb  = ((crc8 >> 7) & 1) ^ bit
            crc8= ((crc8 << 1) & 0xFF) | 0
            if fb: crc8 ^= 0x07
    sig2 = bytes([sig2_lo, crc8 & 0xFF, 0x00])

    lsig_bytes, lsig_records = build_ofdm_lsig(mpdu_len_bytes, 0b1011, "6Mbps legacy")
    records = lsig_records + [
        {"layer":1, "name":"HT-SIG-1  (MCS+BW+Length)",
         "raw": sig1, "user_val": f"MCS{mcs} BW={'40' if bw40 else '20'}MHz LEN={ht_len}",
         "note": "8µs (2×4µs OFDM) — HT rate/length descriptor"},
        {"layer":1, "name":"HT-SIG-2  ← HT FRAME BOUNDARY",
         "raw": sig2, "user_val": f"SGI={int(sgi)} LDPC={int(ldpc)} STBC={int(stbc)}",
         "note": "HT-SIG-2 + CRC8+Tail — marks HT MPDU start (≈SFD for 802.11n)"},
        {"layer":1, "name":"HT-STF  (HT Short Training)",
         "raw": bytes(4), "user_val": "4µs", "note": "MIMO AGC adjustment"},
        {"layer":1, "name":"HT-LTF(s) (HT Long Training)",
         "raw": bytes(4), "user_val": f"4µs×NSS", "note": "Per-stream channel estimation"},
    ]
    return sig1 + sig2, records
def build_vht_sig(mpdu_len_bytes, mcs, nss, bw, sgi, ldpc):
    """Build 802.11ac VHT-SIG-A (2×24b) summary."""
    bw_map = {20:0, 40:1, 80:2, 160:3}
    bw_bits = bw_map.get(bw, 0)
    nss_b = (nss - 1) & 0x7
    siga1 = struct.pack("<I", bw_bits | (0<<2) | (1<<3) | (nss_b<<13))[:3]
    siga2 = struct.pack("<I", (mcs<<4) | (int(sgi)<<0) | (int(ldpc)<<2))[:3]
    lsig_bytes, lsig_records = build_ofdm_lsig(mpdu_len_bytes, 0b1011, "6Mbps legacy")
    records = lsig_records + [
        {"layer":1, "name":"VHT-SIG-A1  (BW+NSS+STBC)",
         "raw": siga1, "user_val": f"BW={bw}MHz NSS={nss}",
         "note": "8µs — VHT rate/NSS/BW descriptor"},
        {"layer":1, "name":"VHT-SIG-A2  ← VHT FRAME BOUNDARY",
         "raw": siga2, "user_val": f"MCS{mcs} SGI={int(sgi)} LDPC={int(ldpc)}",
         "note": "VHT-SIG-A2 — marks VHT MPDU start  (≈SFD for 802.11ac)"},
        {"layer":1, "name":"VHT-STF",
         "raw": bytes(4), "user_val": "4µs", "note": "MIMO AGC"},
        {"layer":1, "name":"VHT-LTF(s)",
         "raw": bytes(4), "user_val": f"4µs×{nss}", "note": "Per-stream channel est."},
        {"layer":1, "name":"VHT-SIG-B  (length per user)",
         "raw": bytes(3), "user_val": f"LEN={mpdu_len_bytes}", "note": "Per-user MPDU length"},
    ]
    return siga1 + siga2, records
def build_he_sig(mpdu_len_bytes, mcs, nss, bw, gi, ldpc):
    """Build 802.11ax HE-SIG-A summary."""
    bw_map = {20:0, 40:1, 80:2, 160:3}
    bw_bits = bw_map.get(bw, 0)
    nss_b = (nss-1) & 0x7
    hesa1 = struct.pack("<I", bw_bits | (0<<2) | (nss_b<<9))[:3]
    hesa2 = struct.pack("<I", (mcs<<4) | (int(ldpc)<<3) | (gi & 0x3))[:3]
    lsig_bytes, lsig_records = build_ofdm_lsig(mpdu_len_bytes, 0b1011, "6Mbps legacy")
    gi_names = {0:"0.8µs(Normal)", 1:"1.6µs(Double)", 2:"3.2µs(Quad)"}
    records = lsig_records + [
        {"layer":1, "name":"RL-SIG  (Repeated L-SIG)",
         "raw": lsig_bytes, "user_val": "repeat", "note": "Confirms HE frame to non-HE stations"},
        {"layer":1, "name":"HE-SIG-A1  (BW+BSS-Color+NSS)",
         "raw": hesa1, "user_val": f"BW={bw}MHz NSS={nss}",
         "note": "8µs — HE BSS colour, UL/DL, NSS"},
        {"layer":1, "name":"HE-SIG-A2  ← HE FRAME BOUNDARY",
         "raw": hesa2, "user_val": f"MCS{mcs} GI={gi_names.get(gi,'?')} LDPC={int(ldpc)}",
         "note": "HE-SIG-A2 — marks HE MPDU start  (≈SFD for 802.11ax)"},
        {"layer":1, "name":"HE-STF",
         "raw": bytes(4), "user_val": "4µs or 8µs", "note": "HE MIMO AGC"},
        {"layer":1, "name":"HE-LTF(s)",
         "raw": bytes(4), "user_val": f"4/8µs×{nss}", "note": "HE channel estimation"},
    ]
    return hesa1 + hesa2, records
def ask_wifi_phy(phy_ch, mpdu_len):
    """Ask PHY-specific parameters and return (phy_records)."""
    phy_records = []

    if phy_ch == '1':  # DSSS
        section("802.11b DSSS PLCP HEADER")
        print("    Long preamble (192µs) or Short preamble (96µs)?")
        sp = get("Short preamble? (y/n)", "n").lower().startswith("y")
        print("    SIGNAL (rate) byte:")
        for k,(rb,rd) in DSSS_RATES.items():
            print(f"      {k} = 0x{rb:02X}  {rd}")
        rate_ch = get("Rate", "4")
        rate_byte, rate_desc = DSSS_RATES.get(rate_ch, (0x6E, "11 Mbps CCK"))
        print(f"    -> Rate: {rate_desc}")
        _, phy_records = build_dsss_plcp(mpdu_len, rate_byte, sp)

    elif phy_ch in ('2','3'):  # OFDM 802.11a/g
        std = "802.11a (5GHz)" if phy_ch=='2' else "802.11g (2.4GHz)"
        section(f"{std} OFDM L-SIG  (legacy preamble: L-STF + L-LTF + L-SIG)")
        print("    L-SIG RATE field (MCS/rate code, 4 bits):")
        for k,(rb,rd) in OFDM_RATE_BITS.items():
            print(f"      {k:>2} Mbps = 0b{rb:04b}  {rd}")
        rate_ch = get("Data rate (Mbps)", "54")
        rate_bits, rate_label = OFDM_RATE_BITS.get(rate_ch, (0b1100, "54 Mbps"))
        print(f"    -> {rate_label}")
        print(f"    NOTE: L-STF (8µs) and L-LTF (8µs) are OFDM analog waveforms.")
        print(f"    They are NOT byte-representable. Shown as placeholder bytes below.")
        _, phy_records = build_ofdm_lsig(mpdu_len, rate_bits, rate_label)

    elif phy_ch == '4':  # HT 802.11n
        section("802.11n HT-MIXED PLCP  (L-STF + L-LTF + L-SIG + HT-SIG1 + HT-SIG2 + HT-STF + HT-LTF)")
        print("    MCS index (0=BPSK 1/2, 7=64QAM 5/6, 8-15=2-stream ...)")
        mcs  = int(get("MCS index (0-31)", "7")) & 0x1F
        bw40 = get("40 MHz bandwidth? (y/n)", "n").lower().startswith("y")
        sgi  = get("Short Guard Interval 400ns? (y/n)", "n").lower().startswith("y")
        stbc = get("STBC? (y/n)", "n").lower().startswith("y")
        ldpc = get("LDPC FEC? (y/n)", "n").lower().startswith("y")
        rate_label = f"MCS{mcs} {'HT40' if bw40 else 'HT20'} {'SGI' if sgi else 'LGI'}"
        _, phy_records = build_ht_sig(mpdu_len, mcs, bw40, sgi, stbc, ldpc, rate_label)

    elif phy_ch == '5':  # VHT 802.11ac
        section("802.11ac VHT PLCP  (L-STF+L-LTF+L-SIG+VHT-SIG-A+VHT-STF+VHT-LTF+VHT-SIG-B)")
        mcs = int(get("MCS index (0-9)", "9")) & 0xF
        nss = int(get("Number of Spatial Streams NSS (1-8)", "1"))
        bw  = int(get("Bandwidth  20/40/80/160 MHz", "80"))
        sgi = get("Short GI 400ns? (y/n)", "n").lower().startswith("y")
        ldpc= get("LDPC FEC? (y/n)", "n").lower().startswith("y")
        _, phy_records = build_vht_sig(mpdu_len, mcs, nss, bw, sgi, ldpc)

    elif phy_ch == '6':  # HE 802.11ax
        section("802.11ax HE PLCP  (L-STF+L-LTF+L-SIG+RL-SIG+HE-SIG-A+HE-STF+HE-LTF)")
        mcs = int(get("MCS index (0-11)", "11")) & 0xF
        nss = int(get("Number of Spatial Streams NSS (1-8)", "1"))
        bw  = int(get("Bandwidth  20/40/80/160 MHz", "80"))
        print("    Guard Interval:  0=0.8µs(Normal)  1=1.6µs  2=3.2µs")
        gi  = int(get("GI (0/1/2)", "0")) & 0x3
        ldpc= get("LDPC FEC? (y/n)", "n").lower().startswith("y")
        _, phy_records = build_he_sig(mpdu_len, mcs, nss, bw, gi, ldpc)

    # phy_ch == '7': no PHY, phy_records stays empty
    return phy_records

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — LAYER 2  (Data Link)
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  Ethernet MAC
# ──────────────────────────────────────────────────────────────────────────────
def ask_l2_ethernet(ethertype_hint="0800"):
    """Returns (dst_mac, src_mac, ethertype_bytes, llc_bytes, snap_bytes, variant_name)."""
    section("LAYER 2 — Ethernet / 802.3  (MAC Header)")

    print("    Variants:")
    print("      1 = Ethernet II        (EtherType >= 0x0600)")
    print("      2 = IEEE 802.3 Raw     (Length only)")
    print("      3 = IEEE 802.3 + LLC")
    print("      4 = IEEE 802.3 + LLC + SNAP")
    v = input("    Select variant [1]: ").strip() or '1'

    dst = get("Destination MAC", "ff:ff:ff:ff:ff:ff",
        help="6-byte MAC address of the RECEIVER of this frame.\n"
             "ff:ff:ff:ff:ff:ff = broadcast (all devices on segment receive it).\n"
             "Used by ARP, DHCP discover, STP — any frame for unknown/all targets.\n"
             "For unicast set to peer's actual MAC (e.g. 00:1A:2B:3C:4D:5E).")
    src = get("Source MAC", "00:11:22:33:44:55",
        help="6-byte MAC address of the SENDER (your interface).\n"
             "Must be your NIC's hardware address — used by the receiver to reply.\n"
             "First 3 bytes = OUI (manufacturer ID), last 3 = device serial.\n"
             "bit0 of byte0 = 1 means multicast source (invalid for normal frames).\n"
             "bit1 of byte0 = 1 means locally-administered (overriding factory MAC).")

    llc_b = b''; snap_b = b''

    if v == '1':
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2,
            help="2-byte protocol identifier telling the receiver what's inside the frame.\n"
                 "0x0800 = IPv4   0x0806 = ARP   0x86DD = IPv6   0x8100 = VLAN tag\n"
                 "0x8808 = MAC Control (Pause/PFC)   0x8809 = LACP   0x88CC = LLDP\n"
                 "Values >= 0x0600 = EtherType (Ethernet II).\n"
                 "Values < 0x0600 = 802.3 Length field (number of payload bytes).")
        variant_name = "Ethernet II"
        type_len_b = et
    elif v == '2':
        variant_name = "IEEE 802.3 Raw"
        type_len_b = None
    elif v == '3':
        variant_name = "IEEE 802.3 + LLC"
        dsap = get_hex("DSAP (2 hex)", "42", 1,
            help="Destination Service Access Point — 1 byte, identifies upper-layer protocol.\n"
                 "0x42 = STP/RSTP   0xAA = SNAP (use when you need EtherType inside 802.3)\n"
                 "0xFE = ISO Network Layer   0x00 = Null SAP")
        ssap = get_hex("SSAP (2 hex)", "42", 1,
            help="Source Service Access Point — 1 byte, same encoding as DSAP.\n"
                 "Identifies the sending protocol layer.  Usually matches DSAP.\n"
                 "0x42 = STP   0xAA = SNAP   0xFE = ISO")
        ctl  = get_hex("Control (2 hex)", "03", 1,
            help="LLC Control field — 1 byte (UI frame) or 2 bytes (I-frame/S-frame).\n"
                 "0x03 = UI (Unnumbered Information) — most common, connectionless.\n"
                 "0x7F = XID   0xE3 = TEST   Other values = numbered I/S frames.")
        llc_b = dsap + ssap + ctl
        type_len_b = None
    elif v == '4':
        variant_name = "IEEE 802.3 + LLC + SNAP"
        dsap = get_hex("DSAP (2 hex, SNAP=aa)", "aa", 1,
            help="For LLC+SNAP frames, DSAP must be 0xAA (SNAP indicator).\n"
                 "This tells the receiver that a 5-byte SNAP header follows the LLC header.")
        ssap = get_hex("SSAP (2 hex, SNAP=aa)", "aa", 1,
            help="For LLC+SNAP frames, SSAP must be 0xAA (SNAP indicator).\n"
                 "Same as DSAP — both 0xAA signals SNAP encapsulation.")
        ctl  = get_hex("Control (2 hex)", "03", 1,
            help="LLC Control = 0x03 (UI frame) for SNAP encapsulation.\n"
                 "Keep as 0x03 for normal data — other values are for LLC link management.")
        llc_b = dsap + ssap + ctl
        oui  = get_hex("SNAP OUI (6 hex)", "000000", 3,
            help="SNAP Organisationally Unique Identifier — 3 bytes.\n"
                 "0x000000 = Ethernet-bridged (most common — use with standard EtherTypes).\n"
                 "0x00000C = Cisco proprietary   0x080007 = AppleTalk")
        pid  = get_hex("SNAP Protocol ID (4 hex)", ethertype_hint, 2,
            help="SNAP Protocol ID — same as EtherType when OUI=0x000000.\n"
                 "0x0800=IPv4  0x0806=ARP  0x86DD=IPv6  0x8100=VLAN\n"
                 "This field lets 802.3 frames carry any protocol that Ethernet II can.")
        snap_b = oui + pid
        type_len_b = None
    else:
        v = '1'
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2)
        variant_name = "Ethernet II"
        type_len_b = et

    return mac_b(dst), mac_b(src), type_len_b, llc_b, snap_b, variant_name, dst, src, v
def assemble_eth_frame(l3_payload, l3_fields,
                       dst_mb, src_mb, type_len_b,
                       llc_b, snap_b, variant,
                       dst_s, src_s, v,
                       preamble, sfd):
    """
    Assemble Ethernet frame.
    type_len_b: pre-set (Ethernet II) or None (802.3, will be computed).
    Returns (full_frame_bytes, records_for_table).
    """
    if v in ('2','3','4'):
        # 802.3: length = LLC + SNAP + l3_payload
        length_val = len(llc_b) + len(snap_b) + len(l3_payload)
        tl = struct.pack('>H', length_val)
        tl_note = f"Length={length_val}B"
        tl_user = str(length_val)
    else:
        tl = type_len_b
        tl_note = f"EtherType 0x{tl.hex().upper()}"
        tl_user = f"0x{tl.hex().upper()}"

    mac_content = dst_mb + src_mb + tl + llc_b + snap_b + l3_payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    mac_frame  = mac_content + fcs
    full_frame = preamble + sfd + mac_frame

    # ── Build record list ──────────────────────────────────────────────────────
    records = [
        {"layer":1,"name":"Preamble",        "raw":preamble, "user_val":preamble.hex(), "note":"7×0x55"},
        {"layer":1,"name":"SFD",             "raw":sfd,      "user_val":sfd.hex(),      "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",         "raw":dst_mb,   "user_val":dst_s,          "note":""},
        {"layer":2,"name":"Src MAC",         "raw":src_mb,   "user_val":src_s,          "note":""},
        {"layer":2,"name":"Type / Length",   "raw":tl,       "user_val":tl_user,        "note":tl_note},
    ]
    if llc_b:
        records += [
            {"layer":2,"name":"LLC DSAP",    "raw":llc_b[0:1],"user_val":llc_b[0:1].hex(),"note":""},
            {"layer":2,"name":"LLC SSAP",    "raw":llc_b[1:2],"user_val":llc_b[1:2].hex(),"note":""},
            {"layer":2,"name":"LLC Control", "raw":llc_b[2:3],"user_val":llc_b[2:3].hex(),"note":""},
        ]
    if snap_b:
        records += [
            {"layer":2,"name":"SNAP OUI",    "raw":snap_b[0:3],"user_val":snap_b[0:3].hex(),"note":""},
            {"layer":2,"name":"SNAP PID",    "raw":snap_b[3:5],"user_val":snap_b[3:5].hex(),"note":""},
        ]
    records += l3_fields
    records.append({"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note})
    return full_frame, records

# ──────────────────────────────────────────────────────────────────────────────
#  Serial / WAN selector
# ──────────────────────────────────────────────────────────────────────────────
def ask_l2_serial():
    section("LAYER 2 — Serial / WAN  (choose protocol)")
    for k,v in SERIAL_TYPES.items():
        marker = "  ←  full 3-type builder" if k == '11' else ""
        print(f"      {k:>2} = {v}{marker}")
    ch = input("    Select [3]: ").strip() or '3'
    if ch not in SERIAL_TYPES: ch = '3'
    return ch, SERIAL_TYPES[ch]

# ──────────────────────────────────────────────────────────────────────────────
#  HDLC control field builders + address
# ──────────────────────────────────────────────────────────────────────────────
def print_hdlc_education():
    print(f"""
  {'═'*110}
  {'HDLC — HIGH-LEVEL DATA LINK CONTROL  (ISO 13239)':^110}
  {'THREE FRAME TYPES:  I-frame (data)  |  S-frame (supervisory)  |  U-frame (management)':^110}
  {'═'*110}

  FRAME STRUCTURE
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  │ Flag(1B) │ Address(1+B) │ Control(1-2B) │ Information(0+B) │ FCS(2-4B) │ Flag(1B) │
  │  0x7E   │  addr+EA     │  type+seq     │  user payload    │  CRC-16   │  0x7E   │
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  FCS covers: Address + Control + Information  (NOT the flags)

  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  FRAME TYPE 1 — I-FRAME (Information)     carries USER DATA with sequence numbering
  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  Purpose : Reliable data transfer using sliding-window ARQ (Go-Back-N or Selective Reject)
  Has Info: YES — carries user payload
  Control : 1 byte (mod-8) or 2 bytes (mod-128)

  MODULO-8 Control (1 byte):
  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
  │ N(S)│ N(S)│ N(S)│ P/F │ N(R)│ N(R)│ N(R)│  0  │
  │  b6 │  b5 │  b4 │  b3 │  b2 │  b1 │  b0 │ fix │
  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  N(S) bits [6:4] = send sequence 0–7
  P/F  bit  [3]   = Poll (command) or Final (response)
  N(R) bits [2:0] = receive seq (= next expected from peer, implicit ACK)
  Bit  [0]        = 0  (identifies I-frame)

  MODULO-128 Control (2 bytes):
  Byte 0:  N(S)(7 bits) + 0         Byte 1:  N(R)(7 bits) + P/F

  N(S)  Send Sequence Number — counts frames we have sent
  N(R)  Receive Sequence Number — confirms receipt of all frames up to N(R)-1

  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  FRAME TYPE 2 — S-FRAME (Supervisory)     flow and error control, NO data
  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  Purpose : ACK, NAK, flow control — no user payload
  Has Info: NO
  Control : 1 byte (mod-8) or 2 bytes (mod-128)

  Control byte:
  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
  │ N(R)│ N(R)│ N(R)│ P/F │  S1 │  S0 │  1  │  0  │
  │  b6 │  b5 │  b4 │  b3 │  b2 │  b1 │ fix │ fix │
  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  Bits [7:5]  N(R) receive sequence number
  Bit  [4]    P/F  Poll / Final
  Bits [3:2]  S1 S0  supervisory function:
              00=RR   Receive Ready       (ready + ACK up to N(R)-1)
              01=REJ  Reject              (go-back-N retransmit from N(R))
              10=RNR  Receive Not Ready   (busy — stop sending)
              11=SREJ Selective Reject    (retransmit only N(R))

  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  FRAME TYPE 3 — U-FRAME (Unnumbered)      link management and control, may carry data
  ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
  Purpose : Link setup/teardown, error reporting, unnumbered data (UI)
  Has Info: SOME subtypes (UI, XID, TEST, FRMR carry data)
  Control : Always 1 byte, NO sequence numbers

  Control byte:
  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
  │  M4 │  M3 │  M2 │ P/F │  M1 │  M0 │  1  │  1  │
  │  b7 │  b6 │  b5 │  b4 │  b3 │  b2 │ fix │ fix │
  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  Bits [7:5] M4..M2 + Bit[4] P/F + Bits[3:2] M1..M0

  Key U-frame types:
  Mnemonic  M4-M0    C/R  Purpose
  ────────  ───────  ───  ──────────────────────────────────────────────────────────
  UI        00000    C/R  Unnumbered Information — send data without numbering (UDP-like)
  SABM      01100    C    Set ABM mod-8  — establish connection (like TCP SYN)
  SABME     01101    C    Set ABM Extended mod-128 — establish with larger window
  DISC      01000    C    Disconnect — tear down link (like TCP FIN)
  UA        00101    R    Unnumbered ACK — accept SABM or DISC
  DM        00011    R    Disconnect Mode — I am not connected
  FRMR      10001    R    Frame Reject — peer sent an invalid frame
  XID       11000    C/R  Exchange ID — negotiate parameters
  TEST      11100    C/R  Test — verify link with echo

  ADDRESS FIELD  (EA = Extension Address bit, bit 0)
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
  0xFF  = Broadcast (all stations accept)
  0x01  = LAPB DTE command  /  0x03 = LAPB DCE command
  LAPD: SAPI(6b)+C/R(1b)+EA(1b)  then  TEI(7b)+EA(1b)  (2-byte address)
  EA bit = 1 means "this is the last address byte"

  FCS FIELD
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Default : CRC-16/CCITT  (2 bytes, polynomial 0x1021, init 0xFFFF)
  Extended: CRC-32  (4 bytes, same as Ethernet)
  Covers  : Address + Control + Information (NOT flags)
  {'═'*110}""")
def build_hdlc_control_i(ns, pf, nr, mod128=False):
    """Build I-frame control field. Returns bytes."""
    if mod128:
        b0 = ((ns & 0x7F) << 1) | 0
        b1 = ((nr & 0x7F) << 1) | (pf & 1)
        return bytes([b0, b1])
    else:
        b = ((ns & 0x7) << 4) | ((pf & 1) << 3) | ((nr & 0x7) << 0) | 0
        # I-frame: bit0=0
        # layout: N(S)[6:4] P/F[3] N(R)[2:0] 0
        b = ((ns & 0x7) << 5) | ((pf & 1) << 4) | ((nr & 0x7) << 1) | 0
        return bytes([b])
def build_hdlc_control_s(nr, pf, s1s0, mod128=False):
    """Build S-frame control field."""
    if mod128:
        b0 = 0x01 | ((s1s0 & 0x3) << 2)   # bits: xx SS 0 0 0 1
        b1 = ((nr & 0x7F) << 1) | (pf & 1)
        return bytes([b0, b1])
    else:
        b = ((nr & 0x7) << 5) | ((pf & 1) << 4) | ((s1s0 & 0x3) << 2) | 0x01
        return bytes([b])
def build_hdlc_control_u(m4m3m2, pf, m1m0):
    """Build U-frame control field (always 1 byte)."""
    b = ((m4m3m2 & 0x7) << 5) | ((pf & 1) << 4) | ((m1m0 & 0x3) << 2) | 0x03
    return bytes([b])
def ask_hdlc_address():
    section("HDLC ADDRESS FIELD")
    print("    0xFF = broadcast (all stations)  0x01 = LAPB DTE  0x03 = LAPB DCE")
    print("    For LAPD (ISDN): 2-byte address (SAPI+TEI)")
    print("    EA bit (bit 0): 1 = last address byte, 0 = more bytes follow")
    addr_type = get("Address type  1=1-byte  2=2-byte(LAPD)", "1")
    if addr_type == '2':
        print("    SAPI (6 bits 0–63), C/R bit (0/1)")
        sapi = int(get("SAPI (0=signalling, 63=LME)", "0")) & 0x3F
        cr   = int(get("C/R bit (0=response, 1=command)", "1")) & 1
        ea0  = 0   # not last byte
        byte0 = (sapi << 2) | (cr << 1) | ea0
        print("    TEI (7 bits 0–126, 127=broadcast)")
        tei  = int(get("TEI (Terminal Endpoint Identifier)", "0")) & 0x7F
        ea1  = 1   # last byte
        byte1 = (tei << 1) | ea1
        addr_bytes = bytes([byte0, byte1])
        addr_note  = f"SAPI={sapi} C/R={cr} TEI={tei} (LAPD 2-byte)"
    else:
        addr_hex = get("Address byte (hex, FF=broadcast)", "ff")
        try:    addr_byte = int(addr_hex, 16) & 0xFF
        except: addr_byte = 0xFF
        addr_bytes = bytes([addr_byte])
        addr_note  = "0xFF broadcast" if addr_byte==0xFF else f"0x{addr_byte:02X}"
    return addr_bytes, addr_note

# ──────────────────────────────────────────────────────────────────────────────
#  Pause Frame  (IEEE 802.3x)
# ──────────────────────────────────────────────────────────────────────────────
def print_pause_education():
    """Print the full educational header for Ethernet Pause Frame."""
    print(f"""
  {'═'*110}
  {'ETHERNET PAUSE FRAME  —  IEEE 802.3x  (MAC Flow Control)':^110}
  {'═'*110}

  PURPOSE
  ───────
  A Pause Frame asks the link partner to temporarily STOP sending data.
  Used for lossless flow control on full-duplex Ethernet links.
  Defined in IEEE 802.3x (now IEEE 802.3-2015, Clause 31).

  FIELD REFERENCE TABLE
  ─────────────────────────────────────────────────────────────────────────────────────────
  Byte  Field               Size    Fixed?  Value / Description
  ────  ──────────────────  ──────  ──────  ──────────────────────────────────────────────
     0  Preamble            7 B     Fixed   0x55 × 7   sync pattern for clock recovery
     7  SFD                 1 B     Fixed   0xD5        start of frame delimiter
     8  Dst MAC             6 B     Semi    01:80:C2:00:00:01  (IEEE reserved multicast)
                                             OR peer's unicast MAC (point-to-point)
    14  Src MAC             6 B     User    Sender's own MAC address
    20  EtherType           2 B     Fixed   0x8808  =  MAC Control EtherType
    22  MAC Ctrl Opcode     2 B     Fixed   0x0001  =  PAUSE  (only defined opcode)
    24  Pause Quanta        2 B     USER    0x0000–0xFFFF  ← THIS IS WHAT YOU SET
                                             0x0000 = resume immediately (cancel pause)
                                             0xFFFF = maximum pause (65535 quanta)
    26  Pad                42 B     Auto    0x00 × 42  (IEEE 802.3 minimum frame = 64 B)
    68  FCS                 4 B     Auto    CRC-32 over Dst MAC → Pad
  ─────────────────────────────────────────────────────────────────────────────────────────

  QUANTA TIMING  (1 quanta = 512 bit-times at link speed)
  ────────────────────────────────────────────────────────
  Link Speed   1 Quanta    0x0001    0x00FF    0x0FFF    0xFFFF (max)
  100 Mbps     5.120 µs    5.12 µs   1.31 ms  83.9 ms   335.5 ms
  1 Gbps       0.512 µs  512  ns   130.6 µs   8.39 ms    33.5 ms
  10 Gbps      0.051 µs   51.2 ns   13.1 µs   839  µs     3.35 ms
  25 Gbps      0.020 µs   20.5 ns    5.2 µs   335  µs     1.34 ms

  HOW TO USE PAUSE QUANTA
  ───────────────────────
  • Set quanta based on your buffer depth and link speed.
  • Rule of thumb:  quanta = (buffer_bytes × 8) / 512 bit-times
  • Send Pause(0xFFFF) first when buffer is critical.
  • Send Pause(0x0000) when buffer drains — cancels the pause early.
  • For 1 GbE switch with 32 KB buffer:  32768 × 8 / 512 = 512 quanta = 0x0200

  DESTINATION MAC CHOICE
  ──────────────────────
  01:80:C2:00:00:01  → IEEE reserved multicast  (NOT forwarded by switches)
  Peer unicast MAC   → Direct point-to-point pause (some NICs prefer this)

  NEGOTIATION REQUIREMENT
  ───────────────────────
  Both endpoints MUST have negotiated PAUSE capability (Auto-Negotiation base
  page bit C8=1).  If not negotiated, Pause frames are silently ignored.
  {'═'*110}""")
def ask_l2_pause():
    """Collect all Pause Frame inputs with per-field explanation."""
    section("LAYER 1  —  Physical  (Preamble + SFD)")
    preamble = get_hex("Preamble  7 B (14 hex)", "55555555555555", 7)
    sfd      = get_hex("SFD       1 B  (2 hex)", "d5", 1)

    section("LAYER 2  —  Ethernet MAC Header")
    print("    Dst MAC options:")
    print("      01:80:c2:00:00:01  — IEEE 802.3x reserved multicast (recommended)")
    print("      Peer unicast MAC   — direct point-to-point pause")
    dst_s = get("Dst MAC", "01:80:c2:00:00:01")
    src_s = get("Src MAC  (your interface MAC)", "00:11:22:33:44:55")

    section("MAC CONTROL  —  EtherType 0x8808 + Opcode")
    print("    EtherType : 0x8808  (fixed — MAC Control, IEEE 802.3)")
    print("    Opcode    : 0x0001  (fixed — PAUSE, the only defined MAC Ctrl opcode)")

    section("PAUSE QUANTA  —  Flow Control Value  (YOUR KEY INPUT)")
    print("    1 quanta = 512 bit-times at the link speed.")
    print("    Examples:")
    print("      0x0000 ( 0) = Cancel / Resume immediately")
    print("      0x0001 ( 1) = Minimal pause (512 bit-times)")
    print("      0x0200 (512) = ~262 µs @ 1 GbE  [typical for 32 KB buffer]")
    print("      0x00FF (255) = ~131 µs @ 1 GbE")
    print("      0xFFFF (65535) = Maximum pause")

    link = get("Link speed for quanta display  1=100M  2=1G  3=10G  4=25G", "2",
        help="Your link speed — used ONLY to calculate and display the pause duration.\n"
             "Does not change the frame bytes — just shows you how long the pause lasts.\n"
             "1 quanta = 512 bit-times at the link speed:\n"
             "  100 Mbps → 1 quanta = 5.12 µs\n"
             "  1 Gbps   → 1 quanta = 512 ns\n"
             "  10 Gbps  → 1 quanta = 51.2 ns")
    speed_map = {'1':100e6,'2':1e9,'3':10e9,'4':25e9}
    speed_bps = speed_map.get(link, 1e9)
    speed_label = {'1':'100 Mbps','2':'1 Gbps','3':'10 Gbps','4':'25 Gbps'}.get(link,'1 Gbps')

    quanta_hex = get("Pause Quanta  (hex, 0000–FFFF)", "00ff",
        help="THE key field of a Pause frame — 2 bytes (0x0000–0xFFFF).\n"
             "Tells the peer how long to STOP transmitting.\n"
             "Duration = Quanta × 512 bit-times at link speed.\n"
             "0x0000 = Resume immediately (cancel a previous pause).\n"
             "0x0001 = Minimal pause (512 bit-times).\n"
             "0x0200 = 512 quanta ≈ 262 µs @ 1 Gbps (typical for 32 KB buffer).\n"
             "0xFFFF = Maximum pause ≈ 33.5 ms @ 1 Gbps.\n"
             "Rule of thumb: quanta = (buffer_bytes × 8) / 512")
    try:
        quanta_val = int(quanta_hex.replace("0x",""), 16) & 0xFFFF
    except:
        quanta_val = 0x00FF
        print("    -> invalid, using 0x00FF")

    bit_time_s = 1.0 / speed_bps
    pause_bits  = quanta_val * 512
    pause_us    = (pause_bits * bit_time_s) * 1e6
    print(f"\n    ┌─────────────────────────────────────────────────────────────┐")
    print(f"    │  Quanta : {quanta_val:5d}  (0x{quanta_val:04X})                                  │")
    print(f"    │  Speed  : {speed_label:<10}                                     │")
    print(f"    │  Pause  : {quanta_val} × 512 = {pause_bits:,} bit-times                    │")
    print(f"    │  Time   : {pause_us:.3f} µs  ({pause_us/1000:.4f} ms)                       │")
    print(f"    └─────────────────────────────────────────────────────────────┘")

    section("PADDING  (auto-computed)")
    print("    IEEE 802.3 minimum frame body = 46 bytes (14B MAC header + 32B payload).")
    print("    Pause frame payload = opcode(2) + quanta(2) + pad(42) = 46 bytes.")
    print("    Padding is always 0x00 × 42. (auto-filled)")

    return preamble, sfd, dst_s, src_s, quanta_val
def build_pause(preamble, sfd, dst_s, src_s, quanta_val):
    """
    Build the complete Ethernet Pause Frame.
    Returns (full_frame_bytes, records_list).

    Frame structure:
    ─────────────────────────────────────────────────────────
    L1  Preamble (7B) + SFD (1B)
    L2  Dst MAC (6B) + Src MAC (6B) + EtherType 0x8808 (2B)
        + Opcode 0x0001 (2B) + Quanta (2B) + Pad 0x00×42 (42B)
    TR  FCS CRC-32 (4B)
    Total: 72 bytes on wire
    ─────────────────────────────────────────────────────────
    """
    et      = bytes.fromhex("8808")     # MAC Control EtherType
    opcode  = bytes.fromhex("0001")     # PAUSE opcode
    quanta  = struct.pack("!H", quanta_val)
    pad     = b'\x00' * 42             # pad to 64-byte minimum

    dst_mb  = mac_b(dst_s)
    src_mb  = mac_b(src_s)

    # FCS covers: Dst MAC → Pad (everything from byte 8 to end of pad)
    fcs_input = dst_mb + src_mb + et + opcode + quanta + pad
    fcs, fcs_note = ask_fcs_eth(fcs_input)

    full_frame = preamble + sfd + fcs_input + fcs

    records = [
        # ── Layer 1 ──────────────────────────────────────────────────────────
        {"layer":1, "name":"Preamble",
         "raw":preamble,
         "user_val":preamble.hex(),
         "note":"7 × 0x55  clock sync / delimiter"},

        {"layer":1, "name":"SFD  (Start Frame Delim)",
         "raw":sfd,
         "user_val":"0xD5",
         "note":"0xD5  marks start of MAC frame"},

        # ── Layer 2 — MAC Header ──────────────────────────────────────────────
        {"layer":2, "name":"Dst MAC  (Pause dest)",
         "raw":dst_mb,
         "user_val":dst_s,
         "note":"01:80:C2:00:00:01 = IEEE reserved multicast (not forwarded)"},

        {"layer":2, "name":"Src MAC  (sender)",
         "raw":src_mb,
         "user_val":src_s,
         "note":"Transmitting station's own MAC"},

        {"layer":2, "name":"EtherType  (MAC Control)",
         "raw":et,
         "user_val":"0x8808",
         "note":"Fixed: 0x8808 = IEEE 802.3 MAC Control"},

        # ── Layer 2 — MAC Control Payload ─────────────────────────────────────
        {"layer":2, "name":"MAC Ctrl Opcode  (PAUSE)",
         "raw":opcode,
         "user_val":"0x0001",
         "note":"Fixed: 0x0001 = PAUSE  (only defined MAC Ctrl opcode)"},

        {"layer":2, "name":"Pause Quanta  ← user value",
         "raw":quanta,
         "user_val":f"0x{quanta_val:04X}  ({quanta_val} decimal)",
         "note":f"Sender must halt for {quanta_val} × 512 bit-times"},

        {"layer":2, "name":"Pad  (min-frame filler)",
         "raw":pad,
         "user_val":"0x00 × 42",
         "note":"Auto: pads frame body to 46 B (IEEE 802.3 minimum)"},

        # ── Trailer ───────────────────────────────────────────────────────────
        {"layer":0, "name":"Ethernet FCS  (CRC-32)",
         "raw":fcs,
         "user_val":"auto/custom",
         "note":fcs_note},
    ]
    return full_frame, records

# ──────────────────────────────────────────────────────────────────────────────
#  PFC — Priority Flow Control  (IEEE 802.1Qbb)
# ──────────────────────────────────────────────────────────────────────────────
def print_pfc_education():
    print(f"""
  {'═'*110}
  {'PFC — PRIORITY FLOW CONTROL  (IEEE 802.1Qbb / DCB)':^110}
  {'═'*110}

  PURPOSE
  ───────
  PFC extends basic Pause (802.3x) to pause individual CoS priority queues
  independently.  Essential for Data Centre Bridging (DCB), RoCE, iSCSI, FCoE.
  Opcode 0x0101 (vs 0x0001 for basic Pause).  Same EtherType 0x8808.

  FIELD TABLE
  ─────────────────────────────────────────────────────────────────────────────────────────
  Byte  Field                    Size   Fixed?   Value / Description
  ────  ─────────────────────── ──────  ───────  ──────────────────────────────────────────
     0  Preamble                 7 B    Fixed    0x55 × 7
     7  SFD                      1 B    Fixed    0xD5
     8  Dst MAC                  6 B    Semi     01:80:C2:00:00:01 (MAC Control mcast)
    14  Src MAC                  6 B    User     Your interface MAC
    20  EtherType                2 B    Fixed    0x8808  (MAC Control)
    22  Opcode                   2 B    Fixed    0x0101  (PFC — distinguishes from 0x0001)
    24  Priority Enable Vector   2 B    USER ←  Bitmask: which priorities to pause
                                                  bit 0=P0  bit 1=P1  ...  bit 7=P7
    26  Quanta[P0]               2 B    USER     Pause quanta for Priority 0
    28  Quanta[P1]               2 B    USER     Pause quanta for Priority 1
    30  Quanta[P2]               2 B    USER     Pause quanta for Priority 2
    32  Quanta[P3]               2 B    USER     Pause quanta for Priority 3
    34  Quanta[P4]               2 B    USER     Pause quanta for Priority 4
    36  Quanta[P5]               2 B    USER     Pause quanta for Priority 5  (RoCE/iSCSI)
    38  Quanta[P6]               2 B    USER     Pause quanta for Priority 6
    40  Quanta[P7]               2 B    USER     Pause quanta for Priority 7
    42  Pad                     26 B    Auto     0x00 × 26  (pad to 64 B min)
    68  FCS                      4 B    Auto     CRC-32

  PRIORITY ENABLE VECTOR  (2 bytes — bit = 1 means pause that priority)
  ─────────────────────────────────────────────────────────────────────
  Bit  Priority  Typical Traffic
   0   P0        Best Effort / Default TCP
   1   P1        Background / Scavenger
   2   P2        Video Streaming
   3   P3        Critical Apps / Call Signalling
   4   P4        Video Conferencing
   5   P5        RoCE / iSCSI / NVMe-oF  ← lossless storage traffic
   6   P6        Internetwork Control (BGP/OSPF)
   7   P7        Network Control (STP/LLDP)

  Common examples:  0x0020=pause P5 only   0x00E0=pause P5+P6+P7   0x00FF=pause all
  {'═'*110}""")
def ask_l2_pfc():
    section("LAYER 1  —  Physical")
    preamble = get_hex("Preamble  7 B", "55555555555555", 7)
    sfd      = get_hex("SFD       1 B", "d5", 1)

    section("LAYER 2  —  Ethernet MAC Header")
    dst_s = get("Dst MAC  (MAC Ctrl multicast)", "01:80:c2:00:00:01")
    src_s = get("Src MAC  (your interface MAC)", "00:11:22:33:44:55")

    section("PFC CONTROL  —  Opcode 0x0101")
    print("    Priority Enable Vector: bitmask selecting which priorities to pause.")
    print("    Examples:  0x0020=P5(RoCE)  0x00E0=P5+P6+P7  0x00FF=all  0x0001=P0 only")
    vec_hex = get("Priority Enable Vector (hex 0000-00FF)", "0020",
        help="8-bit bitmask — each bit=1 means that priority queue is being PAUSED.\n"
             "Bit 0 = Priority 0 (Best Effort)    Bit 4 = Priority 4 (Video Conf)\n"
             "Bit 1 = Priority 1 (Background)     Bit 5 = Priority 5 (RoCE/iSCSI)\n"
             "Bit 2 = Priority 2 (Video)          Bit 6 = Priority 6 (Net Control)\n"
             "Bit 3 = Priority 3 (Critical Apps)  Bit 7 = Priority 7 (STP/LLDP)\n"
             "0x0020 = 0b00100000 = pause only Priority 5 (RoCE/iSCSI lossless traffic).\n"
             "0x00FF = pause all 8 priorities (same effect as basic Pause frame).\n"
             "0x00E0 = pause P5+P6+P7 (storage + control traffic).")
    try:    vec_val = int(vec_hex.replace("0x",""), 16) & 0x00FF
    except: vec_val = 0x0020

    # Show which priorities are enabled
    enabled = [i for i in range(8) if vec_val & (1 << i)]
    print(f"    -> Pausing priorities: {enabled if enabled else 'NONE'}")

    section("QUANTA PER PRIORITY  (2 bytes each, 0x0000 = not pausing)")
    prio_labels = ["P0 Best-Effort","P1 Background","P2 Video","P3 Critical-App",
                   "P4 Video-Conf ","P5 RoCE/iSCSI ","P6 Net-Control ","P7 STP/LLDP   "]
    quanta = []
    for i in range(8):
        enabled_marker = " ← ENABLED" if i in enabled else "  (0=no pause)"
        default = "00ff" if i in enabled else "0000"
        q_hex = get(f"Quanta[{i}]  {prio_labels[i]}{enabled_marker}", default)
        try:    q_val = int(q_hex.replace("0x",""), 16) & 0xFFFF
        except: q_val = 0x00FF if i in enabled else 0x0000
        quanta.append(q_val)

    return preamble, sfd, dst_s, src_s, vec_val, quanta
def build_pfc(preamble, sfd, dst_s, src_s, vec_val, quanta):
    et     = bytes.fromhex("8808")
    opcode = bytes.fromhex("0101")
    vec_b  = struct.pack("!H", vec_val)
    q_bytes = b''.join(struct.pack("!H", q) for q in quanta)
    pad    = b'\x00' * 26

    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)
    fcs_input = dst_mb + src_mb + et + opcode + vec_b + q_bytes + pad
    fcs, fcs_note = ask_fcs_eth(fcs_input)
    full_frame = preamble + sfd + fcs_input + fcs

    prio_labels = ["P0-BestEffort","P1-Background","P2-Video","P3-CriticalApp",
                   "P4-VideoConf","P5-RoCE/iSCSI","P6-NetCtrl","P7-STP/LLDP"]
    enabled = [i for i in range(8) if vec_val & (1 << i)]

    records = [
        {"layer":1,"name":"Preamble",              "raw":preamble, "user_val":preamble.hex(),   "note":"7×0x55"},
        {"layer":1,"name":"SFD",                   "raw":sfd,      "user_val":"0xD5",            "note":"Start Frame Delimiter"},
        {"layer":2,"name":"Dst MAC (MAC Ctrl mcast)","raw":dst_mb, "user_val":dst_s,            "note":"01:80:C2:00:00:01 IEEE reserved"},
        {"layer":2,"name":"Src MAC",               "raw":src_mb,   "user_val":src_s,            "note":"Sender interface MAC"},
        {"layer":2,"name":"EtherType (MAC Control)","raw":et,      "user_val":"0x8808",         "note":"Fixed: MAC Control"},
        {"layer":2,"name":"PFC Opcode",            "raw":opcode,   "user_val":"0x0101",         "note":"PFC (vs 0x0001=basic Pause)"},
        {"layer":2,"name":"Priority Enable Vector", "raw":vec_b,   "user_val":f"0x{vec_val:04X}",
         "note":f"Pause P{enabled} bitmask"},
    ]
    for i in range(8):
        records.append({
            "layer":2,
            "name":f"Quanta[P{i}] {prio_labels[i]}",
            "raw":struct.pack("!H", quanta[i]),
            "user_val":f"0x{quanta[i]:04X} ({quanta[i]})",
            "note":"PAUSED" if i in enabled and quanta[i]>0 else ("resume" if quanta[i]==0 and i in enabled else "not paused"),
        })
    records += [
        {"layer":2,"name":"Pad (min-frame filler)",  "raw":pad,   "user_val":"0x00×26","note":"26B pad to reach 64B minimum"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)",   "raw":fcs,   "user_val":"auto/custom","note":fcs_note},
    ]
    return full_frame, records

# ──────────────────────────────────────────────────────────────────────────────
#  LLDP — Link Layer Discovery Protocol  (IEEE 802.1AB)
# ──────────────────────────────────────────────────────────────────────────────
def print_lldp_education():
    print(f"""
  {'═'*110}
  {'LLDP — LINK LAYER DISCOVERY PROTOCOL  (IEEE 802.1AB)':^110}
  {'═'*110}

  PURPOSE
  ───────
  LLDP lets network devices advertise identity, capabilities, and management
  info to directly connected neighbours over L2.  Vendor-neutral (vs CDP/FDP).
  Each advertisement is sent as a sequence of TLVs (Type-Length-Value).

  TLV FORMAT  (every field in LLDP PDU uses this)
  ──────────────────────────────────────────────────────────────
  Bits 15-9 : TLV Type  (7 bits, 0-127)
  Bits  8-0 : TLV Length (9 bits, 0-511) = byte count of Value
  Bytes  ... : Value

  MANDATORY TLVs (in order)
  ─────────────────────────────────────────────────────────────────────────────
  Type  TLV Name             Subtypes / Value
  ────  ─────────────────── ─────────────────────────────────────────────────
    1   Chassis ID           Sub 4=MAC(6B)  Sub 5=NetAddr  Sub 7=LocalStr
    2   Port ID              Sub 3=MAC(6B)  Sub 5=IfName   Sub 7=LocalStr
    3   TTL                  0=remove-entry  120=default  65535=max
    0   End of LLDPDU        Length=0, must be LAST

  OPTIONAL TLVs
  ─────────────────────────────────────────────────────────────────────────────
  Type  TLV Name             Notes
  ────  ─────────────────── ─────────────────────────────────────────────────
    4   Port Description     ASCII string (e.g. "GigabitEthernet0/1")
    5   System Name          sysName (hostname)
    6   System Description   sysDescr (OS + version)
    7   System Capabilities  4B: supported(2B) + enabled(2B) bitmask
                               bit2=Bridge  bit4=Router  bit7=Station
    8   Management Address   AFI(1B)+Addr(var)+IfNumSubtype(1B)+IfNum(4B)+OID

  SYSTEM CAPABILITY BITS
  ───────────────────────────────────────────────────────
  Bit  0=Other  1=Repeater  2=Bridge  3=WLAN  4=Router
       5=Tel    6=DOCSIS    7=Station
  Example: Switch = 0x0004 supported + 0x0004 enabled
           Router = 0x0010 supported + 0x0010 enabled

  DESTINATION MAC
  ───────────────
  01:80:C2:00:00:0E  → LLDP dedicated multicast (IEEE 802.1AB)
  NOT forwarded by 802.1D bridges.
  {'═'*110}""")
def make_lldp_tlv(tlv_type, value_bytes):
    """Build a single LLDP TLV: 2-byte header (type<<9 | length) + value."""
    length = len(value_bytes)
    header = struct.pack("!H", (tlv_type << 9) | length)
    return header + value_bytes
def ask_l2_lldp():
    section("LAYER 1  —  Physical")
    preamble = get_hex("Preamble  7 B", "55555555555555", 7)
    sfd      = get_hex("SFD       1 B", "d5", 1)

    section("LAYER 2  —  Ethernet MAC Header")
    dst_s = get("Dst MAC  (LLDP multicast)", "01:80:c2:00:00:0e")
    src_s = get("Src MAC  (your interface MAC)", "00:11:22:33:44:55")

    # ── Mandatory TLV 1: Chassis ID ────────────────────────────────────────────
    section("TLV 1 — Chassis ID  (mandatory)")
    print("    Subtypes:  4=MAC address  5=Network address  7=Locally-assigned string")
    ch_sub = get("Chassis ID Subtype  (4=MAC / 7=string)", "4")
    if ch_sub == "4":
        ch_mac = get("Chassis MAC", src_s)
        chassis_val = bytes([4]) + mac_b(ch_mac)
    else:
        ch_str = get("Chassis ID string", "switch01")
        chassis_val = bytes([7]) + ch_str.encode()

    # ── Mandatory TLV 2: Port ID ────────────────────────────────────────────────
    section("TLV 2 — Port ID  (mandatory)")
    print("    Subtypes:  3=MAC address  5=Interface name  7=Locally-assigned string")
    po_sub = get("Port ID Subtype  (5=IfName / 7=string)", "5")
    if po_sub == "3":
        po_mac = get("Port MAC", src_s)
        port_val = bytes([3]) + mac_b(po_mac)
    elif po_sub == "5":
        po_str = get("Interface name", "GigabitEthernet0/1")
        port_val = bytes([5]) + po_str.encode()
    else:
        po_str = get("Port ID string", "port1")
        port_val = bytes([7]) + po_str.encode()

    # ── Mandatory TLV 3: TTL ───────────────────────────────────────────────────
    section("TLV 3 — TTL  (mandatory)")
    print("    0=remove entry immediately   120=default   65535=maximum")
    ttl_val = int(get("TTL (seconds)", "120",
        help="Time To Live — how long neighbours keep this LLDP entry before discarding it.\n"
             "120 = default (2 minutes) — enough for 4 missed 30-second hello intervals.\n"
             "0   = remove this entry immediately (used when device is shutting down).\n"
             "65535 = maximum — entry stays until manually cleared or device reboots.\n"
             "If a device stops sending LLDP, neighbours age out the entry after TTL seconds.")) & 0xFFFF
    ttl_bytes = struct.pack("!H", ttl_val)

    # ── Optional TLVs ──────────────────────────────────────────────────────────
    section("OPTIONAL TLVs")
    opt_tlvs = []

    # Port Description
    if get("Include Port Description TLV? (y/n)", "y").lower().startswith("y"):
        pd_str = get("Port Description", "GigabitEthernet0/1 to CoreSwitch")
        opt_tlvs.append(("Port Description", 4, pd_str.encode()))

    # System Name
    if get("Include System Name TLV? (y/n)", "y").lower().startswith("y"):
        sn_str = get("System Name (hostname)", "SW-ACCESS-01")
        opt_tlvs.append(("System Name", 5, sn_str.encode()))

    # System Description
    if get("Include System Description TLV? (y/n)", "y").lower().startswith("y"):
        sd_str = get("System Description", "Cisco IOS 15.2 Catalyst 2960")
        opt_tlvs.append(("System Description", 6, sd_str.encode()))

    # System Capabilities
    if get("Include System Capabilities TLV? (y/n)", "y").lower().startswith("y"):
        print("    Capability bits: 0x0002=Repeater  0x0004=Bridge  0x0010=Router  0x0080=Station")
        sup_hex = get("Supported capabilities (hex)", "0004")
        ena_hex = get("Enabled  capabilities (hex)", "0004")
        cap_bytes = hpad(sup_hex,2) + hpad(ena_hex,2)
        opt_tlvs.append(("System Capabilities", 7, cap_bytes))

    # Management Address
    if get("Include Management Address TLV? (y/n)", "y").lower().startswith("y"):
        mgmt_ip = get("Management IP address", "192.168.1.1")
        try:
            addr_bytes = b'\x05' + b'\x01' + ip_b(mgmt_ip)  # len=5, AFI=1(IPv4)
        except:
            addr_bytes = b'\x05\x01\xc0\xa8\x01\x01'
        # IfNum subtype=2 (ifIndex), ifIndex=1, OID len=0
        addr_bytes += b'\x02' + struct.pack("!I", 1) + b'\x00'
        opt_tlvs.append(("Management Address", 8, addr_bytes))

    return (preamble, sfd, dst_s, src_s,
            chassis_val, port_val, ttl_val, ttl_bytes,
            opt_tlvs)
def build_lldp(preamble, sfd, dst_s, src_s,
               chassis_val, port_val, ttl_val, ttl_bytes, opt_tlvs):
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)
    et = bytes.fromhex("88cc")

    # Build all TLVs
    tlv1 = make_lldp_tlv(1, chassis_val)
    tlv2 = make_lldp_tlv(2, port_val)
    tlv3 = make_lldp_tlv(3, ttl_bytes)
    end_tlv = make_lldp_tlv(0, b'')

    opt_built = []
    for (name, t, val) in opt_tlvs:
        opt_built.append((name, t, make_lldp_tlv(t, val)))

    lldpdu = tlv1 + tlv2 + tlv3
    for (_,_,tb) in opt_built:
        lldpdu += tb
    lldpdu += end_tlv

    fcs_input = dst_mb + src_mb + et + lldpdu
    fcs, fcs_note = ask_fcs_eth(fcs_input)
    full_frame = preamble + sfd + fcs_input + fcs

    records = [
        {"layer":1,"name":"Preamble",            "raw":preamble, "user_val":preamble.hex(),  "note":"7×0x55"},
        {"layer":1,"name":"SFD",                 "raw":sfd,      "user_val":"0xD5",           "note":""},
        {"layer":2,"name":"Dst MAC (LLDP mcast)","raw":dst_mb,   "user_val":dst_s,           "note":"01:80:C2:00:00:0E not forwarded"},
        {"layer":2,"name":"Src MAC",             "raw":src_mb,   "user_val":src_s,           "note":"Sender MAC"},
        {"layer":2,"name":"EtherType (LLDP)",    "raw":et,       "user_val":"0x88CC",        "note":"IEEE 802.1AB LLDP"},
        # TLV1
        {"layer":3,"name":"TLV1 Chassis-ID hdr", "raw":tlv1[:2], "user_val":"type=1",        "note":f"len={len(chassis_val)}B"},
        {"layer":3,"name":"TLV1 Chassis-ID val", "raw":chassis_val,"user_val":chassis_val.hex()[:20],"note":""},
        # TLV2
        {"layer":3,"name":"TLV2 Port-ID header", "raw":tlv2[:2], "user_val":"type=2",        "note":f"len={len(port_val)}B"},
        {"layer":3,"name":"TLV2 Port-ID value",  "raw":port_val, "user_val":port_val[1:].decode(errors='replace')[:20],"note":""},
        # TLV3
        {"layer":3,"name":"TLV3 TTL header",     "raw":tlv3[:2], "user_val":"type=3",        "note":"len=2B"},
        {"layer":3,"name":"TLV3 TTL value",      "raw":ttl_bytes,"user_val":str(ttl_val),    "note":"seconds"},
    ]
    for (name, t, tb) in opt_built:
        val_b = tb[2:]
        records.append({"layer":3,"name":f"TLV{t} {name} hdr","raw":tb[:2],"user_val":f"type={t}","note":f"len={len(val_b)}B"})
        records.append({"layer":3,"name":f"TLV{t} {name} val","raw":val_b,"user_val":val_b.decode(errors='replace')[:20] if t not in (7,8) else val_b.hex()[:20],"note":""})
    records += [
        {"layer":3,"name":"TLV0 End-of-LLDPDU", "raw":end_tlv,  "user_val":"0x0000",        "note":"type=0 len=0 mandatory last TLV"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,     "user_val":"auto/custom",   "note":fcs_note},
    ]
    return full_frame, records

# ──────────────────────────────────────────────────────────────────────────────
#  VLAN Tagged Frame  (IEEE 802.1Q)
# ──────────────────────────────────────────────────────────────────────────────
def print_vlan_education():
    print(f"""
  {'═'*110}
  {'VLAN TAGGED FRAME  —  IEEE 802.1Q  (VID + PCP + DEI)':^110}
  {'═'*110}

  PURPOSE
  ───────
  802.1Q inserts a 4-byte tag between Src MAC and EtherType, carrying:
    • VLAN ID (VID 0–4094) — which VLAN this frame belongs to
    • PCP (0–7) — CoS/QoS priority for queuing
    • DEI (0/1) — drop eligibility during congestion

  THE 4-BYTE 802.1Q TAG  (inserted at byte offset 12)
  ─────────────────────────────────────────────────────────────────────────────
  Bytes  Field          Size  Value
  ─────  ─────────────  ────  ──────────────────────────────────────────────────
   +0    TPID           2 B   0x8100  (standard)  0x88A8 (Q-in-Q outer)
   +2    PCP            3 b   Priority Code Point: 0–7 (CoS)
   +2    DEI            1 b   Drop Eligible Indicator: 0=keep  1=drop first
   +2    VID           12 b   VLAN ID: 0=untagged/prio  1=native  2–4094=user

  PCP PRIORITY TABLE
  ──────────────────────────────────────────────────────────────────────────────
  PCP  Name                 Typical Use
  ───  ─────────────────── ──────────────────────────────────────────────────
   0   Best Effort          Default TCP/IP traffic
   1   Background           Bulk transfers, backups
   2   Excellent Effort     Business-critical apps
   3   Critical Apps        Signalling, real-time apps
   4   Video                Video streaming (<100ms)
   5   Voice                VoIP RTP (<10ms)
   6   Internetwork Ctrl    BGP, OSPF routing protocols
   7   Network Control      STP, RSTP, LLDP

  DOUBLE TAGGING (Q-in-Q / 802.1ad)
  ──────────────────────────────────
  Outer tag  TPID=0x88A8  (S-Tag: Service/Provider tag)
  Inner tag  TPID=0x8100  (C-Tag: Customer tag)
  Allows Metro Ethernet to tunnel entire customer VLAN space inside provider VLAN.

  FRAME STRUCTURE COMPARISON
  ──────────────────────────────────────────────────────────────────────────────
  Untagged :  DstMAC(6) | SrcMAC(6) | EtherType(2) | Payload
  Tagged   :  DstMAC(6) | SrcMAC(6) | TPID(2) | TCI(2) | EtherType(2) | Payload
  Q-in-Q   :  DstMAC(6) | SrcMAC(6) | TPID_S(2) | TCI_S(2) | TPID_C(2) | TCI_C(2) | EtherType(2) | Payload
  {'═'*110}""")
def ask_l2_vlan():
    section("LAYER 1  —  Physical")
    preamble = get_hex("Preamble  7 B", "55555555555555", 7)
    sfd      = get_hex("SFD       1 B", "d5", 1)

    section("LAYER 2  —  Ethernet MAC Header")
    dst_s = get("Destination MAC", "ff:ff:ff:ff:ff:ff")
    src_s = get("Source MAC",      "00:11:22:33:44:55")

    section("802.1Q VLAN TAG")
    print("    TPID options:  0x8100=standard 802.1Q   0x88A8=Q-in-Q outer (802.1ad)")
    tpid_hex = get("TPID (hex)", "8100",
        help="Tag Protocol Identifier — 2 bytes, identifies this as a VLAN-tagged frame.\n"
             "0x8100 = standard IEEE 802.1Q VLAN tag (used on most access/trunk ports).\n"
             "0x88A8 = IEEE 802.1ad outer tag (S-Tag) for Provider/Metro Ethernet Q-in-Q.\n"
             "0x9100 = Cisco/older proprietary Q-in-Q outer tag (legacy).\n"
             "A frame without 0x8100 here is treated as untagged by 802.1Q-aware switches.")
    try:    tpid_val = int(tpid_hex.replace("0x",""), 16) & 0xFFFF
    except: tpid_val = 0x8100

    print("    PCP (Priority Code Point):  0=BestEffort  3=CritApps  5=Voice  7=NetCtrl")
    pcp = int(get("PCP  (0-7)", "0",
        help="Priority Code Point — 3 bits (0–7), sets CoS/QoS priority for this frame.\n"
             "0=Best Effort (default)  1=Background  2=Excellent Effort  3=Critical Apps\n"
             "4=Video (<100ms)  5=Voice (<10ms, VoIP RTP)  6=Internetwork Control  7=Network Control\n"
             "Switches use PCP to determine which queue to place this frame in.\n"
             "Higher number = higher priority = served first during congestion.")) & 0x7
    print("    DEI (Drop Eligible):  0=keep  1=may be dropped first during congestion")
    dei = int(get("DEI  (0 or 1)", "0",
        help="Drop Eligible Indicator — 1 bit.\n"
             "0 = this frame should be kept even under congestion (non-discard-eligible).\n"
             "1 = this frame may be dropped FIRST when switch buffers are filling up.\n"
             "Used with traffic policing — marked frames are sacrificed before unmarked ones.")) & 0x1
    print("    VID:  0=priority-only  1=native  2-4094=user VLANs  4095=reserved")
    vid = int(get("VID  (0-4094)", "100",
        help="VLAN Identifier — 12 bits (0–4094), assigns frame to a specific VLAN.\n"
             "0    = priority-tagged only (frame carries PCP but belongs to native VLAN).\n"
             "1    = default native VLAN (untagged ports usually belong to VLAN 1).\n"
             "2–4094 = user-defined VLANs (assign different VLANs to different segments).\n"
             "4095 = reserved, never used in practice.\n"
             "Frames with the wrong VID are dropped at the switch port.")) & 0x0FFF

    tci = (pcp << 13) | (dei << 12) | vid
    print(f"    -> TCI = 0x{tci:04X}  (PCP={pcp}  DEI={dei}  VID={vid})")

    section("DOUBLE TAGGING (Q-in-Q)?")
    double_tag = get("Add inner C-Tag (Q-in-Q)? (y/n)", "n").lower().startswith("y")
    inner_tpid_val = 0x8100
    inner_tci = 0x0001
    if double_tag:
        print("    Inner (C-Tag) — customer VLAN")
        inner_tpid_hex = get("Inner TPID (hex)", "8100")
        try: inner_tpid_val = int(inner_tpid_hex.replace("0x",""), 16) & 0xFFFF
        except: pass
        inner_pcp = int(get("Inner PCP (0-7)", "0")) & 0x7
        inner_dei = int(get("Inner DEI (0/1)", "0")) & 0x1
        inner_vid = int(get("Inner VID (0-4094)", "10")) & 0x0FFF
        inner_tci = (inner_pcp << 13) | (inner_dei << 12) | inner_vid
        print(f"    -> Inner TCI = 0x{inner_tci:04X}  (PCP={inner_pcp}  DEI={inner_dei}  VID={inner_vid})")

    section("INNER ETHERTYPE + PAYLOAD")
    print("    Common EtherTypes:  0800=IPv4  0806=ARP  86DD=IPv6  8100=another VLAN tag")
    inner_et_hex = get("Inner EtherType (hex)", "0800")
    try:    inner_et = hpad(inner_et_hex, 2)
    except: inner_et = bytes.fromhex("0800")

    print("    Inner payload hex  (leave empty for 46B zero pad)")
    payload_hex = get("Payload hex", "")
    try:    payload = bytes.fromhex(payload_hex.replace(" ",""))
    except: payload = b''
    # pad to minimum
    min_payload = 46 if not double_tag else 42
    if len(payload) < min_payload:
        payload = payload + b'\x00' * (min_payload - len(payload))

    return (preamble, sfd, dst_s, src_s,
            tpid_val, tci, pcp, dei, vid,
            double_tag, inner_tpid_val, inner_tci,
            inner_et, payload)
def build_vlan(preamble, sfd, dst_s, src_s,
               tpid_val, tci, pcp, dei, vid,
               double_tag, inner_tpid_val, inner_tci,
               inner_et, payload):
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)

    outer_tpid = struct.pack("!H", tpid_val)
    outer_tci_b = struct.pack("!H", tci)

    if double_tag:
        inner_tpid_b = struct.pack("!H", inner_tpid_val)
        inner_tci_b  = struct.pack("!H", inner_tci)
        tag_section  = outer_tpid + outer_tci_b + inner_tpid_b + inner_tci_b
    else:
        tag_section  = outer_tpid + outer_tci_b

    fcs_input = dst_mb + src_mb + tag_section + inner_et + payload
    fcs, fcs_note = ask_fcs_eth(fcs_input)
    full_frame = preamble + sfd + fcs_input + fcs

    pcp_names = {0:"BestEffort",1:"Background",2:"ExcellentEffort",3:"CriticalApps",
                 4:"Video",5:"Voice",6:"IntNetCtrl",7:"NetControl"}
    tpid_name = "802.1Q" if tpid_val==0x8100 else ("802.1ad Q-in-Q" if tpid_val==0x88A8 else f"0x{tpid_val:04X}")

    records = [
        {"layer":1,"name":"Preamble",             "raw":preamble,      "user_val":preamble.hex(),    "note":"7×0x55"},
        {"layer":1,"name":"SFD",                  "raw":sfd,           "user_val":"0xD5",             "note":""},
        {"layer":2,"name":"Dst MAC",              "raw":dst_mb,        "user_val":dst_s,             "note":""},
        {"layer":2,"name":"Src MAC",              "raw":src_mb,        "user_val":src_s,             "note":""},
        {"layer":2,"name":"TPID (outer tag)",     "raw":outer_tpid,    "user_val":f"0x{tpid_val:04X}","note":tpid_name},
        {"layer":2,"name":"TCI outer: PCP+DEI+VID","raw":outer_tci_b, "user_val":f"0x{tci:04X}",
         "note":f"PCP={pcp}({pcp_names.get(pcp,'')})  DEI={dei}  VID={vid}"},
    ]
    if double_tag:
        records += [
            {"layer":2,"name":"TPID (inner C-Tag)",  "raw":struct.pack("!H",inner_tpid_val),
             "user_val":f"0x{inner_tpid_val:04X}","note":"802.1Q inner"},
            {"layer":2,"name":"TCI inner: PCP+DEI+VID","raw":struct.pack("!H",inner_tci),
             "user_val":f"0x{inner_tci:04X}","note":f"VID={inner_tci & 0xFFF}"},
        ]
    records += [
        {"layer":2,"name":"Inner EtherType",      "raw":inner_et,      "user_val":inner_et.hex(),    "note":"payload type"},
        {"layer":3,"name":"Payload",              "raw":payload,       "user_val":payload.hex()[:24],"note":f"{len(payload)}B"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,           "user_val":"auto/custom",     "note":fcs_note},
    ]
    return full_frame, records

# ──────────────────────────────────────────────────────────────────────────────
#  Jumbo Frame  (vendor extension)
# ──────────────────────────────────────────────────────────────────────────────
def print_jumbo_education():
    print(f"""
  {'═'*110}
  {'JUMBO FRAME  —  Non-Standard Vendor Extension  (MTU > 1500 bytes)':^110}
  {'═'*110}

  PURPOSE
  ───────
  Jumbo frames carry larger payloads than the IEEE standard 1500-byte limit.
  No IEEE standard number — requires ALL devices on the path to be configured.

  SIZE PRESETS
  ─────────────────────────────────────────────────────────────────────────
  Preset  Max Payload   Total Frame   Common Use
  ──────  ───────────── ─────────────  ──────────────────────────────────────
    1     1500 B        1518 B         Standard Ethernet baseline
    2     1600 B        1618 B         Baby Giant — MPLS single-label overhead
    3     4470 B        4488 B         FDDI bridging over Ethernet
    4     9000 B        9018 B         Typical Jumbo — NFS, iSCSI, Ceph, HPC
    5     9216 B        9234 B         Extended Jumbo — many storage switches
    6    16110 B       16128 B         Super Jumbo — InfiniBand/HPC bridging
    7    custom        custom          Enter your own value

  EFFICIENCY GAIN  (1 Gbps link, 64-byte header overhead per frame)
  ──────────────────────────────────────────────────────────────────────
  MTU 1500B  → 1564B on wire →  639,846 frames/sec → 97.9% efficiency
  MTU 9000B  → 9064B on wire →  110,304 frames/sec → 99.3% efficiency
  Header savings: ~5.8× fewer frame-level interrupts and checksums

  REQUIREMENT
  ───────────
  Every NIC, switch port, and router interface on the path must be configured
  with matching jumbo MTU.  One misconfigured hop = silent drops.

  VLAN + JUMBO
  ────────────
  A VLAN tag adds 4 bytes to the frame but should NOT reduce payload space.
  Many switches support "9004-byte jumbo" to accommodate the extra 4 bytes.
  {'═'*110}""")
def ask_l2_jumbo():
    section("LAYER 1  —  Physical")
    preamble = get_hex("Preamble  7 B", "55555555555555", 7)
    sfd      = get_hex("SFD       1 B", "d5", 1)

    section("LAYER 2  —  Ethernet MAC Header")
    dst_s = get("Destination MAC", "00:aa:bb:cc:dd:ee")
    src_s = get("Source MAC",      "00:11:22:33:44:55")

    section("PAYLOAD SIZE — Jumbo MTU Selection")
    for k,(sz,desc) in JUMBO_PRESETS.items():
        print(f"    {k} = {sz:6d} B  —  {desc}")
    preset = get("Select preset", "4")
    if preset not in JUMBO_PRESETS: preset = '4'
    max_payload, preset_desc = JUMBO_PRESETS[preset]
    if preset == '7':
        max_payload = int(get("Custom MTU payload size (bytes)", "9000"))
        preset_desc = f"Custom {max_payload}B"

    print(f"\n    Selected: {max_payload}B payload ({preset_desc})")
    print(f"    Total frame will be: {8 + 14 + max_payload + 4}B on wire")

    section("ETHERTYPE + PAYLOAD")
    print("    EtherTypes:  0800=IPv4  86DD=IPv6  0806=ARP")
    et_hex = get("EtherType (hex)", "0800")
    try:    et = hpad(et_hex, 2)
    except: et = bytes.fromhex("0800")

    print(f"    Payload hex  (max {max_payload} bytes = {max_payload*2} hex chars)")
    print(f"    Leave blank for auto-fill with 0x00 up to {max_payload} bytes")
    payload_hex = get("Payload hex", "")
    try:    payload = bytes.fromhex(payload_hex.replace(" ",""))
    except: payload = b''

    if len(payload) < max_payload:
        print(f"    -> Padding payload to {max_payload}B with 0x00")
        payload = payload + b'\x00' * (max_payload - len(payload))
    elif len(payload) > max_payload:
        print(f"    -> Truncating to {max_payload}B")
        payload = payload[:max_payload]

    # Optional VLAN tag
    section("ADD 802.1Q VLAN TAG to Jumbo Frame?")
    add_vlan = get("Add VLAN tag? (y/n)", "n").lower().startswith("y")
    vlan_tag = b''
    vlan_note = ""
    if add_vlan:
        tpid_h = get("TPID (hex)", "8100")
        pcp  = int(get("PCP (0-7)", "0")) & 0x7
        dei  = int(get("DEI (0/1)", "0")) & 0x1
        vid  = int(get("VID (0-4094)", "100")) & 0x0FFF
        tci  = (pcp << 13) | (dei << 12) | vid
        try: tpid_v = int(tpid_h.replace("0x",""), 16) & 0xFFFF
        except: tpid_v = 0x8100
        vlan_tag  = struct.pack("!HH", tpid_v, tci)
        vlan_note = f"TPID=0x{tpid_v:04X} PCP={pcp} DEI={dei} VID={vid}"
        print(f"    -> VLAN tag: {vlan_tag.hex()}  ({vlan_note})")

    return preamble, sfd, dst_s, src_s, et, payload, vlan_tag, vlan_note, max_payload, preset_desc
def build_jumbo(preamble, sfd, dst_s, src_s, et, payload, vlan_tag, vlan_note, max_payload, preset_desc):
    dst_mb = mac_b(dst_s)
    src_mb = mac_b(src_s)

    fcs_input = dst_mb + src_mb + vlan_tag + et + payload
    fcs, fcs_note = ask_fcs_eth(fcs_input)
    full_frame = preamble + sfd + fcs_input + fcs

    records = [
        {"layer":1,"name":"Preamble",             "raw":preamble, "user_val":preamble.hex(),    "note":"7×0x55"},
        {"layer":1,"name":"SFD",                  "raw":sfd,      "user_val":"0xD5",             "note":""},
        {"layer":2,"name":"Dst MAC",              "raw":dst_mb,   "user_val":dst_s,             "note":""},
        {"layer":2,"name":"Src MAC",              "raw":src_mb,   "user_val":src_s,             "note":""},
    ]
    if vlan_tag:
        records.append({"layer":2,"name":"VLAN Tag (802.1Q)","raw":vlan_tag,"user_val":vlan_tag.hex(),"note":vlan_note})
    records += [
        {"layer":2,"name":"EtherType",            "raw":et,       "user_val":et.hex(),          "note":""},
        {"layer":3,"name":f"Jumbo Payload ({preset_desc})","raw":payload,
         "user_val":f"{len(payload)}B",  "note":f"Max MTU={max_payload}B (non-standard jumbo)"},
        {"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,      "user_val":"auto/custom",     "note":fcs_note},
    ]
    return full_frame, records

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — LAYER 3  (Network)
# ══════════════════════════════════════════════════════════════════════════════
def ask_l3_arp():
    section("LAYER 3 — ARP")
    hw_type    = get("Hardware Type (1=Ethernet)", "1",
        help="Identifies the link-layer (hardware) address type.\n"
             "1 = Ethernet (most common)   6 = IEEE 802 networks   15 = Frame Relay\n"
             "Wrong value: receiver discards the ARP or misinterprets addresses.")
    proto_type = get("Protocol Type hex (0800=IPv4)", "0800",
        help="Same as EtherType — identifies the network-layer protocol.\n"
             "0800 = IPv4 (standard)   86DD = IPv6   8100 = VLAN\n"
             "This tells ARP what kind of network address (IP) is being resolved.")
    hw_len     = get("HW Address Length", "6",
        help="Length of hardware (MAC) addresses in this packet, in bytes.\n"
             "6 = Ethernet MAC address (always 6 for Ethernet).\n"
             "Wrong value: receiver won't know where sender/target MACs end.")
    proto_len  = get("Protocol Address Length", "4",
        help="Length of network (IP) addresses in this packet, in bytes.\n"
             "4 = IPv4 address (always 4 for IPv4).   16 = IPv6 address.\n"
             "Wrong value: receiver reads wrong bytes as the IP address.")
    opcode     = get("Opcode  1=Request  2=Reply", "1",
        help="ARP operation code.\n"
             "1 = Request  — 'Who has IP X? Tell IP Y' (broadcast, target MAC = 00:00..)\n"
             "2 = Reply    — 'IP X is at MAC AA:BB:CC:DD:EE:FF' (unicast reply)\n"
             "3 = RARP Request   4 = RARP Reply (reverse ARP, rarely used today)")
    sender_ha  = get("Sender MAC", "00:11:22:33:44:55",
        help="MAC address of the device SENDING this ARP frame.\n"
             "In a Request: your own MAC.   In a Reply: your own MAC.\n"
             "Receiver uses this to update its ARP cache (IP→MAC mapping).")
    sender_pa  = get("Sender IP",  "192.168.1.10",
        help="IP address of the device SENDING this ARP frame (your IP).\n"
             "In a Request: your own IP.   In a Reply: your own IP.\n"
             "Gratuitous ARP: sender IP = target IP (announces your own IP).")
    target_ha  = get("Target MAC", "00:00:00:00:00:00",
        help="MAC address of the TARGET device.\n"
             "In a Request: 00:00:00:00:00:00 (unknown — that's why we're asking!).\n"
             "In a Reply: the MAC of the device that sent the original request.")
    target_pa  = get("Target IP",  "192.168.1.100",
        help="IP address you want to resolve to a MAC address.\n"
             "In a Request: the IP whose MAC you want to find.\n"
             "In a Reply: the IP of the original requester.\n"
             "Must match the IP being queried — receiver ignores non-matching replies.")
    return (hw_type, proto_type, hw_len, proto_len, opcode,
            sender_ha, sender_pa, target_ha, target_pa)
def build_arp(inputs):
    hw_type, proto_type, hw_len, proto_len, opcode, sha, spa, tha, tpa = inputs
    hdr  = struct.pack("!HHBBH",
               int(hw_type), int(proto_type, 16),
               int(hw_len), int(proto_len), int(opcode))
    body = mac_b(sha) + ip_b(spa) + mac_b(tha) + ip_b(tpa)
    raw  = hdr + body
    op_s = "Request" if opcode=="1" else "Reply" if opcode=="2" else opcode
    fields = [
        {"layer":3,"name":"ARP HW Type",       "raw":hdr[0:2],   "user_val":hw_type,    "note":"1=Ethernet"},
        {"layer":3,"name":"ARP Protocol Type", "raw":hdr[2:4],   "user_val":proto_type, "note":"0800=IPv4"},
        {"layer":3,"name":"ARP HW Addr Len",   "raw":hdr[4:5],   "user_val":hw_len,     "note":"bytes"},
        {"layer":3,"name":"ARP Proto Addr Len","raw":hdr[5:6],   "user_val":proto_len,  "note":"bytes"},
        {"layer":3,"name":"ARP Opcode",        "raw":hdr[6:8],   "user_val":opcode,     "note":op_s},
        {"layer":3,"name":"ARP Sender MAC",    "raw":body[0:6],  "user_val":sha,        "note":""},
        {"layer":3,"name":"ARP Sender IP",     "raw":body[6:10], "user_val":spa,        "note":""},
        {"layer":3,"name":"ARP Target MAC",    "raw":body[10:16],"user_val":tha,        "note":""},
        {"layer":3,"name":"ARP Target IP",     "raw":body[16:20],"user_val":tpa,        "note":""},
    ]
    return raw, fields
def ask_l3_ipv4():
    section("LAYER 3 — IPv4  (Source + Destination)")
    print(f"    {C.NOTE}You can enter an IPv4 address OR a domain name for each IP.{C.RESET}")
    print(f"    {C.DIM}Domain names are resolved via your system DNS (requires internet).{C.RESET}")

    src_raw = get("Source IP or domain", "192.168.1.10",
        help="IPv4 address OR domain name of the SENDER.\n"
             "Examples: 192.168.1.10  or  myserver.local  or  eth0.example.com\n"
             "Private ranges: 10.x.x.x / 172.16-31.x.x / 192.168.x.x")
    try:
        src_ip, src_dom = _resolve_host(src_raw.strip())
        if src_dom:
            print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{src_dom}{C.RESET}  →  {C.HEX}{src_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{src_raw}': {e} — using as-is{C.RESET}")
        src_ip, src_dom = src_raw.strip(), ""

    dst_raw = get("Destination IP or domain", "192.168.1.20",
        help="IPv4 address OR domain name of the RECEIVER.\n"
             "Examples: 8.8.8.8  or  google.com  or  example.org\n"
             "Domain resolved to IPv4 — IPv6-only domains may fail.")
    try:
        dst_ip, dst_dom = _resolve_host(dst_raw.strip())
        if dst_dom:
            print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{dst_dom}{C.RESET}  →  {C.HEX}{dst_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{dst_raw}': {e} — using as-is{C.RESET}")
        dst_ip, dst_dom = dst_raw.strip(), ""

    ttl   = get("TTL", "64",
        help="Time To Live — decremented by 1 at each router hop.\n"
             "Packet discarded when TTL reaches 0 (prevents routing loops).\n"
             "64 = Linux/Mac default.   128 = Windows default.   255 = maximum.\n"
             "Low TTL (e.g. 1) = traceroute trick to get ICMP Time Exceeded back.")
    ip_id = get("Identification (decimal)", "4660",
        help="16-bit identifier for this packet (0–65535).\n"
             "All fragments of the same original packet share the same ID.\n"
             "For non-fragmented packets, value is arbitrary (OS usually increments it).")
    dscp  = get("DSCP/ECN (decimal, usu. 0)", "0",
        help="Differentiated Services Code Point + ECN (6+2 bits = 1 byte).\n"
             "0=Best Effort  8=CS1(low)  46=EF(voice/VoIP)  48=CS6(routing protocols)")
    df    = get("DF flag? (y/n)", "y",
        help="Don't Fragment bit in the IP Flags field.\n"
             "y = DF=1: routers MUST NOT fragment this packet.\n"
             "    Required for Path MTU Discovery (PMTUD) to work correctly.\n"
             "n = DF=0: routers may fragment if needed (legacy behaviour).")

    return src_ip, dst_ip, int(ttl), int(ip_id), int(dscp), df.lower().startswith('y'), 0, src_dom, dst_dom


def build_ipv4(l4_payload, src_ip, dst_ip, ttl, ip_id, dscp, df, proto_num):
    flags_frag = 0x4000 if df else 0x0000
    ver_ihl    = (4 << 4) | 5
    tot_len    = 20 + len(l4_payload)
    hdr0 = struct.pack("!BBHHHBBH4s4s",
               ver_ihl, dscp, tot_len, ip_id, flags_frag,
               ttl, proto_num, 0, ip_b(src_ip), ip_b(dst_ip))
    ck = inet_cksum(hdr0)
    hdr = struct.pack("!BBHHHBBH4s4s",
               ver_ihl, dscp, tot_len, ip_id, flags_frag,
               ttl, proto_num, ck, ip_b(src_ip), ip_b(dst_ip))

    flag_s = ("DF" if flags_frag & 0x4000 else "") + ("MF" if flags_frag & 0x2000 else "")
    proto_s = L3_PROTO_NAMES.get(proto_num, str(proto_num))

    fields = [
        {"layer":3,"name":"IP Version + IHL",    "raw":hdr[0:1],  "user_val":"4 / 5",    "note":"IPv4, 20B header"},
        {"layer":3,"name":"IP DSCP/ECN",          "raw":hdr[1:2],  "user_val":str(dscp),  "note":""},
        {"layer":3,"name":"IP Total Length",      "raw":hdr[2:4],  "user_val":"auto",     "note":f"{tot_len}B (20+{len(l4_payload)})"},
        {"layer":3,"name":"IP Identification",    "raw":hdr[4:6],  "user_val":str(ip_id), "note":f"0x{ip_id:04x}"},
        {"layer":3,"name":"IP Flags + FragOffset","raw":hdr[6:8],  "user_val":flag_s or "none", "note":"frag offset=0"},
        {"layer":3,"name":"IP TTL",               "raw":hdr[8:9],  "user_val":str(ttl),   "note":"hops"},
        {"layer":3,"name":"IP Protocol",          "raw":hdr[9:10], "user_val":str(proto_num), "note":proto_s},
        {"layer":3,"name":"IP Header Checksum",   "raw":hdr[10:12],"user_val":"auto",     "note":f"0x{ck:04x} RFC791"},
        {"layer":3,"name":"IP Source Address",    "raw":hdr[12:16],"user_val":src_ip,     "note":""},
        {"layer":3,"name":"IP Destination Addr",  "raw":hdr[16:20],"user_val":dst_ip,     "note":""},
    ]
    return hdr, fields, ck
def ask_l3_stp():
    section("LAYER 3 — STP / RSTP BPDU")
    version   = get("Version  0=STP  2=RSTP", "2",
        help="BPDU protocol version.\n"
             "0 = STP (802.1D original) — slow convergence, 30–50 seconds.\n"
             "2 = RSTP (802.1w/802.1D-2004) — fast convergence, <1 second.\n"
             "3 = MSTP (802.1s) — multiple spanning tree instances.")
    bpdu_type = get("BPDU Type  00=Config  80=TCN", "00",
        help="Type of BPDU message.\n"
             "00 = Configuration BPDU — normal periodic hello from root/designated bridge.\n"
             "80 = Topology Change Notification — alert that topology has changed.\n"
             "02 = RSTP BPDU (used when version=2).")
    flags     = get("Flags (hex)", "00",
        help="8-bit flags field (more important in RSTP).\n"
             "Bit 0: Topology Change   Bit 7: Topology Change Acknowledgment\n"
             "RSTP adds bits 1-6: Proposal, Port Role (2b), Learning, Forwarding, Agreement.\n"
             "0x00 = no flags set.   0x3C = RSTP Designated port, Learning+Forwarding.")
    root_prio = get("Root Priority", "32768",
        help="Priority component of the Root Bridge ID (0–61440, steps of 4096).\n"
             "Bridge with LOWEST Bridge ID becomes Root Bridge.\n"
             "Bridge ID = Priority(2B) + MAC(6B).  Lower priority = more likely to be root.\n"
             "Default: 32768.   Set 4096 to force a switch to become root.")
    root_mac  = get("Root MAC", "00:00:00:00:00:00",
        help="MAC address component of the Root Bridge ID.\n"
             "Together with Root Priority, uniquely identifies the root bridge.\n"
             "Lower MAC wins ties in priority.  Set to the actual root switch's MAC.")
    path_cost = get("Root Path Cost", "0",
        help="Total accumulated cost of the path from THIS bridge to the Root Bridge.\n"
             "0 = this bridge IS the root (or directly connected to root with 0 cost).\n"
             "Cost depends on link speed: 100Mbps=19  1Gbps=4  10Gbps=2  100Gbps=1\n"
             "Bridges use lowest path cost to choose which port faces the root.")
    br_prio   = get("Bridge Priority", "32768",
        help="Priority component of THIS bridge's own Bridge ID.\n"
             "Used to elect Designated Bridge on each segment.\n"
             "Same encoding as Root Priority (steps of 4096, default 32768).")
    br_mac    = get("Bridge MAC", "00:11:22:33:44:55",
        help="MAC address of THIS bridge (the switch sending this BPDU).\n"
             "Together with Bridge Priority, forms the Bridge ID of the sender.")
    port_id   = get("Port ID (hex)", "8001",
        help="2-byte Port ID: Priority(1B, default 0x80) + Port Number(1B).\n"
             "0x8001 = priority 128, port 1.   0x8002 = priority 128, port 2.\n"
             "Used to break ties when two ports of same bridge connect to same segment.")
    msg_age   = get("Message Age (sec)", "0",
        help="Age of this BPDU since it was generated by the root bridge.\n"
             "0 = generated by the root itself.   Incremented by 1 at each bridge hop.\n"
             "When Message Age >= Max Age (20s), BPDU is discarded as stale.")
    max_age   = get("Max Age (sec)", "20",
        help="Maximum time a bridge stores a BPDU before discarding it (default 20s).\n"
             "If no BPDU received within Max Age, bridge assumes root has failed.\n"
             "Increasing this slows failover.  Decreasing speeds it up but risks instability.")
    hello     = get("Hello Time (sec)", "2",
        help="Interval between Configuration BPDUs sent by the Root Bridge (default 2s).\n"
             "Root sends a hello every 2 seconds to prove it's still alive.\n"
             "Reducing this speeds up failure detection but increases traffic.")
    fwd_delay = get("Forward Delay (sec)", "15",
        help="Time spent in Listening and Learning states before moving to Forwarding (default 15s).\n"
             "Total transition time = 2 × Forward Delay = 30 seconds for classic STP.\n"
             "Prevents temporary loops during topology changes.\n"
             "RSTP replaces this with handshake-based fast transition (ignores this field).")
    return (version, bpdu_type, flags, root_prio, root_mac, path_cost,
            br_prio, br_mac, port_id, msg_age, max_age, hello, fwd_delay)
def build_stp(inputs):
    (version, bpdu_type, flags, root_prio, root_mac, path_cost,
     br_prio, br_mac, port_id, msg_age, max_age, hello, fwd_delay) = inputs

    root_id = struct.pack("!H", int(root_prio)) + mac_b(root_mac)
    br_id   = struct.pack("!H", int(br_prio))   + mac_b(br_mac)
    bpdu = (bytes.fromhex("0000") +
            hpad(version,1) + hpad(bpdu_type,1) + hpad(flags,1) +
            root_id + struct.pack("!I", int(path_cost)) + br_id +
            hpad(port_id,2) +
            struct.pack("!HHHH",
                int(msg_age)*256, int(max_age)*256,
                int(hello)*256,   int(fwd_delay)*256))
    fields = [
        {"layer":3,"name":"BPDU Protocol ID",  "raw":bpdu[0:2],  "user_val":"0x0000","note":"always 0"},
        {"layer":3,"name":"BPDU Version",       "raw":bpdu[2:3],  "user_val":version, "note":"0=STP 2=RSTP"},
        {"layer":3,"name":"BPDU Type",          "raw":bpdu[3:4],  "user_val":bpdu_type,"note":"00=Config 80=TCN"},
        {"layer":3,"name":"BPDU Flags",         "raw":bpdu[4:5],  "user_val":flags,   "note":""},
        {"layer":3,"name":"BPDU Root ID",       "raw":bpdu[5:13], "user_val":f"prio={root_prio} mac={root_mac}","note":"8B"},
        {"layer":3,"name":"BPDU Root Path Cost","raw":bpdu[13:17],"user_val":path_cost,"note":""},
        {"layer":3,"name":"BPDU Bridge ID",     "raw":bpdu[17:25],"user_val":f"prio={br_prio} mac={br_mac}","note":"8B"},
        {"layer":3,"name":"BPDU Port ID",       "raw":bpdu[25:27],"user_val":port_id, "note":""},
        {"layer":3,"name":"BPDU Message Age",   "raw":bpdu[27:29],"user_val":msg_age, "note":"sec"},
        {"layer":3,"name":"BPDU Max Age",       "raw":bpdu[29:31],"user_val":max_age, "note":"sec"},
        {"layer":3,"name":"BPDU Hello Time",    "raw":bpdu[31:33],"user_val":hello,   "note":"sec"},
        {"layer":3,"name":"BPDU Forward Delay", "raw":bpdu[33:35],"user_val":fwd_delay,"note":"sec"},
    ]
    return bpdu, fields
def ask_l3_dtp():
    section("LAYER 3 — DTP  (Dynamic Trunking Protocol)")
    print("    Modes:  02=desirable  03=auto  04=on  05=off")
    mode = get("DTP Mode (hex)", "02",
        help="DTP (Dynamic Trunking Protocol) port trunking mode.\n"
             "02=desirable: actively tries to form a trunk with the other end.\n"
             "03=auto: will become a trunk only if the other end is desirable/on.\n"
             "04=on: unconditionally trunks (regardless of other end's mode).\n"
             "05=off: unconditionally access port (no trunking).\n"
             "Cisco proprietary — disable with 'switchport nonegotiate' for security.")
    return mode
def build_dtp(mode):
    snap    = bytes.fromhex("00000c0104")
    payload = b"\x01\x03\x01" + hpad(mode,1) + b"\x00"*26
    mode_s  = {"02":"desirable","03":"auto","04":"on","05":"off"}.get(mode, f"0x{mode}")
    fields  = [
        {"layer":3,"name":"DTP SNAP OUI",  "raw":snap[0:3],    "user_val":"00000c","note":"Cisco"},
        {"layer":3,"name":"DTP SNAP PID",  "raw":snap[3:5],    "user_val":"0104",  "note":"DTP"},
        {"layer":3,"name":"DTP Version",   "raw":payload[0:1], "user_val":"1",     "note":""},
        {"layer":3,"name":"DTP Flags",     "raw":payload[1:2], "user_val":"03",    "note":""},
        {"layer":3,"name":"DTP Domain",    "raw":payload[2:3], "user_val":"01",    "note":""},
        {"layer":3,"name":"DTP Mode",      "raw":payload[3:4], "user_val":mode,    "note":mode_s},
        {"layer":3,"name":"DTP Pad",       "raw":payload[4:],  "user_val":"0x00*26","note":""},
    ]
    return snap + payload, fields
def ask_l3_pagp():
    section("LAYER 3 — PAgP  (Port Aggregation Protocol)")
    print("    Port State flags: 0x01=Active 0x04=Consistent 0x05=Active+Consistent")
    state = get("Port State (hex)", "05",
        help="PAgP (Port Aggregation Protocol) port state bitmask.\n"
             "0x01=Active: port is willing to form a channel.\n"
             "0x04=Consistent: port parameters match the group.\n"
             "0x05=Active+Consistent: normal operating state for channel member.\n"
             "0x00=Inactive: port not participating in channel aggregation.\n"
             "Cisco proprietary — IEEE equivalent is LACP (option 8).")
    return state
def build_pagp(state):
    snap    = bytes.fromhex("00000c0104")
    payload = (b"\x01\x01" + bytes.fromhex("8001") +
               bytes.fromhex("00000001") + hpad(state,1) + b"\x00"*25)
    fields = [
        {"layer":3,"name":"PAgP SNAP OUI",    "raw":snap[0:3],    "user_val":"00000c","note":"Cisco"},
        {"layer":3,"name":"PAgP SNAP PID",    "raw":snap[3:5],    "user_val":"0104",  "note":"PAgP"},
        {"layer":3,"name":"PAgP Version",     "raw":payload[0:1], "user_val":"1",     "note":""},
        {"layer":3,"name":"PAgP Flags",       "raw":payload[1:2], "user_val":"01",    "note":""},
        {"layer":3,"name":"PAgP Port ID",     "raw":payload[2:4], "user_val":"8001",  "note":""},
        {"layer":3,"name":"PAgP System ID",   "raw":payload[4:8], "user_val":"00000001","note":""},
        {"layer":3,"name":"PAgP Port State",  "raw":payload[8:9], "user_val":state,   "note":""},
        {"layer":3,"name":"PAgP Pad",         "raw":payload[9:],  "user_val":"0x00*25","note":""},
    ]
    return snap + payload, fields
def ask_l3_lacp():
    section("LAYER 3 — LACP  (802.3ad Link Aggregation)")
    actor_mac   = get("Actor System MAC",  "00:11:22:33:44:55",
        help="MAC address of THIS switch/NIC participating in LACP.\n"
             "Forms part of the Actor System ID (Priority + MAC).\n"
             "Used by the peer to uniquely identify this LACP participant.")
    actor_key   = get("Actor Key (hex)",   "0001",
        help="2-byte operational key — identifies which ports can be aggregated together.\n"
             "Ports with the same key on the same system can form one LAG (bundle).\n"
             "0x0001 = first aggregation group.   Different keys = different bundles.")
    actor_state = get("Actor State (hex)  [3d=Active+Short+Aggregating+Sync+Col+Dist]", "3d",
        help="8-bit LACP state flags for this actor port.\n"
             "Bit 0: LACP Activity (1=Active, sends PDUs periodically)\n"
             "Bit 1: LACP Timeout (1=Short 1s, 0=Long 30s)\n"
             "Bit 2: Aggregation (1=can aggregate, 0=individual)\n"
             "Bit 3: Synchronisation (1=in sync with partner)\n"
             "Bit 4: Collecting (1=receiving frames from partner)\n"
             "Bit 5: Distributing (1=sending frames to partner)\n"
             "Bit 6: Defaulted (1=using default partner info)\n"
             "Bit 7: Expired (1=partner info has expired)\n"
             "0x3D = 00111101 = Active+Short+Aggregating+Sync+Collecting+Distributing")
    return actor_mac, actor_key, actor_state
def build_lacp(actor_mac, actor_key, actor_state):
    subtype_ver = b"\x01\x01"   # subtype=LACP, version=1
    tlv = (b"\x01\x14" +
           bytes.fromhex("8000") + mac_b(actor_mac) +
           hpad(actor_key,2) + bytes.fromhex("80008001") +
           hpad(actor_state,1) + b"\x00\x00\x00")
    terminator = b"\x00\x00"
    raw = subtype_ver + tlv + terminator
    # offsets into raw
    fields = [
        {"layer":3,"name":"LACP Subtype",       "raw":raw[0:1],  "user_val":"1",       "note":"LACP"},
        {"layer":3,"name":"LACP Version",        "raw":raw[1:2],  "user_val":"1",       "note":""},
        {"layer":3,"name":"LACP Actor TLV Type", "raw":raw[2:3],  "user_val":"01",      "note":"Actor Info"},
        {"layer":3,"name":"LACP Actor TLV Len",  "raw":raw[3:4],  "user_val":"20",      "note":"bytes=20"},
        {"layer":3,"name":"LACP Actor Sys Prio", "raw":raw[4:6],  "user_val":"8000",    "note":"32768"},
        {"layer":3,"name":"LACP Actor Sys MAC",  "raw":raw[6:12], "user_val":actor_mac, "note":""},
        {"layer":3,"name":"LACP Actor Key",      "raw":raw[12:14],"user_val":actor_key, "note":""},
        {"layer":3,"name":"LACP Actor Port Prio","raw":raw[14:16],"user_val":"8000",    "note":""},
        {"layer":3,"name":"LACP Actor Port",     "raw":raw[16:18],"user_val":"8001",    "note":""},
        {"layer":3,"name":"LACP Actor State",    "raw":raw[18:19],"user_val":actor_state,"note":"0x3d=Active+Sync+Agg"},
        {"layer":3,"name":"LACP Actor Reserved", "raw":raw[19:22],"user_val":"000000",  "note":""},
        {"layer":3,"name":"LACP Terminator",     "raw":raw[22:24],"user_val":"0000",    "note":""},
    ]
    return raw, fields

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — LAYER 4  (Transport / Control)
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  ICMP
# ──────────────────────────────────────────────────────────────────────────────
def print_icmp_table():
    print(f"\n  {'─'*100}")
    print(f"  {'ICMP TYPE / CODE REFERENCE TABLE':^100}")
    print(f"  {'─'*100}")
    print(f"  {'Type':>5}  {'Type Name':<28}  {'Code':>5}  Code Description")
    print(f"  {'─'*100}")
    for t, (tname, codes) in sorted(ICMP_TABLE.items()):
        first = True
        for c, cdesc in sorted(codes.items()):
            if first:
                print(f"  {t:5d}  {tname:<28}  {c:5d}  {cdesc}")
                first = False
            else:
                print(f"  {'':5}  {'':28}  {c:5d}  {cdesc}")
    print(f"  {'─'*100}")
def ask_l4_icmp():
    print_icmp_table()
    section("LAYER 4 — ICMP")
    icmp_type = int(get("ICMP Type  (default=8 Echo Request)", "8",
        help="ICMP message type — defines what kind of ICMP message this is.\n"
             "8 = Echo Request (ping sent)   0 = Echo Reply (ping response)\n"
             "3 = Destination Unreachable    11 = Time Exceeded (TTL expired)\n"
             "5 = Redirect   12 = Parameter Problem\n"
             "See the table above for all types and their codes."))
    if icmp_type in ICMP_TABLE:
        codes = ICMP_TABLE[icmp_type][1]
        code_hint = "  ".join(f"{c}={d}" for c,d in sorted(codes.items()))
        print(f"    Valid codes: {code_hint}")
    icmp_code = int(get("ICMP Code", "0",
        help="ICMP sub-code — gives more detail about the type.\n"
             "For Echo Request/Reply (type 8/0): always 0 (only one code).\n"
             "For Destination Unreachable (type 3): 0=net  1=host  3=port  4=frag-needed\n"
             "For Time Exceeded (type 11): 0=TTL in transit  1=reassembly timeout"))
    icmp_id   = int(get("ICMP Identifier (decimal)", "1",
        help="16-bit identifier used to match Echo Requests with Echo Replies.\n"
             "The ping tool usually sets this to the process ID (PID).\n"
             "Receiver copies this value unchanged into the Echo Reply.\n"
             "Allows multiple ping sessions to run simultaneously without confusion."))
    icmp_seq  = int(get("ICMP Sequence   (decimal)", "1",
        help="16-bit sequence number — incremented with each ping request sent.\n"
             "Starts at 1, goes up: 1, 2, 3, ...\n"
             "Receiver copies this into the Reply — sender matches reply to request.\n"
             "Gaps in sequence numbers indicate lost packets."))
    print("    ICMP data payload hex  (default = ping pattern 'abcdefgh')")
    data_hex  = get("ICMP payload hex", "6162636465666768")
    try:
        icmp_data = bytes.fromhex(data_hex.replace(" ",""))
    except ValueError:
        print("    -> invalid hex, using default"); icmp_data = bytes.fromhex("6162636465666768")
    return icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex
def build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex_repr=""):
    rest = struct.pack("!HH", icmp_id, icmp_seq) if icmp_type in ICMP_ECHO_TYPES else b'\x00\x00\x00\x00'
    msg0 = struct.pack("!BBH", icmp_type, icmp_code, 0) + rest + icmp_data
    ck   = inet_cksum(msg0)
    msg  = struct.pack("!BBH", icmp_type, icmp_code, ck) + rest + icmp_data

    tname = ICMP_TABLE.get(icmp_type, (f"Type {icmp_type}",{}))[0]
    cname = ICMP_TABLE.get(icmp_type,("",{}))[1].get(icmp_code, f"Code {icmp_code}")

    fields = [
        {"layer":4,"name":"ICMP Type",     "raw":msg[0:1], "user_val":str(icmp_type), "note":tname},
        {"layer":4,"name":"ICMP Code",     "raw":msg[1:2], "user_val":str(icmp_code), "note":cname},
        {"layer":4,"name":"ICMP Checksum", "raw":msg[2:4], "user_val":"auto",         "note":f"0x{ck:04x} RFC792 over full ICMP"},
    ]
    if icmp_type in ICMP_ECHO_TYPES:
        fields += [
            {"layer":4,"name":"ICMP Identifier","raw":msg[4:6],"user_val":str(icmp_id), "note":f"0x{icmp_id:04x}"},
            {"layer":4,"name":"ICMP Sequence",  "raw":msg[6:8],"user_val":str(icmp_seq),"note":""},
        ]
    else:
        fields.append({"layer":4,"name":"ICMP Rest-of-Header","raw":msg[4:8],"user_val":"0","note":"type-specific"})
    if icmp_data:
        fields.append({"layer":4,"name":"ICMP Data Payload","raw":icmp_data,
                       "user_val":data_hex_repr[:20] if data_hex_repr else icmp_data.hex()[:20],
                       "note":f"{len(icmp_data)}B"})
    return msg, fields, ck

# ──────────────────────────────────────────────────────────────────────────────
#  TCP
# ──────────────────────────────────────────────────────────────────────────────
def port_note(port):
    return WELL_KNOWN_PORTS.get(port, "")
def print_port_table():
    print(f"\n  {'─'*100}")
    print(f"  {'WELL-KNOWN PORT REFERENCE  (TCP & UDP)':^100}")
    print(f"  {'─'*100}")
    ports = sorted(WELL_KNOWN_PORTS.items())
    # print in 3 columns
    cols = 3
    rows = (len(ports) + cols - 1) // cols
    for r in range(rows):
        line = "  "
        for c in range(cols):
            idx = r + c * rows
            if idx < len(ports):
                p, n = ports[idx]
                line += f"  {p:>5} = {n:<18}"
        print(line)
    print(f"  {'─'*100}")
def tcp_checksum(src_ip, dst_ip, tcp_segment):
    """RFC 793: checksum over pseudo-header + TCP segment."""
    pseudo = (ip_b(src_ip) + ip_b(dst_ip) +
              b'\x00' + b'\x06' +
              struct.pack("!H", len(tcp_segment)))
    return inet_cksum(pseudo + tcp_segment)
def print_tcp_handshake_diagram():
    print("""
  ┌──────────────────────────────────────────────────────────────────────┐
  │                 TCP 3-WAY HANDSHAKE FLOW                             │
  │                                                                      │
  │   CLIENT                                          SERVER             │
  │     │                                               │                │
  │     │  ── STEP 1: SYN ──────────────────────────>  │  SEQ=x         │
  │     │             SYN=1  ACK=0                      │                │
  │     │                                               │                │
  │     │  <─ STEP 2: SYN-ACK ───────────────────────  │  SEQ=y ACK=x+1 │
  │     │             SYN=1  ACK=1                      │                │
  │     │                                               │                │
  │     │  ── STEP 3: ACK ──────────────────────────>  │  SEQ=x+1       │
  │     │             SYN=0  ACK=1  ACK_NUM=y+1         │                │
  │     │                                               │                │
  │     │  ── STEP 4: PSH+ACK (data) ───────────────>  │                │
  │     │                                               │                │
  │     │  ── STEP 5: FIN+ACK (close) ──────────────>  │                │
  │     │                                               │                │
  │     │  ── STEP 6: RST (reset) ──────────────────>  │                │
  │                                                                      │
  │  Flags:  SYN=0x02  ACK=0x10  SYN+ACK=0x12  PSH=0x08  FIN=0x01     │
  │          RST=0x04  URG=0x20  ECE=0x40  CWR=0x80                     │
  └──────────────────────────────────────────────────────────────────────┘""")
def ask_l4_tcp(src_ip, dst_ip):
    print_tcp_handshake_diagram()
    print_port_table()
    section("LAYER 4 — TCP")

    print("    Handshake step:")
    for k,(name,_,desc) in TCP_STEPS.items():
        print(f"      {k} = {name:<10}  {desc}")
    step = get("Choose step", "1")
    if step not in TCP_STEPS: step = '1'
    step_name, default_flags, step_desc = TCP_STEPS[step]

    print(f"\n    Building: {step_name}  —  {step_desc}")

    src_port = int(get("Source Port", "49152",
        help="TCP port number on the SENDER side (0–65535).\n"
             "Ports 0–1023 = well-known (HTTP=80, HTTPS=443, SSH=22, DNS=53).\n"
             "Ports 1024–49151 = registered.   49152–65535 = ephemeral (client picks random).\n"
             "For a client connecting to a server, use a random ephemeral port (>49152)."))
    dst_port = int(get("Destination Port", "80",
        help="TCP port number on the RECEIVER side — identifies which service to reach.\n"
             "80=HTTP  443=HTTPS  22=SSH  21=FTP  25=SMTP  53=DNS  3306=MySQL  5432=PG\n"
             "Wrong port: connection refused (RST) or no response (firewall drop)."))
    pn = port_note(dst_port) or port_note(src_port)
    if pn: print(f"    -> Port note: {pn}")

    seq_num  = int(get("Sequence Number  (ISN for SYN, else continuation)", "1000",
        help="32-bit number identifying the position of this segment in the byte stream.\n"
             "SYN (step 1): use a random ISN (Initial Sequence Number) — e.g. 1000.\n"
             "After SYN: each segment's SeqNum = previous SeqNum + bytes sent.\n"
             "Receiver uses this to reassemble data in order and detect duplicates."))
    ack_num  = int(get("Acknowledgement Number  (0 if SYN, else peer_seq+1)",
        "0" if step=='1' else "1001",
        help="32-bit number = next SeqNum the sender EXPECTS from the peer.\n"
             "Meaning: 'I have received everything up to ACK_NUM - 1.'\n"
             "SYN (step 1): 0 (ACK flag not set, no data acknowledged yet).\n"
             "SYN-ACK (step 2): peer_ISN + 1.   ACK (step 3): peer_ISN + 1.\n"
             "Only valid when ACK flag is set in the flags field."))
    data_off = 5
    flags_val = default_flags
    print(f"    TCP Flags (hex, default={default_flags:#04x} = {step_name})")
    flags_in = get("Flags hex (Enter=default)", f"{default_flags:02x}",
        help="8-bit field where each bit enables a TCP control flag.\n"
             "SYN=0x02  ACK=0x10  SYN+ACK=0x12  PSH=0x08  FIN=0x01  RST=0x04\n"
             "URG=0x20  ECE=0x40  CWR=0x80\n"
             "SYN: initiate connection.   ACK: acknowledge data.   FIN: close gracefully.\n"
             "RST: abort connection immediately.   PSH: deliver data to app right away.\n"
             "URG: urgent data present (pointer field matters).   ECE/CWR: congestion.")
    try:    flags_val = int(flags_in, 16)
    except: flags_val = default_flags

    window   = int(get("Window Size (bytes)", "65535",
        help="16-bit receive buffer size — how many bytes the sender can send before waiting for ACK.\n"
             "65535 = maximum without window scaling (RFC 7323 extends this).\n"
             "Smaller value: receiver is telling sender to slow down (flow control).\n"
             "0 = zero window — stop sending (receiver buffer is full)."))
    urg_ptr  = int(get("Urgent Pointer      (0 unless URG set)", "0",
        help="16-bit offset from SeqNum to the end of urgent data.\n"
             "Only meaningful when URG flag is set — points to last urgent byte.\n"
             "Almost never used in modern protocols. Keep 0 for normal frames."))

    # Optional data payload (for PSH+ACK)
    tcp_data = b''
    if step in ('4',):
        print("    TCP data payload hex  (default = 'GET / HTTP/1.0\\r\\n')")
        dhex = get("Data hex", "474554202f20485454502f312e300d0a")
        try:    tcp_data = bytes.fromhex(dhex.replace(" ",""))
        except: tcp_data = b''

    return (step, step_name, src_port, dst_port, seq_num, ack_num,
            data_off, flags_val, window, urg_ptr, tcp_data, src_ip, dst_ip)
def build_tcp(step, step_name, src_port, dst_port, seq_num, ack_num,
              data_off, flags_val, window, urg_ptr, tcp_data,
              src_ip, dst_ip):
    # Build with checksum=0
    hdr_no_ck = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq_num, ack_num,
        (data_off << 4),   # data offset in high nibble
        flags_val,
        window, 0, urg_ptr)
    seg_no_ck = hdr_no_ck + tcp_data
    ck = tcp_checksum(src_ip, dst_ip, seg_no_ck)
    hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq_num, ack_num,
        (data_off << 4),
        flags_val,
        window, ck, urg_ptr)
    seg = hdr + tcp_data

    # Decode flags for display
    flag_names = [n for n,v in TCP_FLAGS.items() if flags_val & v]
    flag_str   = '+'.join(flag_names) if flag_names else "none"
    pn_src = port_note(src_port); pn_dst = port_note(dst_port)

    fields = [
        {"layer":4,"name":"TCP Source Port",     "raw":seg[0:2],  "user_val":str(src_port),
         "note":pn_src or "ephemeral"},
        {"layer":4,"name":"TCP Dest Port",       "raw":seg[2:4],  "user_val":str(dst_port),
         "note":pn_dst or ""},
        {"layer":4,"name":"TCP Sequence Num",    "raw":seg[4:8],  "user_val":str(seq_num),
         "note":f"0x{seq_num:08x}"},
        {"layer":4,"name":"TCP Ack Number",      "raw":seg[8:12], "user_val":str(ack_num),
         "note":f"0x{ack_num:08x}"},
        {"layer":4,"name":"TCP Data Offset+Res", "raw":seg[12:13],"user_val":str(data_off),
         "note":f"{data_off*4}B header, reserved=0"},
        {"layer":4,"name":"TCP Flags",           "raw":seg[13:14],"user_val":f"0x{flags_val:02x}",
         "note":f"{flag_str}  [{step_name}]"},
        {"layer":4,"name":"TCP Window Size",     "raw":seg[14:16],"user_val":str(window),
         "note":"bytes"},
        {"layer":4,"name":"TCP Checksum",        "raw":seg[16:18],"user_val":"auto",
         "note":f"0x{ck:04x}  RFC793 pseudo-hdr+segment"},
        {"layer":4,"name":"TCP Urgent Pointer",  "raw":seg[18:20],"user_val":str(urg_ptr),
         "note":"0 unless URG flag set"},
    ]
    if tcp_data:
        fields.append({"layer":4,"name":"TCP Data Payload","raw":tcp_data,
                       "user_val":tcp_data.hex()[:24],"note":f"{len(tcp_data)}B"})
    return seg, fields, ck

# ──────────────────────────────────────────────────────────────────────────────
#  UDP
# ──────────────────────────────────────────────────────────────────────────────
def udp_checksum(src_ip, dst_ip, udp_datagram):
    """RFC 768: checksum over pseudo-header + UDP datagram."""
    pseudo = (ip_b(src_ip) + ip_b(dst_ip) +
              b'\x00' + b'\x11' +
              struct.pack("!H", len(udp_datagram)))
    return inet_cksum(pseudo + udp_datagram)
def ask_l4_udp(src_ip, dst_ip):
    print_port_table()
    section("LAYER 4 — UDP")
    print("    UDP is connectionless – single datagram, no handshake.")
    print("    Common uses: DNS (53), DHCP (67/68), NTP (123), SNMP (161), TFTP (69)")

    src_port = int(get("Source Port", "49152",
        help="UDP port number on the SENDER side (0–65535).\n"
             "Ephemeral range 49152–65535 for clients.  Well-known: 53=DNS 67/68=DHCP.\n"
             "Unlike TCP, UDP has no connection — port just identifies the sending socket."))
    dst_port = int(get("Destination Port", "53",
        help="UDP port number on the RECEIVER — identifies which service to reach.\n"
             "53=DNS  67=DHCP server  68=DHCP client  69=TFTP  123=NTP  161=SNMP\n"
             "514=Syslog  520=RIP  1194=OpenVPN  5060=SIP"))
    pn = port_note(dst_port) or port_note(src_port)
    if pn: print(f"    -> Port note: {pn}")

    print("    UDP data payload hex")
    print("      DNS query example : 0001010000010000000000000377777703636f6d00000100 01")
    print("      NTP request       : e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    print("      Syslog example    : 3c31343e4a756c2031352030303a30303a303020686f73 74206d657373616765")
    dhex = get("Data hex  (Enter=empty datagram)", "")
    try:    udp_data = bytes.fromhex(dhex.replace(" ",""))
    except: udp_data = b''

    return src_port, dst_port, udp_data, src_ip, dst_ip
def build_udp(src_port, dst_port, udp_data, src_ip, dst_ip):
    length = 8 + len(udp_data)
    # Build with checksum=0
    hdr_no_ck = struct.pack("!HHHH", src_port, dst_port, length, 0)
    dgram_no_ck = hdr_no_ck + udp_data
    ck = udp_checksum(src_ip, dst_ip, dgram_no_ck)
    # RFC 768: if computed checksum is 0, transmit 0xFFFF
    if ck == 0: ck = 0xFFFF
    hdr  = struct.pack("!HHHH", src_port, dst_port, length, ck)
    dgram = hdr + udp_data

    pn_src = port_note(src_port); pn_dst = port_note(dst_port)

    fields = [
        {"layer":4,"name":"UDP Source Port",  "raw":dgram[0:2],"user_val":str(src_port),
         "note":pn_src or "ephemeral"},
        {"layer":4,"name":"UDP Dest Port",    "raw":dgram[2:4],"user_val":str(dst_port),
         "note":pn_dst or ""},
        {"layer":4,"name":"UDP Length",       "raw":dgram[4:6],"user_val":"auto",
         "note":f"{length}B (8 hdr + {len(udp_data)} data)"},
        {"layer":4,"name":"UDP Checksum",     "raw":dgram[6:8],"user_val":"auto",
         "note":f"0x{ck:04x}  RFC768 pseudo-hdr+datagram"},
    ]
    if udp_data:
        fields.append({"layer":4,"name":"UDP Data Payload","raw":udp_data,
                       "user_val":udp_data.hex()[:24],"note":f"{len(udp_data)}B"})
    return dgram, fields, ck

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — WIFI / IEEE 802.11  (MAC frame builder)
# ══════════════════════════════════════════════════════════════════════════════
def print_wifi_education():
    print(f"""
  {'═'*110}
  {'WiFi FRAME  —  IEEE 802.11  (Wireless LAN MAC + PHY Preamble)':^110}
  {'═'*110}

  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  QUESTION: Does WiFi have something like Ethernet's Preamble + SFD?                                     │
  │                                                                                                         │
  │  SHORT ANSWER: YES — but it is very different. WiFi has a PHY-layer preamble called the PLCP            │
  │  (Physical Layer Convergence Procedure) header. The closest equivalent to Ethernet's SFD is the        │
  │  STF (Short Training Field) + LTF (Long Training Field) + SIG field, which together tell the           │
  │  receiver "a frame is starting, here is how to decode it."                                              │
  │                                                                                                         │
  │  KEY DIFFERENCE: Ethernet SFD is 1 byte (0xD5) in baseband.                                           │
  │  WiFi PHY preamble is 20–80+ µs of OFDM/DSSS symbols transmitted BEFORE the MAC frame —               │
  │  it carries timing sync, channel estimation, and rate/length info. It is NOT bytes in the              │
  │  MAC layer. Most protocol analysers (Wireshark/tcpdump) strip it and show only the MPDU.               │
  └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ETHERNET vs WiFi FRAME BOUNDARY COMPARISON
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Ethernet (802.3)           WiFi (802.11)
  ────────────────────────── ─────────────────────────────────────────────────────────────────────────────────
  Preamble   7B  0x55×7      STF   Short Training Field  — AGC / frequency sync (8 OFDM symbols)
  SFD        1B  0xD5    ≈   LTF   Long Training Field   — channel estimation  (2 OFDM symbols)
  [MAC frame starts here]    SIG   Signal / PLCP Header  — rate + length info  (1 OFDM symbol)
                             [MPDU = MAC frame starts here — after SIG is decoded]
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  The STF marks the START of energy on the medium.
  The SIG field is the functional equivalent of SFD — it signals the EXACT start and decode parameters
  for the MPDU that follows.

  PHY PREAMBLE FORMATS BY 802.11 STANDARD
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Standard   PHY Mode         Preamble Structure                       Duration
  ─────────  ───────────────  ───────────────────────────────────────  ──────────
  802.11b    DSSS/CCK         Preamble(144b) + PLCP-Header(48b)        Long: 192µs
             DSSS Short       Short-Preamble(72b) + PLCP-Hdr(24b)     Short: 96µs
  802.11a    OFDM (5 GHz)     L-STF(8µs) + L-LTF(8µs) + L-SIG(4µs)  20µs
  802.11g    ERP-OFDM (2.4G)  Same as 802.11a (L-STF+L-LTF+L-SIG)   20µs
  802.11n    HT-Mixed(2.4/5G) L-STF+L-LTF+L-SIG + HT-SIG1+HT-SIG2   32–40µs
                              + HT-STF + HT-LTF(s)
  802.11ac   VHT (5 GHz)      L-STF+L-LTF+L-SIG + VHT-SIG-A(8µs)    36–76µs
                              + VHT-STF + VHT-LTF(s) + VHT-SIG-B
  802.11ax   HE (2.4/5/6 GHz) L-STF+L-LTF+L-SIG+RL-SIG              ~100µs
                              + HE-SIG-A(8µs) + HE-SIG-B(opt)
                              + HE-STF + HE-LTF(s)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

  PLCP FIELD MEANINGS
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Field      Role                      Ethernet equivalent?
  ─────────  ────────────────────────  ─────────────────────────────────────────────────────────────────────
  STF        Auto Gain Control (AGC)   ≈ Preamble (0x55×7) — sync, clock recovery
             Coarse freq/time sync
  LTF        Fine channel estimation   No Ethernet equivalent — wireless-only
             Phase noise correction
  L-SIG      Rate (4b) + Length(12b)  ≈ SFD (0xD5) — marks start of MPDU, gives its length
             Parity + Tail bits        The receiver KNOWS the MPDU is coming after this
  HT/VHT/    MCS index, BW, STBC,     No Ethernet equivalent — MIMO/OFDMA parameters
  HE-SIG     NSS, Guard Interval,      tell the receiver how many spatial streams,
             LDPC, beamforming info    what bandwidth (20/40/80/160MHz), etc.
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

  DSSS PLCP HEADER FIELDS  (802.11b — the only standard where PLCP is byte-addressable)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Byte  Field          Size   Value / Description
  ────  ─────────────  ─────  ────────────────────────────────────────────────────────────────────────────────
   0    SYNC           128b   0xFF×16 bytes (long preamble)  OR  0xFF×7 bytes (short preamble)
                               Scrambled 1s — same role as Ethernet preamble (symbol sync)
   16   SFD            16b    0xF3A0  (long) OR  0x05CF  (short)  ← EXACT 802.11b SFD value
                               THIS IS THE CLOSEST THING TO ETHERNET SFD IN WiFi
                               Receiver detects this pattern to lock onto frame start
   18   SIGNAL         8b     Data rate encoding:
                               0x0A = 1 Mbps (DBPSK)
                               0x14 = 2 Mbps (DQPSK)
                               0x37 = 5.5 Mbps (CCK)
                               0x6E = 11 Mbps (CCK)
   19   SERVICE        8b     0x00 (reserved in long preamble, used in short)
   20   LENGTH         16b    MPDU length in microseconds (not bytes!)
   22   CRC            16b    CRC-16 over SIGNAL+SERVICE+LENGTH fields
  [MPDU starts at byte 24 for long preamble]
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

  OFDM L-SIG FIELD BITS  (802.11a/g/n/ac/ax legacy preamble — 24 bits total)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Bits   Field    Description
  ─────  ───────  ──────────────────────────────────────────────────────────────────────────────────────────
  [3:0]  RATE     MCS/rate code:
                    0b1011=6Mbps  0b1111=9Mbps  0b1010=12Mbps  0b1110=18Mbps
                    0b1001=24Mbps 0b1101=36Mbps 0b1000=48Mbps  0b1100=54Mbps
  [4]    Reserved Always 0
  [16:5] LENGTH   MPDU length in bytes (12 bits, max 4095)
  [17]   Parity   Even parity over bits [0:16]
  [23:18]Tail     000000 (flushes convolutional encoder)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

  SUMMARY: WiFi SFD EQUIVALENTS BY STANDARD
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Standard   "SFD" Field     Value           Role
  ─────────  ─────────────── ─────────────── ──────────────────────────────────────────────────────────────
  802.11b    DSSS SFD        0xF3A0(long)    Exact SFD — marks frame start in baseband
                             0x05CF(short)
  802.11a/g  L-SIG           rate+len(24b)   Marks MPDU boundary, encodes decode params
  802.11n    HT-SIG-1/2      MCS,BW,len      HT MPDU boundary + spatial stream params
  802.11ac   VHT-SIG-A/B     MCS,NSS,len     VHT MPDU boundary + multi-user params
  802.11ax   HE-SIG-A/B      MCS,NSS,RU      HE/OFDMA MPDU boundary + resource unit
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

  THREE FRAME TYPES
  ─────────────────────────────────────────────────────────────────────────────
  Type  Name        Subtypes    Purpose
  ────  ──────────  ──────────  ────────────────────────────────────────────────
  00    Management  0,1,2,3,4,  BSS admin: Beacon, Probe, Auth, Assoc, Action
                    5,8,10-13
  01    Control     8-14        Medium access: RTS, CTS, ACK, Block-Ack, PS-Poll
  10    Data        0,4,8,12    Payload: Data, Null, QoS-Data, QoS-Null

  FRAME CONTROL FIELD  (2 bytes)
  ─────────────────────────────────────────────────────────────────────────────
  [1:0] Protocol Version  [3:2] Type  [7:4] Subtype
  [8] ToDS  [9] FromDS  [10] MoreFrag  [11] Retry  [12] PwrMgmt
  [13] MoreData  [14] Protected  [15] +HTC/Order

  DS-BIT ADDRESS TABLE
  ─────────────────────────────────────────────────────────────────────────────
  ToDS  FromDS  Addr1(RA)     Addr2(TA)     Addr3       Addr4
  ────  ──────  ────────────  ────────────  ──────────  ──────────
    0     0     Destination   Source        BSSID       —  (IBSS/Ad-Hoc)
    1     0     AP BSSID      Source STA    Dest STA    —  (STA→AP uplink)
    0     1     Dest STA      AP BSSID      Source STA  —  (AP→STA downlink)
    1     1     RA(next-hop)  TA(sender)    DA(dest)    SA(src)  (WDS/Mesh)

  FCS: CRC-32 over entire MPDU (FC → Frame Body), 4B little-endian
  {'═'*110}""")
def ask_wifi_frame():
    # ── PHY mode selection ─────────────────────────────────────────────────────
    section("WiFi PHY MODE  (determines preamble / frame boundary field)")
    print("    NOTE: PHY preamble is transmitted BEFORE the MAC frame on air.")
    print("    It contains the 'SFD equivalent' that marks the MPDU boundary.\n")
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

    # ── Subtype ────────────────────────────────────────────────────────────────
    section(f"SUBTYPE  —  {type_name} frame")
    has_qos = False
    if ftype_ch == '1':
        for k,(sv,sn,sd) in WIFI_MGMT_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<30}  {sd}")
        sub_ch = get("Subtype", "8")
        if sub_ch not in WIFI_MGMT_SUBTYPES: sub_ch = '8'
        subtype_val, subtype_name, _ = WIFI_MGMT_SUBTYPES[sub_ch]
    elif ftype_ch == '2':
        for k,(sv,sn,sd) in WIFI_CTRL_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<25}  {sd}")
        sub_ch = get("Subtype", "13")
        if sub_ch not in WIFI_CTRL_SUBTYPES: sub_ch = '13'
        subtype_val, subtype_name, _ = WIFI_CTRL_SUBTYPES[sub_ch]
    else:
        for k,(sv,sn,qos,sd) in WIFI_DATA_SUBTYPES.items():
            print(f"    {k:>2} = {sn:<15}  QoS={'Yes' if qos else 'No '}  {sd}")
        sub_ch = get("Subtype", "8")
        if sub_ch not in WIFI_DATA_SUBTYPES: sub_ch = '8'
        subtype_val, subtype_name, has_qos, _ = WIFI_DATA_SUBTYPES[sub_ch]

    # ── Frame Control flags ────────────────────────────────────────────────────
    section("FRAME CONTROL FLAGS")
    print("    ToDS / FromDS determine address field roles (see table above).")

    if ftype_ch == '2':
        to_ds = 0; from_ds = 0
        print("    Control frames: ToDS=0 FromDS=0 (fixed)")
    else:
        print("    0/0=IBSS  1/0=STA→AP(uplink)  0/1=AP→STA(downlink)  1/1=WDS")
        to_ds   = int(get("ToDS   (0 or 1)", "1",
            help="To Distribution System bit.\n"
                 "1 = this frame is travelling TOWARD the AP / distribution system.\n"
                 "Set to 1 when a client (STA) sends data UP to the AP.\n"
                 "Controls which meaning Addr1/Addr2/Addr3 have — see table above.")) & 1
        from_ds = int(get("FromDS (0 or 1)", "0",
            help="From Distribution System bit.\n"
                 "1 = this frame is coming FROM the AP / distribution system.\n"
                 "Set to 1 when AP sends data DOWN to a client (STA).\n"
                 "ToDS=1 + FromDS=1 = WDS/mesh bridge frame (AP to AP).")) & 1

    more_frag = int(get("More Fragments (0/1)", "0",
        help="More Fragments bit — used when a large frame is fragmented.\n"
             "1 = more fragments of this frame follow (not the last fragment).\n"
             "0 = this is the last (or only) fragment.\n"
             "Fragment Number in Sequence Control identifies which fragment this is.")) & 1
    retry     = int(get("Retry          (0/1)", "0",
        help="Retry bit — set when retransmitting a frame that was not acknowledged.\n"
             "1 = this is a RETRANSMISSION of a previously sent frame.\n"
             "0 = first transmission.\n"
             "Receiver uses this with SeqNum to detect and discard duplicates.")) & 1
    pwr_mgmt  = int(get("Power Mgmt     (0/1)", "0",
        help="Power Management bit — announces power state AFTER this frame.\n"
             "1 = STA will enter power-save sleep mode after sending this frame.\n"
             "0 = STA remains awake (active mode).\n"
             "AP buffers frames for sleeping STAs and delivers them on PS-Poll.")) & 1
    more_data = int(get("More Data      (0/1)", "0",
        help="More Data bit — set by AP toward sleeping STAs.\n"
             "1 = AP has more buffered frames waiting for this sleeping STA.\n"
             "0 = no more buffered frames.\n"
             "Sleeping STA uses this to decide whether to send another PS-Poll.")) & 1
    protected = int(get("Protected Frame (0/1, 1=encrypted)", "0",
        help="Protected Frame bit — indicates the frame body is encrypted.\n"
             "1 = frame body is encrypted: WEP, TKIP (WPA), CCMP (WPA2), or GCMP (WPA3).\n"
             "0 = frame body is in plaintext (open network or management frames).\n"
             "Unencrypted data frames on a protected network = security misconfiguration.")) & 1
    htc_order = int(get("+HTC/Order     (0/1)", "0",
        help="+HTC/Order bit — has two meanings depending on frame type.\n"
             "For QoS data frames: 1 = HT Control field (4 bytes) is present.\n"
             "For non-QoS frames: 1 = frames must be delivered in order (legacy).\n"
             "Set to 1 when using 802.11n/ac link adaptation or beamforming feedback.")) & 1

    fc_byte0 = (subtype_val << 4) | (type_bits << 2) | 0x00
    fc_byte1 = (to_ds | (from_ds<<1) | (more_frag<<2) | (retry<<3) |
                (pwr_mgmt<<4) | (more_data<<5) | (protected<<6) | (htc_order<<7))
    fc_bytes = bytes([fc_byte0, fc_byte1])

    # ── Duration / ID ──────────────────────────────────────────────────────────
    section("DURATION / ID  (2 bytes)")
    print("    NAV duration in microseconds (Network Allocation Vector).")
    print("    For ACK/CTS: time for remaining exchange.  PS-Poll: AID value.")
    dur_val   = int(get("Duration µs  (0–32767) or AID for PS-Poll", "0",
        help="Duration/ID field — 2 bytes, two different uses:\n"
             "For most frames: NAV value in microseconds (0–32767).\n"
             "  NAV = Network Allocation Vector — tells other STAs how long the\n"
             "  medium will be busy (they defer transmission for this duration).\n"
             "  RTS sets NAV = time for CTS+Data+ACK.  Data sets NAV = time for ACK.\n"
             "For PS-Poll frames: Association ID (AID) of the sleeping station.\n"
             "  AID = value assigned by AP when STA associated (1–2007).")) & 0x7FFF
    dur_bytes = struct.pack("<H", dur_val)

    # ── Address fields ─────────────────────────────────────────────────────────
    section("ADDRESS FIELDS")
    ds_desc = {(0,0):"IBSS/Ad-Hoc  Addr1=Dst  Addr2=Src  Addr3=BSSID",
               (1,0):"STA→AP       Addr1=BSSID  Addr2=SrcSTA  Addr3=DstSTA",
               (0,1):"AP→STA       Addr1=DstSTA  Addr2=BSSID  Addr3=SrcSTA",
               (1,1):"WDS/Mesh     Addr1=RA  Addr2=TA  Addr3=DA  Addr4=SA"}
    print(f"    DS mode: {ds_desc.get((to_ds,from_ds), 'see table')}")

    if (to_ds, from_ds) == (0,0):
        a1_lbl="Addr1  Destination STA"; a2_lbl="Addr2  Source STA"
        a3_lbl="Addr3  BSSID";           need_a4=False
        a1_def="ff:ff:ff:ff:ff:ff"; a2_def="aa:bb:cc:dd:ee:ff"; a3_def="00:11:22:33:44:55"
    elif (to_ds, from_ds) == (1,0):
        a1_lbl="Addr1  AP BSSID";        a2_lbl="Addr2  Source STA"
        a3_lbl="Addr3  Destination STA"; need_a4=False
        a1_def="00:11:22:33:44:55"; a2_def="aa:bb:cc:dd:ee:ff"; a3_def="ff:ff:ff:ff:ff:ff"
    elif (to_ds, from_ds) == (0,1):
        a1_lbl="Addr1  Destination STA"; a2_lbl="Addr2  AP BSSID"
        a3_lbl="Addr3  Source STA";      need_a4=False
        a1_def="aa:bb:cc:dd:ee:ff"; a2_def="00:11:22:33:44:55"; a3_def="cc:dd:ee:ff:00:11"
    else:
        a1_lbl="Addr1  RA (receiver/next-hop AP)"; a2_lbl="Addr2  TA (transmitter/this AP)"
        a3_lbl="Addr3  DA (final destination)";     need_a4=True
        a1_def="00:11:22:33:44:55"; a2_def="aa:bb:cc:dd:ee:ff"; a3_def="ff:ff:ff:ff:ff:ff"

    if ftype_ch == '2':
        subtype_has_a2 = subtype_val not in (0x0C, 0x0D)
        a1_lbl = "Addr1  RA (Receiver Address)"
        a2_lbl = "Addr2  TA (Transmitter Address)"
        a1_def = "ff:ff:ff:ff:ff:ff"; a2_def = "aa:bb:cc:dd:ee:ff"
        need_a4 = False

    addr1 = get(a1_lbl, a1_def)
    if ftype_ch == '2' and not subtype_has_a2:
        addr2 = None
        print(f"    Addr2 not present in {subtype_name} (control frame)")
    else:
        addr2 = get(a2_lbl, a2_def)

    addr3 = get(a3_lbl, a3_def) if ftype_ch != '2' else None
    addr4 = get("Addr4  SA (source address)", "cc:dd:ee:ff:00:11") if need_a4 else None

    # ── Sequence Control ───────────────────────────────────────────────────────
    seq_ctrl_bytes = b''
    if ftype_ch != '2' or subtype_val in (0x08, 0x09):
        section("SEQUENCE CONTROL")
        seq_num  = int(get("Sequence Number  (0–4095)", "100",
            help="12-bit frame sequence number (0–4095, then wraps back to 0).\n"
                 "Incremented by 1 for each new MSDU (data unit) sent.\n"
                 "Receiver uses this to detect and discard duplicate retransmitted frames.\n"
                 "Also used to reorder out-of-sequence frames in Block-Ack scenarios.")) & 0xFFF
        frag_num = int(get("Fragment Number  (0=unfragmented)", "0",
            help="4-bit fragment number (0–15) within the current sequence number.\n"
                 "0 = unfragmented frame (or first/only fragment).\n"
                 "1, 2, 3... = subsequent fragments of a large fragmented MSDU.\n"
                 "Receiver reassembles fragments with same SeqNum in FragNum order.")) & 0xF
        seq_ctrl_val   = (seq_num << 4) | frag_num
        seq_ctrl_bytes = struct.pack("<H", seq_ctrl_val)

    # ── QoS Control ────────────────────────────────────────────────────────────
    qos_bytes = b''
    if has_qos:
        section("QoS CONTROL")
        for tid,(name) in WIFI_TID_NAMES.items():
            print(f"      TID {tid} = {name}")
        tid     = int(get("TID  Traffic ID (0–7)", "0",
            help="Traffic Identifier — 4 bits, maps to 802.1D User Priority.\n"
                 "0=BE(Best Effort)  1=BK(Background)  2=BK  3=BE\n"
                 "4=VI(Video)  5=VI  6=VO(Voice)  7=VO\n"
                 "Determines which AC (Access Category) queue this frame uses:\n"
                 "AC_BK=background  AC_BE=best effort  AC_VI=video  AC_VO=voice\n"
                 "Higher TID = higher priority = shorter backoff = wins medium sooner.")) & 0xF
        eosp    = int(get("EOSP (0/1)", "0",
            help="End Of Service Period — 1 bit, used in U-APSD (Unscheduled APSD) power save.\n"
                 "1 = AP sets this in the LAST frame of a service period delivery.\n"
                 "0 = normal frame (or not the last frame of a service period).\n"
                 "STA enters sleep after receiving frame with EOSP=1.")) & 0x1
        print("    Ack Policy:  0=Normal  1=No-Ack  2=No-Explicit  3=Block-Ack")
        ack_pol = int(get("Ack Policy (0–3)", "0",
            help="Acknowledgment policy for this QoS frame.\n"
                 "0=Normal ACK: receiver sends individual ACK for this frame.\n"
                 "1=No ACK: no acknowledgment (used for multicast, video, lossy streams).\n"
                 "2=No Explicit ACK / PSMP ACK: special power-save multi-poll mode.\n"
                 "3=Block ACK: use Block-Ack agreement — ACK batched with bitmap.\n"
                 "No ACK + Block ACK improve throughput at cost of reliability.")) & 0x3
        amsdu   = int(get("A-MSDU Present (0/1)", "0",
            help="Aggregate MSDU flag — 1 bit.\n"
                 "1 = the frame body contains an A-MSDU (multiple MSDUs concatenated).\n"
                 "0 = normal single MSDU payload.\n"
                 "A-MSDU aggregation reduces per-frame overhead at cost of larger retry unit.")) & 0x1
        txop    = int(get("TXOP Limit (0–255)", "0",
            help="Transmit Opportunity limit — 8 bits.\n"
                 "Set by AP in frames to STA: maximum TXOP duration (in 32µs units) the STA\n"
                 "may use.  0 = one frame per TXOP (conservative).\n"
                 "Higher values allow burst transmission, improving throughput.")) & 0xFF
        qos_lo  = tid | (eosp<<4) | (ack_pol<<5) | (amsdu<<7)
        qos_bytes = bytes([qos_lo, txop])

    # ── HT Control ─────────────────────────────────────────────────────────────
    htc_bytes = b''
    if htc_order:
        section("HT CONTROL  (4 bytes)")
        htc_hex = get("HT Control (8 hex chars)", "00000000")
        try:    htc_bytes = bytes.fromhex(htc_hex.replace(" ",""))[:4]
        except: htc_bytes = b'\x00'*4
        if len(htc_bytes) < 4: htc_bytes = htc_bytes.ljust(4, b'\x00')

    # ── Frame Body ─────────────────────────────────────────────────────────────
    section("FRAME BODY / PAYLOAD")
    frame_body = b''

    if ftype_ch == '3' and subtype_val in (0x00, 0x08):
        print("    1=LLC/SNAP+IPv4  2=LLC/SNAP+raw hex  3=Raw hex  4=Empty")
        body_ch = get("Body type", "1")
        if body_ch in ('1','2'):
            llcsnap = bytes.fromhex("aaaa03000000")
            et_hex  = get("EtherType (hex)", "0800")
            try: et_b = hpad(et_hex, 2)
            except: et_b = bytes.fromhex("0800")
            llcsnap += et_b
            raw_hex = get("Payload hex after LLC/SNAP+EtherType (Enter=empty)", "")
            try:    raw_data = bytes.fromhex(raw_hex.replace(" ",""))
            except: raw_data = b''
            frame_body = llcsnap + raw_data
        elif body_ch == '3':
            raw_hex = get("Raw frame body hex", "")
            try:    frame_body = bytes.fromhex(raw_hex.replace(" ",""))
            except: frame_body = b''

    elif ftype_ch == '1':
        if subtype_val == 0x08:
            use_beacon = get("Use beacon template? (y/n)", "y").lower().startswith("y")
            if use_beacon:
                ssid_str  = get("SSID", "MyNetwork")
                ts        = b'\x00'*8
                bi        = struct.pack("<H", 100)
                cap_info  = struct.pack("<H", 0x0431)
                ssid_b    = bytes([0, len(ssid_str)]) + ssid_str.encode()
                rates_b   = bytes([0x01,0x08,0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24])
                ds_b      = bytes([0x03,0x01, int(get("DS Channel (1-14)", "6"))])
                frame_body = ts + bi + cap_info + ssid_b + rates_b + ds_b
            else:
                ie_hex = get("Management body hex", "")
                try:    frame_body = bytes.fromhex(ie_hex.replace(" ",""))
                except: frame_body = b''
        elif subtype_val == 0x04:
            ssid_str  = get("SSID to probe (empty=broadcast)", "")
            ssid_b    = bytes([0, len(ssid_str)]) + ssid_str.encode()
            frame_body = ssid_b + bytes([0x01,0x04,0x02,0x04,0x0B,0x16])
        else:
            ie_hex = get("Management body hex (Enter=none)", "")
            try:    frame_body = bytes.fromhex(ie_hex.replace(" ",""))
            except: frame_body = b''

    elif ftype_ch == '2':
        ctrl_hex = get("Control frame extra body hex (usually empty)", "")
        try:    frame_body = bytes.fromhex(ctrl_hex.replace(" ",""))
        except: frame_body = b''

    return {
        'phy_ch':        phy_ch,
        'fc_bytes':      fc_bytes,
        'fc_byte0':      fc_byte0,   'fc_byte1':    fc_byte1,
        'type_bits':     type_bits,  'type_name':   type_name,
        'subtype_val':   subtype_val,'subtype_name':subtype_name,
        'has_qos':       has_qos,
        'to_ds':  to_ds, 'from_ds':  from_ds,
        'more_frag': more_frag, 'retry': retry,
        'pwr_mgmt': pwr_mgmt,   'more_data': more_data,
        'protected': protected, 'htc_order': htc_order,
        'dur_val':  dur_val,    'dur_bytes': dur_bytes,
        'addr1': addr1, 'addr2': addr2, 'addr3': addr3, 'addr4': addr4,
        'seq_ctrl_bytes': seq_ctrl_bytes,
        'qos_bytes': qos_bytes,
        'htc_bytes': htc_bytes,
        'frame_body': frame_body,
        'ftype_ch': ftype_ch,
    }
def build_wifi(d):
    """Assemble the 802.11 MPDU from the ask_wifi_frame dict and return
    (full_frame, records, mpdu_bytes, fcs, fcs_computed)."""
    records = []
    fc = d['fc_bytes']

    records += [
        {"layer":2,"name":"FC Byte0 (Type+Subtype)",
         "raw":fc[0:1], "user_val":f"0x{d['fc_byte0']:02X}",
         "note":f"Type={d['type_name']}({d['type_bits']:02b})  Sub={d['subtype_name']}(0x{d['subtype_val']:02X})"},
        {"layer":2,"name":"FC Byte1 (Flags)",
         "raw":fc[1:2], "user_val":f"0x{d['fc_byte1']:02X}",
         "note":(f"ToDS={d['to_ds']} FromDS={d['from_ds']} MoreFrag={d['more_frag']} "
                 f"Retry={d['retry']} PwrMgmt={d['pwr_mgmt']} MoreData={d['more_data']} "
                 f"Protect={d['protected']} HTC={d['htc_order']}")},
        {"layer":2,"name":"Duration / NAV ID",
         "raw":d['dur_bytes'], "user_val":str(d['dur_val']),
         "note":"µs  Network Allocation Vector"},
    ]

    ds_role = {(0,0):("Destination","Source","BSSID",None),
               (1,0):("BSSID","Source STA","Dest STA",None),
               (0,1):("Destination","BSSID","Source",None),
               (1,1):("RA next-hop","TA sender","DA dest","SA source")}
    roles = ds_role.get((d['to_ds'], d['from_ds']), ("Addr1","Addr2","Addr3","Addr4"))

    if d['addr1']:
        records.append({"layer":2,"name":f"Addr1 ({roles[0]})",
                        "raw":mac_b(d['addr1']),"user_val":d['addr1'],"note":"Receiver Address (RA)"})
    if d['addr2']:
        records.append({"layer":2,"name":f"Addr2 ({roles[1]})",
                        "raw":mac_b(d['addr2']),"user_val":d['addr2'],"note":"Transmitter Address (TA)"})
    if d['addr3']:
        records.append({"layer":2,"name":f"Addr3 ({roles[2]})",
                        "raw":mac_b(d['addr3']),"user_val":d['addr3'],"note":""})
    if d['seq_ctrl_bytes']:
        sc_val = struct.unpack("<H", d['seq_ctrl_bytes'])[0]
        records.append({"layer":2,"name":"Sequence Control",
                        "raw":d['seq_ctrl_bytes'],
                        "user_val":f"SeqNum={sc_val>>4} FragNum={sc_val&0xF}",
                        "note":f"0x{sc_val:04X}  (LE on air)"})
    if d['addr4']:
        records.append({"layer":2,"name":f"Addr4 ({roles[3]})",
                        "raw":mac_b(d['addr4']),"user_val":d['addr4'],"note":"WDS/Mesh SA"})
    if d['qos_bytes']:
        qlo = d['qos_bytes'][0]
        records.append({"layer":2,"name":"QoS Control",
                        "raw":d['qos_bytes'],"user_val":f"0x{d['qos_bytes'].hex()}",
                        "note":(f"TID={qlo&0xF}({WIFI_TID_NAMES.get(qlo&0xF,'')})  "
                                f"EOSP={(qlo>>4)&1}  AckPol={WIFI_ACK_POLICY[(qlo>>5)&3]}")})
    if d['htc_bytes']:
        records.append({"layer":2,"name":"HT Control",
                        "raw":d['htc_bytes'],"user_val":d['htc_bytes'].hex(),"note":"802.11n/ac HTC"})

    fb = d['frame_body']
    if fb:
        if fb[:3] == bytes.fromhex("aaaa03"):
            records += [
                {"layer":2,"name":"LLC DSAP+SSAP+Control","raw":fb[0:3],
                 "user_val":"AA AA 03","note":"SNAP header"},
                {"layer":2,"name":"SNAP OUI","raw":fb[3:6],
                 "user_val":fb[3:6].hex(),"note":"000000=Ethernet-bridged"},
                {"layer":2,"name":"SNAP EtherType","raw":fb[6:8],
                 "user_val":fb[6:8].hex(),"note":"Protocol identifier"},
            ]
            if len(fb) > 8:
                records.append({"layer":3,"name":"Frame Body Payload",
                                 "raw":fb[8:],"user_val":f"{len(fb)-8}B","note":"L3 payload"})
        elif d['ftype_ch'] == '1':
            records.append({"layer":3,"name":"Management Body (IEs)",
                            "raw":fb,"user_val":f"{len(fb)}B","note":"Information Elements"})
        else:
            records.append({"layer":3,"name":"Frame Body",
                            "raw":fb,"user_val":f"{len(fb)}B","note":""})

    # assemble MPDU
    mpdu = fc + d['dur_bytes']
    if d['addr1']: mpdu += mac_b(d['addr1'])
    if d['addr2']: mpdu += mac_b(d['addr2'])
    if d['addr3']: mpdu += mac_b(d['addr3'])
    if d['seq_ctrl_bytes']: mpdu += d['seq_ctrl_bytes']
    if d['addr4']: mpdu += mac_b(d['addr4'])
    mpdu += d['qos_bytes'] + d['htc_bytes'] + fb

    section("FCS  —  CRC-32 over entire MPDU")
    print(f"    Covers {len(mpdu)} bytes (FC → end of Frame Body)")
    fcs_ch = input("    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    if fcs_ch == '2':
        try:
            fcs = bytes.fromhex(input("    Enter 8 hex chars: ").strip())
            if len(fcs) != 4: raise ValueError
        except:
            fcs = wifi_crc32(mpdu); print("    -> invalid, using auto")
    else:
        fcs = wifi_crc32(mpdu)

    fcs_computed = wifi_crc32(mpdu)
    records.append({"layer":0,"name":"FCS (CRC-32 over MPDU)",
                    "raw":fcs,"user_val":"auto/custom",
                    "note":f"0x{fcs.hex()}  ({len(mpdu)}B MPDU)"})
    return mpdu + fcs, records, mpdu, fcs, fcs_computed

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — STANDALONE IPv4 PACKET BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def print_ip_education():
    print(f"""
  {'═'*110}
  {'STANDALONE IPv4 PACKET BUILDER  (RFC 791)':^110}
  {'═'*110}

  IPv4 HEADER MAP  (20 bytes minimum, up to 60 bytes with options)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  Byte  Bits  Field               Fixed?  Value / Your Input
  ────  ────  ──────────────────  ──────  ────────────────────────────────────────────────────────────────────
   0    [7:4] Version             Fixed   4 = IPv4 (always)
   0    [3:0] IHL                 Auto    Header length ÷ 4 (5 = 20B, 6 = 24B with options, max 15=60B)
   1    [7:2] DSCP                USER    QoS marking — 0=best effort, 46=VoIP, 48=routing
   1    [1:0] ECN                 USER    Congestion notification: 0=none, 3=CE (Congestion Experienced)
   2-3         Total Length       Auto    Header + Payload in bytes (auto-calculated)
   4-5         Identification     USER    16-bit ID for fragment group (0 for unfragmented OK)
   6    [7]   Reserved flag       Fixed   Always 0
   6    [6]   DF (Don't Fragment) USER    1=do not fragment this packet  0=fragmentation allowed
   6    [5]   MF (More Fragments) USER    1=more fragments follow        0=last or only fragment
   6-7  [12:0] Fragment Offset   USER    Position of this fragment in original packet (×8 bytes)
   8           TTL                USER    Hop limit 0–255 (64=Linux, 128=Windows, 255=max)
   9           Protocol           USER    Upper layer number (1=ICMP 6=TCP 17=UDP 89=OSPF ...)
  10-11        Header Checksum    AUTO    RFC 791 one's complement — auto-calculated or manual
  12-15        Source Address     USER    Your IP address
  16-19        Destination Addr   USER    Target IP address
  20+          Options            USER    Optional (NOP/RR/TS/LSRR/SSRR) — increases IHL
  IHL×4+       Payload            USER    ICMP / TCP / UDP / raw hex / empty

  CHECKSUM CALCULATION
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  1. Build header with checksum field = 0x0000
  2. Sum all 16-bit words across the 20-byte header
  3. Fold carries: while sum > 0xFFFF: sum = (sum & 0xFFFF) + (sum >> 16)
  4. One's complement: checksum = ~sum & 0xFFFF
  Verify: sum all header words incl. checksum → must equal 0xFFFF (result = 0)

  FRAGMENTATION
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  All fragments share the same Identification value.
  Fragment Offset = byte offset from start of original payload ÷ 8.
  MF=1 on all fragments EXCEPT the last.  Last fragment: MF=0.
  DF=1 prevents any fragmentation — router drops and sends ICMP type 3 code 4 back.

  PROTOCOL NUMBERS (common)
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
  1=ICMP  2=IGMP  4=IP-in-IP  6=TCP  17=UDP  41=IPv6(tunnel)
  47=GRE  50=ESP  51=AH  58=ICMPv6  89=OSPF  103=PIM  112=VRRP  132=SCTP
  {'═'*110}""")
def ask_ip_options():
    """Ask whether to add IP options and build them."""
    section("IP OPTIONS  (optional — extends header beyond 20 bytes)")
    print("    IP options increase IHL. Each option has Type(1B)+Length(1B)+Data.")
    print("    1 = No options  (IHL=5, 20-byte header — most common)")
    print("    2 = NOP padding  (Type=0x01, 1 byte, used to align)")
    print("    3 = Record Route (Type=0x07 — routers record their IPs)")
    print("    4 = Timestamp    (Type=0x44 — routers record timestamps)")
    print("    5 = Custom hex   (enter raw option bytes manually)")
    opt_ch = get("Options choice", "1",
        help="IP Options field — rarely used today but defined in RFC 791.\n"
             "Adding options increases the header length (IHL field).\n"
             "Most firewalls and routers DROP packets with IP options (security concern).\n"
             "NOP(0x01): 1-byte pad to align subsequent options to 32-bit boundary.\n"
             "Record Route(0x07): asks each router to record its outbound IP.\n"
             "Timestamp(0x44): asks each router to append its time and IP.\n"
             "LSRR(0x83)/SSRR(0x89): source routing — rarely allowed, often blocked.")

    if opt_ch == '1':
        return b'', []

    elif opt_ch == '2':
        count = int(get("How many NOP bytes (1–40)", "3",
            help="NOP = Type 0x01, single byte.  Used to pad options to 32-bit alignment.\n"
                 "Must pad so total options length is a multiple of 4 bytes."))
        nop = bytes([0x01] * min(count, 40))
        # pad to 4-byte boundary
        if len(nop) % 4:
            nop += bytes([0x00] * (4 - len(nop) % 4))
        records = [{"layer":3,"name":f"IP Option NOP×{len(nop)}",
                    "raw":nop,"user_val":f"{len(nop)}B","note":"0x01 padding"}]
        return nop, records

    elif opt_ch == '3':
        # Record Route: Type(1B)=0x07  Length(1B)=3+4*slots  Pointer(1B)=4  Slots
        slots = int(get("Number of route slots (1–9)", "4",
            help="Number of IP address slots to reserve in the Record Route option.\n"
                 "Each slot = 4 bytes (one IPv4 address).  Routers fill these in order.\n"
                 "Max 9 slots — but most routers ignore/strip this option."))
        slots = max(1, min(9, slots))
        opt_len = 3 + slots * 4
        rr = bytes([0x07, opt_len, 0x04]) + b'\x00' * (slots * 4)
        # pad to 4-byte boundary
        if len(rr) % 4:
            rr += bytes([0x00] * (4 - len(rr) % 4))
        records = [{"layer":3,"name":"IP Option Record Route",
                    "raw":rr,"user_val":f"{slots} slots ({opt_len}B)",
                    "note":f"Type=0x07 Len={opt_len} Ptr=4  {slots} empty slots"}]
        return rr, records

    elif opt_ch == '4':
        # Timestamp: Type=0x44  Length=12(min)  Pointer=5  Overflow(4b)+Flag(4b)
        print("    Timestamp flag:  0=timestamp only  1=IP+timestamp  3=prespecified IPs")
        ts_flag = int(get("Timestamp flag (0/1/3)", "0",
            help="0 = record timestamp only (4 bytes per slot).\n"
                 "1 = record IP address + timestamp (8 bytes per slot).\n"
                 "3 = only record for prespecified IP addresses.")) & 0xF
        slots = int(get("Number of timestamp slots (1–4)", "2",
            help="Number of timestamp entries to reserve.\n"
                 "Each slot: flag=0 → 4 bytes; flag=1 → 8 bytes."))
        slots = max(1, min(4, slots))
        slot_size = 8 if ts_flag else 4
        opt_len = 4 + slots * slot_size
        ts_opt = bytes([0x44, opt_len, 5, ts_flag]) + b'\x00' * (slots * slot_size)
        if len(ts_opt) % 4:
            ts_opt += bytes([0x00] * (4 - len(ts_opt) % 4))
        records = [{"layer":3,"name":"IP Option Timestamp",
                    "raw":ts_opt,"user_val":f"{slots} slots flag={ts_flag}",
                    "note":f"Type=0x44 Len={opt_len}"}]
        return ts_opt, records

    else:  # custom
        print("    Enter raw option bytes in hex (will be padded to 4-byte boundary).")
        opt_hex = get("Option bytes hex", "01010101",
            help="Raw bytes of the IP option(s) in hex.\n"
                 "Must be padded to a multiple of 4 bytes total.\n"
                 "Example: 01 01 01 01 = four NOP bytes (valid 4-byte pad).\n"
                 "Example: 07 0b 04 00 00 00 00 00 00 00 00 = Record Route 2 slots.")
        try:    opt_bytes = bytes.fromhex(opt_hex.replace(" ",""))
        except: opt_bytes = b'\x01\x01\x01\x01'
        if len(opt_bytes) % 4:
            opt_bytes += bytes([0x00] * (4 - len(opt_bytes) % 4))
        if len(opt_bytes) > 40:
            opt_bytes = opt_bytes[:40]
            print("    -> truncated to 40 bytes (max IP options length)")
        records = [{"layer":3,"name":"IP Option Custom",
                    "raw":opt_bytes,"user_val":opt_bytes.hex()[:24],
                    "note":f"{len(opt_bytes)}B"}]
        return opt_bytes, records
def ask_ip_payload():
    """Ask what L4 payload to put inside the IP packet."""
    section("IP PAYLOAD  (Layer 4 content)")
    print("    1 = ICMP  (Echo Request/Reply/Unreachable/Time Exceeded ...)")
    print("    2 = TCP   (SYN / SYN-ACK / ACK / PSH+ACK / FIN / RST)")
    print("    3 = UDP   (DNS / NTP / SNMP / custom ...)")
    print("    4 = Raw hex  (enter payload bytes directly)")
    print("    5 = Empty    (IP header only, no payload)")
    ch = get("Payload type", "1",
        help="Choose what goes inside the IP packet after the header.\n"
             "1=ICMP: ping, error messages, traceroute probes.\n"
             "2=TCP: connection-oriented reliable transport (HTTP, SSH, FTP ...).\n"
             "3=UDP: connectionless fast transport (DNS, NTP, SNMP, TFTP ...).\n"
             "4=Raw: enter any hex bytes — for custom/proprietary protocols.\n"
             "5=Empty: just the IP header with no payload (testing header-only).")
    return ch

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — FLOW CONTROLLERS  (top-level frame assembly)
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  Ethernet flows
# ──────────────────────────────────────────────────────────────────────────────
def flow_eth_arp():
    banner("ETHERNET  +  ARP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0806)  |  L3: ARP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0806")
    arp_inputs    = ask_l3_arp()
    arp_raw, arp_fields = build_arp(arp_inputs)
    full_frame, records = assemble_eth_frame(
        arp_raw, arp_fields, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)
    print_frame_table(records)
    # verify FCS
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref),
    ])
    print_encapsulation(records, full_frame)
def flow_eth_ip_icmp():
    banner("ETHERNET  +  IPv4  +  ICMP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: ICMP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp,
     df, _, src_dom, dst_dom) = ask_l3_ipv4()
    # L4
    icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
    icmp_msg, icmp_fields, icmp_ck = build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
    ip_hdr, ip_fields, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"
    l3_payload = ip_hdr + icmp_msg
    all_upper  = ip_fields + icmp_fields

    full_frame, records = assemble_eth_frame(
        l3_payload, all_upper, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)

    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    ip_ver     = inet_cksum(ip_hdr)
    icmp_ver   = inet_cksum(icmp_msg)
    verify_report([
        ("IP Header Checksum",    f"0x{ip_ck:04x}",  f"0x{ip_ver:04x}",   ip_ver==0),
        ("ICMP Checksum",         f"0x{icmp_ck:04x}",f"0x{icmp_ver:04x}", icmp_ver==0),
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(),  fcs_ref.hex(),        fcs_stored==fcs_ref),
    ])
    print_encapsulation(records, full_frame)
def flow_eth_ip_tcp():
    banner("ETHERNET  +  IPv4  +  TCP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: TCP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp, df, _, src_dom, dst_dom) = ask_l3_ipv4()
    # Force protocol=6 (TCP) regardless of user proto input
    (step, step_name, src_port, dst_port, seq_num, ack_num,
     data_off, flags_val, window, urg_ptr, tcp_data,
     sip, dip) = ask_l4_tcp(src_ip, dst_ip)

    tcp_seg, tcp_fields, tcp_ck = build_tcp(
        step, step_name, src_port, dst_port, seq_num, ack_num,
        data_off, flags_val, window, urg_ptr, tcp_data, src_ip, dst_ip)

    ip_hdr, ip_fields, ip_ck = build_ipv4(
        tcp_seg, src_ip, dst_ip, ttl, ip_id, dscp, df, 6)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"

    l3_payload = ip_hdr + tcp_seg
    all_upper  = ip_fields + tcp_fields

    full_frame, records = assemble_eth_frame(
        l3_payload, all_upper, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)

    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    ip_ver     = inet_cksum(ip_hdr)
    tcp_ver    = tcp_checksum(src_ip, dst_ip, tcp_seg)
    verify_report([
        ("IP Header Checksum",    f"0x{ip_ck:04x}",  f"0x{ip_ver:04x}",  ip_ver==0),
        ("TCP Checksum",          f"0x{tcp_ck:04x}", f"0x{tcp_ver:04x}", tcp_ver==0),
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(),  fcs_ref.hex(),       fcs_stored==fcs_ref),
    ])
    print_encapsulation(records, full_frame)
def flow_eth_ip_udp():
    banner("ETHERNET  +  IPv4  +  UDP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: UDP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp, df, _, src_dom, dst_dom) = ask_l3_ipv4()

    (src_port, dst_port, udp_data,
     sip, dip) = ask_l4_udp(src_ip, dst_ip)

    udp_dgram, udp_fields, udp_ck = build_udp(
        src_port, dst_port, udp_data, src_ip, dst_ip)

    ip_hdr, ip_fields, ip_ck = build_ipv4(
        udp_dgram, src_ip, dst_ip, ttl, ip_id, dscp, df, 17)
    if src_dom: ip_fields[8]['note'] = f"{src_ip}  ({src_dom})"
    if dst_dom: ip_fields[9]['note'] = f"{dst_ip}  ({dst_dom})"

    l3_payload = ip_hdr + udp_dgram
    all_upper  = ip_fields + udp_fields

    full_frame, records = assemble_eth_frame(
        l3_payload, all_upper, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)

    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    ip_ver     = inet_cksum(ip_hdr)
    udp_ver    = udp_checksum(src_ip, dst_ip, udp_dgram)
    verify_report([
        ("IP Header Checksum",    f"0x{ip_ck:04x}",  f"0x{ip_ver:04x}",  ip_ver==0),
        ("UDP Checksum",          f"0x{udp_ck:04x}", f"0x{udp_ver:04x}", udp_ver==0),
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(),  fcs_ref.hex(),       fcs_stored==fcs_ref),
    ])
    print_encapsulation(records, full_frame)
def flow_eth_stp():
    banner("ETHERNET (802.3 + LLC)  +  STP / RSTP BPDU",
           "L1: Preamble+SFD  |  L2: 802.3+LLC  |  L3: BPDU")
    preamble, sfd = ask_layer1_eth()
    stp_inputs = ask_l3_stp()
    bpdu_raw, bpdu_fields = build_stp(stp_inputs)

    # STP always uses 802.3+LLC, fixed MACs
    section("LAYER 2 — 802.3 + LLC  (STP uses fixed multicast)")
    dst_s = get("Destination MAC", "01:80:c2:00:00:00")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    llc_b = bytes.fromhex("424203")   # DSAP=0x42 SSAP=0x42 Ctrl=0x03
    length_val = len(llc_b) + len(bpdu_raw)
    tl    = struct.pack('>H', length_val)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)

    mac_content = dst_mb + src_mb + tl + llc_b + bpdu_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble",        "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",             "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",         "raw":dst_mb,  "user_val":dst_s,         "note":"STP multicast"},
        {"layer":2,"name":"Src MAC",         "raw":src_mb,  "user_val":src_s,         "note":"bridge MAC"},
        {"layer":2,"name":"802.3 Length",    "raw":tl,      "user_val":str(length_val),"note":"bytes"},
        {"layer":2,"name":"LLC DSAP",        "raw":llc_b[0:1],"user_val":"42",        "note":"STP SAP"},
        {"layer":2,"name":"LLC SSAP",        "raw":llc_b[1:2],"user_val":"42",        "note":"STP SAP"},
        {"layer":2,"name":"LLC Control",     "raw":llc_b[2:3],"user_val":"03",        "note":"UI frame"},
    ] + bpdu_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_dtp():
    banner("ETHERNET (802.3 + SNAP)  +  DTP",
           "L1: Preamble+SFD  |  L2: 802.3+SNAP  |  L3: DTP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet 802.3")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    mode  = ask_l3_dtp()
    dtp_raw, dtp_fields = build_dtp(mode)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    length_val = len(dtp_raw)
    tl = struct.pack('>H', length_val)
    mac_content = dst_mb + src_mb + tl + dtp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",     "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC", "raw":dst_mb,  "user_val":dst_s,         "note":"Cisco multicast"},
        {"layer":2,"name":"Src MAC", "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,  "user_val":str(length_val),"note":"bytes"},
    ] + dtp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_pagp():
    banner("ETHERNET (802.3 + SNAP)  +  PAgP",
           "L1: Preamble+SFD  |  L2: 802.3+SNAP  |  L3: PAgP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet 802.3")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    state = ask_l3_pagp()
    pagp_raw, pagp_fields = build_pagp(state)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    length_val = len(pagp_raw)
    tl = struct.pack('>H', length_val)
    mac_content = dst_mb + src_mb + tl + pagp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",     "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC", "raw":dst_mb,  "user_val":dst_s,         "note":"Cisco multicast"},
        {"layer":2,"name":"Src MAC", "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,  "user_val":str(length_val),"note":"bytes"},
    ] + pagp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_lacp():
    banner("ETHERNET II (0x8809)  +  LACP",
           "L1: Preamble+SFD  |  L2: Ethernet II  |  L3: LACP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet II")
    dst_s = get("Destination MAC", "01:80:c2:00:00:02")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    actor_mac, actor_key, actor_state = ask_l3_lacp()
    lacp_raw, lacp_fields = build_lacp(actor_mac, actor_key, actor_state)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    et = bytes.fromhex("8809")
    mac_content = dst_mb + src_mb + et + lacp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble",  "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",       "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",   "raw":dst_mb,  "user_val":dst_s,         "note":"Slow Protocol multicast"},
        {"layer":2,"name":"Src MAC",   "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"EtherType", "raw":et,      "user_val":"0x8809",      "note":"Slow Protocols"},
    ] + lacp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_pause():
    banner("ETHERNET PAUSE FRAME  —  IEEE 802.3x",
           "L1: Preamble+SFD  |  L2: EtherType 0x8808  |  MAC Ctrl Opcode 0x0001  |  Pause Quanta")
    print_pause_education()
    preamble, sfd, dst_s, src_s, quanta_val = ask_l2_pause()
    full_frame, records = build_pause(preamble, sfd, dst_s, src_s, quanta_val)

    print_frame_table(records)

    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref),
    ])
    print_encapsulation(records, full_frame)
def flow_eth_pfc():
    banner("PFC — PRIORITY FLOW CONTROL  IEEE 802.1Qbb",
           "L1: Preamble+SFD  |  L2: EtherType 0x8808  |  Opcode 0x0101  |  8×Priority Quanta")
    print_pfc_education()
    preamble, sfd, dst_s, src_s, vec_val, quanta = ask_l2_pfc()
    full_frame, records = build_pfc(preamble, sfd, dst_s, src_s, vec_val, quanta)
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_lldp():
    banner("LLDP — LINK LAYER DISCOVERY PROTOCOL  IEEE 802.1AB",
           "L1: Preamble+SFD  |  L2: EtherType 0x88CC  |  L3: LLDP TLVs (Chassis+Port+TTL+Options)")
    print_lldp_education()
    inputs = ask_l2_lldp()
    full_frame, records = build_lldp(*inputs)
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_vlan():
    banner("VLAN TAGGED FRAME  —  IEEE 802.1Q  (+Q-in-Q / 802.1ad option)",
           "L1: Preamble+SFD  |  L2: TPID(0x8100)+TCI[PCP+DEI+VID]  |  Inner EtherType  |  Payload")
    print_vlan_education()
    inputs = ask_l2_vlan()
    full_frame, records = build_vlan(*inputs)
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)
def flow_eth_jumbo():
    banner("JUMBO FRAME  —  Non-Standard Vendor Extension",
           "L1: Preamble+SFD  |  L2: Ethernet II  |  Payload up to 9000B+ (MTU > 1500B)")
    print_jumbo_education()
    inputs = ask_l2_jumbo()
    full_frame, records = build_jumbo(*inputs)
    total = len(full_frame)
    print(f"\n  -> Frame size: {total} bytes  ({total*8} bits)")
    if total > 1518:
        overhead_pct = (14 + 4) / total * 100
        print(f"  -> Header overhead: {overhead_pct:.2f}%  (Payload efficiency: {100-overhead_pct:.2f}%)")
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_encapsulation(records, full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  HDLC full builder
# ──────────────────────────────────────────────────────────────────────────────
def flow_hdlc():
    banner("HDLC FRAME BUILDER — ISO 13239",
           "3 Frame Types:  I-frame (data+seq)  |  S-frame (supervisory)  |  U-frame (link mgmt)")
    print_hdlc_education()

    # ── Flags ──────────────────────────────────────────────────────────────────
    section("FLAGS  (frame delimiters)")
    print("    Standard HDLC flag = 0x7E.  Both start and end use same value.")
    flag_hex = get("Flag byte (hex)", "7e",
        help="Frame delimiter — 1 byte, marks the start and end of every HDLC frame.\n"
             "0x7E = 01111110 in binary — the standard HDLC flag.\n"
             "Bit-stuffing inserts a 0 after every 5 consecutive 1-bits inside the frame\n"
             "to prevent 0x7E appearing in the frame content.\n"
             "Keep 0x7E unless working with a non-standard implementation.")
    try:    flag_b = bytes([int(flag_hex, 16) & 0xFF])
    except: flag_b = b'\x7E'

    # ── Address ───────────────────────────────────────────────────────────────
    addr_bytes, addr_note = ask_hdlc_address()

    # ── Frame Type ────────────────────────────────────────────────────────────
    section("HDLC FRAME TYPE")
    print("    1 = I-frame  (Information)   — reliable data with sequence numbers")
    print("    2 = S-frame  (Supervisory)   — ACK/NAK/flow control, no data")
    print("    3 = U-frame  (Unnumbered)    — link setup/teardown/UI datagram")
    ftype = get("Frame type (1/2/3)", "1")
    if ftype not in ('1','2','3'): ftype = '1'

    # ── Modulo (I and S only) ─────────────────────────────────────────────────
    mod128 = False
    if ftype in ('1','2'):
        print("\n    Window size / modulo:")
        print("      Modulo  8: N(S)/N(R) 0–7,   1-byte control  (basic HDLC)")
        print("      Modulo 128: N(S)/N(R) 0–127, 2-byte control  (extended HDLC / ISDN)")
        mod128 = get("Use Modulo-128 extended control? (y/n)", "n",
            help="Modulo controls the sequence number range and control field size.\n"
                 "Modulo-8:   1-byte control, window size up to 7 frames in flight.\n"
                 "            Used in basic HDLC, Cisco HDLC, simple WAN links.\n"
                 "Modulo-128: 2-byte control, window size up to 127 frames in flight.\n"
                 "            Used in ISDN (LAPD/Q.921), X.25 (LAPB), high-throughput links.\n"
                 "Choose 128 when you need large send windows or are building LAPD frames.").lower().startswith("y")

    # ── P/F bit ───────────────────────────────────────────────────────────────
    section("POLL/FINAL (P/F) BIT")
    print("    P=1 in a COMMAND means: 'respond now' (poll)")
    print("    F=1 in a RESPONSE means: 'this is my final response'")
    pf = int(get("P/F bit (0 or 1)", "0",
        help="Poll/Final bit — 1 bit in the control field.\n"
             "In a COMMAND frame: P=1 = Poll — instructs the peer to respond immediately.\n"
             "In a RESPONSE frame: F=1 = Final — this is the last response to a poll.\n"
             "P=0 / F=0 = normal unsolicited frame (no immediate response required).\n"
             "Example: Primary sends RR with P=1 (poll), Secondary responds with RR+F=1.")) & 1

    # ─────────────────────────────────────────────────────────────────────────
    if ftype == '1':
        # I-FRAME
        section("I-FRAME — SEQUENCE NUMBERS")
        print("    N(S) = Send Sequence Number (sequence of THIS frame)")
        print("    N(R) = Receive Sequence Number (acknowledges receipt up to N(R)-1)")
        ns_max = 127 if mod128 else 7
        ns = int(get(f"N(S) Send Sequence  (0–{ns_max})", "0",
            help=f"N(S) — Send Sequence Number of THIS I-frame (0–{ns_max}).\n"
                 "Identifies this frame's position in the outgoing sequence.\n"
                 "Receiver checks N(S) matches what it expects; rejects out-of-order frames.\n"
                 "After sending N(S)=7 (mod-8), next frame has N(S)=0 (wraps around).")) & (0x7F if mod128 else 0x7)
        nr = int(get(f"N(R) Receive/ACK Seq (0–{ns_max})", "0",
            help=f"N(R) — Receive Sequence Number / ACK (0–{ns_max}).\n"
                 "Meaning: 'I have correctly received all frames up to N(R)-1.'\n"
                 "Implicitly acknowledges the peer's frames — piggybacked ACK.\n"
                 "Set to the SeqNum of the NEXT frame you expect from the peer.\n"
                 "Example: peer sent frames 0,1,2 → set N(R)=3 to ACK all three.")) & (0x7F if mod128 else 0x7)
        ctrl_bytes = build_hdlc_control_i(ns, pf, nr, mod128)
        ctrl_note  = f"I-frame  N(S)={ns}  P/F={pf}  N(R)={nr}  {'mod-128' if mod128 else 'mod-8'}"

        section("I-FRAME — INFORMATION PAYLOAD")
        print("    Enter the data payload in hex.")
        print("    Examples:  PPP data: ff030021...  IP packet: 4500...")
        payload_hex = get("Payload hex (Enter=empty)", "")
        try:    info_bytes = bytes.fromhex(payload_hex.replace(" ",""))
        except: info_bytes = b''
        has_info = True

    elif ftype == '2':
        # S-FRAME
        section("S-FRAME — SUPERVISORY FUNCTION")
        for k,(s1,s0,mn,desc) in HDLC_S_SUBTYPES.items():
            print(f"      {k} = {mn:<6}  {desc}")
        s_ch = get("S-frame subtype (1-4)", "1")
        if s_ch not in HDLC_S_SUBTYPES: s_ch = '1'
        s1, s0, s_mn, s_desc = HDLC_S_SUBTYPES[s_ch]
        s1s0 = (s1 << 1) | s0

        nr_max = 127 if mod128 else 7
        nr = int(get(f"N(R) Receive/ACK Sequence (0–{nr_max})", "0",
            help=f"N(R) — Receive/ACK sequence number for this S-frame (0–{nr_max}).\n"
                 "Meaning: 'I have received everything up to N(R)-1 correctly.'\n"
                 "RR with N(R)=5: ACKs frames 0–4, ready to receive frame 5.\n"
                 "REJ with N(R)=3: frames 0–2 OK, retransmit from frame 3 onward.\n"
                 "RNR with N(R)=5: ACKs 0–4, but STOP sending — buffer full.\n"
                 "SREJ with N(R)=3: retransmit only frame 3 (everything else fine).")) & (0x7F if mod128 else 0x7)
        ctrl_bytes = build_hdlc_control_s(nr, pf, s1s0, mod128)
        ctrl_note  = f"S-frame  {s_mn}({s_desc.split('—')[0].strip()})  N(R)={nr}  P/F={pf}  {'mod-128' if mod128 else 'mod-8'}"
        info_bytes = b''
        has_info   = False

    else:
        # U-FRAME
        section("U-FRAME — UNNUMBERED SUBTYPE")
        for k,(m4,m3,m2,m1,m0,mn,cr,desc) in HDLC_U_SUBTYPES.items():
            m_str = f"{m4}{m3}{m2}-{m1}{m0}"
            print(f"    {k:>2} = {mn:<6}  [{m_str}]  {cr:3}  {desc}")
        u_ch = get("U-frame subtype (1-10)", "1")
        if u_ch not in HDLC_U_SUBTYPES: u_ch = '1'
        m4,m3,m2,m1,m0, u_mn, u_cr, u_desc = HDLC_U_SUBTYPES[u_ch]
        m4m3m2 = (m4<<2)|(m3<<1)|m2
        m1m0   = (m1<<1)|m0
        ctrl_bytes = build_hdlc_control_u(m4m3m2, pf, m1m0)
        ctrl_note  = f"U-frame  {u_mn}  P/F={pf}  M={m4}{m3}{m2}-{m1}{m0}  ({u_cr}) {u_desc}"

        # Info field for UI / XID / TEST / FRMR
        info_bytes = b''
        has_info   = u_mn in ("UI", "XID", "TEST", "FRMR")
        if has_info:
            section(f"U-FRAME INFO FIELD  ({u_mn} carries optional data)")
            if u_mn == "XID":
                print("    XID info format: Format-ID(1B) + Group-ID(1B) + Length(1B) + params")
                print("    Default: 81 00 00 (basic XID)")
                xid_hex = get("XID info hex", "810000")
            elif u_mn == "FRMR":
                print("    FRMR info: rejected-ctrl(1-2B) + N(R)(3b)+V(S)(3b)+flags(2B)")
                print("    Flags: W(invalid ctrl) X(info in S/U) Y(info too long) Z(invalid N(R))")
                xid_hex = get("FRMR info hex (3 bytes)", "000000")
            elif u_mn == "TEST":
                print("    TEST info: echo payload (responder copies this back)")
                xid_hex = get("TEST payload hex", "00112233")
            else:  # UI
                print("    UI frame carries data without sequence numbering (like UDP).")
                xid_hex = get("UI payload hex (Enter=empty)", "")
            try:    info_bytes = bytes.fromhex(xid_hex.replace(" ",""))
            except: info_bytes = b''

    # ── FCS ──────────────────────────────────────────────────────────────────
    fcs_input = addr_bytes + ctrl_bytes + info_bytes
    section("FCS  (Frame Check Sequence)")
    print("    1 = CRC-16/CCITT  (2 bytes, standard HDLC, x^16+x^12+x^5+1)")
    print("    2 = CRC-32        (4 bytes, extended HDLC)")
    fcs_mode = get("FCS type (1=CRC-16  2=CRC-32)", "1",
        help="Frame Check Sequence type — detects transmission errors.\n"
             "1 = CRC-16/CCITT (2 bytes): standard HDLC, PPP, X.25, ISDN LAPD.\n"
             "    Polynomial x^16+x^12+x^5+1 (0x1021), init=0xFFFF, stored LE.\n"
             "    Covers: Address + Control + Information fields.\n"
             "2 = CRC-32 (4 bytes): extended HDLC for high-reliability links.\n"
             "    Same polynomial as Ethernet CRC-32 — stronger error detection.\n"
             "    Used when payload > a few KB or when link quality is poor.")

    if fcs_mode == '2':
        crc_auto = crc32_eth(fcs_input)   # same polynomial
        fcs_label = "CRC-32 (4B)"
    else:
        crc_val  = crc16_ccitt(fcs_input)
        crc_auto = crc_val.to_bytes(2, 'little')  # HDLC FCS-16 is little-endian
        fcs_label = "FCS-16/CCITT (2B)"

    print(f"    Auto-computed {fcs_label} = 0x{crc_auto.hex()}")
    custom = get("Use auto FCS? (y=auto  n=enter custom)", "y")
    if custom.lower().startswith('n'):
        fcs_hex = get("Enter FCS hex", crc_auto.hex())
        try:
            fcs_bytes = bytes.fromhex(fcs_hex.replace(" ",""))
            if len(fcs_bytes) not in (2,4):
                raise ValueError
        except:
            print("    -> invalid, using auto")
            fcs_bytes = crc_auto
    else:
        fcs_bytes = crc_auto

    # ── Bit-stuffing option ───────────────────────────────────────────────────
    section("BIT STUFFING  (transparent operation)")
    print("    HDLC uses bit-stuffing: after 5 consecutive 1-bits a 0 is inserted.")
    print("    This prevents 0x7E appearing inside the frame content.")
    do_stuff = get("Apply bit-stuffing to content? (y/n)", "n",
        help="Bit-stuffing ensures 0x7E never appears inside the frame content.\n"
             "How it works: after every 5 consecutive 1-bits, insert a 0-bit.\n"
             "The receiver removes the stuffed 0 — transparent to upper layers.\n"
             "y = apply (correct for synchronous HDLC on physical serial lines).\n"
             "n = skip (correct for async links, or when framing is done by the OS driver).").lower().startswith("y")

    # ── Assemble frame ────────────────────────────────────────────────────────
    inner = addr_bytes + ctrl_bytes + info_bytes + fcs_bytes
    if do_stuff:
        inner = bit_stuff(byte_escape(inner))
        stuff_note = "bit-stuffed + byte-escaped"
    else:
        stuff_note = "raw (no bit-stuffing)"

    full_frame = flag_b + inner + flag_b

    # ── Control field decode for display ──────────────────────────────────────
    ctrl_hex = ctrl_bytes.hex()
    if ftype == '1':
        frame_type_label = "I-frame (Information)"
    elif ftype == '2':
        frame_type_label = f"S-frame (Supervisory) — {s_mn}"
    else:
        frame_type_label = f"U-frame (Unnumbered) — {u_mn}"

    # ── Verify FCS ────────────────────────────────────────────────────────────
    if fcs_mode == '2':
        fcs_verify = crc32_eth(fcs_input)
    else:
        fcs_verify = crc16_ccitt(fcs_input).to_bytes(2, 'little')

    # ── Build records ─────────────────────────────────────────────────────────
    records = [
        {"layer":1, "name":"HDLC Start Flag",
         "raw": flag_b, "user_val": flag_b.hex(),
         "note": "0x7E — frame delimiter (same role as Ethernet Preamble+SFD)"},

        {"layer":2, "name":"HDLC Address",
         "raw": addr_bytes, "user_val": addr_bytes.hex(),
         "note": addr_note},

        {"layer":2, "name":f"HDLC Control  ({frame_type_label})",
         "raw": ctrl_bytes, "user_val": f"0x{ctrl_hex}",
         "note": ctrl_note},
    ]

    # Control field sub-breakdown as individual records (display only — zero-length raw)
    if ftype == '1':
        if mod128:
            records += [
                {"layer":2,"name":"  └─ I-ctrl Byte0: N(S)+0",
                 "raw":b"",
                 "user_val":f"N(S)={ns}",
                 "note":f"bits[7:1]=N(S)={ns}  bit[0]=0(I-frame)"},
                {"layer":2,"name":"  └─ I-ctrl Byte1: N(R)+P/F",
                 "raw":b"",
                 "user_val":f"N(R)={nr} P/F={pf}",
                 "note":f"bits[7:1]=N(R)={nr}  bit[0]=P/F={pf}"},
            ]
        else:
            records.append({"layer":2,"name":"  └─ I-ctrl bits breakdown",
                            "raw":b"",
                            "user_val":f"N(S)={ns} P/F={pf} N(R)={nr}",
                            "note":f"[7:5]N(S)={ns:03b}  [4]P/F={pf}  [3:1]N(R)={nr:03b}  [0]=0"})
    elif ftype == '2':
        records.append({"layer":2,"name":"  └─ S-ctrl bits breakdown",
                        "raw":b"",
                        "user_val":f"N(R)={nr} P/F={pf} {s_mn}",
                        "note":f"[7:5]N(R)={nr:03b}  [4]P/F={pf}  [3:2]SS={s1}{s0}({s_mn})  [1:0]=01"})
    else:
        records.append({"layer":2,"name":"  └─ U-ctrl bits breakdown",
                        "raw":b"",
                        "user_val":f"{u_mn}  P/F={pf}",
                        "note":f"[7:5]M={m4}{m3}{m2}  [4]P/F={pf}  [3:2]M={m1}{m0}  [1:0]=11"})

    if info_bytes:
        records.append({"layer":3,"name":"HDLC Information (payload)",
                        "raw":info_bytes,
                        "user_val":info_bytes.hex()[:30] if len(info_bytes)<=15 else f"{len(info_bytes)}B",
                        "note":f"{len(info_bytes)} bytes"})

    records += [
        {"layer":0, "name":f"HDLC FCS  ({fcs_label})",
         "raw": fcs_bytes, "user_val": fcs_bytes.hex(),
         "note": f"Covers: Addr+Ctrl+Info={len(fcs_input)}B  {stuff_note}"},

        {"layer":1, "name":"HDLC End Flag",
         "raw": flag_b, "user_val": flag_b.hex(),
         "note": "0x7E — frame end delimiter"},
    ]

    # ── Output ────────────────────────────────────────────────────────────────
    banner(f"HDLC FRAME — {frame_type_label}")
    print_frame_table(records)

    fcs_ok = (fcs_bytes == fcs_verify)
    verify_report([
        (f"HDLC {fcs_label}", fcs_bytes.hex(), fcs_verify.hex(), fcs_ok),
    ])
    print_encapsulation(records, full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  Serial / WAN
# ──────────────────────────────────────────────────────────────────────────────
def _resolve_host(host):
    """
    Resolve hostname → IPv4 string.
    Returns (ip_str, resolved_domain) or raises socket.gaierror.
    If host is already an IP, returns it unchanged.
    """
    try:
        socket.inet_aton(host)          # already a valid IPv4 literal
        return host, ""
    except OSError:
        pass
    info = socket.getaddrinfo(host, None, socket.AF_INET)
    return info[0][4][0], host

def ask_ip_or_domain(prompt, default_ip, help_extra=""):
    """
    Ask for an IP address OR a domain name.
    If domain is given, resolve it and show the resolved IP.
    Returns (ip_str, domain_or_empty).
    """
    section(f"IP / DOMAIN  —  {prompt}")
    print(f"    {C.DIM}You can enter either:{C.RESET}")
    print(f"    {C.NOTE}  • An IPv4 address  e.g. 192.168.1.1{C.RESET}")
    print(f"    {C.NOTE}  • A domain name    e.g. google.com  (auto-resolved via DNS){C.RESET}")
    if help_extra:
        print(f"    {C.HELP}  {help_extra}{C.RESET}")

    raw = get(prompt, default_ip,
        help="Enter IPv4 address (e.g. 10.0.0.1) or domain name (e.g. example.com).\n"
             "Domain names are resolved using your system's DNS — requires internet.\n"
             "The resolved IP is shown before you continue.")

    # Try to resolve
    try:
        ip_str, domain = _resolve_host(raw.strip())
        if domain:
            print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{domain}{C.RESET}  →  {C.HEX}{ip_str}{C.RESET}")
        else:
            print(f"    {C.DIM}→ IP literal: {ip_str}{C.RESET}")
        return ip_str, domain
    except Exception as e:
        print(f"    {C.FAIL_}✗ Could not resolve '{raw}': {e}{C.RESET}")
        print(f"    {C.WARN}  Falling back to default: {default_ip}{C.RESET}")
        return default_ip, ""


def flow_serial():
    banner("SERIAL / WAN FRAME BUILDER",
           "L2: PPP | HDLC | SLIP | Modbus RTU | ATM AAL5 | Cisco HDLC | KISS | COBS")
    ch, proto_name = ask_l2_serial()

    # HDLC Full builder — redirect to dedicated 3-frame-type handler
    if ch == '11':
        flow_hdlc()
        return

    start_flag = b'\x7E'; end_flag = b'\x7E'
    if ch in ('3','4','8','10'):
        start_flag = get_hex("Start Flag (2 hex)", "7e", 1)
        end_flag   = get_hex("End   Flag (2 hex)", "7e", 1)

    addr_map = {'3':'ff','4':'ff','8':'ff','10':'0f','7':'01'}
    address = b''
    if ch in addr_map:
        address = get_hex(f"Address/Slave (2 hex)", addr_map[ch], 1)

    control = b''
    if ch in ('3','4','8','10'):
        control = get_hex("Control field (2 hex)", "03", 1)

    # ── L3/L4 payload inside serial frame ─────────────────────────────────────
    l3_payload = b''
    l3_fields  = []

    if ch in ('3','4','8','10'):
        section("LAYER 3/4 — Payload inside Serial frame")
        print(f"    {C.NOTE}Payload options:{C.RESET}")
        print(f"      1 = None  (empty payload)")
        print(f"      2 = Raw hex  (enter bytes directly)")
        print(f"      3 = IPv4 + ICMP  (ping / error messages)")
        print(f"      4 = IPv4 + TCP   (3-way handshake — SYN/SYN-ACK/ACK/data/FIN/RST)")
        print(f"      5 = IPv4 + UDP   (DNS / NTP / SNMP / custom)")
        l3ch = input(f"    {C.PROMPT}Choose [1]: {C.RESET}").strip() or '1'

        if l3ch == '2':
            phex = get("Payload hex", "",
                help="Enter any bytes in hex — for proprietary or custom protocols.\n"
                     "Example: a PPP LCP packet, an IP fragment, or test pattern.")
            try:    l3_payload = bytes.fromhex(phex.replace(" ",""))
            except: l3_payload = b''

        elif l3ch == '3':
            # IPv4 + ICMP
            section("LAYER 3 — IPv4 Source + Destination  (ICMP)")
            src_ip, src_dom = ask_ip_or_domain("Source IP / domain", "192.168.1.10",
                "Source = the WAN endpoint on this side of the serial link.")
            dst_ip, dst_dom = ask_ip_or_domain("Destination IP / domain", "192.168.1.20",
                "Destination = the remote WAN endpoint.")
            ttl  = int(get("TTL", "64",
                help="IP Time To Live — decremented by each router hop.\n"
                     "64=Linux/Mac  128=Windows  Use 1 for traceroute-style probes."))
            ip_id = int(get("IP Identification", "1",
                help="16-bit fragment group ID. Any value for non-fragmented packets."))
            dscp = int(get("DSCP (0=BE  46=VoIP  48=routing)", "0",
                help="QoS class. 0=Best Effort for normal ICMP ping traffic."))
            df = get("DF flag? (y/n)", "y",
                help="Don't Fragment. y = router drops and sends ICMP Frag-Needed if oversized.").lower().startswith('y')
            icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
            icmp_msg, icmp_flds, icmp_ck = build_icmp(
                icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
            ip_hdr, ip_flds, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
            if src_dom: ip_flds[8]['note'] = f"{src_ip}  ({src_dom})"
            if dst_dom: ip_flds[9]['note'] = f"{dst_ip}  ({dst_dom})"
            l3_payload = ip_hdr + icmp_msg
            l3_fields  = ip_flds + icmp_flds

        elif l3ch == '4':
            # IPv4 + TCP
            section("LAYER 3 — IPv4 Source + Destination  (TCP)")
            src_ip, src_dom = ask_ip_or_domain("Source IP / domain", "192.168.1.10",
                "Local WAN endpoint IP (your side of the serial link).")
            dst_ip, dst_dom = ask_ip_or_domain("Destination IP / domain", "93.184.216.34",
                "Remote endpoint IP or domain (e.g. example.com → 93.184.216.34).")
            ttl  = int(get("TTL", "64",
                help="IP Time To Live — decremented by each router hop.\n64=Linux  128=Windows"))
            ip_id = int(get("IP Identification", "1",
                help="Fragment group ID. Any value for non-fragmented TCP packets."))
            dscp = int(get("DSCP (0=BE  46=VoIP  48=routing)", "0",
                help="QoS class. 0=Best Effort for normal TCP."))
            df   = get("DF flag? (y/n)", "y",
                help="Don't Fragment. y = required for TCP PMTUD to work correctly.").lower().startswith('y')
            print_tcp_handshake_diagram()
            (step, step_name, src_port, dst_port, seq_num, ack_num,
             data_off, flags_val, window, urg_ptr, tcp_data, sip, dip) = ask_l4_tcp(src_ip, dst_ip)
            tcp_seg, tcp_flds, tcp_ck = build_tcp(
                step, step_name, src_port, dst_port, seq_num, ack_num,
                data_off, flags_val, window, urg_ptr, tcp_data, src_ip, dst_ip)
            ip_hdr, ip_flds, ip_ck = build_ipv4(tcp_seg, src_ip, dst_ip, ttl, ip_id, dscp, df, 6)
            if src_dom: ip_flds[8]['note'] = f"{src_ip}  ({src_dom})"
            if dst_dom: ip_flds[9]['note'] = f"{dst_ip}  ({dst_dom})"
            l3_payload = ip_hdr + tcp_seg
            l3_fields  = ip_flds + tcp_flds
            # Show checksum status inline
            print(f"\n    {C.DIM}TCP checksum  : 0x{tcp_ck:04X}{C.RESET}")
            print(f"    {C.DIM}IP hdr cksum  : 0x{ip_ck:04X}{C.RESET}")

        elif l3ch == '5':
            # IPv4 + UDP
            section("LAYER 3 — IPv4 Source + Destination  (UDP)")
            src_ip, src_dom = ask_ip_or_domain("Source IP / domain", "192.168.1.10",
                "Local WAN endpoint IP.")
            dst_ip, dst_dom = ask_ip_or_domain("Destination IP / domain", "8.8.8.8",
                "Remote IP or domain (e.g. 8.8.8.8 or dns.google).")
            ttl  = int(get("TTL", "64",
                help="IP Time To Live. 64=Linux/Mac default."))
            ip_id = int(get("IP Identification", "1",
                help="Fragment group ID. Any value for non-fragmented packets."))
            dscp = int(get("DSCP (0=BE  46=VoIP)", "0",
                help="QoS marking. 0=Best Effort for normal UDP."))
            df   = get("DF flag? (y/n)", "n",
                help="Don't Fragment. n = allow fragmentation (normal for UDP).").lower().startswith('y')
            (src_port, dst_port, udp_data, sip, dip) = ask_l4_udp(src_ip, dst_ip)
            udp_dgram, udp_flds, udp_ck = build_udp(src_port, dst_port, udp_data, src_ip, dst_ip)
            ip_hdr, ip_flds, ip_ck = build_ipv4(udp_dgram, src_ip, dst_ip, ttl, ip_id, dscp, df, 17)
            if src_dom: ip_flds[8]['note'] = f"{src_ip}  ({src_dom})"
            if dst_dom: ip_flds[9]['note'] = f"{dst_ip}  ({dst_dom})"
            l3_payload = ip_hdr + udp_dgram
            l3_fields  = ip_flds + udp_flds

    header    = address + control
    crc_input = header + l3_payload

    # CRC selection
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
                if len(cf)==4: fcs=cf; fcs_desc="AAL5 CRC-32 custom"
                else: raise ValueError
            except:
                fcs = crc_val.to_bytes(4,'big'); fcs_desc=f"AAL5 CRC-32 auto over {len(crc_input)}B"
        else:
            fcs = crc_val.to_bytes(4,'big'); fcs_desc=f"AAL5 CRC-32 auto over {len(crc_input)}B"

    content = header + l3_payload + fcs

    # Apply framing
    if ch == '2':
        full_frame = slip_enc(content)
    elif ch in ('3','4','10'):
        full_frame = start_flag + byte_escape(content) + end_flag
    elif ch == '8':
        full_frame = start_flag + bit_stuff(byte_escape(content)) + end_flag
    elif ch == '9':
        pad_len = (48 - (len(content)+8) % 48) % 48
        full_frame = content + b'\x00'*pad_len + fcs
    else:
        full_frame = content

    # Build records
    records = []
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"Start Flag","raw":start_flag,
                        "user_val":start_flag.hex(),"note":"0x7E frame delimiter"})
    if address:
        records.append({"layer":2,"name":"Address","raw":address,
                        "user_val":address.hex(),"note":""})
    if control:
        records.append({"layer":2,"name":"Control","raw":control,
                        "user_val":control.hex(),"note":""})
    records += l3_fields
    if fcs:
        records.append({"layer":0,"name":"CRC/FCS","raw":fcs,
                        "user_val":"auto/custom","note":fcs_desc})
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"End Flag","raw":end_flag,
                        "user_val":end_flag.hex(),"note":"0x7E frame delimiter"})

    banner(f"SERIAL FRAME — {proto_name}")
    print_frame_table(records)
    print_encapsulation(records, full_frame)



# ──────────────────────────────────────────────────────────────────────────────
#  WiFi
# ──────────────────────────────────────────────────────────────────────────────
def flow_wifi():
    banner("WiFi FRAME  —  IEEE 802.11  (PHY Preamble + MAC MPDU)",
           "PHY: STF+LTF+SIG(≈SFD)  |  MAC: FC+Dur+Addr1-4+SeqCtrl+QoS+HTC+Body+FCS")
    print_wifi_education()
    d = ask_wifi_frame()
    full_frame, records, mpdu, fcs, fcs_computed = build_wifi(d)

    # ── Now ask PHY preamble AFTER we know MPDU length ─────────────────────────
    mpdu_len = len(mpdu) + 4  # include FCS in MPDU length for PLCP
    phy_records = ask_wifi_phy(d['phy_ch'], mpdu_len)

    # Prepend PHY records to the record list
    all_records = phy_records + records

    print_frame_table(all_records)
    fcs_ok = (fcs == fcs_computed)
    verify_report([
        ("802.11 FCS (CRC-32 MPDU)", fcs.hex(), fcs_computed.hex(), fcs_ok),
    ])

    # For encapsulation, build phy_bytes to prepend
    phy_bytes = b''.join(r['raw'] for r in phy_records)
    full_with_phy = phy_bytes + full_frame
    print_encapsulation(all_records, full_with_phy)

# ──────────────────────────────────────────────────────────────────────────────
#  Standalone IPv4
# ──────────────────────────────────────────────────────────────────────────────
def flow_ip_standalone():
    banner("STANDALONE IPv4 PACKET BUILDER",
           "RFC 791  |  Full header fields  |  Options  |  Auto or manual checksum  |  L4 payload")
    print_ip_education()

    # ── DSCP/ECN display ──────────────────────────────────────────────────────
    section("DSCP / ECN REFERENCE")
    print(f"  {'Value':>5}  {'DSCP Name':<12}  Description")
    print(f"  {'─'*60}")
    for val, (name, desc) in sorted(DSCP_TABLE.items()):
        print(f"  {val:>5}  {name:<12}  {desc}")
    print(f"  {'─'*60}")

    # ── Protocol reference ─────────────────────────────────────────────────────
    section("PROTOCOL NUMBER REFERENCE")
    print(f"  {'Proto':>5}  {'Name':<8}  Description")
    print(f"  {'─'*60}")
    for num, (name, desc) in sorted(IP_PROTO_NAMES.items()):
        print(f"  {num:>5}  {name:<8}  {desc}")
    print(f"  {'─'*60}")

    # ── IPv4 header fields ────────────────────────────────────────────────────
    section("IPv4 HEADER FIELDS")
    print(f"    {C.NOTE}You can enter an IPv4 address OR a domain name for each IP.{C.RESET}")

    src_raw = get("Source IP or domain", "192.168.1.10",
        help="IPv4 address OR domain name of the SENDER.\n"
             "Examples: 192.168.1.10  or  myserver.local  or  sender.example.com\n"
             "Private: 10.x.x.x / 172.16–31.x.x / 192.168.x.x\n"
             "Loopback: 127.0.0.1   Link-local: 169.254.x.x")
    try:
        src_ip, src_dom = _resolve_host(src_raw.strip())
        if src_dom:
            print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{src_dom}{C.RESET}  →  {C.HEX}{src_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{src_raw}': {e} — using as-is{C.RESET}")
        src_ip, src_dom = src_raw.strip(), ""

    dst_raw = get("Destination IP or domain", "192.168.1.20",
        help="IPv4 address OR domain name of the RECEIVER.\n"
             "Examples: 8.8.8.8  or  google.com  or  example.org\n"
             "Unicast: specific host.   255.255.255.255 = limited broadcast.\n"
             "Multicast: 224.0.0.0–239.255.255.255 (OSPF=224.0.0.5, PIM=224.0.0.13).")
    try:
        dst_ip, dst_dom = _resolve_host(dst_raw.strip())
        if dst_dom:
            print(f"    {C.PASS_}✓ Resolved:{C.RESET}  {C.NOTE}{dst_dom}{C.RESET}  →  {C.HEX}{dst_ip}{C.RESET}")
    except Exception as e:
        print(f"    {C.WARN}Could not resolve '{dst_raw}': {e} — using as-is{C.RESET}")
        dst_ip, dst_dom = dst_raw.strip(), ""

    ttl = int(get("TTL  (Time To Live)", "64",
        help="Hop limit — decremented by 1 at each router. Packet dropped at 0.\n"
             "Prevents routing loops.  64=Linux/Mac default.  128=Windows default.\n"
             "Use 1 for traceroute-style probes (get ICMP Time Exceeded back).\n"
             "Use 255 for link-local protocols (OSPF, VRRP) that must not be forwarded."))

    # Protocol
    print(f"\n    Common protocol numbers: 1=ICMP  6=TCP  17=UDP  47=GRE  89=OSPF  50=ESP")
    proto_in = get("Protocol number", "1",
        help="8-bit field identifying the upper-layer (L4) protocol inside this packet.\n"
             "The receiver uses this to pass payload to the correct socket/handler.\n"
             "Wrong value: OS silently discards payload (no matching socket).\n"
             "Special: 59 = 'No next header' (IPv6 concept, IPv4: means no payload).")
    try:    proto_num = int(proto_in) & 0xFF
    except: proto_num = 1

    proto_name = IP_PROTO_NAMES.get(proto_num, (str(proto_num), "Unknown"))[0]
    print(f"    -> Protocol: {proto_num} = {proto_name}")

    ip_id = int(get("Identification  (0–65535)", "1234",
        help="16-bit ID shared by all fragments of the same original packet.\n"
             "For non-fragmented packets: arbitrary value (OS increments per packet).\n"
             "For fragmented packets: all fragments MUST share the same ID.\n"
             "0 = valid for non-fragmented packets with DF=1 (RFC 6864)."))

    # Flags
    section("IP FLAGS + FRAGMENT OFFSET")
    df = get("DF  Don't Fragment  (y/n)", "y",
        help="DF=1: routers MUST NOT fragment this packet.\n"
             "     If too large: router drops + sends ICMP type 3 code 4 (Frag Needed).\n"
             "     Required for Path MTU Discovery (PMTUD) — always use y for TCP.\n"
             "DF=0: routers may fragment if MTU is smaller than packet size.\n"
             "     Used for UDP/GRE tunnels where fragmentation is acceptable.").lower().startswith('y')
    mf = get("MF  More Fragments  (y/n)", "n",
        help="MF=1: more fragments of this datagram follow this one.\n"
             "MF=0: this is the last (or only) fragment of this datagram.\n"
             "For a non-fragmented packet: MF=0 always.\n"
             "For fragments: MF=1 on every fragment EXCEPT the last.").lower().startswith('y')
    frag_off = int(get("Fragment Offset  (0 for non-fragmented)", "0",
        help="13-bit field specifying the offset of this fragment's data in the\n"
             "original datagram, measured in 8-byte units.\n"
             "0 = first or only fragment (unfragmented packets always use 0).\n"
             "Example: fragment carrying bytes 1480–2959 → offset = 1480÷8 = 185.\n"
             "All fragments except the last have MF=1; last fragment has MF=0.")) & 0x1FFF

    flags_frag = (0 << 15) | ((1 if df else 0) << 14) | ((1 if mf else 0) << 13) | frag_off

    # DSCP / ECN
    section("DSCP / ECN  (Quality of Service)")
    dscp_val = int(get("DSCP value  (0–63, see table above)", "0",
        help="6-bit Differentiated Services Code Point — sets QoS class.\n"
             "0  = CS0/BE = Best Effort (default, no priority).\n"
             "46 = EF = Expedited Forwarding — lowest latency (VoIP, RTP).\n"
             "48 = CS6 = Network Control — routing protocol packets (BGP, OSPF).\n"
             "34–38 = AF41-AF43 = video conferencing class.\n"
             "Routers use DSCP to decide which queue to place the packet in.")) & 0x3F
    ecn_val = int(get("ECN  (0=non-ECN  1=ECT1  2=ECT0  3=CE)", "0",
        help="2-bit Explicit Congestion Notification.\n"
             "0 = Not-ECN-capable (traditional packet, no congestion signalling).\n"
             "1 = ECN-capable Transport, codepoint 1 (ECT1).\n"
             "2 = ECN-capable Transport, codepoint 0 (ECT0).\n"
             "3 = Congestion Experienced (CE) — set by router when buffer filling.\n"
             "Receiver copies CE to TCP/CWR flag, allowing senders to slow down.\n"
             "Only effective when both endpoints and all routers support ECN.")) & 0x3
    tos = (dscp_val << 2) | ecn_val

    # IP Options
    opt_bytes, opt_records = ask_ip_options()
    ihl = 5 + len(opt_bytes) // 4

    # ── L4 Payload ────────────────────────────────────────────────────────────
    payload_ch = ask_ip_payload()
    l4_payload = b''
    l4_records = []
    l4_proto_override = None

    if payload_ch == '1':
        # ICMP — reuse existing builder
        icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
        l4_payload, l4_records, l4_ck = build_icmp(
            icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
        l4_proto_override = 1

    elif payload_ch == '2':
        # TCP — ask_l4_tcp handles step selection internally
        print_tcp_handshake_diagram()
        (step, step_name, src_port, dst_port, seq_num, ack_num,
         data_off, flags_val, window, urg_ptr, tcp_data,
         sip, dip) = ask_l4_tcp(src_ip, dst_ip)
        l4_payload, l4_records, l4_ck = build_tcp(
            step, step_name, src_port, dst_port, seq_num, ack_num,
            data_off, flags_val, window, urg_ptr, tcp_data, src_ip, dst_ip)
        l4_proto_override = 6

    elif payload_ch == '3':
        # UDP
        (src_port, dst_port, udp_data, sip, dip) = ask_l4_udp(src_ip, dst_ip)
        l4_payload, l4_records, l4_ck = build_udp(
            src_port, dst_port, udp_data, src_ip, dst_ip)
        l4_proto_override = 17

    elif payload_ch == '4':
        section("RAW HEX PAYLOAD")
        raw_hex = get("Payload hex bytes", "",
            help="Enter the payload in hexadecimal — any bytes you want inside the IP packet.\n"
                 "Use for custom protocols, encapsulated frames, or test patterns.\n"
                 "Example: GRE header = 00 00 08 00  then inner IP header follows.")
        try:    l4_payload = bytes.fromhex(raw_hex.replace(" ",""))
        except: l4_payload = b''
        if l4_payload:
            l4_records = [{"layer":4,"name":"Raw Payload",
                           "raw":l4_payload,"user_val":f"{len(l4_payload)}B","note":"raw hex"}]
    # payload_ch == '5': empty — l4_payload stays b''

    # Use protocol override if L4 selected a specific protocol
    if l4_proto_override:
        proto_num = l4_proto_override

    # ── Build IP header ────────────────────────────────────────────────────────
    tot_len = ihl * 4 + len(l4_payload)
    ver_ihl = (4 << 4) | ihl

    # Build with checksum=0 first
    hdr0 = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len, ip_id, flags_frag,
        ttl, proto_num, 0,
        ip_b(src_ip), ip_b(dst_ip))
    if opt_bytes:
        hdr0 = hdr0 + opt_bytes

    auto_ck = inet_cksum(hdr0)

    # ── Checksum section — auto or manual ─────────────────────────────────────
    section("IP HEADER CHECKSUM  (RFC 791 — one's complement)")
    print(f"    Header size      : {ihl*4} bytes  (IHL={ihl})")
    print(f"    Auto-computed    : 0x{auto_ck:04X}")
    print(f"    Verify formula   : sum all header 16-bit words → must equal 0xFFFF")
    print(f"\n    Options:")
    print(f"      1 = Use auto-calculated checksum  0x{auto_ck:04X}  (correct)")
    print(f"      2 = Enter custom checksum         (for testing bad-checksum handling)")
    print(f"      3 = Force 0x0000                  (simulate checksum-offload / not computed)")
    ck_ch = input("    Choice [1]: ").strip() or '1'

    if ck_ch == '2':
        ck_hex = get("Custom checksum (4 hex chars)", f"{auto_ck:04x}",
            help="Enter any 4 hex characters as the checksum value.\n"
                 "Use a wrong value to test how receivers handle bad checksums.\n"
                 "FFFF is often used as a 'poison' value in testing.\n"
                 "0000 = not computed (checksum offloading to NIC hardware).")
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

    # ── Assemble final header ─────────────────────────────────────────────────
    hdr = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len, ip_id, flags_frag,
        ttl, proto_num, ck_val,
        ip_b(src_ip), ip_b(dst_ip))
    if opt_bytes:
        hdr = hdr + opt_bytes

    full_packet = hdr + l4_payload

    # ── Checksum verification ─────────────────────────────────────────────────
    ck_verify = inet_cksum(hdr)
    ck_ok     = (ck_verify == 0)   # all-ones after adding stored checksum = valid

    # ── Build records ─────────────────────────────────────────────────────────
    flag_parts = []
    if flags_frag & 0x4000: flag_parts.append("DF")
    if flags_frag & 0x2000: flag_parts.append("MF")
    flag_str = '+'.join(flag_parts) if flag_parts else "none"
    dscp_name = DSCP_TABLE.get(dscp_val, (f"DSCP{dscp_val}", ""))[0]
    ecn_names = {0:"Non-ECN",1:"ECT1",2:"ECT0",3:"CE"}

    records = [
        {"layer":3,"name":"IP Version + IHL",
         "raw":hdr[0:1],"user_val":f"v4 / IHL={ihl}",
         "note":f"Header={ihl*4}B  {'options present' if ihl>5 else 'no options'}"},

        {"layer":3,"name":"IP DSCP + ECN",
         "raw":hdr[1:2],"user_val":f"DSCP={dscp_val}({dscp_name}) ECN={ecn_val}({ecn_names[ecn_val]})",
         "note":f"TOS byte = 0x{tos:02X}"},

        {"layer":3,"name":"IP Total Length",
         "raw":hdr[2:4],"user_val":"auto",
         "note":f"{tot_len}B  (header {ihl*4}B + payload {len(l4_payload)}B)"},

        {"layer":3,"name":"IP Identification",
         "raw":hdr[4:6],"user_val":str(ip_id),
         "note":f"0x{ip_id:04X}  fragment group ID"},

        {"layer":3,"name":"IP Flags + Frag Offset",
         "raw":hdr[6:8],"user_val":f"flags={flag_str}  offset={frag_off}",
         "note":f"DF={int(df)} MF={int(mf)} FragOffset={frag_off} (×8={frag_off*8}B)"},

        {"layer":3,"name":"IP TTL",
         "raw":hdr[8:9],"user_val":str(ttl),
         "note":"hops remaining"},

        {"layer":3,"name":"IP Protocol",
         "raw":hdr[9:10],"user_val":str(proto_num),
         "note":IP_PROTO_NAMES.get(proto_num,(str(proto_num),""))[0]},

        {"layer":3,"name":"IP Header Checksum",
         "raw":hdr[10:12],"user_val":f"0x{ck_val:04X}",
         "note":ck_note},

        {"layer":3,"name":"IP Source Address",
         "raw":hdr[12:16],
         "user_val":f"{src_ip}  ({src_dom})" if src_dom else src_ip,
         "note":f"resolved from {src_dom}" if src_dom else ""},

        {"layer":3,"name":"IP Destination Addr",
         "raw":hdr[16:20],
         "user_val":f"{dst_ip}  ({dst_dom})" if dst_dom else dst_ip,
         "note":f"resolved from {dst_dom}" if dst_dom else ""},
    ]

    # Add option records if present
    records += opt_records

    # Add L4 records
    records += l4_records

    # ── Output ────────────────────────────────────────────────────────────────
    verify_checks = [("IP Header Checksum (RFC791)", f"0x{ck_val:04X}",
                      f"0x{ck_verify:04X} → {'0x0000=PASS' if ck_ok else 'NON-ZERO=FAIL'}", ck_ok)]

    # Add L4 checksum checks
    if payload_ch == '1' and l4_records:
        icmp_ver = inet_cksum(l4_payload)
        verify_checks.append(("ICMP Checksum (RFC792)",
                               f"0x{l4_ck:04X}", f"verify={icmp_ver:04X}", icmp_ver==0))
    elif payload_ch == '2' and l4_records:
        tcp_ver = tcp_checksum(src_ip, dst_ip, l4_payload)
        verify_checks.append(("TCP Checksum (RFC793 pseudo-hdr)",
                               f"0x{l4_ck:04X}", f"verify={tcp_ver:04X}", tcp_ver==0))
    elif payload_ch == '3' and l4_records:
        udp_ver = udp_checksum(src_ip, dst_ip, l4_payload)
        verify_checks.append(("UDP Checksum (RFC768 pseudo-hdr)",
                               f"0x{l4_ck:04X}", f"verify={udp_ver:04X}", udp_ver==0))

    banner(f"STANDALONE IPv4 PACKET  —  {src_ip} → {dst_ip}  proto={proto_name}  {tot_len}B")
    print_frame_table(records)
    verify_report(verify_checks)
    print_encapsulation(records, full_packet)

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — MENUS, DISPATCH TABLE, MAIN
# ══════════════════════════════════════════════════════════════════════════════
L3_ETH_MENU = """
  ┌──────────────────────────────────────────────────────────────────────────┐
  │              LAYER 3  —  Choose protocol to carry in Ethernet            │
  ├────┬─────────────────────────────────────────────────────────────────────┤
  │  1 │ ARP                        (EtherType 0x0806)                       │
  │  2 │ IPv4 + ICMP                (EtherType 0x0800)                       │
  │  3 │ IPv4 + TCP  3-way handshk  (EtherType 0x0800, proto=6)              │
  │  4 │ IPv4 + UDP                 (EtherType 0x0800, proto=17)             │
  │  5 │ STP / RSTP BPDU            (802.3 + LLC wrapper)                    │
  │  6 │ DTP  – Cisco Trunking      (802.3 + SNAP)                           │
  │  7 │ PAgP – Cisco Port Agg.     (802.3 + SNAP)                           │
  │  8 │ LACP – 802.3ad             (EtherType 0x8809)                       │
  │  9 │ Pause Frame  – IEEE 802.3x (EtherType 0x8808, opcode 0x0001)        │
  │ 10 │ PFC  – IEEE 802.1Qbb       (EtherType 0x8808, opcode 0x0101, per-P) │
  │ 11 │ LLDP – IEEE 802.1AB        (EtherType 0x88CC, TLV discovery)        │
  │ 12 │ VLAN Tagged – IEEE 802.1Q  (TPID 0x8100, PCP+DEI+VID + Q-in-Q opt) │
  │ 13 │ Jumbo Frame  – vendor ext  (MTU > 1500B, up to 9000B+)              │
  └────┴─────────────────────────────────────────────────────────────────────┘"""
MAIN_MENU = """
╔════════════════════════════════════════════════════════════════════════════════╗
║           NETWORK FRAME BUILDER  —  LAYERED INPUT FLOW                        ║
╠════════════════════════════════════════════════════════════════════════════════╣
║  SELECT LAYER 2 / STANDALONE TECHNOLOGY                                        ║
╠═══╦════════════════════════════════════════════════════════════════════════════╣
║ 1 ║ Ethernet / 802.3  →  choose L3 protocol (13 options)                      ║
║   ║  ARP | ICMP | TCP | UDP | STP | DTP | PAgP | LACP                         ║
║   ║  Pause(802.3x) | PFC(802.1Qbb) | LLDP(802.1AB) | VLAN(802.1Q) | Jumbo    ║
╠═══╬════════════════════════════════════════════════════════════════════════════╣
║ 2 ║ Serial / WAN  →  choose L2 protocol (11 options incl. HDLC I/S/U)         ║
║   ║  Raw | SLIP | PPP | HDLC-basic | HDLC-Full(I/S/U) | Modbus | ATM ...      ║
╠═══╬════════════════════════════════════════════════════════════════════════════╣
║ 3 ║ WiFi / 802.11  →  choose frame type (Management / Control / Data)         ║
║   ║  Beacon | Probe | Auth | Assoc | RTS | CTS | ACK | QoS-Data | Null        ║
╠═══╬════════════════════════════════════════════════════════════════════════════╣
║ 4 ║ Standalone IPv4 Packet  →  all header fields + options + L4 payload       ║
║   ║  Full header | DSCP/ECN | DF/MF/FragOffset | Options(NOP/RR/TS)           ║
║   ║  Checksum: auto / custom / force-zero  |  L4: ICMP/TCP/UDP/Raw/Empty      ║
╚═══╩════════════════════════════════════════════════════════════════════════════╝"""
L3_DISPATCH = {
    '1' : flow_eth_arp,
    '2' : flow_eth_ip_icmp,
    '3' : flow_eth_ip_tcp,
    '4' : flow_eth_ip_udp,
    '5' : flow_eth_stp,
    '6' : flow_eth_dtp,
    '7' : flow_eth_pagp,
    '8' : flow_eth_lacp,
    '9' : flow_eth_pause,
    '10': flow_eth_pfc,
    '11': flow_eth_lldp,
    '12': flow_eth_vlan,
    '13': flow_eth_jumbo,
}
def main():
    print(MAIN_MENU)
    top = input("  Choose technology  (1=Ethernet  2=Serial  3=WiFi  4=IP): ").strip()

    if top == '1':
        print(L3_ETH_MENU)
        l3ch = input("  Choose L3 protocol (1-13): ").strip()
        fn = L3_DISPATCH.get(l3ch)
        if fn: fn()
        else:  print("  Invalid choice.")

    elif top == '2':
        flow_serial()

    elif top == '3':
        flow_wifi()

    elif top == '4':
        flow_ip_standalone()

    else:
        print("  Invalid choice.")

if __name__ == "__main__":
    try:
        main()
        while input("\nBuild another frame? (y/n): ").strip().lower() == 'y':
            print()
            main()
    except KeyboardInterrupt:
        print("\nExited.")
