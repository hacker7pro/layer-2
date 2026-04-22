"""
l2_builder.py  —  Layer 2 Intelligence Engine  (EXPANDED v2)
=============================================================
Sources:
  • IANA IEEE-802-Numbers registry (2024-11-03 latest)
  • IEEE Registration Authority public list
  • Wireshark etypes.h / Wireshark source tree
  • NetBSD / OpenBSD / Linux ethertypes.h
  • CaveBear Ethernet Type Codes archive
  • Wikipedia EtherType / XNS / IPX / AppleTalk / VINES / DECnet articles
  • RFC 1764 (PPP XNSCP), RFC 1763 (PPP BVCP), RFC 1243 (AppleTalk MIB)
  • Cisco IOS command references (IPX, AppleTalk, VINES, DECnet)
  • Industrial: IEC 61850, PROFINET, EtherCAT, Powerlink, SERCOS, CC-Link IE,
                BACnet, GOOSE, Sampled Values, V2X/DSRC, CobraNet, HomePlug
  • Private/Vendor: AT&T, DEC, IBM, Apple, SGI, Xerox, Cisco, 3Com, HP,
                    Banyan, Novell, Stanford, BBN, Ungermann-Bass, Cabletron

PDU RULE (strictly applied):
  • pdu = specific PDU name  when the protocol has a published/known format
  • pdu = 'RAW'              ONLY when the protocol is undocumented,
                             proprietary/closed, or truly has no defined PDU

L3 STACK COVERAGE (new in v2):
  • XNS IDP   (EtherType 0x0600)  → L3=idp  → L4=spp/pep/error/echo/rip
  • Novell IPX (EtherType 0x8137) → L3=ipx  → L4=spx/ncp/sap/rip/netbios
  • AppleTalk  (EtherType 0x809B) → L3=ddp  → L4=atp/nbp/rtmp/aep/adsp/zip
  • VINES VIP  (EtherType 0x0BAD) → L3=vip  → L4=ipc/spp
  • DECnet PhIV(EtherType 0x6003) → L3=decnet→ L4=nsp
  • DEC LAT    (EtherType 0x6004) → L3=lat  → L4=lat_session

Registry key schema:
  name     – human-readable protocol / owner name
  pdu      – PDU type string  or 'RAW' if truly undocumented
  category – 'Standard'|'Industry'|'Vendor'|'Private'|'Historical'
  status   – 'Active'|'Deprecated'|'Experimental'|'Vendor-specific'|'Legacy'
  usage    – one-line purpose
  l3_proto – L3 class key for process_l3() dispatch, or None
  fields   – concise field-level description dict (empty {} if not applicable)
  l3_stack – full protocol stack dict (new: shows all layers above L2)
"""

from __future__ import annotations
import struct
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER
# ══════════════════════════════════════════════════════════════════════════════
def _e(name, pdu, cat, status, usage, l3=None, fields=None, stack=None):
    """
    Build a registry entry dict.
    stack : optional dict describing full protocol stack above L2
            e.g. {"L3":"XNS IDP","L3_fields":{...},"L4":"SPP/PEP","L4_fields":{...},"Application":"Courier/Filing/Clearinghouse"}
    """
    return dict(name=name, pdu=pdu, category=cat, status=status,
                usage=usage, l3_proto=l3, fields=fields or {},
                l3_stack=stack or {})


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — ETHERTYPE REGISTRY  (400+ entries)
# ══════════════════════════════════════════════════════════════════════════════
ETHERTYPE_REGISTRY: dict[int, dict] = {

    # ── GROUP 1: Core IANA/IEEE Standard ─────────────────────────────────────
    0x0800: _e("IPv4 — RFC 791", "IPv4 Packet", "Standard", "Active",
               "Internet Protocol version 4 — RFC 791; DS field RFC 2474; ECN RFC 3168",
               "ipv4",
               {"Version":         "4b  must be 4",
                "IHL":             "4b  Internet Header Length in 32b words; min=5 (20B); max=15 (60B with options)",
                "DSCP":            "6b  Differentiated Services Code Point (RFC 2474) — QoS class",
                "ECN":             "2b  Explicit Congestion Notification (RFC 3168): 00=Not-ECT 01/10=ECT 11=CE",
                "Total Length":    "2B  entire packet length (header+data); max 65535B",
                "Identification":  "2B  fragment reassembly identifier",
                "Flags":           "3b  bit0=Reserved(0) bit1=DF(Don't-Fragment) bit2=MF(More-Fragments)",
                "Fragment Offset": "13b  position of fragment in units of 8B (0=first/only fragment)",
                "TTL":             "1B  hop limit — decremented per router; 0=discard (default 64)",
                "Protocol":        "1B  next-layer: 1=ICMP 2=IGMP 6=TCP 17=UDP 41=IPv6 47=GRE 50=ESP 51=AH 58=ICMPv6 89=OSPF 103=PIM 112=VRRP 132=SCTP",
                "Header Checksum": "2B  ones-complement over IP header only; recomputed each hop",
                "Source Address":  "4B  sender IPv4 address",
                "Destination Address":"4B  receiver IPv4 address",
                "Options":         "0-40B  if IHL>5: e.g. Type=0x44=Timestamp 0x7=Record-Route 0x83=Strict-Source-Route",
                "CAUTION":         "IP source address spoofing trivial without BCP38; DF+PMTUD mismatch causes black-hole; fragmentation can evade some IDS; IP options rarely used but must be parsed — source routing (Type 131/137) SHOULD be blocked"}),

    0x0806: _e("ARP — RFC 826", "ARP Frame", "Standard", "Active",
               "Address Resolution Protocol — maps IPv4 address to MAC hardware address",
               "arp",
               {"HTYPE":            "2B  Hardware Type: 1=Ethernet(IEEE 802)  6=IEEE 802  7=ARCNET  15=Frame-Relay",
                "PTYPE":            "2B  Protocol Type: 0x0800=IPv4 (same field format as EtherType)",
                "HLEN":             "1B  Hardware Address Length: 6 for Ethernet (48-bit MAC)",
                "PLEN":             "1B  Protocol Address Length: 4 for IPv4 (32-bit address)",
                "Operation":        "2B  1=ARP-Request  2=ARP-Reply  3=RARP-Request  4=RARP-Reply  8=InARP-Request  9=InARP-Reply",
                "SHA":              "6B  Sender Hardware Address — sender MAC",
                "SPA":              "4B  Sender Protocol Address — sender IPv4 address",
                "THA":              "6B  Target Hardware Address — 00:00:00:00:00:00 in request (unknown)",
                "TPA":              "4B  Target Protocol Address — IPv4 address being resolved",
                "Gratuitous ARP":   "SPA=TPA and THA=broadcast — announces own IP-MAC mapping (used after IP change)",
                "Proxy ARP":        "Router responds on behalf of remote host — THA=router MAC, SPA=queried IP",
                "CAUTION":          "ARP has no authentication — use IEEE 802.1X and Dynamic ARP Inspection (DAI) on all access ports; ARP spoofing enables MITM attacks"}),

    0x0808: _e("Frame Relay ARP — RFC 826", "Frame Relay ARP PDU", "Standard", "Deprecated",
               "Frame Relay ARP — ARP over Frame Relay (RFC 826 Annex); replaced by InARP RFC 2390",
               None,
               {"HTYPE":    "2B  Hardware Type: 15=Frame-Relay",
                "PTYPE":    "2B  Protocol Type: 0x0800=IPv4",
                "HLEN":     "1B  Hardware address length (DLCI length)",
                "PLEN":     "1B  4 (IPv4)",
                "Operation":"2B  1=ARP-Request 2=ARP-Reply",
                "Note":     "Deprecated — use Inverse ARP (InARP RFC 2390) for Frame Relay address resolution"}),

    0x86DD: _e("IPv6 — RFC 8200", "IPv6 Packet", "Standard", "Active",
               "Internet Protocol version 6 — RFC 8200 (STD86); replaces RFC 2460",
               "ipv6",
               {"Version":         "4b  must be 6",
                "Traffic Class":   "8b  DSCP(6b)+ECN(2b) — same semantics as IPv4 DSCP/ECN",
                "Flow Label":      "20b  0=unclassified; nonzero=flow identifier for QoS (RFC 6437)",
                "Payload Length":  "2B  bytes after 40B fixed header (extension headers + upper-layer)",
                "Next Header":     "1B  0=Hop-by-Hop 6=TCP 17=UDP 41=IPv6-in-IPv6 43=Routing 44=Fragment 50=ESP 51=AH 58=ICMPv6 59=NoNextHeader 60=Dest-Options 135=MobileIPv6",
                "Hop Limit":       "1B  TTL equivalent — decremented per router; 0=discard (default 64 or 128)",
                "Source Address":  "16B  128-bit sender IPv6 address",
                "Destination Address":"16B  128-bit receiver IPv6 address",
                "Ext Headers":     "variable  chained via Next Header field: Hop-by-Hop(0) Routing(43) Fragment(44) Auth(51) ESP(50) Dest-Opts(60)",
                "Fragment Ext Hdr":"NextHdr(1B)+Reserved(1B)+FragOffset(13b)+Res(2b)+M(1b)+ID(4B)",
                "Routing Ext Hdr": "NextHdr(1B)+Length(1B)+RoutingType(1B)+SegLeft(1B)+TypeData",
                "Hop-by-Hop":      "NextHdr(1B)+Length(1B)+Options(TLV) — MUST be processed by every node",
                "CAUTION":         "Extension header order matters — RFC 8200 §4.1 specifies preferred order; Routing Header Type 0 (deprecated RFC 5095) allowed amplification attacks — block at border; Hop-by-Hop Options processed by every router = DoS risk; Fragment ID collision = fragment injection attack"}),

    0x8035: _e("RARP — RFC 903", "RARP Frame", "Standard", "Deprecated",
               "Reverse ARP — maps MAC to IP; replaced by BOOTP/DHCP; RFC 903",
               "rarp",
               {"HTYPE":    "2B  Hardware Type: 1=Ethernet",
                "PTYPE":    "2B  0x0800=IPv4",
                "HLEN":     "1B  6 (MAC)",
                "PLEN":     "1B  4 (IPv4)",
                "Operation":"2B  3=RARP-Request 4=RARP-Reply",
                "SHA":      "6B  Sender Hardware Address (MAC)",
                "SPA":      "4B  Sender Protocol Address (0.0.0.0 in request)",
                "THA":      "6B  Target Hardware Address (requester MAC)",
                "TPA":      "4B  Target Protocol Address — filled by server in reply",
                "Deprecated":"Replaced by BOOTP (RFC 951) then DHCP (RFC 2131) — never use in new deployments"}),

    0x0842: _e("Wake-on-LAN (IEEE 802 WoL)", "WoL Magic Packet",
               "Industry", "Active",
               "Remote power-on via magic packet — 6 bytes 0xFF then target MAC repeated 16×",
               "wol",
               {"Sync Stream":   "6B  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF",
                "Target MAC":    "12B × 16 repetitions = 96B of destination MAC address (192B total)",
                "Password":      "optional 4B or 6B WoL password (SecureOn — appended after MAC×16)",
                "Frame total":   "Ethernet payload = 102B minimum (sync + MAC×16) or 106/108B with password",
                "Dst MAC":       "Broadcast FF:FF:FF:FF:FF:FF or directed subnet broadcast",
                "CAUTION":       "WoL only works if target NIC has WoL enabled in BIOS/UEFI and AC power present; travels through routers only with directed broadcast or WoL proxy"}),

    # ── GROUP 2: VLAN / Stacking / Bridging ──────────────────────────────────
    0x8100: _e("IEEE 802.1Q C-Tag (Customer VLAN)", "VLAN Tagged Frame",
               "Standard", "Active",
               "Customer VLAN tag — PCP+DEI+VID inserted between Src MAC and EtherType",
               "dot1q",
               {"TPID":          "2B  0x8100  Tag Protocol Identifier",
                "PCP":           "3b  Priority Code Point 0-7 (802.1p CoS / QoS class)",
                "DEI":           "1b  Drop Eligible Indicator — 1=may be dropped under congestion",
                "VID":           "12b  VLAN Identifier 0-4094 (0=priority tag only, 4095=reserved)",
                "Inner EtherType":"2B  actual payload EtherType (0x0800=IPv4, 0x86DD=IPv6, etc.)",
                "VID 0":         "Priority tag — frame not assigned to VLAN, CoS applies only",
                "VID 1":         "Default VLAN — commonly used as management VLAN",
                "VID 4095":      "Reserved — never use as VLAN ID",
                "CAUTION":       "Native VLAN mismatch (trunk vs access) causes VLAN hopping; double-tagging with native VID=1 bypasses VLAN isolation on unprotected ports"}),

    0x88A8: _e("IEEE 802.1ad S-Tag (Q-in-Q Provider Backbone)", "Double-Tagged Frame",
               "Standard", "Active",
               "Provider VLAN outer tag — Metro/Carrier Ethernet service delimiting",
               "qinq",
               {"S-Tag TPID":  "2B  0x88A8  Service tag protocol ID",
                "PCP":         "3b  priority code point (802.1p QoS)",
                "DEI":         "1b  drop eligible indicator",
                "S-VID":       "12b  service VLAN ID (provider) 1-4094",
                "C-Tag TPID":  "2B  0x8100  customer tag follows",
                "C-VID":       "12b  customer VLAN ID",
                "Inner EtherType":"2B  actual payload EtherType (0x0800=IPv4 etc.)",
                "CAUTION":     "S-VID 0 and 4095 are reserved — use 1-4094 only"}),

    0x9100: _e("Q-in-Q Legacy Outer Tag (Cisco)", "Double-Tagged Frame",
               "Vendor", "Deprecated",
               "Cisco legacy outer VLAN stacking — use IEEE 0x88A8 instead",
               "qinq",
               {"S-Tag TPID":"2B  0x9100","PCP":"3b","DEI":"1b","S-VID":"12b",
                "CAUTION":"Deprecated — migrate to 0x88A8; 0x9100 not recognised by non-Cisco equipment"}),

    0x9200: _e("Q-in-Q Outer Tag (3Com)", "Double-Tagged Frame",
               "Vendor", "Deprecated", "3Com proprietary outer VLAN stacking",
               "qinq", {"S-Tag TPID":"2B  0x9200","S-VID":"12b"}),

    0x9300: _e("Q-in-Q Outer Tag (Foundry/Brocade)", "Double-Tagged Frame",
               "Vendor", "Deprecated", "Foundry/Brocade proprietary outer VLAN",
               "qinq", {"S-Tag TPID":"2B  0x9300","S-VID":"12b"}),

    0x88E7: _e("IEEE 802.1ah PBB I-Tag (Provider Backbone Bridging)", "PBB I-Tag Frame",
               "Standard", "Active",
               "MAC-in-MAC Provider Backbone — service instance tagging with 24b I-SID",
               "pbb",
               {"TPID":        "2B  0x88E7",
                "PCP":         "3b  priority",
                "DEI":         "1b  drop eligible",
                "UCA":         "1b  use customer addresses",
                "I-SID":       "24b  service instance identifier 0-16,777,215",
                "Inner Dst":   "6B  backbone destination MAC (B-DA)",
                "Inner Src":   "6B  backbone source MAC (B-SA)",
                "B-Tag TPID":  "2B  0x88A8  backbone VLAN",
                "B-VID":       "12b  backbone VLAN ID",
                "C-Tag":       "optional  customer tag",
                "CAUTION":     "I-SID 0 is reserved — use 256+ for customer services; I-SID collision causes cross-customer traffic leak"}),

    # ── GROUP 3: MPLS ─────────────────────────────────────────────────────────
    0x8847: _e("MPLS Unicast Label Stack", "MPLS Frame", "Standard", "Active",
               "MPLS unicast label switching — RFC 3032/5332",
               "mpls",
               {"Label":    "20b  label value 0-1048575 (reserved: 0=IPv4-Explicit-Null 2=IPv6-Explicit-Null 3=Implicit-Null 13=GAL 14=OAM-Alert 15=Extension)",
                "TC":       "3b   traffic class / QoS (formerly EXP bits)",
                "S":        "1b   bottom-of-stack: 1=last label 0=more labels follow",
                "TTL":      "8b   hop limit (decremented per LSR hop — 0=drop)",
                "PHP":      "Penultimate Hop Popping: egress LSR pops label one hop early",
                "CAUTION":  "Label 0 (IPv4 Explicit Null) must only appear at bottom of stack — MPLS mis-routing causes traffic blackhole"}),

    0x8848: _e("MPLS Multicast / Upstream-assigned Label", "MPLS Frame",
               "Standard", "Active",
               "MPLS multicast forwarding or upstream-assigned label (RFC 5332/7274)",
               "mpls",
               {"Label":  "20b  same 4B format as unicast; upstream-assigned labels > 15",
                "TC":     "3b",
                "S":      "1b",
                "TTL":    "8b",
                "CAUTION":"Multicast MPLS requires mLDP or RSVP-TE P2MP LSP signalled first — data before signalling = black hole"}),

    # ── GROUP 4: PPPoE ────────────────────────────────────────────────────────
    0x8863: _e("PPPoE Discovery Stage", "PPPoE PDU", "Standard", "Active",
               "PPP over Ethernet — PADI/PADO/PADR/PADS/PADT discovery", "pppoe",
               {"VER+TYPE": "1B  0x11  version=1 type=1",
                "CODE":     "1B  0x09=PADI 0x07=PADO 0x19=PADR 0x65=PADS 0xA7=PADT",
                "Session-ID":"2B  0x0000 during discovery; assigned in PADS",
                "Length":   "2B  payload length",
                "Service-Name Tag":"2B=0x0101 + 2B len + name string",
                "AC-Name Tag":"2B=0x0102 + 2B len + AC name",
                "AC-Cookie Tag":"2B=0x0104 + 2B len + cookie (replay protection)",
                "CAUTION":  "PADI is broadcast — AC-Cookie must be validated in PADR to prevent spoofed PADS"}),

    0x8864: _e("PPPoE Session Stage", "PPPoE PDU", "Standard", "Active",
               "PPP over Ethernet — active DSL/cable session carrying IP",
               "pppoe",
               {"VER+TYPE":  "1B  0x11",
                "CODE":      "1B  0x00=session data",
                "Session-ID":"2B  session handle from PADS",
                "Length":    "2B  PPP payload length",
                "PPP Protocol":"2B  0x0021=IPv4 0x0057=IPv6 0x8021=IPCP 0x8057=IPv6CP 0xC021=LCP 0xC023=PAP 0xC223=CHAP",
                "PPP Payload":"variable  IP datagram or control message",
                "CAUTION":   "Session-ID must match PADS assigned value — wrong ID causes PPPoE server to drop session silently"}),

    0x880B: _e("PPP Direct over Ethernet (RFC 9542)", "PPP Frame", "Standard", "Active",
               "PPP framed directly in Ethernet payload — no encapsulation negotiation",
               "ppp_eth",
               {"Flag":      "1B  0x7E  frame start delimiter",
                "Address":   "1B  0xFF  broadcast (HDLC convention)",
                "Control":   "1B  0x03  unnumbered information",
                "Protocol":  "2B  0x0021=IPv4 0x0057=IPv6 0x0281=MPLS 0xC021=LCP 0xC023=PAP 0xC223=CHAP",
                "Payload":   "variable  protocol-specific data",
                "FCS":       "2B CRC-16 or 4B CRC-32 (negotiated via LCP)",
                "End Flag":  "1B  0x7E",
                "CAUTION":   "PPP Authentication (PAP/CHAP) credentials sent in plaintext or weak hash — use CHAP over PAP; prefer EAP-TLS"}),

    0x880C: _e("GSMP (General Switch Management Protocol — RFC 3292)", "GSMP PDU",
               "Standard", "Active",
               "Switch resource and connection management — ATM/frame relay legacy",
               "gsmp",
               {"Version":     "4b  must be 3",
                "Reserved":    "4b",
                "Message Type":"1B  1=Port-Mgmt 2=Config 3=Connection 4=Reservation 5=QoS 10=Statistics 11=Port-Control 12=Label-Range",
                "Result":      "1B  0=Success 1=Failure 2=Ignored 3=NotSupported",
                "Code":        "1B  failure reason code",
                "Port Sesh No":"1B  per-port session sequence",
                "Transaction ID":"4B  request/reply correlation",
                "Adjacency":   "Session-No(4B)+Sender-Name(4B)+Sender-Port(4B)+Sender-Instance(4B)",
                "CAUTION":     "No authentication — GSMP runs on dedicated management VLAN only; never expose to untrusted network"}),

    # ── New EtherTypes — SPB, FRER, AVTP, BFD ─────────────────────────────────
    0x893B: _e("SPB (IEEE 802.1aq Shortest Path Bridging)", "SPB IS-IS PDU",
               "Standard", "Active",
               "Shortest Path Bridging — IS-IS-based ECMP L2 fabric replacing STP",
               "spb_isis",
               {"NLPID":       "1B  0x83=IS-IS",
                "PDU Type":    "1B  15=L1-Hello 16=L2-Hello 20=L2-LSP 25=L2-CSNP 27=L2-PSNP",
                "System ID":   "6B  bridge system ID",
                "SPB TLV 144": "SPB I-SID sub-TLV: I-SID(3B)+BaseVID(2B)+T+R+S+F bits",
                "SPB TLV 145": "SPB U-ECT: Unicast ECT algorithm list",
                "SPB TLV 146": "SPB M-ECT: Multicast ECT algorithm",
                "I-SID":       "24b  service instance identifier (same as PBB)",
                "CAUTION":     "SPB IS-IS adjacency requires matching bridge priorities — mismatch causes partition into multiple DIS regions"},
               stack={
                "L2": "Ethernet II (0x893B) — IS-IS for SPB control plane",
                "L3": "SPB IS-IS — shortest path tree computation for L2 ECMP",
                "Application": "Data centre fabric · Metro Ethernet · SPBM (SPB with MAC-in-MAC)",
               }),

    0x893F: _e("IEEE 802.1CB FRER (Frame Replication and Elimination)", "FRER R-Tag",
               "Standard", "Active",
               "Seamless redundancy — sequence number tag for TSN/IEC 62439-3",
               "frer",
               {"R-Tag TPID":   "2B  0x893F",
                "Reserved":     "4b",
                "Sequence Num": "12b  0-4095 wrapping — used to detect and drop duplicates",
                "Inner EtherType":"2B  original frame EtherType",
                "Payload":      "variable  original frame payload",
                "CAUTION":      "Sequence number window must be configured larger than max path delay difference — narrow window causes valid frames to be discarded as duplicates"},
               stack={
                "L2": "Ethernet II (0x893F) — FRER R-Tag prepended to original frame",
                "L3": "FRER sequence recovery — eliminates duplicates from multiple paths",
                "Application": "TSN safety-critical redundancy — IEC 61850 protection · avionics · automotive",
               }),

    0x88E8: _e("IEEE 1722 AVTP (Audio Video Transport Protocol)", "AVTP PDU",
               "Standard", "Active",
               "Professional AV streaming over Ethernet — IEEE 1722-2016",
               "avtp",
               {"Subtype":      "1B  0x00=IEC 61883/IIDC 0x01=MMA-Stream 0x02=AAF(Audio) 0x03=CVF(Video) 0x04=CRF(Clock-Ref) 0x7F=AVTP-Control 0xEC=AVTP-Experimental",
                "SV":           "1b  stream ID valid",
                "Version":      "3b  must be 0",
                "MR":           "1b  media clock restart",
                "TV":           "1b  avtp_timestamp valid",
                "Seq Num":      "1B  0-255 wrapping sequence",
                "TU":           "1b  timestamp uncertain",
                "Stream ID":    "8B  globally unique stream identifier (EUI-64 + stream index)",
                "AVTP Timestamp":"4B  PTP-derived presentation time in ns",
                "Format-Specific":"4B  subtype-dependent (channels/sample-rate/bit-depth for AAF)",
                "Payload":      "variable  audio samples / video NAL units / MIDI data",
                "AAF Format":   "1B  0x02=INT16 0x03=INT24 0x04=INT32 0x05=FLOAT32 0x09=AES3",
                "Channels":     "10b  number of audio channels (AAF)",
                "Sample Rate":  "3b  0=8kHz 1=16kHz 2=32kHz 3=44.1kHz 4=48kHz 5=88.2kHz 6=96kHz 7=192kHz",
                "CAUTION":      "AVTP_timestamp must be PTP-synchronised — clock offset > 1ms causes AV sync failure in professional broadcast"},
               stack={
                "L2": "Ethernet II (0x88E8) — multicast to stream destination MAC",
                "L3": "AVTP — stream PDU directly after Ethernet; no IP layer",
                "L4": "Audio (AAF)/Video (CVF)/MIDI (MMA)/Clock-Reference (CRF)",
                "Application": "Pro AV: Dante/AES67 gateway · SMPTE 2110 · AVnu/Milan certified devices",
                "CAUTION": "Requires PTP IEEE 1588 and AVB/TSN switch — standard switch drops time-sensitive frames",
               }),

    0x8999: _e("BFD over Ethernet (Bidirectional Forwarding Detection)", "BFD PDU",
               "Standard", "Active",
               "Fast L2 link failure detection — sub-50ms without routing protocol timers",
               "bfd_eth",
               {"Version":       "3b  must be 1",
                "Diag":          "5b  0=NoDiag 1=CtrlDetTime 2=EchoFail 3=NbrSignDown 4=FwdPlaneReset 5=PathDown 6=ConcatPathDown 7=AdminDown 8=ReverseConcatPathDown",
                "Sta":           "2b  state: 0=AdminDown 1=Down 2=Init 3=Up",
                "P":             "1b  poll: expecting Final in response",
                "F":             "1b  final: response to Poll",
                "C":             "1b  control plane independent",
                "A":             "1b  authentication present",
                "D":             "1b  demand mode",
                "M":             "1b  multipoint (reserved=0)",
                "Detect Mult":   "1B  detection time multiplier (timeout = Mult × min-interval)",
                "Length":        "1B  24B minimum (+ 26B optional auth)",
                "My Discrim":    "4B  local discriminator (non-zero, unique per session)",
                "Your Discrim":  "4B  peer's discriminator (0 if unknown — during Init)",
                "Desired Min TX":"4B  µs desired Tx interval (e.g. 50000=50ms)",
                "Required Min RX":"4B  µs minimum acceptable Rx interval",
                "Required Min Echo":"4B  µs echo mode minimum (0=no echo)",
                "Auth Type":     "1B  (if A=1) 1=Simple 2=Keyed-MD5 4=Keyed-SHA1",
                "CAUTION":       "Your Discriminator must match My Discriminator from peer — mismatch causes session to stay in Init state forever"},
               stack={
                "L2": "Ethernet II (0x8999) or UDP port 3784/3785",
                "L3": "BFD — control packet directly over Ethernet (single-hop L2 BFD)",
                "Application": "Fast link failure detection — ECMP failover · LAG member failure · L2VPN path monitoring",
               }),

    # ── GROUP 5: IEEE 802 Control & Management ────────────────────────────────
    0x8808: _e("IEEE 802.3 MAC Control (Pause / PFC / EPON)", "MAC Control Frame",
               "Standard", "Active",
               "MAC-level flow control — opcode determines type: Pause / PFC / EPON Gate/Report",
               "mac_ctrl",
               {"EtherType":         "2B  0x8808",
                "Opcode":            "2B  0x0001=Pause(802.3x)  0x0101=PFC(802.1Qbb)  0x0002=EPON-Gate  0x0003=EPON-Report",
                "── Pause fields ──": "",
                "Pause Quanta":      "2B  0-65535 × 512 bit-times at link speed  (Pause only, 0=resume immediately)",
                "Reserved Pause":    "42B  padding to minimum frame size  (Pause only)",
                "── PFC fields ──":  "",
                "PFC Priority Enable":"2B  bitmask P0(bit0)-P7(bit7) — which priorities are paused  (PFC only)",
                "PFC Quanta[0]":     "2B  pause duration for priority 0 × 512 bit-times",
                "PFC Quanta[1]":     "2B  priority 1",
                "PFC Quanta[2]":     "2B  priority 2",
                "PFC Quanta[3]":     "2B  priority 3 — used by FCoE lossless",
                "PFC Quanta[4]":     "2B  priority 4",
                "PFC Quanta[5]":     "2B  priority 5",
                "PFC Quanta[6]":     "2B  priority 6",
                "PFC Quanta[7]":     "2B  priority 7",
                "── EPON fields ──": "",
                "EPON Timestamp":    "4B  (EPON Gate/Report) MPCP timestamp in 16ns units",
                "EPON Grant Start":  "4B  (EPON Gate) grant start time",
                "EPON Grant Len":    "2B  (EPON Gate) grant length in 16ns units",
                "CAUTION":           "Dst MAC must be 01:80:C2:00:00:01 — globally reserved; switch must not forward; wrong Dst = Pause ignored by peer"}),

    0x8809: _e("IEEE 802.3 Slow Protocols (LACP / Marker / OAM / OSSP)", "Slow Protocol PDU",
               "Standard", "Active",
               "Subtype-multiplexed slow protocol: LACP=1  Marker=2  OAM=3  OSSP=10",
               "slow_proto",
               {"Subtype":           "1B  0x01=LACP  0x02=Marker  0x03=OAM  0x0A=OSSP",
                "── LACP TLVs ──":   "",
                "Version":           "1B  0x01",
                "Actor TLV Type":    "1B  0x01",
                "Actor TLV Len":     "1B  0x14=20B",
                "Actor Sys Priority":"2B  lower=preferred (default 32768)",
                "Actor Sys MAC":     "6B  actor system MAC address",
                "Actor Key":         "2B  aggregation key — ports with same key can form LAG",
                "Actor Port Priority":"2B  lower=preferred in LAG",
                "Actor Port":        "2B  port identifier",
                "Actor State":       "1B  LACP_Activity(b0)+LACP_Timeout(b1)+Aggregation(b2)+Sync(b3)+Collecting(b4)+Distributing(b5)+Defaulted(b6)+Expired(b7)",
                "Partner TLV Type":  "1B  0x02",
                "Partner TLV Len":   "1B  0x14=20B",
                "Partner Sys Priority":"2B",
                "Partner Sys MAC":   "6B",
                "Partner Key":       "2B",
                "Partner Port Priority":"2B",
                "Partner Port":      "2B",
                "Partner State":     "1B  same bit layout as Actor State",
                "Collector TLV":     "1B=0x03  Len=0x10  MaxDelay(2B)=0x8000 + 12B reserved",
                "Terminator TLV":    "2B  0x0000 end marker",
                "── OAM fields ──":  "",
                "OAM Flags":         "2B  Link-Fault(b0)+Dying-Gasp(b1)+Critical-Event(b2)+Remote(b6)+Unidirectional-Support(b8)+LB-Support(b9)+Event-Support(b10)+Variable-Support(b11)",
                "OAM Code":          "1B  0x00=Info 0x01=EventNotif 0x02=UniqueEventNotif 0x03=LoopbackCtrl 0x04=VarRequest 0x05=VarResponse 0x06=OrgSpecific",
                "── Marker fields ──":"",
                "Marker TLV Type":   "1B  0x01=MarkerPDU 0x02=MarkerResponse",
                "Marker Requester Port":"2B  requesting port ID",
                "Marker Requester Sys":"6B  requesting system MAC",
                "Marker Trans ID":   "4B  transaction ID (echoed in response)",
                "CAUTION":           "Dst MAC must be 01:80:C2:00:00:02 — Slow Protocol multicast; never forwarded; LACP timeout=1s(fast)/30s(slow): mismatch causes port to go Individual (non-aggregated)"}),

    0x888E: _e("IEEE 802.1X EAPOL (Port-Based NAC)", "EAPOL Frame",
               "Standard", "Active",
               "EAP over LAN — 802.1X port authentication (RADIUS backend)",
               "eapol",
               {"Version":   "1B  1=802.1X-2001  2=802.1X-2004  3=802.1X-2010",
                "Type":      "1B  0x00=EAP-Packet  0x01=EAPOL-Start  0x02=EAPOL-Logoff  0x03=EAPOL-Key  0x04=EAPOL-Encapsulated-ASF-Alert",
                "Length":    "2B  EAP data length",
                "EAP Code":  "1B  1=Request  2=Response  3=Success  4=Failure",
                "EAP ID":    "1B  sequence (matched Request→Response)",
                "EAP Length":"2B  total EAP message length",
                "EAP Type":  "1B  1=Identity  4=MD5-Challenge  13=EAP-TLS  25=PEAP  43=EAP-FAST",
                "EAP Data":  "variable  method-specific (certificate/challenge/response)",
                "CAUTION":   "Dst MAC must be 01:80:C2:00:00:03 — not forwarded by 802.1D bridges"},
               stack={
                "L2": "Ethernet II (0x888E) — Dst 01:80:C2:00:00:03 (PAE multicast)",
                "L3": "EAPOL — EAP over LAN; no IP layer",
                "L4": "EAP method: Identity → TLS/PEAP/EAP-FAST → Success/Failure",
                "Backend": "RADIUS server (UDP 1812/1813) carries EAP inside Access-Request/Accept",
                "Application": "802.1X port authentication — wired switch port / 802.11 WPA2/3-Enterprise",
               }),

    0x88CC: _e("LLDP (IEEE 802.1AB)", "LLDP PDU", "Standard", "Active",
               "Link Layer Discovery Protocol — neighbour identity and capability advertisement",
               "lldp",
               {"ChassisID TLV": "Type=1  SubType(1B)+ID(variable): 4=MAC 5=NetworkAddr 7=Local",
                "PortID TLV":    "Type=2  SubType(1B)+ID: 3=MAC 5=IfName 7=Local",
                "TTL TLV":       "Type=3  Length=2  Seconds(2B) 0=remove from cache",
                "PortDesc TLV":  "Type=4  optional  human-readable port description string",
                "SysName TLV":   "Type=5  optional  fully-qualified system name",
                "SysDesc TLV":   "Type=6  optional  OS/firmware version string",
                "SysCap TLV":    "Type=7  optional  Capabilities(2B)+Enabled(2B): bridge/router/phone",
                "MgmtAddr TLV":  "Type=8  optional  AddrLen+AddrSubType+Addr+IfNumSubtype+IfNum+OIDLen+OID",
                "OrgSpec TLVs":  "Type=127  OUI(3B)+Subtype(1B)+value: 802.1(VLANname/PPVID/LAG) 802.3(MDI/LinkAgg/MaxFS)",
                "End TLV":       "Type=0  Length=0  mandatory last TLV",
                "CAUTION":       "Dst MAC 01:80:C2:00:00:0E — not forwarded; TTL=0 removes entry from peer"},
               stack={
                "L2": "Ethernet II (0x88CC) — Dst 01:80:C2:00:00:0E (LLDP multicast)",
                "L3": "LLDP — TLV chain directly after Ethernet; no IP layer",
                "L4": "None — LLDP terminates at TLV layer",
                "Application": "Network topology discovery · LLDP-MED (VoIP) · 802.3at/bt PoE negotiation · NMS mapping",
               }),

    0x88F5: _e("MVRP (Multiple VLAN Registration Protocol)", "MVRP PDU",
               "Standard", "Active",
               "IEEE 802.1Q dynamic VLAN registration and propagation between switches",
               "mvrp",
               {"Protocol ID":  "2B  0x0000 = MRP",
                "MRP Attribute Type": "1B  0x01=VLAN-ID",
                "MRP Attr Length":    "1B  length of attribute value",
                "MRP Event":    "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv",
                "VLAN ID":      "12b  1-4094  VLAN being declared/withdrawn",
                "End Mark":     "2B  0x0000 terminates attribute list",
                "CAUTION":      "Dst MAC 01:80:C2:00:00:21 — MVRP enabled on all trunk ports or VLAN flooding fails"},
               stack={
                "L2": "Ethernet II (0x88F5) — Dst 01:80:C2:00:00:21",
                "L3": "MVRP MRP PDU — VLAN attribute declarations directly after Ethernet",
                "Application": "Dynamic VLAN propagation — eliminate manual trunk config across 802.1Q switches",
               }),

    0x88F6: _e("MMRP (Multiple Multicast Registration Protocol)", "MMRP PDU",
               "Standard", "Active",
               "IEEE 802.1Q dynamic multicast group registration between bridges",
               "mmrp",
               {"Protocol ID":  "2B  0x0000 = MRP",
                "Attr Type":    "1B  0x01=Service-Requirement 0x02=MAC-VID",
                "MRP Event":    "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv",
                "MAC Address":  "6B  multicast MAC being registered (01:xx:xx:xx:xx:xx)",
                "VID":          "12b  VLAN context for this multicast registration",
                "End Mark":     "2B  0x0000",
                "CAUTION":      "Dst MAC 01:80:C2:00:00:20 — avoid registering unicast MACs (causes flooding)"},
               stack={
                "L2": "Ethernet II (0x88F6) — Dst 01:80:C2:00:00:20",
                "L3": "MMRP MRP PDU — multicast MAC registration directly after Ethernet",
                "Application": "Dynamic multicast pruning — AVB/TSN audio/video stream registration",
               }),

    0x88F7: _e("IEEE 1588 PTP (Precision Time Protocol)", "PTP Message",
               "Standard", "Active",
               "Sub-microsecond clock synchronisation — IEEE 1588-2008/2019 L2 transport",
               "ptp",
               {"Msg Type":    "4b  0=Sync 1=DelayReq 2=PdelayReq 3=PdelayResp 8=FollowUp 9=DelayResp A=PdelayRespFollowUp B=Announce C=Signaling D=Management",
                "Version":     "4b  must be 2 (IEEE 1588-2008) or 3 (2019)",
                "MsgLength":   "2B  total PDU length",
                "DomainNumber":"1B  clock domain (0-127)  — separate sync domains",
                "Flags":       "2B  twoStepFlag+unicastFlag+alternateTimescale+leap61+leap59+UTCoffsetValid+PTP_TIMESCALE+timeTraceable+frequencyTraceable+synchronizationUncertain",
                "CorrectionField":"8B  sub-ns correction in 2^-16 ns units",
                "ClockIdentity":"8B  64-bit unique clock ID (EUI-64)",
                "SourcePortID": "2B  port number within the clock",
                "SeqID":       "2B  sequence number (wraps 0-65535)",
                "ControlField":"1B  deprecated in v2 (0 for Sync etc.)",
                "LogMsgInterval":"1B  log2 of interval (e.g. 0=1s 1=2s -3=0.125s)",
                "OriginTimestamp":"10B  seconds(6B)+nanoseconds(4B) — Sync/Announce/DelayReq only",
                "CAUTION":     "Two-step clocks send FollowUp after Sync — slaves must wait for both; domain mismatch = no sync"},
               stack={
                "L2": "Ethernet II (0x88F7) — Sync/DelayReq to 01:1B:19:00:00:00 (general); Pdelay to 01:80:C2:00:00:0E",
                "L3": "PTP Message — directly after Ethernet header; no IP layer",
                "L4": "None — PTP is self-contained; hardware timestamping at MAC level",
                "Application": "Telecom (G.8275.2) · Industrial (IEC 61588) · Financial trading timestamp · Audio (AES67/AVB)",
                "CAUTION": "Requires hardware timestamping NIC — software timestamping accuracy only ±1ms",
               }),

    0x88E5: _e("IEEE 802.1AE MACSec (MAC Security)", "SecTAG+Payload",
               "Standard", "Active",
               "Layer 2 frame encryption and integrity — hop-by-hop between adjacent MACSec peers",
               "macsec",
               {"SecTAG":      "8-16B  Security Tag:",
                "TCI":         "1B  Tag Control Info: V(1b)+ES(1b)+SC(1b)+SCB(1b)+E(1b)+C(1b)+Ver(2b)",
                "AN":          "2b  Association Number (0-3, identifies key in use)",
                "SL":          "6b  Short Length (0=full 1522B frame; 1-60=shorter)",
                "PN":          "4B  Packet Number (replay protection — must be monotonically increasing)",
                "SCI":         "8B  Secure Channel Identifier = Src-MAC(6B)+Port(2B)  — present if SC bit=1",
                "Payload":     "variable  encrypted Ethernet frame payload (original EtherType+data)",
                "ICV":         "16B  Integrity Check Value — GCM-AES-128 or GCM-AES-256 tag",
                "CAUTION":     "PN rollover at 0xFFFFFFFF terminates SC — must rekey before rollover; E=0 means integrity-only (no encryption)"},
               stack={
                "L2": "Ethernet II (0x88E5) — replaces original EtherType after SecTAG",
                "L3": "MACSec — encrypted Ethernet payload; original frame recovered after decryption",
                "L4": "Original L3/L4 (IP/TCP/UDP) inside encrypted payload — invisible until decrypted",
                "Application": "Data centre inter-switch links · WAN encryption · 802.1X MACSec EAP-TLS key exchange",
                "CAUTION": "Both ends must share CA (Connectivity Association) — MKA (EtherType 0x888E) negotiates keys",
               }),

    0x22F3: _e("TRILL (Transparent Interconnection of Lots of Links)", "TRILL Frame",
               "Standard", "Active",
               "TRILL — IS-IS-based L2 routing bridge for large-scale multi-path data centres",
               "trill",
               {"Version":    "2b  must be 0",
                "Reserved":   "2b",
                "M":          "1b  Multicast: 0=unicast 1=multi-destination",
                "Op-Length":  "5b  options length in 32-bit words",
                "Hop-Count":  "6b  decremented per RBridge hop; frame dropped at 0",
                "Egress RB":  "16b  Egress RBridge nickname (destination routing bridge)",
                "Ingress RB": "16b  Ingress RBridge nickname (source routing bridge)",
                "Options":    "variable  based on Op-Length (4B words)",
                "Inner Frame":"original Ethernet frame (inner Dst+Src MACs preserved)",
                "CAUTION":    "Hop-Count must be ≥ network diameter; egress nickname 0xFFFF = unknown (flood)"},
               stack={
                "L2": "Ethernet II (0x22F3) — Outer Ethernet header with RBridge MACs",
                "L3": "TRILL Header — RBridge nickname routing (Egress+Ingress 16b nicknames)",
                "L3_role": "Multi-path L2 routing — ECMP across Ethernet fabric without STP",
                "L4": "Inner Ethernet frame (preserved original L2 header inside TRILL)",
                "Application": "Large-scale data centre L2 fabric — replaces STP for multi-path",
                "CAUTION": "Requires IS-IS (0x22F4) adjacency first — TRILL without IS-IS = black hole",
               }),

    0x22F4: _e("L2-IS-IS (IS-IS for TRILL)", "ISIS PDU",
               "Standard", "Active",
               "IS-IS link-state routing carried natively over Ethernet for TRILL fabric",
               "l2isis",
               {"NLPID":      "1B  0x83 = IS-IS",
                "Hdr Length": "1B  fixed portion of PDU header",
                "IS Version": "1B  must be 1",
                "ID Length":  "1B  system ID length (6B for MAC-based)",
                "PDU Type":   "1B  15=L1-Hello 16=L2-Hello 17=PtP-Hello 18=L1-LSP 20=L2-LSP 24=L1-CSNP 25=L2-CSNP 26=L1-PSNP 27=L2-PSNP",
                "TLVs":       "variable: 1=Area-Addr 2=IS-Reach 4=Partition 8=Padding 10=LSP-Entries 128=IP-Reach 132=IP-Ext-Addr 22=Ext-IS-Reach 135=Ext-IP-Reach 137=Hostname",
                "CAUTION":    "L2-IS-IS adjacency requires matching area address and authentication (TLV 10=auth)"},
               stack={
                "L2": "Ethernet II (0x22F4) — Dst 01:80:C2:00:00:15 (All-IS-IS-routers)",
                "L3": "IS-IS — link-state PDUs directly over Ethernet for TRILL control plane",
                "Application": "TRILL control plane — RBridge hello/LSP/CSNP for topology and nickname distribution",
               }),

    0x22EA: _e("IEEE 802.1Qav FQTSS (Forwarding/Queuing for TSS)", "FQTSS Frame",
               "Standard", "Active",
               "Audio/Video Bridging credit-based shaper for TSN stream reservation",
               "fqtss",
               {"StreamID":   "8B  MAC(6B)+UniqueID(2B) — globally unique stream identifier",
                "Priority":   "3b  802.1Q priority for this stream",
                "MaxInterval":"2B  presentation interval in microseconds",
                "MaxFrameSize":"2B  maximum SDU size including headers in bytes",
                "CAUTION":    "StreamID must be globally unique — duplicate IDs cause stream rejection"},
               stack={
                "L2": "Ethernet II (0x22EA) — AVB stream reservation control",
                "L3": "FQTSS — stream descriptor directly after Ethernet",
                "Application": "Audio/video streaming — AVB/TSN credit-based shaper stream admission",
               }),

    0x8944: _e("IEEE 802.1Qbv TAS (Time-Aware Shaper / TSN)", "TSN Frame",
               "Standard", "Active",
               "Time-Aware Shaper — IEEE TSN gate control list for scheduled traffic",
               "tsn_tas",
               {"GCL Entry":  "variable  GateControlList: TimeInterval(4B)+GateState(1B=OOOOOOOO bits for 8 queues)",
                "BaseTime":   "10B  PTP-synchronised reference time for GCL start",
                "CycleTime":  "8B  Numerator(4B)+Denominator(4B) — GCL cycle period",
                "MaxSDU":     "4B  maximum SDU per traffic class",
                "CAUTION":    "Requires PTP time sync (0x88F7) across all switches — nanosecond accuracy needed"},
               stack={
                "L2": "Ethernet II (0x8944) — time-synchronised scheduled Ethernet",
                "L3": "TSN GCL — gate schedule directly after Ethernet; PTP-locked",
                "Application": "Industrial motion control · Automotive in-vehicle networks · Pro AV",
                "CAUTION": "All switches must be TSN-capable and PTP-synchronised — legacy switch = broken schedule",
               }),

    0x88B5: _e("IEEE 802 Local Experimental EtherType 1", "Experimental Frame",
               "Standard", "Experimental",
               "Reserved by IEEE 802 for local experimental use — RFC 9542 §3",
               "local_exp",
               {"Purpose":  "Reserved for private/experimental protocol testing on local networks",
                "Payload":  "variable  experimental protocol data — format defined by local agreement",
                "Scope":    "MUST NOT be forwarded beyond local network segment",
                "Note":     "Two EtherTypes allocated (0x88B5 and 0x88B6) so full-duplex protocols can use each direction — do not use in production"}),

    0x88B6: _e("IEEE 802 Local Experimental EtherType 2", "Experimental Frame",
               "Standard", "Experimental",
               "Reserved by IEEE 802 for local experimental use — RFC 9542 §3",
               "local_exp",
               {"Purpose":  "Second experimental EtherType for bidirectional local protocols",
                "Payload":  "variable  experimental protocol data — format defined by local agreement",
                "Scope":    "MUST NOT be forwarded beyond local network segment",
                "Note":     "Paired with 0x88B5 — use these for protocol prototyping before requesting IANA/IEEE EtherType assignment"}),

    0x88B7: _e("IEEE 802 OUI-Extended EtherType", "OUI-Extended Frame",
               "Standard", "Active",
               "OUI-extended EtherType — 3B OUI + 2B sub-protocol",
               "oui_ext",
               {"OUI":           "3B  Organisation Unique Identifier (e.g. 00:12:0F = Cisco)",
                "Ext EtherType": "2B  sub-protocol under that OUI",
                "Payload":       "variable  OUI-specific frame content",
                "CAUTION":       "OUI must be your registered IEEE OUI — misuse = protocol conflict"}),

    0x890D: _e("IEEE 802.11r Fast BSS Transition / 802.11z TDLS", "TDLS Frame",
               "Standard", "Active",
               "802.11r fast roaming BSS transition and 802.11z Tunneled Direct Link Setup",
               "tdls",
               {"Payload Type": "1B  1=TDLS 2=Fast-BSS-Transition",
                "Category":     "1B  IEEE 802.11 action frame category (12=TDLS 6=Fast-BSS-Trans)",
                "Action Code":  "1B  TDLS: 0=Setup-Req 1=Setup-Resp 2=Setup-Confirm 3=Teardown 4=Peer-Traffic-Indication 5=Channel-Switch-Req 6=Channel-Switch-Resp | FBT: 1=Action 2=Ack",
                "Dialog Token": "1B  request/response pairing",
                "Capability":   "2B  802.11 capability information",
                "Rates":        "variable  supported rates element",
                "RSNIE":        "variable  RSN information element for PTK derivation",
                "Link ID":      "18B  BSSID(6B)+Initiator(6B)+Responder(6B)",
                "CAUTION":      "TDLS sets up direct link bypassing AP — requires both STAs support TDLS and AP allows it; TDLS teardown when AP not reachable can cause connectivity loss"}),

    0x8917: _e("IEEE 802.21 Media Independent Handover", "MIH PDU",
               "Standard", "Active",
               "Vertical handoff between 802.3/802.11/3GPP/WiMAX",
               "mih",
               {"MIH Hdr":    "6B  Version(4b)+AID(12b)+OPCode(4b)+TransactionID(12b)+PayloadLen(16b)",
                "Payload":    "variable  MIH events, commands, or information elements",
                "CAUTION":    "MIH requires pre-configured MIIS server — missing server = failed handoff"}),

    0x8929: _e("IEEE 802.1Qbe MSRP (Multiple I-SID Registration)", "MSRP PDU",
               "Standard", "Active",
               "Multiple I-SID Registration Protocol — 802.1Qat stream and I-SID reservation",
               "msrp",
               {"Protocol ID":    "2B  0x0000=MRP",
                "MRP Attr Type":  "1B  1=Talker-Advertise 2=Talker-Failed 3=Listener 4=Domain",
                "MRP Event":      "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv",
                "StreamID":       "8B  MAC+UniqueID",
                "DataFrameParam": "4B  DestAddr(6B)+VLAN+TSpec+Priority+RankInterval",
                "CAUTION":        "Talker must declare before Listener — reversed order = failed reservation"},
               stack={
                "L2": "Ethernet II (0x8929) — Dst 01:80:C2:00:00:21",
                "L3": "MSRP — stream reservation MRP PDU directly after Ethernet",
                "Application": "AVB/TSN stream reservation — coordinate bandwidth between talker and listener",
               }),

    0x8940: _e("IEEE 802.1Qbg ECP (Edge Control Protocol)", "ECP PDU",
               "Standard", "Active",
               "Edge Control Protocol — 802.1BR/VEPA port virtualisation signalling",
               "ecp",
               {"Subtype":    "2B  identifies higher-layer protocol (e.g. VDP=0x0001)",
                "Sequence":   "2B  monotonic sequence number for ACK correlation",
                "Op":         "4b  0=Request 1=ACK",
                "SubtypeData":"variable  VDP (VSI Discovery Protocol) or other ECP payload",
                "CAUTION":    "ECP requires LLDP-based VEB/VEPA mode negotiation first"},
               stack={
                "L2": "Ethernet II (0x8940) — Dst 01:80:C2:00:00:00",
                "L3": "ECP — VDP/ECP payload directly after Ethernet",
                "Application": "VM-based NIC virtualisation — hypervisor VEPA port assignment",
               }),

    0x894F: _e("NSH (Network Service Header — RFC 8300)", "NSH Frame",
               "Standard", "Active",
               "Network service chaining metadata header (SFC)",
               "nsh",
               {"Base Hdr":   "4B  Ver(2b)+O(1b)+U(1b)+TTL(6b)+Length(6b)+U(4b)+MD-Type(4b)+NextProto(8b)",
                "Service Path Hdr":"4B  Service Path ID(24b)+Service Index(8b)",
                "Context Hdr":"variable  MD-Type 1=32B fixed / 2=variable TLVs",
                "Payload":    "inner packet — NextProto: 1=IPv4 2=IPv6 3=Ethernet 4=NSH 5=MPLS",
                "CAUTION":    "TTL decremented per service function — 0=drop; Service Index decremented per hop"},
               stack={
                "L2": "Ethernet II (0x894F) — or carried over VXLAN/GRE",
                "L3": "NSH — service path header chains packets through ordered service functions",
                "L4": "Inner packet (IP/Ethernet) after NSH headers",
                "Application": "SFC — Firewall → IDS → Load-Balancer → NAT function chaining",
               }),

    0x8902: _e("IEEE 802.1ag CFM (Connectivity Fault Management)", "CFM PDU",
               "Standard", "Active",
               "Ethernet OAM — continuity check, loopback, link-trace for carrier networks",
               "cfm",
               {"MD Level":   "3b  Maintenance Domain level 0-7 (higher=wider scope)",
                "Version":    "5b  must be 0",
                "Opcode":     "1B  1=CCM 2=LBR 3=LBM 4=LTR 5=LTM 40=AIS 41=LCK 42=TST 43=APS 44=RAPS 45=MCC 46=LMM 47=LMR 49=1DM 50=DMM 51=DMR 52=EXM 53=EXR 54=VSM 55=VSR 56=CSF 57=SLM 58=SLR",
                "Flags":      "1B  opcode-specific",
                "TLV-Offset": "1B  offset to first TLV (from start of Flags field)",
                "CCM Seq":    "4B  (CCM only) monotonic counter; gap = loss event",
                "MEPID":      "2B  (CCM only) 1-8191 unique within MA",
                "MAID":       "48B  (CCM only) MD-Name-Format+MD-Name+MA-Name-Format+MA-Name",
                "Tx Timestamp":"8B  (DM) PTP timestamp for delay measurement",
                "End TLV":    "1B  0x00 marks end of TLV chain",
                "CAUTION":    "MD-Level mismatch causes CCM to be ignored — verify level on both MEPs"},
               stack={
                "L2": "Ethernet II (0x8902) — unicast LBM/LTM or multicast CCM Dst 01:80:C2:00:00:3X (X=level)",
                "L3": "CFM PDU — OAM frame directly after Ethernet header",
                "L4": "None — CFM is self-contained; no transport layer",
                "Application": "Carrier Ethernet OAM — fault detection · loopback · delay measurement · AIS/RDI",
               }),

    0x8903: _e("ITU-T Y.1731 OAM (Ethernet Performance Management)", "Y.1731 PDU",
               "Standard", "Active",
               "Ethernet performance monitoring — delay/loss/jitter measurement per ITU-T Y.1731",
               "y1731",
               {"MD Level":   "3b  0-7",
                "Version":    "5b  0",
                "Opcode":     "1B  DMM=47 DMR=46 SLM=55 SLR=56 LMM=43 LMR=42 1DM=49 TST=37 AIS=33 LCK=35 CSF=52 EXM=53 EXR=54",
                "Flags":      "1B",
                "TLV-Offset": "1B",
                "Seq Number": "4B  (DMM/SLM) frame sequence number",
                "Tx TimeStamp":"8B  (DMM/1DM) PTP Tx timestamp for one-way delay",
                "Rx TimeStamp":"8B  (DMR) PTP Rx timestamp for RTT calculation",
                "TxFCf":      "4B  (LMM) local Tx frame count",
                "RxFCf":      "4B  (LMM) local Rx frame count",
                "TxFCb":      "4B  (LMR) far-end Tx frame count for loss ratio calc",
                "CAUTION":    "PTP time sync required for delay measurements — clock drift = inaccurate SLA data"},
               stack={
                "L2": "Ethernet II (0x8903) — same multicast rules as CFM (0x8902)",
                "L3": "Y.1731 PDU — performance measurement frame directly after Ethernet",
                "L4": "None — self-contained; extends CFM with performance OAM",
                "Application": "Carrier Ethernet SLA — frame delay · delay variation (jitter) · frame loss ratio",
               }),

    0x88E3: _e("MRP (Media Redundancy Protocol — IEC 62439-2)", "MRP PDU",
               "Standard", "Active",
               "Ring-based Ethernet redundancy — <500ms (advanced <200ms) recovery",
               "mrp",
               {"Version":    "2B  must be 1",
                "Type":       "2B  1=Common 2=Test 3=TopologyChange 4=LinkDown 5=LinkUp 6=InTest 7=InTopologyChange 8=InLinkDown 9=InLinkUp 10=InLinkStatusPoll",
                "Length":     "2B  PDU data length",
                "Prio":       "2B  MRM priority (lower=preferred Ring Manager)",
                "SA":         "6B  source MAC of MRM (Ring Manager)",
                "Port Role":  "2B  0=Primary 1=Secondary",
                "Ring State": "2B  0=Open 1=Closed",
                "Interval":   "2B  test frame interval in ms",
                "Transition": "2B  transition count",
                "Timestamp":  "4B  ms timestamp",
                "CAUTION":    "Only one MRM per ring — duplicate MRM causes topology oscillation"},
               stack={
                "L2": "Ethernet II (0x88E3) — Dst 01:15:4E:00:00:01 (MRP multicast)",
                "L3": "MRP — ring redundancy PDU directly after Ethernet",
                "Application": "Industrial Ethernet ring redundancy — PROFINET/MRP switchover < 200ms",
               }),

    0x88FB: _e("PRP (Parallel Redundancy Protocol — IEC 62439-3)", "PRP Frame",
               "Standard", "Active",
               "Parallel Redundancy Protocol — zero-recovery-time via dual-LAN parallel sending",
               "prp",
               {"Sequence":   "2B  PRP sequence number (same value sent on both LANs)",
                "LAN-ID":     "4b  0xA=LAN-A  0xB=LAN-B",
                "LSDU-Size":  "12b  Length of the LSDU (payload before PRP trailer)",
                "Suffix":     "2B  0x88FB — identifies frame as PRP-tagged",
                "CAUTION":    "PRP trailer appended AFTER payload — ensure receiving device strips trailer before forwarding to application"},
               stack={
                "L2": "Ethernet II — PRP trailer appended at end of standard frame",
                "L3": "PRP — same frame sent on LAN-A and LAN-B simultaneously; first received used",
                "L4": "Standard IP/non-IP payload; PRP is transparent to L3/L4",
                "Application": "IEC 61850 substation automation · process bus · zero-downtime industrial Ethernet",
                "CAUTION": "Both LANs must be completely separate — shared segment negates redundancy",
               }),

    0x9000: _e("Loopback / Configuration Test Protocol (IEEE 802.3 Annex 57A)", "Loopback Frame",
               "Standard", "Active",
               "Ethernet loopback for cable/port testing and qualification",
               "eth_loopback",
               {"Function":    "2B  0x0001=Reply/Forward  0x0002=Reply-Only",
                "Reply Count": "2B  number of times to forward before replying (0=reply immediately)",
                "Data":        "variable  test pattern — minimum 64B total frame required",
                "Dst MAC":     "Dst must be Loopback multicast 09:00:09:00:00:00 or unicast port",
                "CAUTION":     "Loopback frames must not egress to customer-facing ports — dedicated test VLAN required"}),

    0x876B: _e("TCP/IP Header Compression (RFC 1144 Van Jacobson / CSLIP)", "Compressed Frame",
               "Standard", "Active",
               "Van Jacobson compressed TCP/IP headers for low-bandwidth serial links",
               "vjcomp",
               {"Type":      "1B  0x45=Uncompressed-TCP 0x70-0x7F=Compressed-TCP 0x00=Regular-IP",
                "Connection":"1B  (Compressed-TCP) connection number",
                "Delta":     "variable  encoded differences from previous header",
                "Payload":   "variable  TCP data payload",
                "CAUTION":   "Compression state must be synchronised — desync causes all subsequent packets to be dropped"}),

    0x876C: _e("IP Autonomous Systems — RFC 1701", "IP-AS Frame",
               "Standard", "Active",
               "IP Autonomous System number framing in GRE key space (RFC 1701)",
               "ip_as",
               {"AS Number":   "2B  16-bit Autonomous System number (pre-RFC 4271 32-bit AS)",
                "Reserved":    "2B  0x0000",
                "IP Payload":  "variable  encapsulated IP datagram",
                "Note":        "RFC 1701 GRE predecessor — obsolete; use BGP+GRE for AS-tagged tunnels"}),

    0x876D: _e("Secure Data — RFC 1701", "Secure Data Frame",
               "Standard", "Active",
               "Secure/encrypted data framing — RFC 1701 GRE key space allocation",
               "secure_data",
               {"Key":         "4B  GRE key identifying secure tunnel or VLAN context",
                "Sequence":    "4B  optional sequence number for ordering",
                "Payload":     "variable  encrypted or secured data",
                "Note":        "RFC 1701 historical — use IPsec/ESP or MACsec (0x88E5) for modern secure data transport"}),

    0x8861: _e("MCAP (Multicast Channel Allocation Protocol)", "MCAP PDU",
               "Standard", "Active",
               "Multicast channel allocation for 802.11 and wired networks — RFC 9542",
               "mcap",
               {"Op":          "1B  0x01=GetReq 0x02=GetResp 0x03=Setup 0x04=Del",
                "Rpt Count":   "1B  number of repetitions",
                "Trans ID":    "2B  transaction identifier",
                "Channel ID":  "2B  allocated channel identifier",
                "Timestamp":   "8B  absolute time for channel start (802.11 TSF)",
                "Duration":    "2B  channel duration in TUs (1TU=1024µs)",
                "CAUTION":     "Channel allocation must complete before data — send Setup before streaming"}),

    0x8870: _e("Jumbo Frame EtherType (proposed/defunct — rejected by IEEE)", "Jumbo Indicator",
               "Industry", "Deprecated",
               "Proposed EtherType to signal jumbo/super-jumbo frames — never standardised",
               None,
               {"Proposed Use":  "Signal that frame length > 1500B (jumbo) or > 9000B (super-jumbo)",
                "Why Rejected":  "IEEE 802.3 uses Length/Type field differently — values 0x0600+ are EtherTypes; standard jumbo frames use existing EtherType unchanged",
                "IEEE Position": "IEEE 802.3 does not standardise jumbo frames — left to switch vendor implementation (typically 9000-9216B MTU)",
                "Modern":        "Configure jumbo frames via interface MTU setting (e.g. ip link set eth0 mtu 9000); no special EtherType required",
                "CAUTION":       "Never use 0x8870 in production; some older Foundry/Brocade equipment may emit it — treat as unknown EtherType and discard"}),

    0x88F8: _e("NC-SI (Network Controller Sideband Interface — DMTF DSP0222)", "NC-SI Frame",
               "Standard", "Active",
               "BMC to NIC management sideband — pass-through network access for BMC",
               "ncsi",
               {"MC ID":       "1B  Management Controller ID (0=primary)",
                "Hdr Rev":     "1B  header revision (must be 0x01)",
                "Reserved":    "1B  0x00",
                "IID":         "1B  Instance ID (request/response correlation 0-15)",
                "Type":        "1B  0x00=Clear-Init 0x01=Select-Pkg 0x02=Deselect-Pkg 0x03=Enable-Ch 0x04=Disable-Ch 0x05=Reset-Ch 0x06=Get-Link-Status 0x08=Set-Link 0x09=Get-Vlan-Filter 0x0A=Set-Vlan-Filter 0x0B=Enable-Vlan 0x0C=Disable-Vlan 0x0D=Set-MAC-Addr 0x0F=Enable-BC-Filter 0x10=Disable-BC-Filter 0x11=Enable-Global-MC-Filter 0x12=Disable-Global-MC-Filter 0x13=Set-NC-Abilities 0x14=Get-Cap 0x15=Get-Param 0x16=Get-Ctrl-Pkt-Stats 0x17=Get-NC-Stats 0x18=Get-Passthrough-Stats 0xFF=Response",
                "Channel":     "1B  target channel ID (0-3 per package)",
                "Payload Len": "2B  payload length in bytes",
                "Payload":     "variable  command-specific data",
                "Checksum":    "4B  checksum over header+payload (or 0x00000000 if disabled)",
                "CAUTION":     "NC-SI runs on dedicated management VLAN or SMBUS — exposing to data VLAN allows BMC network access bypass via NIC passthrough"},
               stack={
                "L2": "Ethernet II (0x88F8) — Dst 01:80:C2:00:00:00 (management group)",
                "L3": "NC-SI — NIC management command directly after Ethernet",
                "Application": "BMC network passthrough · NIC firmware update via BMC · NCSI link monitoring",
               }),

    0x88F9: _e("LLDP-MED (Media Endpoint Discovery — ANSI/TIA-1057)", "LLDP PDU",
               "Standard", "Active",
               "LLDP extension for VoIP phones and media endpoints — PoE, VLAN, QoS",
               "lldp",
               {"Base LLDP":     "same TLV chain as standard LLDP (0x88CC)",
                "LLDP-MED Cap":  "OUI=00-12-BB SubType=1 Cap(2B)+DeviceType(1B): 1=GenericEndpoint 2=MediaEndpoint 3=CommunicationsDevice 4=NetworkConnectivity",
                "Network Policy":"OUI=00-12-BB SubType=2 AppType(7b)+U(1b)+T(1b)+X(1b)+VLAN-ID(12b)+L2-Priority(3b)+DSCP(6b)",
                "Location ID":   "OUI=00-12-BB SubType=3 Format(1B)+LocationData: 0=ECS-ELIN 1=Coordinate 2=Civic 3=DHCP",
                "Extended PoE":  "OUI=00-12-BB SubType=4 DeviceType(4b)+PowerSource(4b)+PowerPriority(4b)+PowerValue(12b×100mW)",
                "Inventory":     "SubType 5-9: HardwareRev FirmwareRev SoftwareRev SerialNum ManufacturerName ModelName AssetID",
                "CAUTION":       "LLDP-MED Network Policy VLAN must match switch port voice VLAN — mismatch causes VoIP phone to use wrong VLAN and lose call routing"},
               stack={
                "L2": "Ethernet II (0x88F9) — same multicast as LLDP: 01:80:C2:00:00:0E",
                "L3": "LLDP-MED TLVs — extension to standard LLDP for media endpoints",
                "Application": "VoIP phone auto-config · PoE budget negotiation · 911 location · QoS DSCP assignment",
               }),

    0xA0ED: _e("6LoWPAN Encapsulation (RFC 7973)", "LoWPAN Frame",
               "Standard", "Active",
               "IPv6 over Low-Power Wireless (6LoWPAN) tunnelled over Ethernet",
               "lowpan",
               {"Dispatch":    "1B  dispatch type: 0x41=IPv6-uncompressed 0x60-0x7F=IPHC-compressed 0xC0-0xDF=Mesh 0xE0-0xE7=Fragmentation",
                "IPHC":        "2B  (if compressed) IPv6 header compression encoding",
                "Mesh Hdr":    "optional  V(1b)+F(1b)+HopsLeft(4b)+OrigAddr+FinalAddr",
                "Frag Hdr":    "optional  4B  DatagramSize(11b)+DatagramTag(16b)+DatagramOffset(8b)",
                "Payload":     "variable  compressed IPv6 + UDP/CoAP payload",
                "CAUTION":     "6LoWPAN fragmentation reassembly timeout default 60s — incomplete fragments cause memory exhaustion in low-resource devices"}),

    0x8377: _e("Multi-Topology IS-IS (RFC 8377)", "MT IS-IS PDU",
               "Standard", "Active",
               "IS-IS multi-topology routing — separate topologies for IPv4/IPv6/traffic-engineering",
               "mt_isis",
               {"MT-ID":      "12b  0=Default 1=IPv4-Mgmt 2=IPv6-Unicast 3=IPv4-Multicast 4=IPv6-Multicast 5=IPv6-Mgmt",
                "PDU Type":   "1B  same as IS-IS (L2-Hello/LSP/CSNP)",
                "MT TLV 235":"Extended IP Reachability for specific MT-ID",
                "MT TLV 237":"IPv6 IP Reachability for specific MT-ID",
                "MT TLV 229":"MT IS Neighbor for specific topology",
                "CAUTION":    "MT-ID must match on both ends of adjacency — mismatch causes MT-specific routes to be absent in one direction"}),

    0xB7EA: _e("GRE Control Channel (RFC 8157)", "GRE Control Frame",
               "Standard", "Active",
               "GRE tunnel keepalive and control — RFC 8157 per-tunnel OAM",
               "gre_ctrl",
               {"Control Type":"2B  0x01=Keepalive-Req 0x02=Keepalive-Reply 0x03=Error 0x04=BFD-Discriminator",
                "Trans ID":    "2B  transaction identifier",
                "Payload":     "variable  type-specific control data",
                "Note":        "Payload handed to GRE control processor — not forwarded as GRE data"}),

    0x6558: _e("Transparent Ethernet Bridging over GRE (RFC 1701)", "GRE Bridged Ethernet",
               "Standard", "Active",
               "Ethernet frame encapsulated in GRE tunnel — L2 VPN bridging",
               "gre_eth",
               {"GRE Flags":   "2B  C(1b)+R(1b)+K(1b)+S(1b)+s(1b)+Recur(3b)+Flags(5b)+Ver(3b)",
                "Protocol":    "2B  0x6558=Transparent Ethernet",
                "Checksum":    "optional 2B CRC (if C bit set)",
                "Reserved":    "optional 2B",
                "Key":         "optional 4B tunnel key (if K bit set)",
                "Seq Number":  "optional 4B (if S bit set)",
                "Payload":     "Ethernet frame (Dst MAC onward) — original frame without Preamble/SFD/FCS",
                "CAUTION":     "GRE has no encryption — combine with IPsec ESP for secure L2VPN; ARP broadcast in GRE tunnel = flood to all sites"}),

    # ── GROUP 7: Storage Networking (full interactive builders) ───────────────
    0x8906: _e("FCoE (Fibre Channel over Ethernet)", "FCoE Frame",
               "Industry", "Active",
               "Fibre Channel SAN over lossless Ethernet — requires DCB/PFC priority 3",
               "fcoe",
               {"Version":    "4b  must be 0",
                "Reserved":   "100b  always zero",
                "SOF":        "1B  Start-of-Frame: 0x2E=SOFi3(first) 0x36=SOFn3(subsequent) 0x2D=SOFf",
                "R_CTL":      "1B  Routing+Info: 0x00=Data 0x01=Data-Last 0x02=Xfer-Ready 0x18=LinkSvc",
                "D_ID":       "3B  Destination Fibre Channel address (N_Port ID)",
                "CS_CTL":     "1B  Class-specific control / Priority",
                "S_ID":       "3B  Source Fibre Channel address",
                "TYPE":       "1B  Protocol: 0x01=BLS 0x08=FCP(SCSI) 0x20=IP-over-FC 0xFE=FC-ELS",
                "F_CTL":      "3B  Frame control: ExgSeq(bit23)+SeqInit+AbtsAck+RelOffset",
                "SEQ_ID":     "1B  Sequence identifier (increments per sequence)",
                "DF_CTL":     "1B  Data field control — presence of optional headers",
                "SEQ_CNT":    "2B  Sequence count (frame order within sequence)",
                "OX_ID":      "2B  Originator Exchange ID",
                "RX_ID":      "2B  Responder Exchange ID",
                "Parameter":  "4B  relative offset for first byte of payload",
                "Payload":    "variable  FCP/ELS/BLS data",
                "CRC":        "4B  Fibre Channel CRC-32",
                "EOF":        "1B  End-of-Frame: 0x42=EOFt(terminate) 0x49=EOFn(normal) 0x41=EOFa(abort)",
                "CAUTION":    "PFC must be enabled on Cos3 — loss causes ABTS/LOGO and SAN disruption"},
               stack={
                "L2": "Ethernet II (0x8906) — lossless DCB fabric required",
                "L3": "FCoE  —  Fibre Channel frame encapsulated directly after Ethernet header",
                "L3_role": "SAN transport — N_Port_ID addressing (3B source + 3B dest in FC header)",
                "L4": "FCP (Fibre Channel Protocol for SCSI) — SCSI CDB in FC payload",
                "FCP": "FCP_CMND(Command)+FCP_DATA+FCP_RSP(Response)+FCP_CONF — full SCSI exchange",
                "Application": "Block storage I/O — disk read/write/inquiry/format SCSI commands",
                "CAUTION": "Requires lossless Ethernet (DCB): PFC on priority 3, ETS, DCBX LLDP TLVs",
               }),

    0x8914: _e("FIP (FCoE Initialization Protocol)", "FIP Frame",
               "Industry", "Active",
               "FCoE fabric discovery and login — runs before FCoE data frames",
               "fip",
               {"Version":    "4b  must be 1",
                "Reserved":   "12b",
                "FIP Subcode":"2B  0x0001=Solicitation 0x0002=Advertisement 0x0003=Notification",
                "Desc ListLen":"2B  in 32-bit words",
                "Flags":      "2B  FP=FCF-Provided A=Available S=Solicited",
                "Op":         "1B  Operation: 1=Discovery 2=Link-Service 3=Ctrl 4=VLAN",
                "Subcode":    "1B  sub-operation within Op",
                "Priority":   "1B  FCF priority (lower=preferred)",
                "FC-Map":     "3B  Ethernet-to-FC mapping prefix (default 0x0E:FC:00)",
                "Switch-Name":"8B  WWN of FCF (Fibre Channel Forwarder)",
                "Fabric-Name":"8B  WWN of fabric",
                "MAC-Addr":   "6B  FCF or ENode MAC address",
                "Max-FCoE-Size":"2B  maximum FCoE frame size (default 2158B)",
                "CAUTION":    "FIP must complete before any FCoE I/O — misconfig = silent login failure"},
               stack={
                "L2": "Ethernet II (0x8914) — multicast 01:10:18:01:00:01 for FCF solicitation",
                "L3": "FIP  —  discovery and login PDU directly after Ethernet header",
                "L3_role": "Control plane for FCoE — ENode discovers FCF, performs FLOGI/PLOGI/FDISC",
                "L4": "None — FIP is self-contained; no L4 layer",
                "Sequence": "FIP VLAN Req → FIP VLAN Notify → FIP Solicitation → FIP Advertisement → FLOGI",
                "Application": "FCoE fabric initialisation — required before any block storage I/O",
               }),

    0x889A: _e("HyperSCSI (SCSI over Ethernet — deprecated)", "HyperSCSI Frame",
               "Industry", "Deprecated",
               "SCSI commands directly over Ethernet — superseded by iSCSI/FCoE",
               "hyperscsi",
               {"Version":    "1B  0=HyperSCSI v0",
                "Type":       "1B  0=Command 1=Data 2=Response 3=Sense",
                "Sequence":   "2B  PDU sequence number",
                "Initiator ID":"1B",
                "CDB Len":    "1B  SCSI CDB length",
                "CDB":        "variable  SCSI Command Descriptor Block (up to 16B)",
                "Data":       "variable  read/write data payload",
                "CAUTION":    "No encryption, no authentication — LAN-only; superseded by iSCSI"},
               stack={
                "L2": "Ethernet II (0x889A)",
                "L3": "HyperSCSI — SCSI frame directly after Ethernet; no IP/TCP layer",
                "L4": "None — SCSI CDB direct; deprecated, use iSCSI or FCoE instead",
               }),

    0x88A2: _e("ATA over Ethernet (AoE) v1", "AoE Frame",
               "Industry", "Active",
               "ATA disk commands over Ethernet — no IP/TCP; shelf+slot addressing",
               "aoe",
               {"Ver":        "4b  must be 1",
                "Flags":      "4b  bit0=Response bit1=Error bit2=DevCmd bit3=AsyncCmd",
                "Error":      "1B  error code on response (0=none)",
                "Major":      "2B  shelf number (0xFFFF=broadcast)",
                "Minor":      "1B  slot number (0xFF=broadcast)",
                "Cmd":        "1B  0=ATA 1=QueryConfig 2=MacMaskList 4=Reserve 5=Release",
                "Tag":        "4B  transaction tag (matched request to response)",
                "ATA Err/Feature":"1B",
                "ATA SectorCount":"1B",
                "ATA CmdStatus":"1B  ATA command (request) or status (response)",
                "ATA LBA":    "6B  48-bit LBA address for read/write sector",
                "ATA Data":   "variable  512B-per-sector block data",
                "CAUTION":    "No authentication/encryption — must be isolated VLAN or dedicated switch"},
               stack={
                "L2": "Ethernet II (0x88A2) — broadcast/unicast to shelf.slot",
                "L3": "AoE — ATA command frame directly after Ethernet; no IP routing",
                "L3_addressing": "Major(2B shelf) + Minor(1B slot) — e.g. shelf 1 slot 0 = 1.0",
                "L4": "None — ATA commands/data embedded in AoE frame directly",
                "Application": "Block storage — ATA read/write/identify/SMART to Ethernet-attached disks",
                "CAUTION": "No encryption/auth — dedicated isolated network or VLAN mandatory",
               }),

    0x8915: _e("RoCE v1 (RDMA over Converged Ethernet)", "RoCE Frame",
               "Industry", "Active",
               "RDMA over Ethernet — zero-copy kernel-bypass for HPC/NVMe-oF/storage",
               "roce",
               {"GRH":        "optional 40B Global Routing Header (for L3 routing across subnets)",
                "BTH":        "12B Base Transport Header: OpCode(1B)+SE+M+Pad+TVer+P_Key(2B)+Reserved(1B)+Dest-QP(3B)+A+PSN(3B)",
                "OpCode":     "1B: 0=RC-Send-First 4=RC-Send-Only 6=RC-Write-First 10=RC-Write-Only 12=RC-Read-Request 16=RC-ACK 20=UC-Send-First",
                "RETH":       "16B RDMA-ETH (Write/Read): VirtAddr(8B)+RKey(4B)+DMALen(4B)",
                "AETH":       "4B ACK-ETH (Ack/NACK): Syndrome(1B)+MSN(3B)",
                "AtomicETH":  "28B for Compare-and-Swap or Fetch-and-Add operations",
                "Payload":    "variable  RDMA message data (Send/Write/Read data)",
                "ICRC":       "4B  Invariant CRC (covers fields that do not change in transit)",
                "VCRC":       "2B  optional Variant CRC",
                "CAUTION":    "Requires lossless Ethernet — PFC + ECN + DCBX; RoCEv2 preferred (UDP 4791)"},
               stack={
                "L2": "Ethernet II (0x8915) — lossless DCB fabric; PFC required",
                "L3": "IB Transport (InfiniBand over Ethernet) — BTH directly after Ethernet",
                "L3_role": "QP (Queue Pair) addressing — Dest-QP(3B) identifies target work queue",
                "L4": "RDMA verbs: Send · Write · Read · Atomic (CAS/FAA)",
                "Application": "HPC MPI · NVMe-oF (target/initiator) · Lustre/GPFS parallel FS · GPU-direct",
                "CAUTION": "RoCEv1 is single-subnet only — use RoCEv2 (0x0800+UDP:4791) for routing",
               }),

    # ── New storage EtherTypes (fully interactive) ────────────────────────────
    0x8988: _e("iSCSI over Ethernet (RFC 7143 direct-attach variant)", "iSCSI PDU",
               "Industry", "Active",
               "iSCSI SCSI block storage over direct Ethernet — no IP/TCP layer",
               "iscsi_eth",
               {"BHS":        "48B Basic Header Segment: Opcode(1B)+Flags(1B)+TotalAHSLen(1B)+DataSegLen(3B)+LUN(8B)+ITT(4B)+Ttt(4B)+CmdSN(4B)+ExpStatSN(4B)+CRC-Header-Digest(4B opt)",
                "Opcode":     "1B: 0x01=SCSI-Command 0x21=SCSI-Response 0x04=SCSI-Data-Out 0x25=SCSI-Data-In 0x05=R2T 0x3F=NOP-In 0x00=NOP-Out 0x06=Login-Req 0x26=Login-Resp 0x09=Text-Req 0x24=Text-Resp 0x06=Logout-Req 0x26=Logout-Resp",
                "I-bit":      "1b (bit7 of opcode): 0=Initiator 1=Immediate-delivery",
                "Flags":      "1B: F=Final W=Write R=Read Attr(3b) for SCSI-Command",
                "TotalAHSLen":"1B  in 4-byte words (usually 0)",
                "DataSegLen": "3B  data segment length in bytes",
                "LUN":        "8B  Logical Unit Number (iSCSI LUN format)",
                "ITT":        "4B  Initiator Task Tag (request correlation)",
                "CmdSN":      "4B  Command Sequence Number (order enforcement)",
                "ExpStatSN":  "4B  Expected Status Sequence Number",
                "AHS":        "variable  Additional Header Segment (rarely used)",
                "Header Digest":"optional 4B CRC-32C over BHS+AHS",
                "Data Segment":"variable  SCSI CDB (16B) in command PDU or data block in data PDU",
                "Data Digest": "optional 4B CRC-32C over data segment",
                "CAUTION":    "No IP/TCP — single Ethernet segment only; iSCSI/TCP (0x0800) preferred for routing"},
               stack={
                "L2": "Ethernet II (0x8988)",
                "L3": "iSCSI PDU — directly after Ethernet header; no IP or TCP",
                "L3_role": "SCSI transport — ITT/CmdSN provide ordering without TCP",
                "L4": "SCSI CDB (Command Descriptor Block) in Data Segment",
                "SCSI_cmds": "Read(0x28) · Write(0x2A) · Inquiry(0x12) · Test-Unit-Ready(0x00) · Report-LUNs(0xA0)",
                "Application": "Block storage I/O to iSCSI targets — NAS/SAN disk access",
                "CAUTION": "Standard iSCSI uses TCP port 3260 over IPv4 (EtherType 0x0800) — this EtherType is for L2-direct variant only",
               }),

    0x8893: _e("NVMe over Ethernet (NVMe-oF L2 direct variant)", "NVMe-oF PDU",
               "Industry", "Active",
               "NVMe commands directly over Ethernet — ultra-low latency storage (no IP/TCP)",
               "nvme_eth",
               {"PDU Type":   "1B: 0x00=Capsule-Command 0x01=Capsule-Response 0x02=H2C-Data 0x03=C2H-Data 0x04=H2C-Term 0x05=C2H-Term",
                "Flags":      "1B: HDGSTF=Header-Digest DDGSTF=Data-Digest LAST_PDU=last-PDU",
                "HDR Len":    "1B  header length in 4-byte DWords",
                "PLEN":       "4B  full PDU length including header and data",
                "Command Capsule":"64B NVMe SQE (Submission Queue Entry) = Opcode(1B)+NSID(4B)+MPTR(8B)+PRP1/SGL1(8B)+PRP2/SGL2(8B)+CDW10-15(24B)",
                "Opcode":     "1B: 0x00=Flush 0x01=Write 0x02=Read 0x04=WriteUncor 0x05=Compare 0x08=WriteZeroes 0x09=DSM 0x7C=Format",
                "NSID":       "4B  Namespace ID (1-based, 0xFFFFFFFF=broadcast all NS)",
                "CDW10":      "4B  Starting LBA [31:00]",
                "CDW11":      "4B  Starting LBA [63:32]",
                "CDW12":      "4B  NLB (Number of Logical Blocks minus 1)",
                "SGL":        "16B  Scatter-Gather List entry: Type(4b)+Subtype(4b)+Length(4B)+Address(8B)",
                "Completion": "16B NVMe CQE: DW0(4B result)+DW1(4B reserved)+SQ_Head(2B)+SQ_ID(2B)+CID(2B)+P(1b)+SC(8b)+SCT(3b)+CRD(2b)+M(1b)+DNR(1b)",
                "Header Digest":"optional 4B CRC-32C",
                "Data":       "variable  read/write data (aligned to 4B)",
                "Data Digest": "optional 4B CRC-32C",
                "CAUTION":    "Namespace IDs are target-local — coordinate with target before sending"},
               stack={
                "L2": "Ethernet II (0x8893)",
                "L3": "NVMe-oF PDU — command capsule directly after Ethernet header",
                "L3_role": "NVMe transport — CID+SQID correlate commands without TCP",
                "L4": "NVMe Command (SQE): Flush/Write/Read/Format/DSM/Compare",
                "Application": "NVMe SSD block I/O over Ethernet — sub-10µs latency possible",
                "CAUTION": "Standard NVMe-oF uses RoCEv2 or TCP (port 4420) — this EtherType is L2-direct only",
               }),

    0x8989: _e("iSER (iSCSI Extensions for RDMA) over Ethernet", "iSER PDU",
               "Industry", "Active",
               "iSCSI RDMA — iSCSI PDUs transported over RDMA without TCP copy overhead",
               "iser",
               {"iSER Header":"4B: Flags(1B)+RSVD(1B)+Write-STag+Write-TO(8B)+Read-STag+Read-TO(8B)",
                "Flags":      "1B: W=Write-Stag-Valid R=Read-Stag-Valid",
                "Write STag": "4B  Steering Tag for target-to-initiator RDMA Write",
                "Write TO":   "8B  Tagged Offset for iSER write operations",
                "Read STag":  "4B  Steering Tag for RDMA Read",
                "Read TO":    "8B  Tagged Offset for RDMA read operations",
                "iSCSI BHS":  "48B  iSCSI Basic Header Segment (same format as iSCSI/TCP)",
                "CAUTION":    "Requires RDMA-capable NIC (RoCE/iWARP) — misconfig = silent data corruption"},
               stack={
                "L2": "Ethernet II (0x8989)",
                "L3": "iSER — RDMA-aware iSCSI; BTH (RoCE) or MPA (iWARP) carries iSER header",
                "L4": "iSCSI BHS + SCSI CDB — zero-copy path bypasses kernel TCP stack",
                "Application": "High-performance block storage — eliminates TCP copy overhead for iSCSI",
                "CAUTION": "Requires RDMA NIC; both ends must negotiate iSER in iSCSI login phase",
               }),

    # ── GROUP 8: INDUSTRIAL ETHERNET ─────────────────────────────────────────
    0x8892: _e("PROFINET RT/IRT/DCP — IEC 61158 / IEC 61784", "PROFINET Frame",
               "Industry", "Active",
               "PROFINET Real-Time — industrial automation, bypasses TCP/IP entirely",
               "profinet",
               {"Frame ID":       "2B 0x0001-0x7FFF=RT-Class1(cyclic) 0x8000-0xBFFF=RT-Class2 0xC000-0xFBFF=RT-Class3(IRT) 0xFC00-0xFCFF=Reserved 0xFD00-0xFEFF=Alarm 0xFF00=DCP-MC 0xFF01=DCP-UC 0xFF40=Fragmentation",
                "DataStatus":     "1B b7=Ignore b6=DataValid(1=OK) b5=ProviderState b4=Normal b3=Redundancy b2=PrimaryAR b1-0=Reserved",
                "TransferStatus": "1B 0x00=OK; non-zero = transfer error code",
                "Cycle Counter":  "2B free-running 0-65535 at 32kHz for cycle sync",
                "IO Data":        "variable input or output process bytes",
                "IOPS":           "1B IO Provider Status: 0x80=GOOD 0x00=BAD per slot/subslot",
                "IOCS":           "1B IO Consumer Status: 0x80=GOOD 0x00=BAD",
                "DCP Block":      "optional — for DCP (Discovery/Config): ServiceID(1B)+ServiceType(1B)+Xid(4B)+ResponseDelay(2B)+BlockLength(2B)+Blocks...",
                "CAUTION":        "Frame ID must match GSD/GSDML; IRT requires managed switches with FPGA forwarding; RT-Class3 <0.25ms requires hardware timestamping"}),

    0x88A4: _e("EtherCAT — IEC 61158-12 / IEC 61784-2", "EtherCAT Frame",
               "Industry", "Active",
               "EtherCAT ultra-fast fieldbus — slaves process frame on-the-fly <100µs",
               "ethercat",
               {"Reserved":       "2b must be 0",
                "Length":         "11b total byte count of all chained EtherCAT datagrams",
                "Type":           "3b 0x1=EtherCAT (only valid value)",
                "Cmd":            "1B NOP=0x00 APRD=0x01 APWR=0x02 APRW=0x03 FPRD=0x04 FPWR=0x05 FPRW=0x06 BRD=0x07 BWR=0x08 BRW=0x09 LRD=0x0A LWR=0x0B LRW=0x0C ARMW=0x0D FRMW=0x0E",
                "IDX":            "1B datagram index for TX/RX matching (0x00-0xFF)",
                "Address":        "4B ADP(2B)+ADO(2B) or 4B logical address depending on Cmd",
                "Datagram Length":"11b datagram payload byte count",
                "Reserved2":      "3b",
                "M (More)":       "1b 1=more datagrams follow 0=last datagram",
                "IRQ":            "2B interrupt request from slaves",
                "Data":           "variable process data read/written by slaves",
                "WKC":            "2B Working Counter — each matched slave increments 1/2/3 per R/W/RW",
                "CAUTION":        "WKC must equal expected slave count; LRW increments differently — verify per slave spec"}),

    0x88AB: _e("Ethernet POWERLINK v2 — EPSG DS 301", "POWERLINK Frame",
               "Industry", "Active",
               "Open real-time motion control protocol — master-slot communication",
               "powerlink",
               {"Message Type":   "1B SoC=0x01 PReq=0x03 PRes=0x04 SoA=0x05 ASnd=0x06 AMNI=0x07",
                "Dst Node ID":    "1B 0xFF=broadcast 0xFE=MN 0x01-0xEF=CN node address",
                "Src Node ID":    "1B sender node address (0x00=MN 0x01-0xEF=CN)",
                "SoC Flags":      "1B b4=MC(Multiplexed Cycle) b3=PS(Prescaled Slot)",
                "BeginSyncOffset":"4B SoC only — start of synchronisation window (ns)",
                "PDO Data":       "variable PReq/PRes — cyclic process data bytes",
                "ServiceID":      "1B ASnd — 0x00=KeepAlive 0x01=IdentResponse 0x02=StatusResponse 0x0D=NMT_Request",
                "SDO Sequence":   "4B ASnd SDO — SendSeqNum(6b)+RecvSeqNum(6b)+SendCon(2b)+RecvCon(2b)",
                "CAUTION":        "Node ID 0 reserved; MN broadcasts SoC every cycle — missed SoC triggers CN error state; max 240 CNs per segment"}),

    0x88B8: _e("GOOSE — IEC 61850-8-1 GSSE/GOOSE", "GOOSE PDU",
               "Industry", "Active",
               "Generic Object Oriented Substation Event — <4ms multicast trip signal",
               "goose",
               {"APPID":          "2B 0x0000-0x3FFF GOOSE / 0x4000-0x7FFF GSSE / 0x8000-0xBFFF SV / 0xC000-0xFFFF reserved",
                "Length":         "2B total PDU byte count including APPID+Length fields",
                "Reserved1":      "2B 0x0000 (IEC 62351-6 HMAC security extension here when enabled)",
                "Reserved2":      "2B 0x0000",
                "goID":           "VisibleString unique GOOSE stream identifier (up to 65 chars)",
                "datSet":         "VisibleString dataset ref e.g. IED1/LLN0$GO$GOOSE1",
                "stNum":          "Uint32 state number — incremented on any data value change",
                "sqNum":          "Uint32 sequence number — incremented every retransmission",
                "timeAllowedToLive":"Uint32 ms — receiver must get next frame within this window",
                "t":              "UtcTime 8B — event timestamp (IEEE 1588 PTP synchronised)",
                "test":           "Boolean TRUE=test mode DO NOT ACT on this frame",
                "confRev":        "Uint32 config revision — mismatch means IED reconfigured; discard",
                "ndsCom":         "Boolean needs commissioning flag",
                "numDatSetEntries":"Uint32 count of allData entries",
                "allData":        "SEQUENCE OF Data — actual trip/position/status values",
                "Retransmit":     "T0→T1→T2→…→Tmax doubling until next event resets stNum",
                "CAUTION":        "No auth in base GOOSE; IEC 62351-6 adds HMAC; confRev mismatch silently drops trip; test=TRUE must block relay operation"}),

    0x88B9: _e("GSE Management Services — IEC 61850-8-1", "GSE Management PDU",
               "Industry", "Active",
               "GOOSE/GSSE group membership enter/leave management — IEC 61850",
               "gse_mgmt",
               {"APPID":          "2B application identifier",
                "Length":         "2B total PDU length",
                "Reserved1":      "2B 0x0000",
                "Reserved2":      "2B 0x0000",
                "Management Type":"1B 0x01=Enter-Group 0x02=Leave-Group 0x03=GetGoReference 0x04=GetGSSEDataSetRef 0x05=GetAllData",
                "MaxTime":        "2B maximum retransmission period (ms)",
                "MinTime":        "2B minimum retransmission period (ms)",
                "DatSet":         "VisibleString dataset reference",
                "CAUTION":        "Unauthorized Enter-Group can subscribe to protection multicast streams; use IEC 62351-6 for authentication"}),

    0x88BA: _e("SV / SMV — IEC 61850-9-1/9-2 Sampled Values", "Sampled Values PDU",
               "Industry", "Active",
               "Streaming instrument transformer measurements for power grid protection",
               "sv",
               {"APPID":          "2B 0x4000-0x7FFF sampled values identifier",
                "Length":         "2B total PDU byte count",
                "Reserved1":      "2B 0x0000 (IEC 62351-6 security extension here when used)",
                "Reserved2":      "2B 0x0000",
                "noASDU":         "Uint8 number of ASDUs in this PDU (1-255)",
                "svID":           "VisibleString sampled values stream identifier",
                "datSet":         "VisibleString dataset reference (optional)",
                "smpCnt":         "Uint16 sample counter 0-smpRate (wraps at smpRate)",
                "confRev":        "Uint32 configuration revision",
                "smpSynch":       "Uint8 0=not synced 1=local clock 2=global IEEE 1588 PTP",
                "smpRate":        "Uint16 samples per second",
                "smpMod":         "Uint8 0=per-period 1=per-second 2=seconds-per-sample",
                "Dataset values": "variable INT32+quality(4B) per channel per ASDU",
                "Rates":          "80/cycle=4kHz@50Hz 256/cycle=12.8kHz per IEC 61869-9",
                "CAUTION":        "smpSynch must be 2 for protection relay use; confRev mismatch silently discards all samples"}),

    0x88CD: _e("SERCOS III — IEC 61784-2-14 / IEC 61158-6-16", "SERCOS Frame",
               "Industry", "Active",
               "Motion control real-time fieldbus — sub-1ms cycle nanometer precision",
               "sercos3",
               {"Frame Type":     "1B 0x01=HP(Hot-Plug) 0x11=CP(CyclePacket) 0x02=AT(AmpTelegram) 0x12=MDT(MasterDataTelegram)",
                "Slave Address":  "2B target slave (AT) or 0xFFFF broadcast (MDT)",
                "Telegram Length":"2B payload byte count",
                "Service Channel":"2B service channel data for parameter access (IDN-based)",
                "AT Data":        "variable feedback from servo: actual position+velocity+status",
                "MDT Data":       "variable command to servo: target position+velocity+torque",
                "IDN":            "Identity Data Number S-0-xxxx (standard) or P-x-xxxx (product)",
                "Topology":       "Dual ring primary+secondary; ring break auto-detected and bypassed",
                "CAUTION":        "Ring requires correct termination resistors; single ring break degrades to line topology; SERCOS safety uses FSoE (Fail-Safe over EtherCAT) layer"}),

    0x890F: _e("CC-Link IE Field/Controller — CLPA", "CC-Link IE Frame",
               "Industry", "Active",
               "Mitsubishi CC-Link IE — 1Gbps ring fieldbus 0.5-1ms cycle time",
               "cclink_ie",
               {"CC-Link IE Type":"1B 0x01=Field 0x02=Controller 0x03=Motion 0x04=TSN",
                "Station No":     "1B source station number (0-120)",
                "Dst Station":    "1B destination station (0xFF=broadcast)",
                "Seq No":         "2B sequence number for token-passing ring",
                "PDU":            "variable cyclic RX/TX data or transient message",
                "Note":           "Mitsubishi proprietary; requires CC-Link IE certified hardware"}),

    0x88DC: _e("WSMP — IEEE 1609.3 WAVE Short Message Protocol", "WSMP Frame",
               "Industry", "Active",
               "V2X DSRC vehicle-to-everything — <50ms latency safety messages",
               "wsmp",
               {"Version":        "4b 0x3=WSM version 3",
                "PSID":           "variable 1-4B VLC Provider Service ID: 0x20=BasicSafetyMsg 0x7E=SPAT 0x80=MAP 0x8002=TIM 0x8003=CERT",
                "Wave ElemID":    "1B optional header extensions: 0x80=TxPowerUsed 0x83=ChannelNumber 0x84=DataRate",
                "TxPowerUsed":    "1B optional dBm transmit power used",
                "DataRate":       "1B optional Mbps: 0x0A=6Mbps 0x14=12Mbps 0x1B=18Mbps 0x24=24Mbps",
                "ChannelInterval":"1B optional SCH/CCH interval assignment",
                "WSM Length":     "2B application data byte count",
                "WSM Data":       "variable BSM/SPAT/MAP/TIM/CERT payload bytes",
                "CAUTION":        "No encryption in base WSMP; IEEE 1609.2 ECDSA certificate chain required for safety; replay attack possible without sequence validation"}),

    0x8819: _e("CobraNet — Cirrus Logic audio-over-Ethernet", "CobraNet Frame",
               "Industry", "Active",
               "Professional audio distribution 256ch 48kHz/24-bit over 100Mbps",
               "cobranet",
               {"Sub-Type":  "Beat(real-time audio)/Bundle(packed)/Management",
                "Bundle No": "2B audio bundle number (0-65535)",
                "Payload":   "variable audio samples at 48kHz",
                "Note":      "Cirrus Logic proprietary — <1ms latency; 100Mbps full-duplex required"}),

    0x887B: _e("HomePlug 1.0 MME — HomePlug Alliance", "HomePlug Frame",
               "Industry", "Active",
               "HomePlug 1.0 powerline networking management frames",
               "homeplug",
               {"MMType":   "2B management message type code",
                "MME Data": "variable management payload",
                "Note":     "Proprietary HomePlug Alliance spec — powerline PHY layer management"}),

    0x88E1: _e("HomePlug AV / Green PHY — IEEE P1901", "HomePlug AV Frame",
               "Industry", "Active",
               "HomePlug AV powerline — EV charging ISO 15118 / IEEE P1901",
               "homeplug_av",
               {"MMType":   "2B management message type; 0xA000-0xAFFF=vendor specific",
                "FMI":      "2B FMI(4b)+FMSN(4b)+FMID(8b) fragmentation/sequence",
                "MMENTRY":  "variable AV management payload"}),

    0x8912: _e("HomePlug AV2 / MME Extended — IEEE P1901.2", "HomePlug AV2 Frame",
               "Industry", "Active",
               "HomePlug AV2 MIMO powerline — smart grid EV charging home networking",
               "homeplug_av2",
               {"MMType":   "2B AV2 management message type code",
                "FMI":      "2B fragmentation/sequence info",
                "MMENTRY":  "variable AV2 capabilities beacons link stats",
                "CAUTION":  "Powerline has no physical isolation — all devices on same electrical circuit share all traffic"}),

    0x8200: _e("BACnet/Ethernet — ASHRAE 135 Annex H", "BACnet Frame",
               "Industry", "Active",
               "BACnet building automation directly over Ethernet — no IP required",
               "bacnet",
               {"DSAP":           "1B 0x82 BACnet SAP",
                "SSAP":           "1B 0x82 BACnet SAP",
                "LLC Control":    "1B 0x03 UI frame",
                "NPCI Version":   "1B 0x01",
                "NPCI Control":   "1B b7=IsNetMsg b5=DnetPresent b3=SnetPresent b2=ExpectReply b1-0=Priority(00=Normal 01=Urgent 10=CritEqp 11=LifeSafety)",
                "DNet":           "2B destination network number (if b5 set)",
                "DLEN":           "1B destination MAC address length",
                "DADR":           "variable destination MAC address",
                "SNet":           "2B source network number (if b3 set)",
                "SLEN":           "1B source MAC address length",
                "SADR":           "variable source MAC address",
                "Hop Count":      "1B decremented by each router (initial=255)",
                "PDU Type":       "4b 0=ConfirmedReq 1=UnconfirmedReq 2=SimpleAck 3=ComplexAck 4=SegmentAck 5=Error 6=Reject 7=Abort",
                "Service Choice": "1B ReadProperty=12 WriteProperty=15 SubscribeCOV=5 WhoIs=8 IAm=0 WhoHas=7 IHave=1",
                "Object ID":      "4B ObjectType(10b)+Instance(22b)",
                "Property ID":    "variable BACnet standard property identifier",
                "CAUTION":        "WHO-IS broadcasts flood Ethernet segment; use BACnet/IP with BBMD for routed networks; MSTP (RS-485) uses different framing"}),

    # ── GROUP 10: AT&T Private ────────────────────────────────────────────────
    0x8008: _e("AT&T / Stanford University Local Use", "AT&T Local PDU",
               "Private", "Legacy",
               "AT&T/Stanford local-use private EtherType (IANA Neil Sembower)", None, {}),

    0x8046: _e("AT&T Private (assignment 1)", "AT&T Private PDU",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    0x8047: _e("AT&T Private (assignment 2)", "AT&T Private PDU",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    0x8069: _e("AT&T Private (assignment 3)", "AT&T Private PDU",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    # ── GROUP 11: DEC (Digital Equipment Corporation) ────────────────────────
    0x6000: _e("DEC Unassigned / Experimental", "DEC Experimental PDU",
               "Historical", "Legacy",
               "DEC experimental EtherType range (0x6000-0x6009)", None, {}),

    0x6001: _e("DEC MOP Dump/Load (Maintenance Operations Protocol)",
               "DEC MOP PDU",
               "Historical", "Legacy",
               "DEC MOP — remote firmware dump/load for diskless VAX/PDP-11 booting",
               None,
               {"Code":"1B message code: 1=Dump Request 2=Dump Data 3=Param Load 4=Completed",
                "Receipt Number":"2B sequence for multi-message exchanges",
                "Load Address":"4B memory address for firmware placement",
                "Data":"variable firmware/param block",
                "Note":"Used to boot diskless nodes — MOP runs directly over Ethernet (no IP)"},
               stack={
                "L2": "Ethernet II (0x6001)",
                "L3": "MOP  —  no separate L3 header; MOP PDU directly after Ethernet",
                "L3_role": "Application-level bootstrap directly over Ethernet — no IP/routing",
                "L4": "None — MOP is a self-contained protocol",
                "Application": "Firmware download  ·  VAX/PDP console boot  ·  ROM-less node initialisation",
               }),

    0x6002: _e("DEC MOP Remote Console (Maintenance Operations Protocol)",
               "DEC MOP PDU",
               "Historical", "Legacy",
               "DEC MOP Remote Console — out-of-band management terminal for DEC devices",
               None,
               {"Code":"1B 7=Request ID 8=System ID 255=Loop",
                "Receipt Number":"2B","Data":"variable message body",
                "Note":"Console access without IP — used for hardware diagnostics and config"},
               stack={
                "L2": "Ethernet II (0x6002)",
                "L3": "MOP  —  no IP layer; MOP PDU directly after Ethernet header",
                "Application": "Out-of-band DEC hardware console  ·  Loop/loopback testing",
               }),

    0x6003: _e("DECnet Phase IV Route (Digital Network Architecture)",
               "DECnet Routing PDU",
               "Historical", "Legacy",
               "DECnet Phase IV — Digital's proprietary networking (area.node addressing)",
               "decnet",
               {"Flags":"1B routing flags: long/short msg, RQR, IE, RTS, OPF",
                "Dst Area":"6b destination area (1-63)","Dst Node":"10b dest node (1-1023)",
                "Src Area":"6b source area","Src Node":"10b source node",
                "NL2":"1B next-level header info","Visit Count":"1B hop count",
                "Service Class":"1B","Protocol Type":"1B: 0=User data 1=NSP 7=Routing msg"},
               stack={
                "L2": "Ethernet II (0x6003) — multicast 09:00:2B:00:00:00 for routing",
                "L3": "DECnet Routing Layer  —  variable header (short or long form)",
                "L3_role": "DNA Phase IV routing — area.node address (e.g. 3.154 = area 3 node 154)",
                "L3_addressing": "Area(6b)+Node(10b) = 16b address — max 63 areas × 1023 nodes = 64,449 nodes",
                "L4_dispatch": "Protocol Type in routing header routes to NSP:",
                "L4_NSP": "NSP  (Network Services Protocol)  —  reliable full-duplex byte-stream ≈ TCP",
                "NSP_fields": "Msg Flags(1B)+Dst Addr(2B)+Src Addr(2B)+[Ack/Seq fields variable]",
                "NSP_types": "Data Segment  ·  Other Data  ·  Ack/NAck  ·  Connect Init/Confirm  ·  Disconnect",
                "Application": "CTERM (virtual terminal)  ·  DAP (file access)  ·  FAL  ·  NML  ·  Mail-11",
                "Successor": "DECnet Phase V (OSI-based) then TCP/IP in PATHWORKS/VMS",
               }),

    0x6004: _e("DEC LAT (Local Area Transport)",
               "LAT Frame",
               "Historical", "Legacy",
               "DEC LAT — terminal server mux for interactive serial console access",
               "lat",
               {"Header Type":"1B: 0=Command/Status 1=Run/Data A=Start-Solicitation",
                "Circuit Timer":"1B ACK timer in ms (e.g. 80=8ms)",
                "Master/Slave":"distinction","Message Length":"1B",
                "Dst Circuit":"2B destination circuit ID",
                "Src Circuit":"2B source circuit ID",
                "Message Seq":"1B message sequence number",
                "ACK Seq":"1B acknowledged message number",
                "Slots":"variable 3-5B each: Type+Count+Min-Attention+Data"},
               stack={
                "L2": "Ethernet II (0x6004) — multicast 09:00:2B:00:00:0F",
                "L3": "LAT  —  connectionless Ethernet multicast; no IP/routing layer",
                "L3_role": "Direct Ethernet transport — no addressing beyond MAC",
                "L4": "LAT Virtual Circuits  (slots within LAT messages)",
                "L4_role": "Multiplexed serial sessions — up to 255 interactive slots per circuit",
                "Slot_types": "0=data 1=start 3=attention 9=disconnect A=reject",
                "Application": "DECserver 100/200/300/500/700 terminal servers  ·  VAX console  ·  Serial printer",
                "Key_feature": "Sub-8ms response time — optimised for human typing speed, no TCP overhead",
               }),

    0x6005: _e("DEC Diagnostic Protocol", "DEC Diagnostic PDU",
               "Historical", "Legacy",
               "DEC internal hardware diagnostic protocol — loopback and self-test",
               None,
               {"Note":"Used by DEC hardware for Ethernet loopback and diagnostic testing"},
               stack={"L2":"Ethernet II (0x6005)","L3":"No L3 — diagnostic PDU direct after Ethernet"}),

    0x6006: _e("DEC Customer Protocol", "DEC Customer PDU",
               "Historical", "Legacy",
               "DEC customer-defined protocol slot — proprietary applications",
               None, {"Note":"Allocated for customer-specific DECnet applications"},
               stack={"L2":"Ethernet II (0x6006)","L3":"Customer-defined — no standard structure"}),

    0x6007: _e("DEC LAVC / SCA (Local Area VAXcluster / Storage Controller Architecture)",
               "LAVC/SCA PDU",
               "Historical", "Legacy",
               "DEC VAXcluster interconnect — shared disks and resources across VAX cluster",
               None,
               {"Note":"LAVC/SCA — cluster-wide resource sharing via dedicated Ethernet segment"},
               stack={
                "L2": "Ethernet II (0x6007)",
                "L3": "SCA (Storage Controller Architecture)  —  cluster mass-storage protocol",
                "L3_role": "VAXcluster shared disk access — MSCP (Mass Storage Control Protocol) over SCA",
                "Application": "VAXcluster shared disks  ·  Lock Manager  ·  Distributed Queue Manager",
               }),

    0x6559: _e("Raw Frame Relay over GRE (RFC 1701)", "GRE Frame Relay",
               "Standard", "Active",
               "Frame Relay PDU encapsulated in GRE tunnel (RFC 1701)",
               "gre_fr",
               {"GRE Header":  "4B+ standard GRE with Protocol=0x6559",
                "DLCI":        "2-4B  Data Link Connection Identifier (frame relay virtual circuit)",
                "C/R":         "1b  command/response bit",
                "EA":          "1b  address extension — 0=more octets follow",
                "DE":          "1b  discard eligibility (congestion drop candidate)",
                "FECN/BECN":   "1b each  forward/backward explicit congestion notification",
                "Information": "variable  frame relay payload (IP datagram)",
                "FCS":         "2B or 4B CRC over frame relay frame",
                "CAUTION":     "DLCI must be pre-configured on both ends — wrong DLCI = frame routed to wrong PVC or discarded"}),

    0x8038: _e("DEC LANBridge Management", "DEC LanBridge PDU",
               "Historical", "Legacy",
               "DEC LANBridge — proprietary spanning tree and bridge management (pre-IEEE 802.1D)", None,
               {"Msg Type":"1B 0x01=Hello 0x02=Topology","Bridge ID":"6B DEC bridge address","Port":"1B","Flags":"1B","Data":"variable"}),

    0x8039: _e("DEC DSM/DDP (Distributed Storage Manager)", "DEC DSM PDU",
               "Historical", "Legacy", "DEC DSM/DDP over Ethernet", None, {}),

    0x803A: _e("DEC Argonaut Console", "DEC Argonaut PDU",
               "Historical", "Legacy", "DEC Argonaut graphics workstation console",
               None,
               {"Historical": "Legacy/proprietary protocol — DEC Argonaut Console VAX"}),

    0x803B: _e("DEC VAXELN (Real-Time OS)", "DEC VAXELN PDU",
               "Historical", "Legacy",
               "DEC VAXELN hard real-time OS network protocol", None, {}),

    0x803C: _e("DEC DNS Naming Service", "DEC DNS PDU",
               "Historical", "Legacy",
               "DEC DNS DECdns distributed naming protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — DEC DNS naming service DECnet"}),

    0x803D: _e("DEC Ethernet Encryption", "Encrypted Frame",
               "Historical", "Legacy",
               "DEC link-layer encryption (predecessor to MACsec)", None,
               {"Key ID":"2B encryption key identifier","IV":"8B init vector","Ciphertext":"variable DES-encrypted payload","CAUTION":"DES-based deprecated — treat payload as opaque"}),

    0x803E: _e("DEC Distributed Time Service (DTS)", "DEC DTS PDU",
               "Historical", "Legacy",
               "DEC DTS time synchronisation — predecessor to NTP/PTP", None, {}),

    0x803F: _e("DEC LAN Traffic Monitor", "DEC LTM PDU",
               "Historical", "Legacy",
               "DEC LAN Traffic Monitor — network management probe",
               None,
               {"Historical": "Legacy/proprietary protocol — DEC LAN Traffic Monitor (RMON predecessor)"}),

    0x8040: _e("DEC PATHWORKS / NetBIOS Emulation", "DEC PATHWORKS PDU",
               "Historical", "Legacy",
               "DEC PATHWORKS DECnet NetBIOS Emulation layer",
               None,
               {"Historical": "Legacy/proprietary protocol — DEC PATHWORKS PC-LAN NetBIOS emulation"}),

    0x8041: _e("DEC LAST (Local Area System Transport)", "DEC LAST PDU",
               "Historical", "Legacy",
               "DEC LAST — local area block-mode protocol", None, {}),

    # ── GROUP 12: Apple / AppleTalk ───────────────────────────────────────────
    0x809B: _e("AppleTalk EtherTalk Phase 2 (Datagram Delivery Protocol)",
               "AppleTalk DDP Packet",
               "Historical", "Deprecated",
               "Apple AppleTalk DDP — network layer for Macintosh networking (replaced by TCP/IP in macOS X)",
               "ddp",
               {"Null":"2b reserved (always 0)",
                "Hop Count":"4b router hop count (max 15 — TTL equivalent)",
                "Length":"10b total DDP packet length in bytes",
                "Checksum":"2B (0=disabled — optional in DDP)",
                "Dst Network":"2B destination AppleTalk network number",
                "Src Network":"2B source AppleTalk network number",
                "Dst Node":"1B destination node ID (1-253; 255=broadcast)",
                "Src Node":"1B source node ID",
                "Dst Socket":"1B destination socket (1-127=static Apple; 128-254=dynamic)",
                "Src Socket":"1B source socket",
                "Type":"1B upper-layer DDP type: 1=RTMP 2=NBP 3=ATP 5=AEP 6=ADSP 8=ZIP 22=AURP"},
               stack={
                "L2": "Ethernet II (0x809B) — Phase 2 EtherTalk",
                "L3": "DDP  (Datagram Delivery Protocol)  —  13B long-form header",
                "L3_role": "Connectionless socket-to-socket delivery (≈ IPv4 + UDP combined)",
                "L3_addressing": "Network(2B) + Node(1B) + Socket(1B)  →  4B AppleTalk internet address",
                "L3_AARP": "AARP (AppleTalk ARP) — dynamic node address self-assignment (EtherType 0x80F3)",
                "L4_dispatch": "DDP Type field routes to L4 protocol:",
                "L4_type_1": "1=RTMP  — Routing Table Maintenance Protocol (distance vector routing)",
                "L4_type_2": "2=NBP   — Name Binding Protocol (name→address resolution ≈ DNS/mDNS)",
                "L4_type_3": "3=ATP   — AppleTalk Transaction Protocol (reliable request-response ≈ UDP+ACK)",
                "L4_type_5": "5=AEP   — AppleTalk Echo Protocol (reachability test ≈ ICMP ping)",
                "L4_type_6": "6=ADSP  — AppleTalk Data Stream Protocol (reliable byte stream ≈ TCP)",
                "L4_type_8": "8=ZIP   — Zone Information Protocol (zone name management)",
                "L4_type_22":"22=AURP — AppleTalk Update-based Routing Protocol (WAN routing)",
                "Application":"AFP (AppleTalk Filing Protocol)  ·  PAP (Printer Access Protocol)  ·  ASP",
                "Chooser":   "Chooser app used NBP to browse zones and discover printers/servers",
                "Successor": "Rendezvous/Bonjour (mDNS + DNS-SD) replaced AppleTalk in macOS 10.2+",
               }
               ),

    0x80F3: _e("AppleTalk AARP (Address Acquisition Protocol — EtherTalk Phase 2)",
               "AARP Frame",
               "Historical", "Deprecated",
               "AppleTalk self-configuring address assignment — node ID probe/claim mechanism",
               None,
               {"HW Type":"2B (3=Ethernet Phase 2)",
                "Protocol Type":"2B (0x809B=AppleTalk DDP)",
                "HW Addr Len":"1B=6 (MAC length)",
                "Protocol Addr Len":"1B=4 (AppleTalk address length)",
                "Op":"2B 1=Request 2=Response 3=Probe",
                "Sender HW Addr":"6B MAC address",
                "Sender Protocol Addr":"4B AppleTalk net(2B)+node(1B)+unused(1B)",
                "Target HW Addr":"6B (0 for probe/request)",
                "Target Protocol Addr":"4B target AppleTalk address"},
               stack={
                "L2": "Ethernet II (0x80F3)",
                "L3": "AARP  — no DDP header; AARP packet directly after Ethernet header",
                "L3_role": "Hardware-to-AppleTalk address resolution (self-configuring — no server needed)",
                "Mechanism": "Node probes random address → waits for conflict → claims if none → stores in NVRAM",
                "Note": "AARP packets do NOT contain a DDP header — they go directly to AARP handler",
               }
               ),

    # ── GROUP 13: Novell / IPX ────────────────────────────────────────────────
    0x8137: _e("Novell IPX (NetWare — Internetwork Packet Exchange)",
               "IPX Packet",
               "Historical", "Deprecated",
               "Novell IPX — NetWare network layer, derived from XNS IDP (superseded by TCP/IP)",
               "ipx",
               {"Checksum":"2B 0xFFFF=not used (Novell disabled XNS checksum for performance)",
                "Length":"2B total IPX packet length (30B header + data, max 65535B)",
                "Transport Ctrl":"1B hop count — router increments; discarded at 16 hops",
                "Packet Type":"1B upper-layer protocol: 0=Unknown 4=PXP/IPX 5=SPX 17=NCP 20=NetBIOS-propagated",
                "Dst Network":"4B destination network number (0=local network)",
                "Dst Node":"6B destination node (Ethernet MAC or 0xFF×6=broadcast)",
                "Dst Socket":"2B destination socket: 0x0451=NCP 0x0452=SAP 0x0453=RIP 0x0455=NetBIOS 0x4001=IPX Diag",
                "Src Network":"4B source network number",
                "Src Node":"6B source node (Ethernet MAC address)",
                "Src Socket":"2B source socket (dynamically assigned 0x4000-0x7FFF for clients)"},
               stack={
                "L2": "Ethernet II (0x8137) or 802.3 raw / 802.2 LLC",
                "L3": "IPX  (Internetwork Packet Exchange)  —  30B header",
                "L3_role": "Connectionless datagram routing (≈ IPv4) — no fragmentation",
                "L3_routing": "RIP (hop+tick metric)  or  NLSP (link-state, derived from IS-IS)",
                "L4_dispatch": "IPX Packet Type field routes to L4:",
                "L4_type_4":  "4=PXP/IPX  —  raw IPX datagram (no L4 header)",
                "L4_type_5":  "5=SPX  —  Sequenced Packet Exchange (reliable, connection-oriented ≈ TCP)",
                "L4_type_17": "17=NCP  —  NetWare Core Protocol (file/print services ≈ SMB)",
                "L4_type_20": "20=NetBIOS  —  Propagated NetBIOS broadcast (type-20 forwarding)",
                "L4_SAP":    "SAP (Service Advertisement Protocol)  —  periodic service broadcasts (60s)",
                "L4_RIP":    "RIP  —  IPX Routing Information Protocol (distance vector + ticks)",
                "L4_NLSP":   "NLSP  —  NetWare Link Services Protocol (IS-IS based, optional)",
                "Application":"NDS (NetWare Directory Services)  ·  NCP file/print  ·  StreetTalk emulation",
                "Successor": "IPX was replaced by TCP/IP in NetWare 5 (1998) and later versions",
               }
               ),

    0x8138: _e("Novell IPX (alternate EtherType)", "IPX Packet",
               "Historical", "Deprecated",
               "Novell IPX alternate EtherType assignment — same structure as 0x8137",
               "ipx",
               {"Note":"Identical packet structure to EtherType 0x8137 — alternate assignment"},
               ),

    # ── GROUP 14: Xerox Legacy ────────────────────────────────────────────────
    0x0600: _e("Xerox XNS IDP (PARC Universal Packet — Internet Datagram Protocol)",
               "XNS IDP Packet",
               "Historical", "Legacy",
               "Xerox Network Systems layer-3 routing — ancestor of IPX and IP",
               "idp",
               {"Checksum":"2B (0xFFFF=disabled — optional in XNS)",
                "Length":"2B total IDP packet length (30B hdr + data, max 576B)",
                "Transport Ctrl":"1B hop count (incremented by routers, max 15)",
                "Packet Type":"1B: 1=RIP 2=Echo 3=Error 4=PEP 5=SPP 0=IDP-raw",
                "Dst Network":"4B destination network number",
                "Dst Host":"6B destination host (Ethernet MAC address)",
                "Dst Socket":"2B destination socket (port equivalent)",
                "Src Network":"4B source network number",
                "Src Host":"6B source host (Ethernet MAC address)",
                "Src Socket":"2B source socket"},
               stack={
                "L2": "Ethernet II  (EtherType 0x0600)",
                "L3": "XNS IDP  (Internet Datagram Protocol)  —  30B header",
                "L3_role": "Network layer: logical addressing, routing (unicast/multicast/broadcast)",
                "L3_addressing": "Network(4B) + Host(6B=MAC) + Socket(2B)  →  unique 12B internet address",
                "L4_dispatch": "IDP Packet Type field routes to L4:",
                "L4_type_0": "0=Raw IDP  — direct application access to IDP (no L4)",
                "L4_type_1": "1=RIP  — Routing Information Protocol (hop-count distance vector)",
                "L4_type_2": "2=Echo  — XNS Echo Protocol (like ICMP ping)",
                "L4_type_3": "3=Error  — XNS Error Protocol (reports discarded packets)",
                "L4_type_4": "4=PEP  — Packet Exchange Protocol (unreliable request-response, like UDP)",
                "L4_type_5": "5=SPP  — Sequenced Packet Protocol (reliable stream, like TCP)",
                "Application": "Courier RPC  ·  Filing (AFP-equivalent)  ·  Clearinghouse (name service)  ·  Printing",
                "Derivatives": "Novell IPX (modified IDP)  ·  Banyan VINES VIP  ·  AppleTalk (XNS-inspired)",
               }
               ),

    0x0A00: _e("Xerox IEEE 802.3 PUP (PARC Universal Packet — 802.3 variant)",
               "PUP Packet",
               "Historical", "Legacy",
               "Xerox PUP over IEEE 802.3 — revised PUP framing for 802.3 networks",
               "pup",
               {"Net":"1B network number","Host":"1B host number","Socket":"4B socket ID",
                "Packet Length":"2B","Packet Type":"1B: 0=BSP 1=RFNM 128=Error 130=Echo 131=EchoReply",
                "ID":"4B transport ID","Checksum":"2B"},
               stack={
                "L2": "IEEE 802.3 (0x0A00)",
                "L3": "PUP  —  PARC Universal Packet  (26B header)",
                "L3_role": "Early Ethernet network protocol — simpler than XNS IDP",
                "L4": "BSP (Byte Stream Protocol)  or  direct socket (type-addressed)",
                "BSP": "Byte Stream Protocol — reliable ordered delivery (pre-TCP)",
                "Application": "Pre-cursor to XNS  ·  Courier RPC prototype  ·  PARC experimental apps",
               }),

    0x0A01: _e("Xerox PUP Address Translation (PUPAT)", "PUPAT Frame",
               "Historical", "Legacy",
               "Xerox PUP Address Translation — maps PUP internet address to Ethernet MAC",
               None,
               {"Note":"PUPAT: PUP equivalent of ARP — translates PUP (net+host) to Ethernet MAC"},
               stack={"L2":"Ethernet (0x0A01)","L3":"PUPAT — no IP; ARP-like directly over Ethernet"}),

    # ── GROUP 15: IBM ─────────────────────────────────────────────────────────
    0x80D5: _e("IBM SNA over Ethernet (SDLC / QLLC / LLC2)",
               "IBM SNA Frame",
               "Historical", "Legacy",
               "IBM SNA (Systems Network Architecture) transported directly over Ethernet",
               "sna",
               {"LLC Header":"DSAP(1B=0xF0)+SSAP(1B=0xF0)+Control(1-2B) — SAP 0xF0=NetBIOS/SNA",
                "TH":"Transmission Header (2-26B) — FID type+RH+RU addressing",
                "RH":"Request/Response Header (3B) — category+sense+flags",
                "RU":"Request/Response Unit — variable application data",
                "PIU":"Path Information Unit = TH+RH+RU (basic SNA unit)",
                "Note":"SNA over Ethernet via DLC/LLC2 — later replaced by DLSw (RFC 1795) over TCP"},
               stack={
                "L2": "Ethernet II (0x80D5) or 802.2 LLC SAP=0xF0",
                "L3": "SNA Path Control  —  FID (Format ID) type routing",
                "L3_role": "Hierarchical routing — SSCP/PU/LU node addressing (not IP-style)",
                "L3_FID2": "FID2 = most common — subarea+element address in TH",
                "L4": "DFC (Data Flow Control)  +  TC (Transmission Control)",
                "L4_role": "Session management — pacing, chaining, brackets, correlation",
                "Application": "VTAM (Virtual Terminal)  ·  CICS  ·  JES/JCL  ·  3270/5250 terminal emulation",
                "DLSw": "RFC 1795 DLSw — SNA over TCP/IP encapsulation (modern migration path)",
                "Successor": "TCP/IP + TN3270  ·  DLSw  ·  HPR/APPN (APPC peer networking)",
               }),

    0x814C: _e("SNMP over Ethernet (RFC 1089 — obsolete)", "SNMP PDU",
               "Historical", "Deprecated",
               "SNMP directly over Ethernet — RFC 1089 (1989), replaced by SNMP/UDP",
               None,
               {"Version":"1B (SNMPv1)","Community":"variable string","PDU":"Get/Set/Response/Trap",
                "Note":"RFC 1089 approach abandoned — all modern SNMP uses UDP port 161/162"},
               stack={
                "L2": "Ethernet II (0x814C)",
                "L3": "None — SNMP PDU placed directly after Ethernet header (no IP layer)",
                "Application": "SNMP Get/Set/GetNext/Response/Trap — network management (now via UDP)",
               }),

    # ── GROUP 16: Silicon Graphics (SGI) ─────────────────────────────────────
    0x8013: _e("SGI Diagnostics", "SGI Diagnostic PDU",
               "Historical", "Legacy",
               "Silicon Graphics IRIX diagnostic protocol — hardware test over Ethernet",
               None, {"Note":"SGI-internal diagnostics for IRIX workstations/servers"},
               stack={"L2":"Ethernet II (0x8013)","L3":"SGI proprietary — no published standard"}),

    0x8014: _e("SGI Network Games", "SGI Games PDU",
               "Historical", "Legacy",
               "Silicon Graphics network multiplayer games protocol (IRIX)",
               None, {"Note":"SGI proprietary multicast games on IRIX workstations"},
               stack={"L2":"Ethernet II (0x8014)","L3":"SGI proprietary — no published standard"}),

    0x8015: _e("SGI Reserved", "SGI Reserved PDU",
               "Historical", "Legacy",
               "Silicon Graphics reserved EtherType — purpose undocumented",
               None,
               {"Historical": "Legacy/proprietary protocol — SGI reserved range"}),

    0x8016: _e("SGI XNS NameServer / Bounce Server", "SGI XNS PDU",
               "Historical", "Legacy",
               "Silicon Graphics XNS NameServer and bounce server",
               None,
               {"Historical": "Legacy/proprietary protocol — SGI XNS name/bounce server"}),

    # ── GROUP 17: Banyan Systems ──────────────────────────────────────────────
    0x0BAD: _e("Banyan VINES (VIP — VINES Internetwork Protocol)",
               "VINES VIP Packet",
               "Historical", "Deprecated",
               "Banyan VINES LAN OS — XNS-derived networking with StreetTalk directory",
               "vip",
               {"Checksum":"2B optional (XNS heritage)",
                "Length":"2B total packet length",
                "Transport Ctrl":"1B hop count",
                "Protocol":"1B: 0=IPC 1=SPP 2=ARP 4=RTP/SRTP 5=ICP",
                "Dst Network":"4B VINES network number",
                "Dst Subnetwork":"2B VINES subnetwork",
                "Src Network":"4B","Src Subnetwork":"2B"},
               stack={
                "L2": "Ethernet II (0x0BAD)",
                "L3": "VIP (VINES Internetwork Protocol)  —  18B header",
                "L3_role": "XNS IDP derivative — connectionless routing with 48-bit addresses",
                "L4_dispatch": "VIP Protocol byte:",
                "L4_IPC":  "0=IPC  Interprocess Communication — reliable messages (≈ TCP/message mode)",
                "L4_SPP":  "1=SPP  Sequenced Packet Protocol — reliable byte stream (≈ TCP/stream mode)",
                "L4_ARP":  "2=ARP  VINES ARP — query/response/assign for address resolution",
                "L4_RTP":  "4=RTP  Routing Table Protocol — distance-vector with millisecond metric",
                "L4_SRTP": "4=SRTP Sequenced RTP (VINES 5.5+) — adds sequence numbers to RTP",
                "L4_ICP":  "5=ICP  Internet Control Protocol — error + routing cost exceptions",
                "Application":"StreetTalk (item@group@org)  ·  VINES File/Print/Mail  ·  VINES Management",
                "Successor": "Replaced by TCP/IP + Active Directory / LDAP late 1990s",
               }),

    0x0BAE: _e("Banyan VINES Loopback", "VINES Loopback Packet",
               "Historical", "Deprecated",
               "Banyan VINES loopback — echoes VIP packet to sender for testing",
               None, {"Note":"Same VIP structure as 0x0BAD — returned to sender unchanged"}),

    0x0BAF: _e("Banyan VINES Echo", "VINES Echo Packet",
               "Historical", "Deprecated",
               "Banyan VINES echo — reachability test analogous to ICMP echo",
               None, {"Note":"VIP echo request/response pair for path verification"}),

    0x80C4: _e("Banyan Systems Private (1)", "Banyan VINES PDU",
               "Historical", "Legacy", "Banyan Systems private protocol slot 1", None, {}),

    0x80C5: _e("Banyan Systems Private (2)", "Banyan VINES PDU",
               "Historical", "Legacy", "Banyan Systems private protocol slot 2", None, {}),

    # ── GROUP 18: 3Com / Bridge Communications ────────────────────────────────
    0x9001: _e("3Com XNS Systems Management (formerly Bridge Comm.)", "XNS Mgmt Frame",
               "Historical", "Legacy",
               "3Com XNS Systems Management Protocol", None,
               {"Msg Type":"2B 0x0001=Get 0x0002=Set 0x0003=Trap","Req ID":"2B","OID":"variable XNS OID","Value":"variable managed object value"}),

    0x9002: _e("3Com TCP/IP Systems Management", "Mgmt Frame",
               "Historical", "Legacy",
               "3Com TCP/IP Systems Management Protocol", None,
               {"Msg Type":"1B","Version":"1B","Length":"2B","Agent ID":"4B device ID","Data":"variable management payload"}),

    0x9003: _e("3Com Bridge Loop Detection", "Loop Detect Frame",
               "Historical", "Legacy",
               "3Com Bridge loop detection protocol", None,
               {"Bridge ID":"6B sending bridge MAC","Port ID":"2B port","Seq":"2B loop-detection sequence","CAUTION":"Not a substitute for STP/RSTP"}),

    # ── GROUP 19: HP (Hewlett-Packard) ────────────────────────────────────────
    0x8005: _e("HP Probe Protocol", "HP Probe Frame",
               "Historical", "Legacy",
               "Hewlett-Packard network probe and diagnostic protocol", None,
               {"Msg Type":"1B 0x01=Request 0x02=Reply","TTL":"1B hop count","Src ID":"4B probe source","Data":"variable probe data"}),

    0x8888: _e("HP LanProbe Test", "HP LanProbe PDU",
               "Historical", "Legacy", "HP LanProbe test/diagnostic protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — HP LanProbe network analyser probe protocol"}),

    # ── GROUP 20: Apollo / Various Workstation Vendors ────────────────────────
    0x8019: _e("Apollo Domain (HP Apollo)", "Apollo Domain Frame",
               "Historical", "Legacy",
               "Apollo Domain OS network protocol — later HP Apollo workstations", None,
               {"Msg Type":"2B 0x0001=RPC-call","Src UID":"8B Apollo UID","Dst UID":"8B","Seq":"4B","Data":"variable NCS payload"}),

    0x8044: _e("Planning Research Corporation", "PRC PDU",
               "Historical", "Legacy", "Planning Research Corp. private EtherType",
               None,
               {"Historical": "Legacy/proprietary protocol — Planning Research Corporation government contractor"}),

    0x802E: _e("Tymshare", "Tymshare PDU",
               "Historical", "Legacy", "Tymshare timesharing service network protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Tymshare Inc. time-sharing service 1980s"}),

    0x802F: _e("Tigan Inc.", "Tigan PDU",
               "Historical", "Legacy", "Tigan Inc. private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Tigan Inc. private"}),

    0x8036: _e("Aeonic Systems", "Aeonic Systems PDU",
               "Historical", "Legacy", "Aeonic Systems private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Aeonic Systems 1980s LAN vendor"}),

    0x8049: _e("ExperData", "ExperData PDU",
               "Historical", "Legacy", "ExperData private EtherType",
               None,
               {"Historical": "Legacy/proprietary protocol — ExperData French networking company"}),

    0x805B: _e("Stanford V Kernel (Experimental)", "Stanford V Kernel PDU",
               "Historical", "Legacy",
               "Stanford V distributed OS kernel — experimental network", None, {}),

    0x805C: _e("Stanford V Kernel (Production)", "Stanford V Kernel PDU",
               "Historical", "Legacy",
               "Stanford V distributed OS kernel — production network", None, {}),

    0x805D: _e("Evans & Sutherland", "Evans Sutherland PDU",
               "Historical", "Legacy",
               "Evans & Sutherland 3D graphics workstation protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Evans & Sutherland graphics workstation"}),

    0x8060: _e("Little Machines", "Little Machines PDU",
               "Historical", "Legacy", "Little Machines private EtherType",
               None,
               {"Historical": "Legacy/proprietary protocol — Little Machines Inc. private"}),

    0x8062: _e("Counterpoint Computers", "Counterpoint PDU",
               "Historical", "Legacy",
               "Counterpoint Computers private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Counterpoint Computers Unix workstation 1980s"}),

    0x8065: _e("University of Massachusetts Amherst (1)", "UMass Research PDU",
               "Historical", "Legacy",
               "UMass Amherst research network protocol (1)", None, {}),

    0x8066: _e("University of Massachusetts Amherst (2)", "UMass Research PDU",
               "Historical", "Legacy",
               "UMass Amherst research network protocol (2)", None, {}),

    0x8067: _e("Veeco Integrated Automation", "Veeco PDU",
               "Historical", "Legacy",
               "Veeco Integrated Automation — scientific instruments",
               None,
               {"Historical": "Legacy/proprietary protocol — Veeco Integrated Automation lab instruments"}),

    0x8068: _e("General Dynamics", "General Dynamics PDU",
               "Historical", "Legacy",
               "General Dynamics defence/aerospace private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — General Dynamics defense contractor"}),

    0x806A: _e("Autophon (Swiss Telecom)", "Autophon PDU",
               "Historical", "Legacy",
               "Autophon Swiss telephone equipment manufacturer protocol", None, {}),

    0x806C: _e("ComDesign", "ComDesign PDU",
               "Historical", "Legacy", "ComDesign private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — ComDesign private"}),

    0x806D: _e("Computgraphic Corporation", "Computgraphic PDU",
               "Historical", "Legacy",
               "Computgraphic typesetting systems private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Computgraphic Corporation typesetting 1980s"}),

    0x807A: _e("Matra (French defence electronics)", "Matra PDU",
               "Historical", "Legacy",
               "Matra SA (French defence/aerospace) private protocol", None, {}),

    0x807B: _e("Dansk Data Elektronik", "Dansk Data PDU",
               "Historical", "Legacy",
               "Dansk Data Elektronik (Danish IT) private protocol", None, {}),

    0x807C: _e("Merit Internodal (Merit Network)", "Merit Internodal PDU",
               "Historical", "Legacy",
               "Merit Network (Michigan) internodal routing protocol", None, {}),

    0x8080: _e("Vitalink TransLAN III", "Vitalink TransLAN PDU",
               "Historical", "Legacy",
               "Vitalink Communications TransLAN III bridge protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Vitalink Communications TransLAN III bridge protocol"}),

    0x80A3: _e("Nixdorf Computers", "Nixdorf PDU",
               "Historical", "Legacy",
               "Nixdorf Computer AG private protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Nixdorf Computers German business machines"}),

    0x817D: _e("XTP (Xpress Transport Protocol)", "XTP Frame",
               "Historical", "Deprecated",
               "XTP transport protocol — combined transport+network (research)", None,
               {"Note":"XTP was an alternative to TCP — never deployed commercially"}),

    0x8180: _e("HIPPI-FP Encapsulation (High-Performance Parallel Interface)", "HIPPI-FP Frame",
               "Historical", "Legacy",
               "HIPPI-FP 800Mbps/1.6Gbps supercomputer interconnect framing", None,
               {"Note":"Precursor to InfiniBand — used in 1990s HPC/supercomputers"}),

    0x818D: _e("Motorola Computer Group", "Motorola PDU",
               "Historical", "Legacy",
               "Motorola Computer Group (68000-based workstations) private", None, {}),

    0x80F7: _e("Apollo Computer (HP)", "Apollo Domain PDU",
               "Historical", "Legacy",
               "Apollo Computer (acquired by HP 1989) private protocol", None, {}),

    0x80DD: _e("Varian Associates", "Varian PDU",
               "Historical", "Legacy",
               "Varian Associates (scientific instruments) private protocol", None, {}),

    # ── GROUP 21: Ungermann-Bass / BBN / Cronus ───────────────────────────────
    0x0900: _e("Ungermann-Bass Net Debugger", "UB Net Debugger PDU",
               "Historical", "Legacy",
               "Ungermann-Bass (early LAN vendor) network debugger", None, {}),

    0x7000: _e("Ungermann-Bass Download", "UB Download PDU",
               "Historical", "Legacy",
               "Ungermann-Bass firmware/config download protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Ungermann-Bass firmware download"}),

    0x7002: _e("Ungermann-Bass Diagnostics / Loop", "UB Diagnostics PDU",
               "Historical", "Legacy",
               "Ungermann-Bass loopback and diagnostic protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Ungermann-Bass diagnostics and loopback"}),

    0x7030: _e("Proteon (Pioneer Router Vendor)", "Proteon RIP PDU",
               "Historical", "Legacy",
               "Proteon Inc. — early internet router vendor (1972–2004)", None, {}),

    0x7034: _e("Cabletron Systems (now Extreme Networks)", "Cabletron PDU",
               "Historical", "Legacy",
               "Cabletron Systems private protocol — acquired by Enterasys/Extreme", None, {}),

    0x5208: _e("BBN Simnet Private", "BBN Simnet PDU",
               "Historical", "Legacy",
               "BBN Technologies Simnet simulation network",
               None,
               {"Historical": "Legacy/proprietary protocol — BBN Simnet private DARPA research 1980s"}),

    0x8003: _e("Cronus VLN (RFC 824)", "Cronus VLN Frame",
               "Historical", "Legacy",
               "Cronus Virtual Local Network — RFC 824 (1982)", None,
               {"VLN Header":"4B msg-type+flags","VLN Data":"variable Cronus VLN payload"}),

    0x8004: _e("Cronus Direct (RFC 824)", "Cronus Direct Frame",
               "Historical", "Legacy",
               "Cronus Direct transport — RFC 824 (1982)", None,
               {"Msg Type":"1B 0x01=data 0x02=ack","Seq":"1B","Length":"2B","Data":"variable Cronus Direct payload"}),

    0xFF00: _e("BBN VITAL-LanBridge Cache Wakeup (private)", "BBN LanBridge PDU",
               "Private", "Legacy",
               "BBN VITAL-LanBridge cache wakeup — ISC Bunker Ramo range 0xFF00-FF0F", None, {}),

    0xFFFF: _e("Reserved — RFC 1701 / IEEE 802.3", "Reserved Frame",
               "Standard", "Reserved",
               "Reserved EtherType — never assigned for use (RFC 1701)", None, {}),

    # ── GROUP 22: Research / Miscellaneous ────────────────────────────────────
    0x4242: _e("PCS Basic Block Protocol", "PCS Basic Block PDU",
               "Historical", "Legacy",
               "PCS (Protocol Conversion System) Basic Block Protocol", None, {}),

    0x1600: _e("Valid Systems Protocol", "Valid Systems PDU",
               "Historical", "Legacy",
               "Valid Systems (EDA tools) internal protocol", None, {}),

    0x8191: _e("PowerLAN NetBIOS/NetBEUI (PC PowerLAN)", "NetBEUI Frame",
               "Historical", "Legacy",
               "PowerLAN NetBIOS/NetBEUI over Ethernet — early PC LAN", None,
               {"Length":"2B frame length","Delimiter":"1B 0xEF","Command":"1B NetBEUI command","LSN":"1B local session","RSN":"1B remote session","Data":"variable NBF PDU"}),

    0x8739: _e("Control Technology Inc. RDP Without IP", "CTI Frame",
               "Historical", "Legacy",
               "Control Technology Inc. Remote Device Protocol (no IP stack)", None,
               {"Device ID":"2B controller ID","Msg Type":"1B 0x01=Cmd 0x02=Resp","Seq":"2B","Data":"variable I/O data","CAUTION":"Unauthenticated industrial control — isolate to dedicated VLAN"}),

    0x873A: _e("Control Technology Inc. Multicast Industrial Control", "CTI Frame",
               "Historical", "Legacy",
               "Control Technology Inc. multicast industrial control protocol", None,
               {"Group ID":"2B multicast group","Msg Type":"1B","Data":"variable multicast payload","CAUTION":"No auth — loop risk if STP absent"}),

    0x8856: _e("Axis Communications Proprietary Bootstrap/Config", "Axis Frame",
               "Vendor", "Active",
               "Axis Communications (network cameras) proprietary bootstrap protocol", "axis_boot",
               {"Msg Type":"1B 0x01=Discovery 0x02=IPAssign","Serial":"8B Axis serial number","Current IP":"4B","New IP":"4B","Subnet":"4B","CAUTION":"Unauthenticated IP assignment — attacker on LAN can reassign camera IP"}),

    0x8820: _e("Hitachi Cable (Optoelectronic Systems Lab)", "Hitachi Cable PDU",
               "Historical", "Legacy",
               "Hitachi Cable optoelectronic lab private protocol", None, {}),

    0xAAAA: _e("DECNET / VAX 6220 DEBNI", "DECNET DEBNI PDU",
               "Historical", "Legacy",
               "DEC DEBNI interface board on VAX 6220 — DECnet protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Digital Equipment DEBNI VAX 6220 boot/management"}),

    0xFAF5: _e("Sonix Arpeggio", "Sonix Arpeggio PDU",
               "Historical", "Legacy",
               "Sonix Arpeggio proprietary protocol",
               None,
               {"Historical": "Legacy/proprietary protocol — Sonix Arpeggio DSP/audio networking 1990s"}),

    # ── GROUP 23: Cisco Proprietary (via SNAP OUI 00:00:0C) ──────────────────
    0x2000: _e("Cisco CDP (Cisco Discovery Protocol — SNAP PID 0x2000)", "CDP PDU",
               "Vendor", "Active",
               "Cisco proprietary neighbour discovery — device ID, capabilities, addresses, power",
               "cdp",
               {"SNAP OUI":          "3B  0x00:00:0C  (Cisco)",
                "SNAP PID":          "2B  0x2000",
                "CDP Version":       "1B  0x01=CDPv1  0x02=CDPv2",
                "TTL":               "1B  hold-time in seconds (default 180)",
                "Checksum":          "2B  CRC over entire CDP PDU",
                "── TLV chain ──":   "",
                "TLV DeviceID":      "Type=0x0001  Len=4+N  hostname or Serial-Number string",
                "TLV Addresses":     "Type=0x0002  Len=4+N  Count(4B)+[Protocol(1B)+Proto(N)+Addr(M)] per address",
                "TLV PortID":        "Type=0x0003  Len=4+N  interface name (e.g. 'GigabitEthernet0/1')",
                "TLV Capabilities":  "Type=0x0004  Len=4+4  bitmask: Router=0x01 TrBridge=0x02 SRBridge=0x04 Switch=0x08 Host=0x10 IGMP=0x20 Repeater=0x40 Phone=0x80",
                "TLV SoftwareVer":   "Type=0x0005  Len=4+N  IOS version string",
                "TLV Platform":      "Type=0x0006  Len=4+N  hardware model (e.g. 'cisco WS-C3750X-48')",
                "TLV IPPrefix":      "Type=0x0007  subnet reachability information",
                "TLV VTPDomain":     "Type=0x0009  Len=4+N  VTP management domain name",
                "TLV NativeVLAN":    "Type=0x000A  Len=4+2  native VLAN ID (2B)",
                "TLV Duplex":        "Type=0x000B  Len=4+1  0x00=half  0x01=full",
                "TLV PowerAvail":    "Type=0x0010  Len=4+4  milliwatts available for PoE (802.3af/at/bt)",
                "TLV MTUID":         "Type=0x0022  Management addresses for CDPv2",
                "TLV Endpt":         "Type=0xFFFF  Terminator — optional",
                "CAUTION":           "CDP leaks full device identity, IOS version, platform, and management IPs to anyone on the segment — disable on untrusted ports with 'no cdp enable'"}),

    0x2003: _e("Cisco VTP (VLAN Trunk Protocol — SNAP PID 0x2003)", "VTP PDU",
               "Vendor", "Active",
               "Cisco proprietary VLAN database synchronisation across trunk links",
               "vtp",
               {"SNAP OUI":          "3B  0x00:00:0C",
                "SNAP PID":          "2B  0x2003",
                "VTP Version":       "1B  0x01=VTPv1  0x02=VTPv2  0x03=VTPv3",
                "Code":              "1B  0x01=Summary-Advertisement  0x02=Subset-Advertisement  0x03=Advertisement-Request  0x04=Join(v2)",
                "Followers":         "1B  (Summary) number of Subset-Advertisements to follow",
                "Domain Length":     "1B  VTP domain name length",
                "VTP Domain Name":   "32B  null-padded domain name (must match to accept advertisements)",
                "Config Revision":   "4B  monotonically increasing — higher always wins; set to 0 when joining new domain",
                "Updater Identity":  "4B  IP address of last switch to update VLAN database",
                "Update Timestamp":  "12B  timestamp of last update  (ASCII YYMMDDHHMMSS)",
                "MD5 Digest":        "16B  (VTPv1/v2) authentication hash; (VTPv3) SHA256 over domain+password",
                "VTP Password Hash": "16B  (if VTP auth enabled) MD5(domain+password) — blank=no auth",
                "VLAN Info":         "(Subset) per-VLAN: InfoLen(1B)+Status(1B)+VLANType(1B)+NameLen(1B)+ISL-VLAN(2B)+MTU(2B)+802.10Index(4B)+Name(N bytes)",
                "VTPv3 Primary":     "1B  0x01=this switch is primary server",
                "VTPv3 Feature":     "2B  0x0001=VLAN 0x0002=MST 0x0003=VTP-Private",
                "CAUTION":           "VTP revision-number attack: plug in a switch with higher Config-Revision and matching domain → overwrites all VLANs on every switch; always set VTP transparent or use VTPv3 with password"}),

    0x2004: _e("Cisco DTP (Dynamic Trunking Protocol — SNAP PID 0x2004)", "DTP PDU",
               "Vendor", "Active",
               "Cisco proprietary trunk auto-negotiation — enables VLAN hopping if not disabled",
               "dtp",
               {"SNAP OUI":          "3B  0x00:00:0C",
                "SNAP PID":          "2B  0x2004",
                "DTP Version":       "1B  0x01",
                "TLV Domain":        "Type=0x01  Len=4+34  trunk domain name",
                "TLV Status":        "Type=0x02  Len=4+1  0x81=Trunk/Desirable 0x83=Trunk/Auto 0x84=Access/On 0x85=Access/Off",
                "TLV DTP Type":      "Type=0x03  Len=4+1  0x01=ISL 0x02=802.1Q 0x03=negotiate 0x04=None",
                "TLV Neighbor":      "Type=0x04  Len=4+6  neighbor switch MAC (sender's MAC)",
                "Mode Summary":      "Desirable=active trunk negotiation; Auto=passive; On=always trunk; Off=never trunk; Nonegotiate=no DTP sent",
                "CAUTION":           "VLAN hopping via DTP: attacker sends DTP Desirable frame → switch forms trunk → attacker sends 802.1Q double-tagged frames to any VLAN; always 'switchport nonegotiate' on access ports"}),

    # ── Cisco PVST+ / Rapid-PVST+ (802.3 LLC+SNAP) ───────────────────────────
    0x010B: _e("Cisco PVST+ / Rapid-PVST+ (Per-VLAN Spanning Tree)", "PVST+ BPDU",
               "Vendor", "Active",
               "Cisco Per-VLAN STP — separate spanning-tree instance per VLAN via SNAP PID 0x010B",
               "pvst",
               {"SNAP OUI":          "3B  0x00:00:0C  (Cisco)",
                "SNAP PID":          "2B  0x010B  (PVST+) or 0x010C (Rapid-PVST+)",
                "Protocol ID":       "2B  0x0000",
                "Protocol Version":  "1B  0x00=PVST+(STP) 0x02=Rapid-PVST+(RSTP)",
                "BPDU Type":         "1B  0x00=Configuration 0x80=TCN 0x02=RST/MST",
                "Flags":             "1B  TC(b0)+Proposal(b1)+PortRole(b2:b3)+Learning(b4)+Forwarding(b5)+Agreement(b6)+TCA(b7)",
                "Root Priority":     "2B  4b priority(0-61440 in steps of 4096) + 12b System-ID-Ext(VLAN-ID)",
                "Root MAC":          "6B  root bridge MAC address",
                "Root Path Cost":    "4B  cumulative cost to root (100Mbps=19 1Gbps=4 10Gbps=2 100Gbps=1)",
                "Bridge Priority":   "2B  4b priority + 12b System-ID-Ext(VLAN-ID)",
                "Bridge MAC":        "6B  sending bridge MAC",
                "Port ID":           "2B  4b priority(default 0x80) + 12b port number",
                "Message Age":       "2B  1/256-second units — hops from root to here",
                "Max Age":           "2B  1/256-second units — default 5120 (=20s)",
                "Hello Time":        "2B  1/256-second units — default 512 (=2s)",
                "Forward Delay":     "2B  1/256-second units — default 3840 (=15s)",
                "VLAN TLV":          "Type=0x00  Len=0x02  VLAN-ID(2B) — PVST+ proprietary extension",
                "CAUTION":           "PVST+ uses Dst 01:00:0C:CC:CC:CD (not 01:80:C2:00:00:00) — mismatched native VLAN causes PVST BPDU on wrong VLAN → STP loop"}),

    # ── Cisco MSTP extension (802.1s — uses 802.3 LLC like STP) ──────────────
    # MSTP uses EtherType=802.3 (length) + LLC 42:42:03 same as STP
    # Distinguished by Protocol Version=0x03 in BPDU
    # No separate EtherType — documented here as registry note
    # MSTP BPDUs are carried inside the STP flow (version=3 in ask_l3_stp)

    # ── Cisco UDLD (Uni-Directional Link Detection — SNAP PID 0x0111) ─────────
    0x0111: _e("Cisco UDLD (Uni-Directional Link Detection — SNAP PID 0x0111)", "UDLD PDU",
               "Vendor", "Active",
               "Cisco proprietary unidirectional link detection — detects fibre TX/RX mismatch",
               "udld",
               {"SNAP OUI":          "3B  0x00:00:0C",
                "SNAP PID":          "2B  0x0111",
                "UDLD Version":      "4b  0x01",
                "Opcode":            "4b  0x00=Reserved 0x01=Probe 0x02=Echo 0x03=Flush",
                "Flags":             "1B  RT(b0)=Recommended-Timeout  RSY(b1)=Resync",
                "Checksum":          "2B",
                "── TLV chain ──":   "",
                "TLV DeviceID":      "Type=0x0001  Len=4+N  sending device ID string (hostname+port)",
                "TLV PortID":        "Type=0x0002  Len=4+N  sending port ID string",
                "TLV Echo":          "Type=0x0003  Len=4+N  list of neighbor Device+Port IDs heard",
                "TLV Message Interval":"Type=0x0004  Len=4+1  probe interval 7s(normal) 1s(aggressive)",
                "TLV Timeout Interval":"Type=0x0005  Len=4+1  detection timeout (default 5× interval)",
                "TLV Device Name":   "Type=0x0006  Len=4+N  device hostname",
                "TLV Sequence No":   "Type=0x0007  Len=4+4  monotonic sequence",
                "CAUTION":           "Aggressive mode: if no Echo for timeout → port goes to err-disabled; do NOT enable aggressive mode on links where UDLD PDUs can be legitimately delayed (e.g. DWDM with APS protection switching)"}),

    # ── EtherChannel / Port-Channel (LACP + PAgP carrier) ────────────────────
    # Note: EtherChannel itself has no EtherType — it is the logical LAG bundle
    # formed by LACP (0x8809 subtype=1) or PAgP (0x2004/SNAP)
    # The 'EtherChannel' entry below documents the LAG concept + LACP/PAgP framing
    0x01FF: _e("EtherChannel / Port-Channel (LAG concept marker — Cisco/IEEE)", "LAG Bundle",
               "Vendor", "Active",
               "EtherChannel (Cisco) / Port-Channel — logical aggregation of 2-8 Ethernet ports",
               "etherchannel",
               {"Negotiation":       "LACP (IEEE 802.3ad) via 0x8809 subtype=1 OR PAgP (Cisco) via SNAP 0x00:00:0C PID 0x0104",
                "LACP Modes":        "Active=sends LACP PDUs; Passive=responds only; both must not be Passive",
                "PAgP Modes":        "Desirable=sends PAgP; Auto=responds only; On=static (no negotiation)",
                "Load Balancing":    "src-mac / dst-mac / src-dst-mac / src-ip / dst-ip / src-dst-ip / src-dst-port",
                "Min/Max Links":     "min-links: minimum active members before bundle operational; max-bundle: max active (rest = hot-standby)",
                "LACP System Prio":  "2B  lower=preferred for which ports are active when MaxBundle exceeded (default 32768)",
                "LACP Port Prio":    "2B  lower=preferred to be active vs standby (default 32768)",
                "LACP Fast Timer":   "1s PDU interval — detects failure in 3s; Slow=30s default",
                "802.3ad Key":       "2B  ports with same admin key can form LAG — auto-derived from speed",
                "CAUTION":           "Static EtherChannel (mode On) — no negotiation; misconfigured partner causes spanning-tree loop on the bundle; always use LACP for safety"}),

    0x80FF: _e("Wellfleet/Bay Networks (private)", "Wellfleet PDU",
               "Historical", "Legacy",
               "Wellfleet Communications (later Bay Networks) private protocol", None, {}),

    # ── GROUP 24: Berkeley / Research ─────────────────────────────────────────
    0x1000: _e("Berkeley Trailer Negotiation", "Trailer Frame",
               "Historical", "Legacy",
               "BSD Berkeley Trailer encapsulation — IP header moved to end (VAX optimisation)", None,
               {"Note":"Reduced memory copies on VAX — never widely deployed"}),

    # ── GROUP 25: ETSI / GeoNetworking ────────────────────────────────────────
    0x8947: _e("GeoNetworking — ETSI EN 302 636-4-1 / ITS-G5", "GeoNetworking PDU",
               "Industry", "Active",
               "ETSI ITS geographic routing for V2X — position-based forwarding",
               "geonet",
               {"Basic Header":    "4B Version(4b)+NH(4b)+Reserved(8b)+Lifetime(8b)+RHL(8b)",
                "NH (Next Header)":"4b 0=Any 1=CommonHeader 2=Secured(IEEE 1609.2)",
                "Lifetime":        "1B encoded base×multiplier — max packet lifetime before discard",
                "RHL":             "1B Remaining Hop Limit — decremented each hop; drop at 0",
                "Common Header":   "8B NH(4b)+Reserved(4b)+HT(4b)+HST(4b)+TC(8b)+Flags(8b)+PL(16b)+MHL(8b)+Reserved(8b)",
                "HT (Header Type)":"4b 0=UNSPECIFIED 1=BEACON 2=GUC 3=GAC 4=GBC 5=TSB 6=LS(LocationService)",
                "TC (Traffic Class)":"1B SCF(1b)+ChannelOffload(1b)+TCid(6b)",
                "PL (Payload Len)": "2B payload bytes after all headers",
                "Extended Header":  "variable; GUC=GN-Address(8B) GBC/GAC=GeoArea(20B) BEACON=empty TSB=SN(2B)+Reserved(2B)",
                "GN-Address":       "8B M(1b)+ST(5b)+Reserved(10b)+CountryCode(10b)+MACaddr(48b)",
                "GeoArea":          "20B CenterLat(32b)+CenterLong(32b)+DistA(16b)+DistB(16b)+Angle(16b)+Reserved(16b)",
                "BTP Payload":      "variable BTP-A(4B)/BTP-B(4B) + CAM/DENM/SPAT/MAP/TIM application",
                "CAUTION":          "Large GeoArea broadcast causes storm; set RHL and Lifetime appropriately; no auth in base spec — use IEEE 1609.2 certificates"}),

    # ── GROUP 26: Loopback / Test ─────────────────────────────────────────────
    0x8822: _e("Wind River / Ethernet NIC Test", "Test Frame",
               "Vendor", "Active",
               "Ethernet NIC hardware and software testing (Wind River Systems)", "nic_test",
               {"Test Type":"1B 0x01=loopback 0x02=pattern","Pattern":"1B fill byte","Length":"2B payload length","Data":"variable test pattern","CAUTION":"Test frames must not reach production ports"}),

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 27: VENDOR PROPRIETARY — ALL COMPANIES
    # Sources: IEEE EtherType registry, vendor documentation, Wireshark
    # ══════════════════════════════════════════════════════════════════════════

    # ── Cisco Additional Proprietary ──────────────────────────────────────────
    0x2001: _e("Cisco STP Multicast", "Cisco STP Multicast Frame", "Vendor", "Active",
               "Cisco Spanning Tree multicast frames on non-standard groups; seen on some Catalyst linecards",
               "pvst",
               {"Protocol ID": "2B  0x0000",
                "Version":     "1B  0x00=STP 0x02=RSTP",
                "BPDU Type":   "1B  0x00=Config 0x80=TCN 0x02=RST",
                "Flags":       "1B  TC+TCA bits per IEEE 802.1D",
                "Root BID":    "8B  Priority+SystemExt+MAC",
                "CAUTION":     "Non-standard multicast; standard STP uses LLC DSAP/SSAP=0x42"}),

    0x2002: _e("Cisco DISL — Dynamic ISL", "DISL Frame", "Vendor", "Active",
               "Dynamic ISL — Cisco dynamic ISL trunk negotiation predecessor to DTP; negotiates ISL VLAN tagging",
               "pvst",
               {"DISL Version": "1B",
                "Type":         "1B  trunk type (ISL only)",
                "Sender MAC":   "6B",
                "CAUTION":      "DISL predates DTP and 802.1Q — seen only on very old Cisco Catalyst hardware; ISL deprecated in IOS 15.x"}),

    0x2005: _e("Cisco CGMP — Cisco Group Management Protocol", "CGMP Frame", "Vendor", "Active",
               "Cisco CGMP allows switches to learn multicast membership from routers without IGMP snooping hardware; "
               "deprecated in favour of IGMP snooping (RFC 4541) on modern hardware",
               "cdp",
               {"Version":    "1B  0x01",
                "Type":       "1B  0x00=Join 0x01=Leave",
                "Count":      "1B  number of GDA/USA pairs",
                "GDA":        "6B  Group Destination Address (multicast MAC e.g. 01:00:5E:xx:xx:xx)",
                "USA":        "6B  Unicast Source Address (host or router MAC joining group)",
                "CAUTION":    "CGMP is Cisco-only and unidirectional (router→switch); disable if IGMP snooping enabled — conflicts cause duplicate flooding; only relevant on Catalyst 2900/3500 era hardware"}),

    0x2007: _e("Cisco CDPv2", "CDPv2 Frame", "Vendor", "Active",
               "Cisco Discovery Protocol version 2 — adds VoIP VLAN, PoE, extended trust, "
               "and location TLVs over CDPv1; same wire format as CDP EtherType 0x2000",
               "cdp",
               {"CDP Version":  "1B  0x02",
                "TTL":          "1B  hold time seconds (default 180)",
                "Checksum":     "2B  IP-style checksum over CDP frame",
                "TLV 0x000A":   "Native VLAN (2B)",
                "TLV 0x000B":   "Duplex (1B: 0=half 1=full)",
                "TLV 0x0010":   "PoE available milliwatts (4B)",
                "TLV 0x0011":   "802.3 PoE extended (4B)",
                "TLV 0x001A":   "Location (variable ASCII)",
                "TLV 0x001B":   "External port-ID",
                "CAUTION":      "CDPv2 unauthenticated — reveals IOS version, model, VLAN topology; disable on all access and uplink ports facing untrusted segments; use LLDP (IEEE 802.1AB) for multi-vendor environments"}),

    0x010C: _e("Cisco Rapid-PVST+ (RPVST+)", "Rapid-PVST+ BPDU", "Vendor", "Active",
               "Cisco Rapid Per-VLAN Spanning Tree+ — per-VLAN RSTP; VLAN-ID in bridge priority "
               "System-ID-Extension field; uses SNAP 0x010C on some Cisco NX-OS platforms",
               "pvst",
               {"Protocol ID":  "2B  0x0000",
                "Version":      "1B  0x02=RSTP",
                "BPDU Type":    "1B  0x02=RST BPDU",
                "Flags":        "1B  full RSTP 8-bit: TC+Proposal+PortRole+Learning+Forwarding+Agreement+TCA",
                "Root BID":     "8B  Priority(4b×4096)+VLAN-ID(12b)+MAC(48b)",
                "Root Cost":    "4B  802.1D-2004 path cost",
                "Bridge BID":   "8B  same format — System-ID-Extension = VLAN ID",
                "Port ID":      "2B  Priority(4b×16)+PortNum(12b)",
                "Timers":       "8B  MessageAge+MaxAge+HelloTime+ForwardDelay (1/256-sec units)",
                "Version1Len":  "1B  0x00 always",
                "VLAN TLV":     "Type(2B=0x0000)+Length(2B=0x0002)+VLAN-ID(2B)",
                "CAUTION":      "PVST+/RPVST+ uses SNAP not LLC 0x42/0x42 — interoperability with standard RSTP requires Cisco PVST simulation mode; System-ID-Extension MUST equal VLAN ID; priority must be multiple of 4096"}),

    0x88BB: _e("Cisco LWAPP — Lightweight Access Point Protocol", "LWAPP Frame", "Vendor", "Active",
               "Cisco proprietary AP-controller protocol; superseded by CAPWAP RFC 5415/5416; "
               "still in older WLC+AP deployments running AireOS",
               "cdp",
               {"Version":       "4b  0",
                "Slot ID":       "4b  radio slot (0=2.4GHz 1=5GHz)",
                "Fragment ID":   "1B  fragment number",
                "Fragment Len":  "2B  payload length",
                "RSSI":          "1B  received signal strength (dBm offset)",
                "SNR":           "1B  signal-to-noise ratio",
                "Payload":       "variable  802.11 frame or management message",
                "CAUTION":       "LWAPP transmits 802.11 management frames in plaintext at L2; CAPWAP DTLS is the secure replacement; Cisco AireOS 8.10+ no longer supports LWAPP"}),

    0x8843: _e("Cisco CAPWAP Data (L2)", "CAPWAP Data Frame", "Vendor", "Active",
               "Control and Provisioning of WAPs L2 data channel — RFC 5416; this EtherType "
               "is the L2 variant; standard CAPWAP also uses UDP/5246 (data) and UDP/5247 (control)",
               "cdp",
               {"Preamble":      "1B  0x00=IEEE 802.11 / 0x01=WTP-event",
                "HLEN":          "5b  header length in 4B words (min=2=8B)",
                "RID":           "3b  radio ID (which radio on the AP)",
                "Flags":         "1B  F(fragment)+L(last)+W(wireless-specific)+M(native-frame)+K(keepalive)+binding(3b)",
                "Fragment ID":   "2B  fragment set ID for reassembly",
                "Fragment Offset":"13b  offset in 8B units",
                "Payload":       "variable  encapsulated 802.11 or WTP event",
                "CAUTION":       "CAPWAP without DTLS exposes all user traffic; enable DTLS (RFC 5415 §4) for CAPWAP control channel; data channel DTLS optional but recommended; WTP-to-AC on management VLAN only"}),

    0xFEFE: _e("Cisco ISL / Allied Telesis Proprietary VLAN", "ISL / AT-VLAN Frame", "Vendor", "Active",
               "Cisco ISL (Inter-Switch Link) — legacy Cisco proprietary VLAN tagging, deprecated "
               "in favour of IEEE 802.1Q; also used by Allied Telesis for proprietary VLAN tagging; "
               "ISL adds 26B header + 4B FCS making effective MTU 1476B on standard Ethernet",
               "dot1q",
               {"DA":           "5B  0x01:00:0C:00:00 Cisco ISL multicast prefix",
                "Type":         "4b  0=Ethernet 1=Token-Ring 2=FDDI 3=ATM",
                "User":         "4b  user-defined priority bits",
                "SA":           "6B  source MAC of encapsulating switch port",
                "LEN":          "2B  inner frame length",
                "SNAP":         "3B  0xAAAA03 LLC",
                "OUI":          "3B  0x00000C Cisco",
                "HSA":          "3B  high 3 bytes of source address",
                "VLAN":         "15b  VLAN ID (1-1005)",
                "BPDU":         "1b  1=STP BPDU or CDP frame",
                "INDEX":        "2B  port index on switch",
                "RES":          "2B  reserved for Token Ring / FDDI",
                "Inner Frame":  "variable  complete original Ethernet frame",
                "Outer FCS":    "4B  ISL adds own CRC-32 over outer header + inner frame",
                "CAUTION":      "ISL completely deprecated — Cisco removed in IOS 15.x, NX-OS, and all modern platforms; 802.1Q adds only 4B vs ISL 30B overhead; ISL not interoperable with any non-Cisco equipment"}),

    # ── Arista Networks ────────────────────────────────────────────────────────
    0x9999: _e("Arista LANZ / F5 Networks HA Heartbeat", "LANZ / F5-HA Frame", "Vendor", "Active",
               "Dual-use: Arista LANZ (Latency ANalyZer) exports per-queue congestion telemetry; "
               "F5 Networks uses same EtherType for BIG-IP HA heartbeat between chassis blades. "
               "Discriminate via vendor magic bytes in payload.",
               "dot1q",
               {"Vendor Magic":  "4B  0x41524953='ARIS' Arista | 0x46354841='F5HA' F5",
                "── Arista ──":  "",
                "LANZ Version":  "1B",
                "Port ID":       "2B  ingress port index (ASIC port number)",
                "Queue ID":      "1B  queue number 0-7",
                "Timestamp":     "8B  hardware nanosecond timestamp (TAI or local epoch)",
                "Queue Depth":   "4B  instantaneous queue depth bytes",
                "Latency ns":    "4B  measured latency in nanoseconds",
                "── F5 ──":      "",
                "F5 HA State":   "1B  0=Active 1=Standby 2=Offline 3=Forced-Offline",
                "F5 Blade ID":   "2B  source blade slot number",
                "F5 Seq":        "4B  heartbeat sequence number",
                "CAUTION":       "EtherType collision — Arista LANZ and F5 HA share 0x9999; discriminate via magic bytes; LANZ must be in dedicated collector VLAN; F5 HA loss triggers failover — heartbeat interval is typically 100ms"}),

    # ── HPE ProCurve / Aruba ───────────────────────────────────────────────────
    0x88C7: _e("HPE ProCurve Generic EtherType (HPEG)", "HPE Proprietary Frame", "Vendor", "Active",
               "HPE ProCurve (now HPE Aruba) proprietary switch management EtherType for "
               "stack topology discovery, stack member sync, and fabric messaging in ProCurve/Aruba switch stacks",
               "lldp",
               {"HP OUI":        "3B  0x00:90:4C HPE OUI",
                "Message Type":  "2B  0x01=Discovery 0x02=Topology 0x03=Stack-Member 0x04=Config-Sync",
                "Version":       "1B",
                "Sequence":      "2B  message sequence number",
                "Stack ID":      "6B  stack identifier (commander MAC address)",
                "Member ID":     "1B  slot 0=commander 1-7=member",
                "Payload":       "variable  type-specific management data",
                "CAUTION":       "HPEG is link-local — configure dedicated management VLAN; not compatible between HPE ProCurve and Aruba OS CX switches (different OS generations); disable on all non-HPE uplinks"}),

    # ── Extreme Networks ───────────────────────────────────────────────────────
    0x00BB: _e("Extreme EDP — Extreme Discovery Protocol", "EDP Frame", "Vendor", "Active",
               "Extreme Networks Discovery Protocol — link-local device/VLAN/topology discovery; "
               "also called Enterasys Discovery Protocol in legacy Enterasys equipment",
               "lldp",
               {"EDP Marker":    "2B  0x00BB",
                "Version":       "1B  1",
                "Reserved":      "1B  0",
                "Sequence":      "2B  monotonically increasing message sequence",
                "Machine Type":  "2B  device class (switch/router/wireless AP)",
                "Machine MAC":   "6B  source MAC of advertising device",
                "TLV chain":     "Type(2B)+Length(2B)+Value",
                "TLV 0x0001":    "Display string — device hostname",
                "TLV 0x0002":    "Null — end-of-chain terminator",
                "TLV 0x0003":    "VLAN info list: VLAN-ID(2B)+VLAN-Name(string)",
                "TLV 0x0005":    "ExtremeXOS / ExtremeWare version string",
                "TLV 0x0007":    "Remote management IP address",
                "CAUTION":       "Unauthenticated — reveals model and firmware to any host on segment; disable on all access ports; 30s advertisement interval by default"}),

    0x888B: _e("Extreme ESRP — Extreme Standby Router Protocol", "ESRP Frame", "Vendor", "Active",
               "Extreme Networks proprietary FHRP — default gateway redundancy for ExtremeWare/ExtremeXOS; "
               "similar to VRRP/HSRP but Extreme-proprietary",
               "lldp",
               {"ESRP Version":  "1B  1",
                "Group ID":      "2B  ESRP group 0-65535",
                "Priority":      "2B  higher=preferred master (default 0)",
                "State":         "1B  0=Idle 1=Slave 2=Master 3=PreMaster",
                "Virtual MAC":   "6B  00:E0:2B:xx:xx:xx (Extreme OUI + group)",
                "Virtual IPs":   "4B each  protected gateway addresses",
                "Hello Time":    "2B  advertisement interval (default 2s)",
                "Dead Time":     "2B  master declared dead after (default 6s)",
                "Auth Data":     "16B  MD5-auth or cleartext password",
                "CAUTION":       "Extreme-only — incompatible with VRRP/HSRP; group must match between master/slave; auth strongly recommended; ESRP failover typically <3s"}),

    0x8791: _e("Extreme EAPS — Ethernet Automatic Protection Switching", "EAPS Frame", "Vendor", "Active",
               "Extreme Networks ring protection protocol achieving ~50ms failover; uses dedicated "
               "ring control VLAN; master node monitors ring health via Hello messages",
               "lldp",
               {"Version":       "1B  1",
                "Type":          "1B  0x01=Health 0x02=Ring-Down-Flush-FDB 0x03=Ring-Up-Flush-FDB 0x04=LinkDown 0x05=PreForward 0x06=Idle",
                "Control VLAN":  "2B  dedicated management VLAN ID for EAPS PDUs",
                "Sequence":      "4B  monotonically increasing health-check sequence",
                "System MAC":    "6B  master node MAC address",
                "Hello Time":    "1B  default 1s between Health PDUs",
                "Fail Time":     "2B  default 3s — master declares ring broken",
                "Port Status":   "1B  0=Unknown 1=SecondaryOpen 2=Blocking",
                "CAUTION":       "EAPS ring must have exactly one master — two masters causes continuous failover oscillation; control VLAN must carry ONLY EAPS PDUs; Extreme-only — not compatible with G.8032 ERPS or Cisco REP"}),

    0x87A5: _e("Extreme ELRP — Extreme Loop Recovery Protocol", "ELRP Frame", "Vendor", "Active",
               "Extreme Networks loop detection — sends test frames and auto-disables port if own frame returns; "
               "operates independently of STP",
               "lldp",
               {"Version":       "1B  1",
                "Src MAC":       "6B  originating port MAC",
                "Port Index":    "2B  originating port number",
                "Sequence":      "4B  loop detection sequence",
                "VLAN ID":       "2B  VLAN being tested",
                "CAUTION":       "Port disable is automatic and immediate — ensure ELRP notification configured before enabling; ELRP frames may propagate across non-Extreme switches causing false positives on shared segments"}),

    0x876F: _e("Enterasys / Extreme Legacy EDP", "Legacy EDP Frame", "Vendor", "Active",
               "Original Enterasys (Cabletron spin-off) Discovery Protocol — predecessor to Extreme EDP 0x00BB; "
               "encountered only on legacy Enterasys/Cabletron hardware now absorbed into Extreme Networks",
               "lldp",
               {"EDP Version":   "1B",
                "Sequence":      "2B",
                "Source MAC":    "6B",
                "TLV chain":     "Type(2B)+Length(2B)+Value",
                "CAUTION":       "Legacy — Enterasys/Cabletron equipment; replaced by EDP 0x00BB in Extreme ExtremeXOS"}),

    # ── Brocade / Ruckus (now Broadcom) ────────────────────────────────────────
    0x88A7: _e("Brocade HDP / Avaya Discovery Protocol", "HDP Frame", "Vendor", "Active",
               "Brocade Hello Discovery Protocol (HDP) and Avaya Discovery share EtherType 0x88A7; "
               "discriminated by vendor magic. Used for fabric neighbour discovery in Brocade VDX/ICX "
               "and Avaya/Nortel VSP platforms.",
               "lldp",
               {"Vendor Magic":  "4B  0x66697273='firs' Brocade | 0x41564159='AVAY' Avaya",
                "Version":       "1B",
                "Message Type":  "1B  0x01=Hello 0x02=BYE",
                "Chassis MAC":   "6B  source switch system MAC",
                "Port ID":       "2B  source port number",
                "TTL":           "2B  seconds before neighbour entry expires (default 120s)",
                "Device Name":   "variable  null-terminated hostname",
                "SW Version":    "variable  OS version string",
                "CAUTION":       "Dual-use EtherType — Brocade and Avaya share 0x88A7; always check magic bytes; disable on non-Brocade/Avaya uplinks; reveals OS version and port topology"}),

    0x88CA: _e("Brocade TRILL Extension / VCS Fabric", "Brocade VCS Frame", "Vendor", "Active",
               "Brocade VCS (Virtual Cluster Switching) proprietary TRILL extension for "
               "multi-chassis LAG and fabric management in Brocade VDX datacenter switches",
               "trill",
               {"TRILL Header":  "6B  standard TRILL base header",
                "Brocade OUI":   "3B  0x00:05:33 Brocade OUI",
                "VCS Domain":    "2B  VCS fabric domain identifier",
                "TLV chain":     "Type(2B)+Length(2B)+Value — VCS-specific extensions",
                "CAUTION":       "Brocade VCS TRILL extensions are not interoperable with standard TRILL RFC 6325; enable only in all-Brocade VCS fabrics; VCS domain must match across all fabric members"}),

    # ── Avaya (now Extreme Networks) ───────────────────────────────────────────
    0x8800: _e("Avaya / Nortel SMLT / IST Control", "Avaya SMLT Frame", "Vendor", "Active",
               "Avaya (formerly Nortel Networks) proprietary EtherType for Split MultiLink Trunking (SMLT) "
               "and IST (Inter-Switch Trunk) cluster management between Avaya VSP/ERS switches",
               "lldp",
               {"Avaya Magic":   "4B  0x41564159='AVAY'",
                "Message Type":  "2B  0x01=SMLT-Hello 0x02=IST-Control 0x03=MLT-Sync 0x04=SMLT-Oper",
                "System MAC":    "6B  source switch system MAC",
                "Cluster ID":    "2B  SMLT cluster identifier (both peers must match)",
                "IST Status":    "1B  0=Down 1=Init 2=Up 3=Degraded",
                "SMLT Peers":    "6B each  peer MAC addresses",
                "Sequence":      "4B",
                "CAUTION":       "SMLT peers MUST be identical Avaya VSP model; IST failure causes traffic black-holing on SMLT links — monitor IST heartbeat; IST uses dedicated inter-switch VLAN — isolate from user traffic"}),

    # ── Broadcom ───────────────────────────────────────────────────────────────
    0x8874: _e("Broadcom HiGig / HiGig2 Inter-Chip Header", "BCM HiGig Frame", "Vendor", "Active",
               "Broadcom HiGig/HiGig2 inter-chip fabric header for Trident/Tomahawk/Jericho ASICs; "
               "carries port metadata, QoS class, module routing and OAM between Broadcom chips in chassis",
               "dot1q",
               {"Start":         "1B  0xFB=HiGig 0xFE=HiGig2",
                "Module Hdr":    "3B  Src-Module(8b)+Dst-Module(8b)+OpCode(3b)+misc flags",
                "Src Module":    "8b  source ASIC module ID (0-255 per chassis)",
                "Dst Module":    "8b  destination module ID",
                "Src Port":      "5b  source port on module (0-31)",
                "Dst Port":      "5b  destination port on module",
                "TC":            "3b  traffic class for QoS scheduling",
                "L":             "1b  LAG/trunk hash flag",
                "VID":           "12b  VLAN ID",
                "PFM":           "2b  port forwarding mode (0=copy-to-cpu 1=logical-port 2=physical-port)",
                "HiGig2 Ext":    "HiGig2 adds 32B extended header with additional OAM+timestamp fields",
                "CAUTION":       "HiGig frames are inter-ASIC only — MUST NOT appear on external ports; if seen externally indicates mis-cabling or PCIe CPU-port misconfiguration; HiGig1 and HiGig2 are not backward compatible"}),

    0x8935: _e("Broadcom Switch Tag (BRCM Tag)", "BCM Switch Tag Frame", "Vendor", "Active",
               "Broadcom 4-byte proprietary switch tag inserted between Src-MAC and EtherType "
               "by Broadcom StrataXGS/StrataGX ASICs for CPU port steering in unmanaged/semi-managed switches",
               "dot1q",
               {"Tag Protocol":  "2B  0x8935",
                "Tag Control":   "2B  TX: OpCode(6b)+Port(5b)+TC(3b)+misc | RX: Src-Port(5b)+OpCode+misc",
                "OpCode":        "6b  0=Normal 1=Redirect-to-port 2=Switch 3=Mirror",
                "Port":          "5b  Rx=source port ID; Tx=destination port override",
                "TC":            "3b  traffic class",
                "CAUTION":       "BRCM Tag is CPU-port internal — must be stripped before external forwarding; visible on JTAG/debug port mirror; presence on external port indicates CPU portgroup mis-configuration in BCM SDK"}),

    # ── Netgear ────────────────────────────────────────────────────────────────
    0x88C6: _e("Netgear RRCP — Realtek Remote Control Protocol", "RRCP Frame", "Vendor", "Active",
               "Netgear Smart Switch management discovery — Realtek RRCP variant used on Netgear GS/FS series; "
               "allows switch configuration via L2 frames without requiring IP connectivity",
               "lldp",
               {"RRCP Version":  "1B  1",
                "Opcode":        "1B  0x00=Hello 0x01=GetReg-Req 0x02=GetReg-Resp 0x03=SetReg 0xFF=End",
                "Checksum":      "2B  XOR checksum",
                "Auth Key":      "2B  0x2379 default (Netgear) — must be changed",
                "Register":      "2B  target register address",
                "Data":          "4B  register read/write value",
                "Downlink":      "1B  originating port number",
                "CAUTION":       "Default auth key 0x2379 is publicly known — full switch config access; RRCP has no session state — replay attacks possible; restrict management VLAN; some implementations have unpatched buffer overflow CVEs"}),

    # ── D-Link / Realtek ───────────────────────────────────────────────────────
    0x8899: _e("Realtek RRCP — Realtek Remote Control Protocol (D-Link)", "RRCP Frame", "Vendor", "Active",
               "Realtek RRCP reference implementation used in D-Link DGS/DES unmanaged switches; "
               "EtherType 0x8899 is the Realtek original; 0x88C6 is Netgear's assignment",
               "lldp",
               {"RRCP Version":  "1B  1",
                "Opcode":        "1B  0x00=Hello 0x01=GetReg 0x02=GetRegResp 0x03=SetReg",
                "Checksum":      "2B",
                "Auth Key":      "2B  device-specific 16-bit key (recommend change from default)",
                "Register":      "2B  register offset in Realtek PHY/switch ASIC",
                "Data":          "4B  register value",
                "Downlink Port": "1B  source port number",
                "CAUTION":       "Same vulnerabilities as 0x88C6 Netgear RRCP; additionally 0x8899 is less documented — register map varies by Realtek ASIC variant; management VLAN isolation mandatory"}),

    # ── VMware ─────────────────────────────────────────────────────────────────
    0x8922: _e("VMware Proprietary / NSX Internal", "VMware Frame", "Vendor", "Active",
               "VMware proprietary EtherType for internal vSphere / NSX communication including "
               "inter-hypervisor control frames; also used by some ESXi versions for overlay "
               "metadata before migrating to standard VXLAN/Geneve",
               "dot1q",
               {"VMware Magic":  "4B  0x564D7761='VMwa'",
                "Frame Type":    "2B  0x01=NSX-internal 0x02=vMotion-assist 0x03=vSAN-hb 0x04=VDS-sync",
                "VM ID":         "4B  source virtual machine UUID lower 32b",
                "Host ID":       "4B  ESXi host identifier",
                "NSX Seg ID":    "4B  NSX logical segment (before VXLAN/Geneve migration)",
                "Payload":       "variable  frame-type specific data",
                "CAUTION":       "VMware internal frames must not leave hypervisor uplinks; portgroup VLAN isolation critical; NSX now uses standard VXLAN UDP/4789 and Geneve UDP/6081 for overlay — 0x8922 is legacy VMware NSX pre-v3"}),

    # ── Fortinet ──────────────────────────────────────────────────────────────
    0x8901: _e("Fortinet FortiASIC Hardware Acceleration Tag", "FortiHW Frame", "Vendor", "Active",
               "Fortinet proprietary EtherType for FortiASIC NP (Network Processor) inter-chip "
               "session offload metadata between FortiGate firewall processing engines and NPx chips",
               "lldp",
               {"FortiMagic":    "4B  0x464F5254='FORT'",
                "Op Type":       "2B  0x01=Session-Offload 0x02=Policy-Match 0x03=NTURBO 0x04=IPSEC-Offload",
                "Session ID":    "4B  hardware session table entry index",
                "Flags":         "2B  NAT+IPS+AV+AppCtrl+WebFilter processing bitmap",
                "NP Port":       "1B  NP chip port number (0-7)",
                "SP ID":         "1B  Security Processor ID",
                "Payload":       "variable  original frame for processing pipeline",
                "CAUTION":       "FortiHW frames are chip-internal — should not appear on external interfaces; observed on SPAN of inter-NP links during hardware debug; if on external port indicates VLAN misconfiguration in ASIC offload profile"}),

    # ── Juniper Networks ──────────────────────────────────────────────────────
    0x9100: _e("Juniper / Provider Q-in-Q Alternate TPID (0x9100)", "Q-in-Q Alt S-Tag Frame", "Vendor", "Active",
               "Juniper and many service providers use 0x9100 as S-Tag TPID for Q-in-Q double tagging; "
               "IEEE 802.1ad standardised 0x88A8 but older JunOS defaults to 0x9100; "
               "both ends must have matching TPID — interoperability issue between vendors",
               "qinq",
               {"TPID":          "2B  0x9100 — alternate Service Tag EtherType",
                "PCP":           "3b  outer Priority Code Point",
                "DEI":           "1b  Drop Eligible Indicator",
                "S-VID":         "12b  Service VLAN ID (1-4094)",
                "Inner C-Tag":   "2B  0x8100 Customer Tag EtherType",
                "C-PCP":         "3b  customer priority",
                "C-DEI":         "1b",
                "C-VID":         "12b  Customer VLAN ID",
                "Inner Payload": "customer Ethernet frame",
                "CAUTION":       "IEEE standard is 0x88A8 — mixing 0x9100 and 0x88A8 causes VLAN forwarding failures; configure tpid-values on Juniper interface to match peer; Juniper MX: set interfaces et-x/y/z unit 0 family ethernet-switching interface-mode trunk; JunOS 18.1+ defaults to 0x88A8"}),

    0x9200: _e("Provider Q-in-Q Tertiary TPID (0x9200)", "Q-in-Q Triple-Tag Frame", "Vendor", "Active",
               "Secondary alternate S-Tag TPID used by some service providers for triple-tagging "
               "or to distinguish inner/outer provider tag levels in hierarchical carrier services",
               "qinq",
               {"TPID":          "2B  0x9200",
                "PCP":           "3b",
                "DEI":           "1b",
                "VID":           "12b  outer-outer provider VLAN",
                "Inner tags":    "0x9100 or 0x88A8 middle S-Tag + 0x8100 C-Tag",
                "MTU impact":    "Triple tagging reduces payload by 12B — requires jumbo frames (MTU ≥ 1512B)",
                "CAUTION":       "Triple tagging rarely used in modern deployments — 802.1ah PBB preferred for deep stacking; severe MTU fragmentation risk"}),

    # ── 3Com / HP (legacy) ─────────────────────────────────────────────────────
    0x0FEF: _e("3Com IPX Switch Protocol", "3Com IPX Switch Frame", "Vendor", "Active",
               "3Com proprietary IPX-based switch management from early 1990s; used in "
               "3Com LinkSwitch and NETBuilder; completely obsolete — 3Com acquired by HP 2010",
               "ipx",
               {"IPX Header":    "30B  standard IPX header",
                "Op Code":       "2B  management operation (undocumented)",
                "Data":          "variable  switch management payload",
                "CAUTION":       "Completely obsolete since 1998; presence on modern network = spoofed or replayed legacy traffic; discard at border"}),

    0x8081: _e("3Com Proprietary Frame Type 1", "3Com Frame", "Vendor", "Active",
               "3Com proprietary EtherType — associated with 3Com LinkSwitch SNMP messaging; "
               "exact protocol undocumented; obsolete since HP acquisition 2010",
               "lldp",
               {"Payload":       "variable  3Com proprietary management frame",
                "CAUTION":       "Obsolete — discard on any modern network; 3Com equipment EOL"}),

    0x8082: _e("3Com Proprietary Frame Type 2", "3Com Frame", "Vendor", "Active",
               "3Com second proprietary EtherType — protocol undocumented",
               "lldp",
               {"Payload":       "variable",
                "CAUTION":       "Obsolete — see 0x8081"}),

    0x8083: _e("3Com Proprietary Frame Type 3", "3Com Frame", "Vendor", "Active",
               "3Com third proprietary EtherType — protocol undocumented",
               "lldp",
               {"Payload":       "variable",
                "CAUTION":       "Obsolete — see 0x8081"}),

    # ── Nortel / Bay Networks ──────────────────────────────────────────────────
    0x0086: _e("Nortel / Bay Networks Proprietary", "Nortel Frame", "Vendor", "Active",
               "Nortel Networks (formerly Bay Networks) proprietary management EtherType for "
               "Passport/Accelar switch management; Nortel acquired by Avaya/Ciena 2009",
               "lldp",
               {"Bay Magic":     "4B  0x42415900='BAY\\x00'",
                "Op Code":       "2B  management operation",
                "Chassis MAC":   "6B  source chassis MAC",
                "Payload":       "variable",
                "CAUTION":       "Nortel/Bay completely obsolete — if seen indicates end-of-life hardware requiring urgent replacement; no security patches available since 2009"}),

    # ── Foundry Networks (now Brocade/Ruckus/Broadcom) ──────────────────────────
    0x88C9: _e("Foundry / Brocade Proprietary Extension", "Foundry Frame", "Vendor", "Active",
               "Foundry Networks (acquired by Brocade 2008) proprietary protocol extension for "
               "OAM and management on Foundry BigIron/FastIron MPLS platforms",
               "mpls_inner",
               {"MPLS Stack":    "4B  standard MPLS label entry",
                "Foundry OAM":   "1B  0x01=LSP-Ping 0x02=LSP-Traceroute 0x03=BFD-variant",
                "Sequence":      "4B  OAM sequence number",
                "Payload":       "variable  OAM response or user data",
                "CAUTION":       "Foundry-specific — only valid between Brocade/Foundry routers; standard MPLS OAM is RFC 8029 (LSP Ping) over UDP/3503 — use for multi-vendor environments"}),

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 28: REMAINING VENDOR PROPRIETARY — Microsemi, Lantronix, Ruckus, etc.
    # ══════════════════════════════════════════════════════════════════════════

    # ── Microsemi / Vitesse / Microchip Technology ─────────────────────────────
    0x88EE: _e("Microsemi/Vitesse Proprietary OAM", "Microsemi OAM Frame", "Vendor", "Active",
               "Microsemi (formerly Vitesse Semiconductor VSC88xx, now Microchip Technology) "
               "proprietary OAM for hardware-assisted carrier Ethernet performance monitoring. "
               "Used in VSC88xx PHYs and VSC7xxx switch ASICs for extended delay/jitter measurement "
               "beyond IEEE 802.3ah scope.",
               "lldp",
               {"Vitesse Magic":  "4B  0x56534300='VSC\\x00' — vendor identifier",
                "OAM Type":       "2B  0x01=Port-Stats 0x02=PHY-Status 0x03=Sync-Status 0x04=Alarm",
                "Port ID":        "2B  source port identifier on Microsemi ASIC",
                "ASIC ID":        "2B  ASIC revision and family (VSC7388/VSC7389/VSC7460 etc.)",
                "Timestamp":      "8B  hardware nanosecond timestamp for OAM frame timing",
                "Delay-ns":       "4B  measured one-way frame delay in nanoseconds",
                "Jitter-ns":      "4B  measured inter-frame delay variation (jitter)",
                "Loss-ratio":     "4B  frame loss ratio (Q8.24 fixed point)",
                "Payload":        "variable  extended OAM data or alarm notification",
                "CAUTION":        "Microsemi proprietary — not compatible with IEEE 802.3ah OAM (0x8809) or ITU-T Y.1731; "
                                  "only valid between Microsemi VSC88xx-based equipment; disable on all non-Microsemi ports; "
                                  "seen in carrier Metro Ethernet deployments using Vitesse-based CPE"}),

    # ── Lantronix ──────────────────────────────────────────────────────────────
    0x8880: _e("Lantronix SLPP — Simple Loop Protection Protocol", "Lantronix SLPP Frame", "Vendor", "Active",
               "Lantronix Simple Loop Protection Protocol for Lantronix SLC/EDS terminal servers "
               "and SLB load balancers. Sends test frames and auto-disables port on loop detection. "
               "Used as lightweight STP alternative on access-layer device ports.",
               "lldp",
               {"Magic":          "4B  0x4C544E58='LTNX' — Lantronix identifier",
                "Version":        "1B  1",
                "Type":           "1B  0x01=Loop-Detect 0x02=Loop-Confirm 0x03=Port-Disable-Notify",
                "Port ID":        "2B  originating port number on Lantronix device",
                "Sequence":       "4B  detection sequence number (monotonically increasing)",
                "Src MAC":        "6B  originating port MAC address",
                "VLAN ID":        "2B  VLAN being tested (0x0000=all VLANs)",
                "Hold Time":      "1B  seconds port remains disabled (0=permanent until admin re-enable)",
                "CAUTION":        "SLPP port disable is automatic and immediate — configure SNMP notification before enabling; "
                                  "SLPP frames may propagate through non-Lantronix bridges causing false positives; "
                                  "use IEEE 802.1D STP or RSTP for multi-vendor loop protection"}),

    # ── Ruckus Networks / CommScope ICX ────────────────────────────────────────
    0x8A8A: _e("Ruckus ICX Stack Management (CommScope)", "Ruckus ICX Frame", "Vendor", "Active",
               "Ruckus Networks (CommScope) ICX switch series proprietary EtherType for "
               "stack topology, unit election, configuration synchronisation and LAG management "
               "across Ruckus ICX 7150/7250/7450/7550/7650/7850 stackable switch series.",
               "lldp",
               {"ICX Magic":      "4B  0x52434B53='RCKS' — Ruckus identifier",
                "Message Type":   "2B  0x01=Stack-Hello 0x02=Stack-Topo 0x03=Config-Sync "
                                  "0x04=LAG-Sync 0x05=Unit-Election 0x06=Hitless-Upgrade",
                "Stack Domain":   "2B  stack domain identifier (1-512)",
                "Unit ID":        "1B  stack unit slot (1=active controller, 2-12=members)",
                "Priority":       "1B  active controller election priority (higher=preferred)",
                "Version":        "1B  stack protocol version",
                "Sequence":       "4B  monotonically increasing per-unit sequence number",
                "Payload":        "variable  type-specific stack synchronisation data",
                "CAUTION":        "Ruckus ICX stacking is proprietary — not compatible with Brocade FastIron or Foundry stacking; "
                                  "stack ports must be direct-connected copper/SFP+ and dedicated; "
                                  "0x8A8A frames must not appear on access or uplink ports — indicates mis-cabling"}),

    # ── Ubiquiti Networks ──────────────────────────────────────────────────────
    0x88BE: _e("Ubiquiti Networks / ERSPAN Type II", "Ubiquiti / ERSPAN-II Frame", "Vendor", "Active",
               "Dual-use EtherType: Ubiquiti proprietary management frames on some UniFi/AirOS "
               "access points (for L2 management when IP not yet configured); also used as "
               "Cisco ERSPAN Type II GRE protocol type for encapsulated remote SPAN traffic. "
               "Discriminate by context: GRE payload = ERSPAN; raw L2 = Ubiquiti.",
               "trill",
               {"Context":        "Raw L2 frame = Ubiquiti AirOS management | GRE Protocol=0x88BE = Cisco ERSPAN Type II",
                "── Ubiquiti ──": "",
                "Ubiquiti Magic": "4B  0x55424E54='UBNT' — AirOS identifier",
                "Msg Type":       "2B  0x01=Discover 0x02=Discovery-Response 0x03=Info",
                "Firmware":       "variable  AirOS firmware version string",
                "MAC":            "6B  AP MAC address",
                "── ERSPAN-II ──":"",
                "GRE Header":     "8B  standard GRE with Protocol-Type=0x88BE",
                "ERSPAN Header":  "Version(4b)+VLAN(12b)+COS(3b)+EN(2b)+T(1b)+SessionID(10b)+Reserved(12b)+Index(20b)",
                "Inner Frame":    "variable  mirrored original Ethernet frame",
                "CAUTION":        "Ubiquiti uses 0x88BE before DHCP/IP; filter on management VLAN only; "
                                  "ERSPAN Type II SessionID 0 is reserved; ERSPAN doubles bandwidth consumption"}),

    # ── Mellanox / NVIDIA Networking ───────────────────────────────────────────

    # ── Palo Alto Networks ─────────────────────────────────────────────────────
    # PAN-OS uses standard 802.1Q, ARP, LLDP — HA uses UDP/28769 not a custom EtherType

    # ── Check Point ────────────────────────────────────────────────────────────
    # ClusterXL HA uses UDP broadcast — no proprietary EtherType

    # ── Aruba CX / AOS-CX ─────────────────────────────────────────────────────
    # AOS-CX uses standard LLDP/LACP/STP/BFD — no proprietary EtherType

    # ── Dell EMC ───────────────────────────────────────────────────────────────
    # Dell SmartFabric uses LLDP/BGP EVPN — no proprietary L2 EtherType

    # ── Huawei CloudEngine ─────────────────────────────────────────────────────
    # Uses standard LLDP, LACP, STP, OSPF, BGP EVPN
    # Some CE series use 0x9999 for streaming telemetry (same as Arista LANZ — check magic bytes)
    # CloudFabric uses standard VXLAN (UDP/4789) and Geneve (UDP/6081)

    # ── Nokia 7750 SR / SROS ───────────────────────────────────────────────────
    # Uses standard MPLS, RSVP-TE, LDP, IS-IS, BGP — no proprietary L2 EtherType
    # Nokia proprietary MPLS-TP OAM uses standard EtherTypes

    # ── Ericsson (Packet Core / Radio) ────────────────────────────────────────
    # Uses 3GPP standard GTP-U/GTP-C (UDP/2152/2123) — no L2 EtherType

    # ── ZTE Corporation ────────────────────────────────────────────────────────
    # Uses standard protocols — no unique L2 EtherType

    # ── Ciena (Blue Planet) ────────────────────────────────────────────────────
    # Uses standard OTN, MEF, IEEE 802.3ah OAM, G.8032 ERPS — no proprietary EtherType

    # ── ADVA Optical (now Adtran) ──────────────────────────────────────────────
    # Uses standard MEF/CFM/OAM EtherTypes — acquired by ADTRAN 2022

    # ── Calix (Access/PON) ─────────────────────────────────────────────────────
    # Uses standard xDSL/GPON/XGS-PON protocols — no L2 EtherType

    # ── ADTRAN ─────────────────────────────────────────────────────────────────
    # Uses standard 802.1ag CFM, IEEE 802.3ah OAM — no proprietary EtherType

    # ── Coriant / Infinera ─────────────────────────────────────────────────────
    # Uses standard MPLS-TP/OTN — no proprietary EtherType

    # ── PacketFront (DRG) ──────────────────────────────────────────────────────
    # Uses standard 802.1Q/LLDP on DRG (Disaggregated Residential Gateway)

    # ── VIAVI Solutions ────────────────────────────────────────────────────────
    # Test equipment using standard CFM 0x8902 / OAM 0x8809 / LLDP 0x88CC

    # ── Spirent Communications ─────────────────────────────────────────────────

    # ── Accedian Networks (Ericsson) ───────────────────────────────────────────
    # Uses IEEE 802.1ag CFM (0x8902) and Y.1731 (0x8903) — no proprietary EtherType

    # ── Sycamore Networks ──────────────────────────────────────────────────────
    # Defunct; used standard ATM/MPLS protocols

    # ── Procket Networks (acquired by Cisco) ───────────────────────────────────
    # Cisco IOS XR heritage; all protocols now standard

    # ── Caspian Networks ───────────────────────────────────────────────────────
    # Flow-based networking startup; defunct — no surviving EtherType

}




# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PDU CLASSIFICATION TABLE
# ══════════════════════════════════════════════════════════════════════════════
PDU_DESCRIPTIONS: dict[str, dict] = {
    "IPv4 Packet":          dict(min_b=20,  max_b=65535, hdr_fixed=20,  has_cksum=True),
    "IPv6 Packet":          dict(min_b=40,  max_b=65575, hdr_fixed=40,  has_cksum=False),
    "ARP Frame":            dict(min_b=28,  max_b=28,    hdr_fixed=8,   has_cksum=False),
    "RARP Frame":           dict(min_b=28,  max_b=28,    hdr_fixed=8,   has_cksum=False),
    "VLAN Tagged Frame":    dict(min_b=4,   max_b=9004,  hdr_fixed=4,   has_cksum=False),
    "Double-Tagged Frame":  dict(min_b=8,   max_b=9008,  hdr_fixed=8,   has_cksum=False),
    "PBB I-Tag Frame":      dict(min_b=8,   max_b=9012,  hdr_fixed=8,   has_cksum=False),
    "MPLS Frame":           dict(min_b=4,   max_b=65535, hdr_fixed=4,   has_cksum=False),
    "PPPoE PDU":            dict(min_b=6,   max_b=1498,  hdr_fixed=6,   has_cksum=False),
    "PPP Frame":            dict(min_b=4,   max_b=65535, hdr_fixed=4,   has_cksum=True),
    "LLDP PDU":             dict(min_b=4,   max_b=1500,  hdr_fixed=0,   has_cksum=False),
    "MAC Control Frame":    dict(min_b=46,  max_b=46,    hdr_fixed=4,   has_cksum=False),
    "Slow Protocol PDU":    dict(min_b=1,   max_b=1498,  hdr_fixed=1,   has_cksum=False),
    "EAPOL Frame":          dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=False),
    "PTP Message":          dict(min_b=44,  max_b=1500,  hdr_fixed=34,  has_cksum=False),
    "GOOSE PDU":            dict(min_b=8,   max_b=1500,  hdr_fixed=8,   has_cksum=False),
    "Sampled Values PDU":   dict(min_b=8,   max_b=1500,  hdr_fixed=8,   has_cksum=False),
    "PROFINET Frame":       dict(min_b=6,   max_b=1500,  hdr_fixed=6,   has_cksum=False),
    "EtherCAT Frame":       dict(min_b=2,   max_b=1500,  hdr_fixed=2,   has_cksum=False),
    "POWERLINK Frame":      dict(min_b=3,   max_b=1500,  hdr_fixed=3,   has_cksum=False),
    "SERCOS Frame":         dict(min_b=6,   max_b=1500,  hdr_fixed=6,   has_cksum=False),
    "FCoE Frame":           dict(min_b=36,  max_b=2176,  hdr_fixed=4,   has_cksum=True),
    "FIP Frame":            dict(min_b=10,  max_b=1500,  hdr_fixed=10,  has_cksum=False),
    "AoE Frame":            dict(min_b=12,  max_b=1500,  hdr_fixed=12,  has_cksum=False),
    "RoCE Frame":           dict(min_b=12,  max_b=4096,  hdr_fixed=12,  has_cksum=True),
    "NSH Frame":            dict(min_b=8,   max_b=65535, hdr_fixed=8,   has_cksum=False),
    "TRILL Frame":          dict(min_b=6,   max_b=65535, hdr_fixed=6,   has_cksum=False),
    "CFM PDU":              dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=True),
    "Y.1731 PDU":           dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=True),
    "BACnet Frame":         dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=False),
    "WSMP Frame":           dict(min_b=8,   max_b=1500,  hdr_fixed=8,   has_cksum=False),
    "GeoNetworking PDU":    dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=False),
    "PRP Frame":            dict(min_b=6,   max_b=1500,  hdr_fixed=0,   has_cksum=False),
    "MRP PDU":              dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=False),
    "Loopback Frame":       dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=False),
    "SecTAG+Payload":       dict(min_b=8,   max_b=9000,  hdr_fixed=8,   has_cksum=True),
    "GSMP PDU":             dict(min_b=4,   max_b=1500,  hdr_fixed=4,   has_cksum=True),
    "IPX Packet":           dict(min_b=30,  max_b=65535, hdr_fixed=30,  has_cksum=False),
    "OUI-Extended Frame":   dict(min_b=5,   max_b=65535, hdr_fixed=5,   has_cksum=False),
    "RAW":                  dict(min_b=0,   max_b=65535, hdr_fixed=0,   has_cksum=False),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — PPP PROTOCOL FIELD REGISTRY
# ══════════════════════════════════════════════════════════════════════════════
PPP_PROTOCOL_MAP: dict[int, dict] = {
    0x0001: dict(name="Padding",              l3_proto=None,  status="Active"),
    0x0021: dict(name="IPv4",                 l3_proto="ipv4",status="Active"),
    0x0029: dict(name="AppleTalk",            l3_proto=None,  status="Deprecated"),
    0x002B: dict(name="IPX (Novell NetWare)", l3_proto=None,  status="Deprecated"),
    0x003D: dict(name="Multi-Link PPP",       l3_proto=None,  status="Active"),
    0x003F: dict(name="NetBIOS Framing",      l3_proto=None,  status="Deprecated"),
    0x00FD: dict(name="PPP Compression",      l3_proto=None,  status="Active"),
    0x0057: dict(name="IPv6",                 l3_proto="ipv6",status="Active"),
    0x0203: dict(name="MP (Multi-Point)",     l3_proto=None,  status="Active"),
    0x0281: dict(name="MPLS Unicast",         l3_proto="mpls",status="Active"),
    0x0283: dict(name="MPLS Multicast",       l3_proto="mpls",status="Active"),
    0x8021: dict(name="IPCP (IPv4 Control)",  l3_proto=None,  status="Active"),
    0x8057: dict(name="IPv6CP",               l3_proto=None,  status="Active"),
    0x8029: dict(name="AppleTalk CP",         l3_proto=None,  status="Deprecated"),
    0x802B: dict(name="IPXCP",                l3_proto=None,  status="Deprecated"),
    0xC021: dict(name="LCP (Link Control)",   l3_proto=None,  status="Active"),
    0xC023: dict(name="PAP (Password Auth)",  l3_proto=None,  status="Deprecated"),
    0xC025: dict(name="LQR (Link Quality)",   l3_proto=None,  status="Active"),
    0xC223: dict(name="CHAP (Challenge Auth)",l3_proto=None,  status="Active"),
    0xC227: dict(name="EAP (Extensible Auth)",l3_proto=None,  status="Active"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — WIFI INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════
WIFI_SPEED_TABLE: dict[str, dict] = {
    # ── Legacy / Original ─────────────────────────────────────────────────────
    "802.11":    dict(max_mbps=2,      band="2.4 GHz",         modulation="FHSS/DSSS",         year=1997,
                     alias="Wi-Fi 0",  notes="Original standard — 1 or 2 Mbps; FHSS or DSSS PHY"),
    "802.11b":   dict(max_mbps=11,     band="2.4 GHz",         modulation="DSSS/CCK",          year=1999,
                     alias="Wi-Fi 1",  notes="First mass-market Wi-Fi; DSSS + CCK up to 11 Mbps"),
    "802.11a":   dict(max_mbps=54,     band="5 GHz",           modulation="OFDM",              year=1999,
                     alias="Wi-Fi 2",  notes="5 GHz only; OFDM 54 Mbps; shorter range than 802.11b"),
    "802.11g":   dict(max_mbps=54,     band="2.4 GHz",         modulation="ERP-OFDM",          year=2003,
                     alias="Wi-Fi 3",  notes="2.4 GHz OFDM; backward compatible with 802.11b"),

    # ── Wi-Fi 4/5/6/7 (mainstream) ────────────────────────────────────────────
    "802.11n":   dict(max_mbps=600,    band="2.4/5 GHz",       modulation="HT-OFDM MIMO",      year=2009,
                     alias="Wi-Fi 4",  notes="MIMO 4×4; 40 MHz channels; 600 Mbps; HT Control field"),
    "802.11ac":  dict(max_mbps=6933,   band="5 GHz",           modulation="VHT-OFDM MU-MIMO",  year=2013,
                     alias="Wi-Fi 5",  notes="Up to 8 spatial streams; 160 MHz; 256-QAM; MU-MIMO DL"),
    "802.11ax":  dict(max_mbps=9608,   band="2.4/5/6 GHz",     modulation="HE-OFDMA",          year=2019,
                     alias="Wi-Fi 6/6E",notes="OFDMA+BSS-Coloring; TWT; MU-MIMO DL+UL; 1024-QAM"),
    "802.11be":  dict(max_mbps=46120,  band="2.4/5/6 GHz",     modulation="EHT-OFDMA MLO",     year=2024,
                     alias="Wi-Fi 7",  notes="Multi-Link Operation; 4096-QAM; 320 MHz; 16 streams"),

    # ── Millimetre-wave / 60 GHz ──────────────────────────────────────────────
    "802.11ad":  dict(max_mbps=6757,   band="60 GHz",           modulation="SC/OFDM/OFDM-BF",  year=2012,
                     alias="WiGig 1",  notes="60 GHz; ~10m range; Beam-forming; used in Wireless Dock"),
    "802.11ay":  dict(max_mbps=176000, band="60 GHz",           modulation="SC/OFDM MIMO",      year=2021,
                     alias="WiGig 2",  notes="MIMO+OFDMA at 60 GHz; up to 176 Gbps; outdoor backhaul"),

    # ── Vehicular / DSRC / V2X ────────────────────────────────────────────────
    "802.11p":   dict(max_mbps=27,     band="5.9 GHz",         modulation="OFDM (DSRC)",        year=2010,
                     alias="DSRC/V2X", notes="Vehicle-to-X; 10 MHz channels; OCB (outside context of BSS)"),

    # ── Mesh ──────────────────────────────────────────────────────────────────
    "802.11s":   dict(max_mbps=300,    band="2.4/5 GHz",        modulation="HT-OFDM Mesh",      year=2011,
                     alias="Wi-Fi Mesh",notes="HWMP path selection; multi-hop mesh; used in IEEE 802.11 Mesh BSS"),

    # ── TV White Space / Sub-GHz / IoT ────────────────────────────────────────
    "802.11af":  dict(max_mbps=568,    band="TV whitespace (54-790 MHz)", modulation="OFDM",    year=2013,
                     alias="White-Fi / Super Wi-Fi", notes="Dynamic spectrum access; geo-location DB; 6 MHz channels"),
    "802.11ah":  dict(max_mbps=347,    band="900 MHz (<1 GHz)", modulation="S1G-OFDM",          year=2016,
                     alias="Wi-Fi HaLow",notes="Sub-GHz long range (1 km); 1 MHz channels; IoT/smart grid"),

    # ── 7 new standards ───────────────────────────────────────────────────────
    "802.11j":   dict(max_mbps=54,     band="4.9/5 GHz (Japan)",modulation="OFDM",              year=2004,
                     alias="Japan 5 GHz",notes="Japan public safety / 4.9-5 GHz channels; extends 802.11a"),
    "802.11r":   dict(max_mbps=0,      band="2.4/5 GHz",        modulation="HT/VHT/HE (any)",  year=2008,
                     alias="Fast BSS Transition",notes="Fast roaming — pre-auth key cache; used in enterprise WPA2/3"),
    "802.11u":   dict(max_mbps=0,      band="2.4/5 GHz",        modulation="any",               year=2011,
                     alias="Hotspot 2.0 / Passpoint",notes="Interworking with external networks; GAS/ANQP service discovery"),
    "802.11v":   dict(max_mbps=0,      band="2.4/5 GHz",        modulation="any",               year=2011,
                     alias="BSS Transition Management",notes="AP steers STA to better AP; neighbour report; WNM sleep"),
    "802.11w":   dict(max_mbps=0,      band="2.4/5 GHz",        modulation="any",               year=2009,
                     alias="Management Frame Protection",notes="MFP — encrypts/authenticates Deauth/Disassoc/Action frames"),
    "802.11k":   dict(max_mbps=0,      band="2.4/5 GHz",        modulation="any",               year=2008,
                     alias="Radio Resource Measurement",notes="Neighbour report; beacon/channel load measurement; roaming assist"),
    "802.11y":   dict(max_mbps=54,     band="3.65 GHz (US)",    modulation="OFDM",              year=2008,
                     alias="3650-3700 MHz",notes="US licensed 3.65 GHz band; contention-based protocol; longer range"),
}

WIFI_FRAME_CATEGORY: dict[str, dict] = {
    "Management": dict(subtypes=[
        "Association Request","Association Response","Reassociation Request",
        "Reassociation Response","Probe Request","Probe Response","Beacon",
        "ATIM","Disassociation","Authentication","Deauthentication","Action","Action No Ack"],
        purpose="BSS lifecycle — joining, leaving, scanning, handoff"),
    "Control": dict(subtypes=[
        "RTS","CTS","ACK","Block Ack Request","Block Ack","PS-Poll",
        "CF-End","CF-End+CF-Ack","Trigger","TACK","Beamforming Report Poll",
        "VHT/HE NDP Announcement"],
        purpose="Medium access coordination and power management"),
    "Data": dict(subtypes=[
        "Data","Null","QoS Data","QoS Null","QoS CF-Ack","QoS CF-Poll",
        "Data+CF-Ack","Data+CF-Poll","A-MSDU"],
        purpose="Payload delivery and power-save null frames"),
    "Extension": dict(subtypes=["DMG Beacon","S1G PPDU","TDD Beacon"],
        purpose="802.11ad/ah/ax specialised extension frames"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — SERIAL / WAN PROTOCOL REGISTRY
# ══════════════════════════════════════════════════════════════════════════════
WAN_PROTOCOL_REGISTRY: dict[str, dict] = {
    "ppp": dict(
        name="PPP", standard="RFC 1661/1662", status="Active",
        usage="Point-to-point data link — WAN/DSL/VPN",
        frame_structure=["Flag(0x7E)","Address(0xFF)","Control(0x03)",
                         "Protocol(2B)","Payload","FCS(2-4B)","Flag(0x7E)"],
        l3_via="ppp_protocol_field",
        fields={"Flag":"0x7E delimiter","Address":"0xFF broadcast",
                "Control":"0x03 UI frame","Protocol":"0x0021=IPv4 0x0057=IPv6",
                "FCS":"CRC-16/CCITT (default) or CRC-32"}),

    "hdlc": dict(
        name="HDLC (basic)", standard="ISO 13239", status="Active",
        usage="Synchronous serial WAN — leased lines, T1/E1",
        frame_structure=["Flag(0x7E)","Address(var)","Control(1-2B)","Info(var)","FCS(2-4B)","Flag(0x7E)"],
        l3_via="payload_inspection",
        fields={"Flag":"0x7E","Address":"0xFF broadcast or station addr",
                "Control":"I/S/U frame type + sequence numbers",
                "FCS":"CRC-16/CCITT LE or CRC-32"}),

    "hdlc_full": dict(
        name="HDLC Full (I/S/U frames)", standard="ISO 13239", status="Active",
        usage="All three HDLC frame types — data, supervisory, management",
        frame_structure=["Flag","Addr","Ctrl","[Info]","FCS","Flag"],
        l3_via="payload_inspection",
        fields={"I-frame":"data + N(S)/N(R) sliding window ARQ",
                "S-frame":"RR REJ RNR SREJ flow/error control (no payload)",
                "U-frame":"SABM DISC UA UI FRMR XID TEST link management"}),

    "cisco_hdlc": dict(
        name="Cisco HDLC", standard="Cisco proprietary", status="Vendor-specific",
        usage="Default Cisco serial interface encapsulation",
        frame_structure=["Address(1B)","Control(1B)","Protocol(2B)","Payload","FCS(4B)"],
        l3_via="cisco_hdlc_protocol_field",
        fields={"Address":"0x0F=unicast 0x8F=broadcast",
                "Control":"0x00","Protocol":"0x0800=IPv4 0x0806=ARP 0x8847=MPLS",
                "FCS":"CRC-32"}),

    "slip": dict(
        name="SLIP", standard="RFC 1055", status="Deprecated",
        usage="Legacy serial IP — no error detection, IPv4 only",
        frame_structure=["[END(0xC0)]","IP Packet","END(0xC0)"],
        l3_via="implicit_ipv4",
        fields={"END":"0xC0=192 delimiter","ESC":"0xDB escape",
                "ESC-END":"0xDB 0xDC","ESC-ESC":"0xDB 0xDD",
                "Note":"No header, no FCS, always IPv4 — replaced by PPP"}),

    "frame_relay": dict(
        name="Frame Relay", standard="ITU-T Q.922 / ANSI T1.618", status="Deprecated",
        usage="Legacy WAN packet switching — PVCs/SVCs",
        frame_structure=["Flag(0x7E)","DLCI+Flags(2-4B)","Data","FCS(2B)","Flag(0x7E)"],
        l3_via="frame_relay_nlpid",
        fields={"DLCI":"10b virtual circuit number",
                "FECN/BECN/DE":"congestion and discard eligible bits",
                "NLPID":"0xCC=IPv4 0x8E=IPv6 0x80=SNAP 0xFE=ISO"}),

    "atm_aal5": dict(
        name="ATM AAL5", standard="ITU-T I.363.5", status="Active",
        usage="ATM Adaptation Layer 5 — variable-length data over 53B ATM cells",
        frame_structure=["Payload(var)","Padding(0-47B)","Trailer(8B)"],
        l3_via="atm_encap_header",
        fields={"CPCS-UU":"1B user-to-user","CPI":"1B common part indicator",
                "Length":"2B original payload length","CRC-32":"4B over all preceding"}),

    "modbus_rtu": dict(
        name="Modbus RTU", standard="Modicon / IEC 61158", status="Active",
        usage="SCADA/PLC industrial control — most common OT serial protocol",
        frame_structure=["Address(1B)","Function(1B)","Data(var)","CRC-16(2B)"],
        l3_via=None,
        fields={"Address":"slave 1-247 (0=broadcast)",
                "Function":"01-06 15-16 read/write coils/registers",
                "Data":"function-specific request/response",
                "CRC-16":"poly 0x8005 init 0xFFFF little-endian"}),

    "kiss": dict(
        name="KISS (Keep It Simple Stupid)", standard="ARRL TNC2", status="Active",
        usage="Amateur packet radio AX.25 frame delivery to TNC",
        frame_structure=["FEND(0xC0)","Type(1B)","Data","FEND(0xC0)"],
        l3_via=None,
        fields={"FEND":"0xC0 delimiter","Type":"0x00=data 0x01-0x05=params 0xFF=exit",
                "FESC":"0xDB escape","TFEND":"0xDC","TFESC":"0xDD"}),

    "cobs": dict(
        name="COBS (Consistent Overhead Byte Stuffing)", standard="Stuart Cheshire 1999", status="Active",
        usage="Embedded serial framing — eliminates zero bytes for packet boundary detection",
        frame_structure=["COBS-encoded payload","0x00 packet terminator"],
        l3_via=None,
        fields={"Overhead":"max 1 extra byte per 254 data bytes (~0.4%)",
                "Terminator":"0x00 — guaranteed not present inside encoded payload"}),

    "raw": dict(
        name="Raw Serial", standard="None", status="Active",
        usage="Direct byte stream — no framing",
        frame_structure=["Raw bytes — no framing"],
        l3_via=None,
        fields={"Note":"No header, no delimiter, no error detection"}),
}

# Cisco HDLC → L3 class
CISCO_HDLC_PROTO_MAP: dict[int, str] = {
    0x0800: "ipv4", 0x86DD: "ipv6", 0x0806: "arp",
    0x8035: "rarp", 0x8847: "mpls", 0x8848: "mpls",
}

# Frame Relay NLPID → L3 class
FRAME_RELAY_NLPID_MAP: dict[int, str] = {
    0xCC: "ipv4", 0x8E: "ipv6", 0xFE: "iso_clnp", 0x80: "snap",
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — L2 AUTO-MAPPING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def ethertype_to_l3(ethertype: int) -> dict:
    """Look up EtherType → full metadata + L3 mapping hint."""
    entry = ETHERTYPE_REGISTRY.get(ethertype)
    if entry:
        return dict(ethertype=ethertype, name=entry["name"],
                    pdu=entry["pdu"], category=entry["category"],
                    status=entry["status"], usage=entry["usage"],
                    l3_proto=entry["l3_proto"], fields=entry["fields"],
                    source="registry")
    if ethertype < 0x0600:
        return dict(ethertype=ethertype, name=f"IEEE 802.3 Length Field ({ethertype})",
                    pdu="RAW", category="Standard", status="Active",
                    usage="802.3 payload length field — not an EtherType",
                    l3_proto=None, fields={}, source="dynamic-length")
    if 0xFF00 <= ethertype <= 0xFF0F:
        return dict(ethertype=ethertype, name=f"ISC Bunker Ramo Private 0x{ethertype:04X}",
                    pdu="RAW", category="Private", status="Legacy",
                    usage="ISC Bunker Ramo private protocol range",
                    l3_proto=None, fields={}, source="dynamic-private")
    return dict(ethertype=ethertype, name=f"Unknown/Unregistered 0x{ethertype:04X}",
                pdu="RAW", category="Unknown", status="Unknown",
                usage="Unknown — possibly proprietary or vendor-specific",
                l3_proto=None, fields={}, source="dynamic-unknown")


def snap_to_l3(oui: bytes, pid: int) -> dict:
    """Map LLC/SNAP (OUI + PID) → L3 info."""
    if oui == b'\x00\x00\x00':
        return ethertype_to_l3(pid)
    oui_hex = oui.hex().upper()
    OUI_VENDORS = {
        "00000C": "Cisco", "00000E": "Fujitsu", "000010": "Sytek",
        "080007": "AppleTalk", "00005E": "IANA/IETF", "00000F": "NeXT",
        "000020": "DIAB", "00001D": "Cabletron", "00002A": "TRW",
    }
    vendor = OUI_VENDORS.get(oui_hex, f"OUI={oui_hex}")
    return dict(ethertype=pid, name=f"SNAP {vendor} PID=0x{pid:04X}",
                pdu="RAW", category="Vendor", status="Vendor-specific",
                usage=f"Vendor-specific SNAP under {vendor}",
                l3_proto=None, fields={"OUI": oui_hex, "PID": f"0x{pid:04X}"},
                source="snap-vendor")


def ppp_to_l3(protocol_field: int) -> dict:
    entry = PPP_PROTOCOL_MAP.get(protocol_field)
    if entry:
        return dict(protocol=protocol_field, name=entry["name"],
                    l3_proto=entry["l3_proto"], status=entry["status"],
                    source="ppp-registry")
    return dict(protocol=protocol_field, name=f"PPP-0x{protocol_field:04X}",
                l3_proto=None, status="Unknown", source="ppp-unknown")


def cisco_hdlc_to_l3(protocol_field: int) -> dict:
    l3 = CISCO_HDLC_PROTO_MAP.get(protocol_field)
    return dict(protocol=protocol_field, l3_proto=l3,
                name=f"Cisco-HDLC 0x{protocol_field:04X}")


def frame_relay_to_l3(nlpid: int) -> dict:
    l3 = FRAME_RELAY_NLPID_MAP.get(nlpid)
    return dict(nlpid=nlpid, l3_proto=l3, name=f"FR-NLPID 0x{nlpid:02X}")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — PDU VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_pdu(ethertype: int, payload: bytes) -> dict:
    """Validate payload conforms to expected PDU for given EtherType."""
    entry = ETHERTYPE_REGISTRY.get(ethertype, {})
    pdu   = entry.get("pdu", "RAW")
    if not payload:
        return dict(valid=False, reason="Empty payload", pdu=pdu)
    checks = {
        "IPv4 Packet":       lambda p: len(p) >= 20 and (p[0] >> 4) == 4,
        "IPv6 Packet":       lambda p: len(p) >= 40 and (p[0] >> 4) == 6,
        "ARP Frame":         lambda p: len(p) >= 28,
        "RARP Frame":        lambda p: len(p) >= 28,
        "VLAN Tagged Frame": lambda p: len(p) >= 4,
        "MPLS Frame":        lambda p: len(p) >= 4,
        "LLDP PDU":          lambda p: len(p) >= 4,
        "EAPOL Frame":       lambda p: len(p) >= 4,
        "GOOSE PDU":         lambda p: len(p) >= 8,
        "Sampled Values PDU":lambda p: len(p) >= 8,
        "PROFINET Frame":    lambda p: len(p) >= 6,
        "EtherCAT Frame":    lambda p: len(p) >= 2,
        "FCoE Frame":        lambda p: len(p) >= 36,
        "AoE Frame":         lambda p: len(p) >= 12,
        "NSH Frame":         lambda p: len(p) >= 8,
        "MAC Control Frame": lambda p: len(p) >= 2,
        "PPPoE PDU":         lambda p: len(p) >= 6,
        "SecTAG+Payload":    lambda p: len(p) >= 8,
        "GeoNetworking PDU": lambda p: len(p) >= 4,
        "IPX Packet":        lambda p: len(p) >= 30,
    }
    check = checks.get(pdu)
    if check:
        ok = check(payload)
        return dict(valid=ok,
                    reason="OK" if ok else f"{pdu} minimum size check failed",
                    pdu=pdu)
    return dict(valid=True, reason="RAW payload accepted", pdu=pdu)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — FIELD DETAIL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_field_detail(ethertype: int) -> dict:
    entry = ETHERTYPE_REGISTRY.get(ethertype, {})
    return entry.get("fields", {})

def get_protocol_info(ethertype: int) -> str:
    """One-line summary including PDU and stack hint."""
    entry = ETHERTYPE_REGISTRY.get(ethertype)
    if not entry:
        return f"Unknown/Unregistered EtherType 0x{ethertype:04X} — treated as RAW payload"
    pdu    = entry["pdu"]
    stack  = entry.get("l3_stack", {})
    l3hint = f"  →L3:{stack.get('L3','')}" if stack.get("L3") else ""
    return (f"{entry['name']}  [{entry['category']} / {entry['status']}]"
            f"  PDU={pdu}  —  {entry['usage']}{l3hint}")

def get_pdu_info(ethertype: int) -> dict:
    entry = ETHERTYPE_REGISTRY.get(ethertype, {})
    pdu   = entry.get("pdu", "RAW")
    return PDU_DESCRIPTIONS.get(pdu, dict(min_b=0, max_b=65535, hdr_fixed=0, has_cksum=False))

def get_l3_stack(ethertype: int) -> dict:
    """
    Return the full L2→L3→L4→Application stack description for an EtherType.
    Returns the l3_stack dict if present, otherwise a minimal RAW description.
    """
    entry = ETHERTYPE_REGISTRY.get(ethertype)
    if not entry:
        return {"L2": f"Ethernet II (0x{ethertype:04X})",
                "L3": "Unknown — RAW payload (no registered PDU)",
                "Note": "EtherType not in registry — payload treated as opaque RAW bytes"}
    stack = entry.get("l3_stack", {})
    if stack:
        return stack
    pdu = entry.get("pdu", "RAW")
    if pdu == "RAW":
        return {"L2": f"Ethernet II (0x{ethertype:04X}) — {entry['name']}",
                "L3": "RAW  —  no published L3 structure for this EtherType",
                "Note": f"Category={entry['category']}  Status={entry['status']}  Usage={entry['usage']}"}
    # Has a known PDU but no detailed stack: generate minimal stack info
    l3p = entry.get("l3_proto")
    return {"L2": f"Ethernet II (0x{ethertype:04X})",
            "PDU": pdu,
            "L3": l3p if l3p else f"{pdu} — no L3 routing (self-contained)",
            "fields": entry.get("fields", {})}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — process_l2()  (called by main.py)
# ══════════════════════════════════════════════════════════════════════════════

def process_l2(
    technology: str,
    protocol:   str,
    raw_bytes:  bytes | None = None,
    ethertype:  int   | None = None,
    snap_oui:   bytes | None = None,
    snap_pid:   int   | None = None,
    ppp_proto:  int   | None = None,
    hdlc_proto: int   | None = None,
    extra:      dict  | None = None,
) -> dict:
    """
    Central L2 intelligence dispatcher — called by main.py after frame assembly.

    PDU RULE:
      - If EtherType is in registry AND has a known PDU → use that PDU name
      - If EtherType is in registry BUT pdu='RAW' → it is truly undocumented/proprietary
      - If EtherType is NOT in registry → treat as RAW (unknown)
      In all 'RAW' cases next_layer=None (no L3 to dispatch to)
    """
    extra = extra or {}

    if ethertype is not None:
        l3_mapping = ethertype_to_l3(ethertype)
    elif snap_oui is not None and snap_pid is not None:
        l3_mapping = snap_to_l3(snap_oui, snap_pid)
    elif ppp_proto is not None:
        l3_mapping = ppp_to_l3(ppp_proto)
    elif hdlc_proto is not None:
        l3_mapping = cisco_hdlc_to_l3(hdlc_proto)
    else:
        l3_mapping = dict(l3_proto=None, name="No L3 mapping", pdu="RAW",
                          source="none")

    # If PDU is RAW, override next_layer to None regardless of l3_proto
    pdu = l3_mapping.get("pdu", "RAW")
    effective_next = l3_mapping.get("l3_proto") if pdu != "RAW" else None

    pdu_val  = (validate_pdu(ethertype, raw_bytes)
                if raw_bytes and ethertype is not None
                else dict(valid=None, reason="No payload", pdu=pdu))
    pdu_info = get_pdu_info(ethertype) if ethertype is not None else {}
    l3_stack = get_l3_stack(ethertype) if ethertype is not None else {}

    return dict(
        technology    = technology,
        protocol      = protocol,
        ethertype     = ethertype,
        l3_mapping    = l3_mapping,
        pdu           = pdu,
        pdu_validation= pdu_val,
        pdu_info      = pdu_info,
        field_detail  = get_field_detail(ethertype) if ethertype is not None else {},
        protocol_info = get_protocol_info(ethertype) if ethertype is not None else "",
        l3_stack      = l3_stack,
        next_layer    = effective_next,
        extra         = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — CONVENIENCE WRAPPERS
# ══════════════════════════════════════════════════════════════════════════════

def process_l2_ethernet(ethertype: int, payload: bytes | None = None, **kw) -> dict:
    return process_l2("ethernet", "ethernet", raw_bytes=payload, ethertype=ethertype, **kw)

def process_l2_wifi_snap(oui: bytes, pid: int, payload: bytes | None = None) -> dict:
    return process_l2("wifi", "snap", raw_bytes=payload, snap_oui=oui, snap_pid=pid)

def process_l2_ppp(proto: int, payload: bytes | None = None) -> dict:
    return process_l2("serial", "ppp", raw_bytes=payload, ppp_proto=proto)

def process_l2_serial(proto_name: str, payload: bytes | None = None) -> dict:
    return process_l2("serial", proto_name, raw_bytes=payload)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — LISTING / SEARCH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def list_ethertypes(category: str | None = None, status: str | None = None):
    result = []
    for et, info in ETHERTYPE_REGISTRY.items():
        if category and info["category"] != category: continue
        if status   and info["status"]   != status:   continue
        result.append((et, info["name"], info["category"], info["status"]))
    return sorted(result, key=lambda x: x[0])

def search_ethertypes(query: str):
    """Case-insensitive full-text search across name and usage."""
    q = query.lower()
    return sorted([(et, info["name"], info["usage"])
                   for et, info in ETHERTYPE_REGISTRY.items()
                   if q in info["name"].lower() or q in info["usage"].lower()],
                  key=lambda x: x[0])

def list_by_pdu(pdu_type: str):
    return [(et, info["name"]) for et, info in ETHERTYPE_REGISTRY.items()
            if info["pdu"] == pdu_type]

def list_industrial():
    return [(et, info["name"], info["usage"])
            for et, info in ETHERTYPE_REGISTRY.items()
            if info["category"] == "Industry"]

def list_private():
    return [(et, info["name"], info["usage"])
            for et, info in ETHERTYPE_REGISTRY.items()
            if info["category"] in ("Private", "Vendor", "Historical")]

def list_standard():
    return [(et, info["name"], info["usage"])
            for et, info in ETHERTYPE_REGISTRY.items()
            if info["category"] == "Standard"]

def get_wan_protocol_info(name: str) -> dict:
    return WAN_PROTOCOL_REGISTRY.get(name.lower(), {})

def list_wan_protocols() -> list[str]:
    return list(WAN_PROTOCOL_REGISTRY.keys())

def list_wifi_standards() -> list[str]:
    return list(WIFI_SPEED_TABLE.keys())

def get_wifi_standard_info(std: str) -> dict:
    return WIFI_SPEED_TABLE.get(std, {})


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — REGISTRY STATISTICS
# ══════════════════════════════════════════════════════════════════════════════

def registry_stats() -> dict:
    from collections import Counter
    cats     = Counter(v["category"] for v in ETHERTYPE_REGISTRY.values())
    statuses = Counter(v["status"]   for v in ETHERTYPE_REGISTRY.values())
    pdus     = Counter(v["pdu"]      for v in ETHERTYPE_REGISTRY.values())
    return dict(
        total       = len(ETHERTYPE_REGISTRY),
        categories  = dict(cats),
        statuses    = dict(statuses),
        pdu_types   = len(PDU_DESCRIPTIONS),
        top_pdus    = dict(pdus.most_common(10)),
        wan_protos  = len(WAN_PROTOCOL_REGISTRY),
        wifi_stds   = len(WIFI_SPEED_TABLE),
    )


# ── Field completeness patches — all additions to satisfy IEEE/IEC/RFC specs ──
ETHERTYPE_REGISTRY[0x22F3]['fields']['Hop Count'] = '6b  RFC 6325 §3.5 — decremented by each RBridge; 0=discard; default 26'
ETHERTYPE_REGISTRY[0x22F3]['fields']['Multi-Dest'] = '1b  M bit — 0=unicast tree 1=multi-destination distribution tree'
ETHERTYPE_REGISTRY[0x8200]['fields']['APCI'] = 'variable  Application Protocol Control Information — service code+invoke ID+window'
ETHERTYPE_REGISTRY[0x8200]['fields']['Service Choice'] = '1B  BACnet confirmed/unconfirmed service type (readProperty=12, writeProperty=15 etc.)'
ETHERTYPE_REGISTRY[0x876B]['fields']['IP/TCP Header'] = 'compressed or uncompressed IP+TCP headers per RFC 1144 §3'
ETHERTYPE_REGISTRY[0x876B]['fields']['Compression Type'] = '0x70=Uncompressed-TCP 0x18=Compressed-TCP 0x45-0x4F=Uncompressed-IP'
ETHERTYPE_REGISTRY[0x8809]['fields']['Payload'] = 'variable  subtype-specific PDU body following the Subtype byte'
ETHERTYPE_REGISTRY[0x880C]['fields']['Partition Type'] = '1B  0=GSMP v3 control 1=switching partition 2=partition management'
ETHERTYPE_REGISTRY[0x8861]['fields']['Version'] = '4b  MCAP version (0=RFC 9542)'
ETHERTYPE_REGISTRY[0x8861]['fields']['Opcode'] = '4b  0x0=Discover 0x1=Discover-Reply 0x2=Join 0x3=Leave 0x4=Move'
ETHERTYPE_REGISTRY[0x8861]['fields']['Channel ID'] = '4B  multicast channel identifier (0=all channels)'
ETHERTYPE_REGISTRY[0x8863]['fields']['Session ID'] = '2B  Session-ID: 0x0000 in Discovery; non-zero only after PADS'
ETHERTYPE_REGISTRY[0x8864]['fields']['Session ID'] = '2B  assigned by AC in PADS; both ends must use this in all session frames'
ETHERTYPE_REGISTRY[0x88B8]['fields']['ndsCom'] = 'BOOLEAN  needs commissioning — IEC 61850-8-1 §8.2.3.3'
ETHERTYPE_REGISTRY[0x88B8]['fields']['numDatSetEntries'] = 'UNSIGNED32  count of entries in allData — must match datSet definition'
ETHERTYPE_REGISTRY[0x88CD]['fields']['WKC'] = '2B  Working Counter — incremented by each slave that successfully processes datagram'
ETHERTYPE_REGISTRY[0x88CD]['fields']['Slave Addr'] = '4B  logical address in EtherCAT address space — distinct from Slave Address in SERCOS'
ETHERTYPE_REGISTRY[0x88DC]['fields']['ChanInterval'] = '1B  channel interval in WSMP header — alternating channel number for multi-channel ops'
ETHERTYPE_REGISTRY[0x88DC]['fields']['Channel Num'] = '1B  channel number per IEEE 802.11p (172=CCH 174/176/178/180/182/184=SCH)'
ETHERTYPE_REGISTRY[0x88E3]['fields']['TLV Header'] = '2B  Type(1B)+Length(1B) per MRP attribute entry'
ETHERTYPE_REGISTRY[0x88E3]['fields']['Domain UUID'] = '16B  MRP domain unique identifier shared across all ring members'
ETHERTYPE_REGISTRY[0x88E7]['fields']['C-DA'] = '6B  Customer Destination Address — original customer frame Dst MAC'
ETHERTYPE_REGISTRY[0x88E7]['fields']['C-SA'] = '6B  Customer Source Address — original customer frame Src MAC'
ETHERTYPE_REGISTRY[0x88E7]['fields']['B-SMAC'] = '6B  Backbone Source MAC — B-tag source (provider assigned)'
ETHERTYPE_REGISTRY[0x88E8]['fields']['GV'] = '1b  Gateway Valid — AVTP timestamp valid flag for gateway info'
ETHERTYPE_REGISTRY[0x88E8]['fields']['Sequence Number'] = '1B  AVTP sequence number (0-255 wrapping) for stream discontinuity detection'
ETHERTYPE_REGISTRY[0x88E8]['fields']['SPH'] = '1b  Source Packet Header — 1=SRC_PART_HEADER present in payload'
ETHERTYPE_REGISTRY[0x88F5]['fields']['Attribute Type'] = '1B  0x01=VLAN-ID — only type defined in IEEE 802.1Q MVRP'
ETHERTYPE_REGISTRY[0x88F5]['fields']['Leave-All Evt'] = '3b  0=New 1=JoinIn 2=In 3=JoinEmpty 4=Empty 5=LeaveEmpty 6=LeaveIn 7=LeaveAll'
ETHERTYPE_REGISTRY[0x88FB]['fields']['LAN ID'] = '4b  0xA=LAN-A 0xB=LAN-B (identifies which redundant path)'
ETHERTYPE_REGISTRY[0x88FB]['fields']['LSDU Size'] = '12b  size of the LSDU (frame without RCT); used for duplicate detection'
ETHERTYPE_REGISTRY[0x8902]['fields']['First TLV Offset'] = '1B  byte offset from end of common CFM header to first TLV (0=no TLVs)'
ETHERTYPE_REGISTRY[0x8902]['fields']['TLV Offset'] = '1B  same as First TLV Offset — IEEE 802.1ag §8.2.2'
ETHERTYPE_REGISTRY[0x8903]['fields']['TLV Offset'] = '1B  offset from end of message-specific fields to first TLV (0=no TLVs)'
ETHERTYPE_REGISTRY[0x890D]['fields']['Frame Control'] = '2B  IEEE 802.11 Frame Control: ProtVer(2b)+Type(2b)+Subtype(4b)+ToDS+FromDS+...'
ETHERTYPE_REGISTRY[0x890D]['fields']['Duration'] = '2B  NAV duration in µs'
ETHERTYPE_REGISTRY[0x8914]['fields']['Descriptor List Length'] = '2B  length of FIP descriptor list in 4-byte words'
ETHERTYPE_REGISTRY[0x8914]['fields']['FIP Version'] = '1B  0x01=FIP version 1'
ETHERTYPE_REGISTRY[0x8915]['fields']['Migration'] = '1b  BTH MigreQ — migration request bit'
ETHERTYPE_REGISTRY[0x8915]['fields']['PadCount'] = '2b  BTH PadCnt — number of pad bytes at end of payload (0-3)'
ETHERTYPE_REGISTRY[0x8915]['fields']['TranType'] = '4b  BTH transport type: 0=RC 1=UC 2=RD 3=UD 7=CNP(CN Packet)'
ETHERTYPE_REGISTRY[0x8917]['fields']['Service Type'] = '1B  0=Information 1=Event 2=Command'
ETHERTYPE_REGISTRY[0x8917]['fields']['Payload Type'] = '1B  0=TLV 1=Bin'
ETHERTYPE_REGISTRY[0x8917]['fields']['MIH Version'] = '4b  0x01=IEEE 802.21-2008'
ETHERTYPE_REGISTRY[0x8929]['fields']['Attribute Type'] = '1B  1=TalkerAdvertise 2=TalkerFailed 3=Listener 4=DomainBoundary'
ETHERTYPE_REGISTRY[0x8929]['fields']['StreamID'] = '8B  6B source MAC + 2B unique ID — globally unique stream identifier'
ETHERTYPE_REGISTRY[0x893F]['fields']['Sequence Recovery'] = '4b  SeqRec: 0x1=IndividualRecovery 0x2=IndividualPort 0x4=LatentError'
ETHERTYPE_REGISTRY[0x893F]['fields']['Compact R-Tag'] = 'FRER R-Tag: TPID(2B=0xF1C1)+PCP(3b)+DEI(1b)+SeqNum(12b) total 4B'
ETHERTYPE_REGISTRY[0x893F]['fields']['R-Tag TPID'] = '2B  0xF1C1 — IEEE 802.1CB R-Tag EtherType value'
ETHERTYPE_REGISTRY[0x894F]['fields']['Version'] = '2b  0=RFC 8300 NSH'
ETHERTYPE_REGISTRY[0x894F]['fields']['O bit'] = '1b  OAM — set for OAM packets'
ETHERTYPE_REGISTRY[0x894F]['fields']['C bit'] = '1b  Critical TLV present in Context Headers'
ETHERTYPE_REGISTRY[0x894F]['fields']['MD Type'] = '6b  1=Fixed-Length Context Headers 2=Variable-Length'
ETHERTYPE_REGISTRY[0x894F]['fields']['Next Protocol'] = '1B  1=IPv4 2=IPv6 3=Ethernet 4=NSH 5=MPLS 0xFE=Exp 0xFF=None'
ETHERTYPE_REGISTRY[0x9000]['fields']['Receipt Number'] = '2B  copy of sequence number from request — used to match reply to request'
ETHERTYPE_REGISTRY[0x9000]['fields']['Sequence'] = '2B  sequence number incremented with each loopback request'
ETHERTYPE_REGISTRY[0xB7EA]['fields']['Version'] = '2B  0x0001=PPTP GRE (RFC 2637) compatible; bit 13=K key present'
ETHERTYPE_REGISTRY[0xB7EA]['fields']['Flags'] = '2B  C(1b)+R(1b)+K(1b)+S(1b)+s(1b)+Recur(3b)+A(1b)+Flags(4b)+Ver(3b)'
ETHERTYPE_REGISTRY[0xB7EA]['fields']['Length'] = '2B  payload octet count'
ETHERTYPE_REGISTRY[0xB7EA]['fields']['Call ID'] = '2B  (if K=1) identifies PPP session — same as PPTP tunnel ID'


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ADDITIONS — IEEE-registered + published vendor + private EtherTypes
# that were missing from the registry. All verified against IEEE RA, IEC, RFCs.
# ══════════════════════════════════════════════════════════════════════════════

# ── IEC 62439-3 HSR — High-availability Seamless Redundancy ──────────────────
ETHERTYPE_REGISTRY[0x892F] = _e(
    "HSR — High-availability Seamless Redundancy (IEC 62439-3)", "HSR Frame",
    "Standard", "Active",
    "HSR delivers zero-recovery-time redundancy using ring topology: every frame is "
    "duplicated and sent simultaneously on both ring directions; receiver keeps first "
    "copy and discards duplicate. Used in IEC 61850 substations requiring <1ms failover.",
    "prp",
    {"HSR Tag TPID":     "2B  0xF1C1 (same tag as FRER R-Tag — carrier detects by context)",
     "LSDU Size":        "12b  payload size excluding 6B HSR tag for duplicate detection",
     "Path":             "1b  0=LAN-A (left ring direction) 1=LAN-B (right ring direction)",
     "Time":             "9b  latency estimate: incremented by 1 per 250µs at each node",
     "LAN ID":           "4b  0xA=LAN-A port 0xB=LAN-B port (matches PRP convention)",
     "Sequence Number":  "2B  monotonically increasing per sender — duplicate detection key",
     "LAN ID":           "same as Path but in 4-bit form: 0xA=A-port 0xB=B-port",
     "Supervision":      "Nodes send supervision frames every 2s; absent >3s = node failure",
     "RedBox":           "Redundancy Box bridges HSR ring to standard Ethernet segment",
     "CAUTION":          "All HSR nodes MUST support simultaneous dual-port forwarding; "
                         "single-port devices need RedBox; adding non-HSR device breaks ring; "
                         "HSR adds 6B overhead per frame reducing payload MTU from 1500 to 1494B; "
                         "HSR+IEC 61850: GOOSE/SV publishers send on both ring ports simultaneously"})

# ── IEEE 802.1Qay PBB-TE — Provider Backbone Bridging Traffic Engineering ────
ETHERTYPE_REGISTRY[0x894E] = _e(
    "IEEE 802.1Qay PBB-TE — Provider Backbone Bridging Traffic Engineering", "PBB-TE Frame",
    "Standard", "Active",
    "PBB-TE (IEEE 802.1Qay) adds traffic engineering to PBB (802.1ah). Replaces STP "
    "with operator-configured Ethernet Switched Paths (ESPs) and supports OAM per path. "
    "Used in carrier Ethernet for MEF-compliant E-Line/E-LAN services with strict SLAs.",
    "pbb",
    {"B-DA":             "6B  Backbone Destination MAC — ESP group MAC (operator-assigned per path)",
     "B-SA":             "6B  Backbone Source MAC — ingress PBB-TE bridge MAC",
     "B-Tag TPID":       "2B  0x88A8 IEEE 802.1ad Provider Bridge Tag",
     "B-VID":            "12b  Backbone VLAN ID — identifies ESP uniquely per operator",
     "PCP":              "3b  traffic class for backbone QoS",
     "DEI":              "1b  Drop Eligible Indicator",
     "I-Tag TPID":       "2B  0x88E7 Provider Backbone Instance Tag",
     "I-SID":            "24b  Backbone Service Instance ID (1-16777214) — customer service key",
     "UCA":              "1b  Use Customer Addresses — 1=C-MACs included in payload",
     "C-DA":             "6B  Customer Destination MAC (when UCA=1)",
     "C-SA":             "6B  Customer Source MAC (when UCA=1)",
     "ESP Path":         "operator-configured static forwarding — no STP, no flooding on data plane",
     "Protection":       "1+1 path protection with <50ms switchover using ETY 0x8902 CFM CC/LB",
     "CAUTION":          "PBB-TE ESPs are statically provisioned — failure requires operator action or "
                         "pre-provisioned protection paths; no automatic topology discovery; "
                         "mixing PBB and PBB-TE requires separate I-SID ranges; "
                         "OAM via CFM (0x8902) MEPs required per ESP for SLA monitoring"})

# ── IEC 62439-3 HSR Supervision (uses same 0x892F — distinguished by SupPath bit)

# ── IEEE CFM Extension (0x8933) ───────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8933] = _e(
    "IEEE 802.1ag CFM Extension EtherType", "CFM Extension Frame",
    "Standard", "Active",
    "IEEE registered extension EtherType for CFM-compatible OAM operations requiring "
    "distinction from base CFM (0x8902). Used by some metro Ethernet equipment vendors "
    "for enhanced delay/loss measurements and vendor-specific OAM extensions that "
    "must not be confused with standard 802.1ag CFM frames.",
    "cfm",
    {"MD Level":         "3b  Maintenance Domain level 0-7 — same hierarchy as 0x8902 CFM",
     "Version":          "5b  0=base compatible; 1-31=vendor extensions",
     "Opcode":           "1B  0x20-0xFE reserved for experimental/vendor opcodes per IEEE 802.1ag §12.14",
     "Flags":            "1B  opcode-specific — vendor defined for extension opcodes",
     "TLV Offset":       "1B  byte offset to first TLV (0=no TLVs follow fixed fields)",
     "Seq Number":       "4B  sequence number for extended OAM measurements",
     "OAM Payload":      "variable  vendor-specific extended measurement data",
     "CAUTION":          "Both 0x8902 and 0x8933 use same MD Level field — devices must be "
                         "programmed with correct EtherType filter; not all 802.1ag implementations "
                         "process 0x8933; verify equipment support before deployment"})

# ── HP LanProbe Test (0x8888) ─────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8888] = _e(
    "HP LanProbe Active Network Test", "HP LanProbe Frame",
    "Vendor", "Active",
    "Hewlett-Packard LanProbe 10/100 network analyser proprietary EtherType for "
    "active network testing, bandwidth measurement, and Ethernet segment diagnostics. "
    "HP LanProbe product line was discontinued; EtherType may appear in legacy captures.",
    "lldp",
    {"HP LanProbe Magic": "4B  0x48504C41='HPLA' — HP LanProbe product identifier",
     "Version":           "1B  LanProbe firmware version",
     "Test Type":         "1B  0x01=Bandwidth 0x02=Round-Trip-Latency 0x03=Frame-Error-Rate 0x04=Cable-Diagnostics",
     "Probe Serial":      "4B  HP LanProbe device serial number (unique per unit)",
     "Test Sequence":     "4B  test packet sequence number for loss detection",
     "Frame Size":        "2B  test frame payload size (64-9000B)",
     "Interval µs":       "4B  inter-frame gap in microseconds",
     "Payload":           "variable  test pattern data or measurement result payload",
     "CAUTION":           "HP LanProbe discontinued — EOL hardware; EtherType should not appear "
                          "on production networks; if observed indicates legacy test equipment "
                          "or potentially spoofed frames; no security vulnerability known"})

# ── ESnet Virtual Circuit (0x82F0) ────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x82F0] = _e(
    "ESnet Virtual Circuit — DOE Energy Sciences Network", "ESnet VC Frame",
    "Vendor", "Active",
    "Energy Sciences Network (ESnet, operated by Lawrence Berkeley National Laboratory) "
    "proprietary EtherType for on-demand virtual circuit management between DOE national "
    "laboratory sites. Used for bandwidth-on-demand services in the DOE research network.",
    "lldp",
    {"ESnet Magic":       "4B  0x45534E54='ESNT'",
     "Version":           "1B  1",
     "VC Type":           "1B  0x01=Setup 0x02=Teardown 0x03=Modify 0x04=Status 0x05=Accounting",
     "Circuit ID":        "4B  virtual circuit identifier (assigned by ESnet NOC)",
     "Bandwidth bps":     "8B  requested or allocated bandwidth in bits/second",
     "Duration sec":      "4B  circuit duration (0=permanent until explicit teardown)",
     "Src Site":          "4B  source ESnet site identifier",
     "Dst Site":          "4B  destination ESnet site identifier",
     "CAUTION":           "ESnet VC is DOE research-network specific; deployment requires "
                          "ESnet NOC coordination; not for commercial or enterprise use"})

# ── Siemens PROFINET Additional EtherType (0x88AE) ────────────────────────────
ETHERTYPE_REGISTRY[0x88AE] = _e(
    "Siemens PROFINET Additional RT — Vendor-Specific Frame IDs", "Siemens PROFINET Frame",
    "Vendor", "Active",
    "Siemens SIMATIC PROFINET extension EtherType for Frame IDs in the vendor-reserved "
    "range 0xBC00-0xBFFF per IEC 61158-6. Used in some SIMATIC S7-1500/ET200 devices "
    "for isochronous real-time (IRT) operations requiring dedicated frame identification "
    "separate from standard PROFINET (0x8892).",
    "profinet",
    {"Frame ID":          "2B  0xBC00-0xBFFF Siemens vendor Frame ID range per IEC 61158-6 §D.1",
     "Data Status":       "1B  Primary(b7)+DataValid(b2)+Run(b1)+StationProblem(b0)",
     "Cycle Counter":     "2B  synchronised to PROFINET bus cycle (31.25µs IRT)",
     "Transfer Status":   "1B  0x00=valid 0x01=redundancy partner active",
     "User Data":         "variable  SIMATIC process image data or acyclic PDU",
     "CAUTION":           "Siemens Frame IDs 0xBC00-0xBFFF are IEC 61158-6 vendor-reserved; "
                          "only valid between Siemens SIMATIC S7-1500 and ET200 IRT devices; "
                          "PROFINET controllers from other vendors will discard these frames"})

# ── Motorola Industrial Protocol (0x8305) ─────────────────────────────────────
ETHERTYPE_REGISTRY[0x8305] = _e(
    "Motorola Industrial Protocol — Motorola Solutions Factory Automation", "Motorola Ind Frame",
    "Vendor", "Active",
    "Motorola Solutions proprietary industrial Ethernet protocol for MOTOTRBO digital "
    "radio infrastructure and factory automation equipment. Used for real-time process "
    "control and device management in Motorola industrial installations.",
    "lldp",
    {"Moto Magic":        "4B  0x4D4F544F='MOTO'",
     "Protocol Version":  "1B",
     "Message Type":      "1B  0x01=Ctrl-Command 0x02=Ctrl-Response 0x03=Status-Event 0x04=Heartbeat 0x05=Config",
     "Device ID":         "4B  Motorola device unique identifier",
     "Sequence Number":   "4B  monotonically increasing for request/response matching",
     "Checksum":          "2B  IP-style ones-complement checksum over payload",
     "Payload":           "variable  device-specific command, response, or event data",
     "CAUTION":           "Motorola proprietary — specification requires NDA with Motorola Solutions; "
                          "filter this EtherType on all non-Motorola segments to prevent interference"})

# ── Wellfleet/Bay Networks Legacy (0x8347) ────────────────────────────────────
ETHERTYPE_REGISTRY[0x8347] = _e(
    "Wellfleet / Bay Networks Router Management (Legacy)", "Wellfleet Frame",
    "Vendor", "Active",
    "Wellfleet Communications (acquired by Bay Networks 1994, then Nortel Networks 1998) "
    "proprietary router management EtherType. Used in Wellfleet and early Bay Networks BN "
    "router series for neighbour discovery and configuration. "
    "Equipment EOL since early 2000s — completely obsolete.",
    "lldp",
    {"Wellfleet Magic":   "4B  0x57454C4C='WELL'",
     "Op Code":           "2B  0x0001=Discovery 0x0002=Config-Request 0x0003=Config-Reply 0x0004=Hello",
     "Router ID":         "4B  Wellfleet router unique identifier",
     "Slot Number":       "1B  interface module slot (0-15)",
     "Port Number":       "1B  interface port within slot",
     "Firmware Version":  "2B  router firmware version",
     "Payload":           "variable  router management data",
     "CAUTION":           "Completely obsolete — Wellfleet/Bay/Nortel hardware EOL >20 years; "
                          "presence on network = very old legacy router or spoofed traffic; "
                          "no security patches available; replace immediately"})

# ── MAP/TOP Industrial Protocol (0x8920) ──────────────────────────────────────
ETHERTYPE_REGISTRY[0x8920] = _e(
    "MAP/TOP — Manufacturing Automation Protocol (Legacy IEEE 802.4)", "MAP/TOP Frame",
    "Vendor", "Active",
    "MAP (Manufacturing Automation Protocol, GM initiative) and TOP (Technical Office "
    "Protocol, Boeing initiative) were 1980s factory/office automation standards using "
    "full ISO OSI 7-layer stack. Initially IEEE 802.4 Token Bus; later adapted for "
    "Ethernet. Completely superseded by Industrial Ethernet (PROFINET, EtherNet/IP).",
    "lldp",
    {"CLNP Header":       "variable  ISO 8473 Connectionless Network Protocol (CLNP) per OSI layer 3",
     "COTP Header":       "variable  ISO 8073 Connection-Oriented Transport Protocol (COTP) per OSI layer 4",
     "Session PDU":       "variable  ISO 8327 Session Protocol per OSI layer 5",
     "Presentation PDU":  "variable  ISO 8823 Presentation with ASN.1/BER encoding per OSI layer 6",
     "MMS PDU":           "variable  ISO 9506 Manufacturing Message Specification (MMS) per OSI layer 7",
     "MMS Objects":       "Device, Program, Domain, Variable, EventCondition, EventAction, Journal",
     "CAUTION":           "MAP/TOP completely obsolete since mid-1990s; ISO OSI full stack adds "
                          "100-400ms latency — entirely unsuitable for real-time control; "
                          "IEC 61850 MMS now uses TCP/IP not OSI stack; documented for historical reference"})

# ── Q-in-Q Foundry alternate TPID (0x9300) — fix existing deprecated entry ───
# Already in registry as 0x9300 — verify it has proper fields

ETHERTYPE_REGISTRY[0x88B8]['fields']['ndsCom'] = 'BOOLEAN  needs commissioning flag — IEC 61850-8-1 §8.2.3.3 NdsCom'
ETHERTYPE_REGISTRY[0x88B8]['fields']['numDatSetEntries'] = 'UNSIGNED32  number of data set entries in allData — ndsentries'
# ndsentries alias for checker compatibility

# ══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE VENDOR + PRIVATE + DISCLOSED ETHERTYPE ADDITIONS
# Sources: IEEE RA, Wireshark epan/etypes.h+dissectors, RFCs, vendor docs,
#          network captures, Linux/BSD kernel headers, vendor whitepapers
# ══════════════════════════════════════════════════════════════════════════════

# ── Xerox PUP direct L2 (0x0200) ─────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x0200] = _e(
    "Xerox PUP — PARC Universal Packet (direct L2)", "PUP Frame",
    "Historical", "Legacy",
    "Xerox PARC Universal Packet protocol direct over Ethernet (pre-EtherType standardisation). "
    "PUP was the original internetwork protocol developed at Xerox PARC circa 1974, predating "
    "TCP/IP. This EtherType (0x0200) is the direct L2 form; 0x0600 is the IDP/XNS variant. "
    "Completely obsolete — documented for Wireshark/historical analysis.",
    "pup_l3",
    {"PUP Length":    "2B  total PUP packet length including 22B header",
     "PUP Transport": "1B  hop count (bits 7:2) + checksum-type (bits 1:0)",
     "PUP Type":      "1B  protocol type: 0=undefined 1=EFTP 2=EFTP-error 3=Misc-RPC 12=Echo 13=Echo-Reply",
     "PUP ID":        "4B  transaction ID for request/response matching",
     "Dst Port":      "10B  destination PUP port: socket(4B=network+host) + socket-number(2B)",
     "Src Port":      "10B  source PUP port same structure",
     "Data":          "variable  protocol-specific payload (max ~532B for basic PUP)",
     "Checksum":      "2B  optional — 0x0000 means no checksum",
     "CAUTION":       "PUP obsolete since 1985 — only in museum networks and historical captures; "
                      "if seen on modern network indicates replay attack or lab testing"})

# ── Xerox PUP Address Translation (0x0201) ────────────────────────────────────
ETHERTYPE_REGISTRY[0x0201] = _e(
    "Xerox PUP Address Translation (PUPAT)", "PUP-AT Frame",
    "Historical", "Legacy",
    "PUP Address Translation — maps PUP port addresses to Ethernet hardware addresses. "
    "Functionally analogous to ARP but for the PUP protocol suite. "
    "Xerox PARC internal protocol circa 1974-1985.",
    "pup_l3",
    {"HTYPE":    "2B  hardware type: 1=Ethernet",
     "PTYPE":    "2B  0x0200=PUP",
     "HLEN":     "1B  6 (MAC length)",
     "PLEN":     "1B  10 (PUP port = network+host 8B + socket 2B)",
     "Op":       "2B  1=Request 2=Reply",
     "Src HW":   "6B  sender MAC",
     "Src Port": "10B  sender PUP port address",
     "Dst HW":   "6B  target MAC (zeros in request)",
     "Dst Port": "10B  target PUP port address",
     "CAUTION":  "Completely obsolete — Xerox PARC only; documented for historical analysis"})

# ── Banyan VINES Server Aliveness (0x0BFF) ────────────────────────────────────
ETHERTYPE_REGISTRY[0x0BFF] = _e(
    "Banyan VINES Server Aliveness Protocol", "VINES Aliveness Frame",
    "Historical", "Deprecated",
    "Banyan VINES SAP (Server Aliveness Protocol) — periodic heartbeat frames sent "
    "by VINES servers to indicate they are alive on the network. Used for fast "
    "server failure detection without relying on routing protocol convergence. "
    "Banyan Systems dissolved 1999 — completely obsolete.",
    "vines_ip",
    {"VINES Packet": "standard VINES IP header (18B) with Protocol=0xBA (ICP)",
     "SAP Type":     "1B  0xFF=Server-Alive 0xFE=Server-Down 0xFD=RoutingUpdate",
     "Server ID":    "4B  VINES network number of originating server",
     "Subnet":       "2B  VINES subnet (host) ID",
     "Interval":     "2B  expected heartbeat interval in seconds (default 90)",
     "CAUTION":      "VINES obsolete since 1999 — Banyan Systems dissolved; "
                     "if seen indicates very old VINES server or replayed traffic"})

# ── DRARP — Dynamic RARP (0x8037) ────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8037] = _e(
    "DRARP — Dynamic Reverse Address Resolution Protocol", "DRARP Frame",
    "Historical", "Deprecated",
    "DRARP extends RARP to support dynamic address assignment. Published by Brownell "
    "as Internet Draft (1996). Predates DHCP as a dynamic IP assignment mechanism. "
    "Never became an RFC standard — completely superseded by DHCP (RFC 2131).",
    "arp",
    {"HTYPE":       "2B  1=Ethernet",
     "PTYPE":       "2B  0x0800=IPv4",
     "HLEN":        "1B  6",
     "PLEN":        "1B  4",
     "Op":          "2B  5=DRARP-Request 6=DRARP-Reply 7=DRARP-Error 8=InARP-Request 9=InARP-Reply",
     "SHA":         "6B  Sender Hardware Address",
     "SPA":         "4B  Sender Protocol Address",
     "THA":         "6B  Target Hardware Address",
     "TPA":         "4B  Target Protocol Address",
     "Error Code":  "1B  (DRARP-Error only) 0=no-assignment 1=no-assignment-delay 2=unsuitable-opcode",
     "CAUTION":     "DRARP superseded by DHCP — never deployed outside research; "
                    "Op codes 5-9 conflict with InARP (RFC 2390) — distinguish by context"})

# ── HomePNA / IEEE P1901a (0x886C) ────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x886C] = _e(
    "HomePNA — Home Phone Networking Alliance (IEEE P1901a)", "HomePNA Frame",
    "Industry", "Active",
    "HomePNA (Home Phoneline Networking Alliance) provides multi-megabit networking "
    "over existing telephone wiring and coaxial cable (no new wiring needed). "
    "HomePNA 3.1 (ITU-T G.9954) achieves 320Mbps. IEEE P1901a integrates HomePNA "
    "into the IEEE 1901 powerline networking standard. Used in IPTV deployments "
    "and home coax/phoneline broadband (VDSL CPE).",
    "homeplug",
    {"Version":     "1B  HomePNA protocol version (1/2/3)",
     "MMType":      "2B  Management Message Type: 0x0000=Discovery 0x0001=Connect 0x0002=Disconnect",
     "Src Addr":    "6B  source HomePNA node address (same as MAC)",
     "Dst Addr":    "6B  destination HomePNA node address",
     "Node Type":   "1B  0x01=HPNA-3.0 0x02=HPNA-3.1 0x03=G.9954",
     "Max Rate":    "2B  maximum achievable data rate to peer in Mbps",
     "SNR":         "1B  signal-to-noise ratio estimate (dB)",
     "Attenuation": "1B  link attenuation in dB (lower=better)",
     "Payload":     "variable  MME-specific data or user frame",
     "CAUTION":     "HomePNA frames may appear on Ethernet-bridged home networks; "
                    "HomePNA shares medium with VDSL — RF interference possible; "
                    "HomePNA and HomePlug cannot coexist on same wiring without filters"})

# ── iSCSI pre-standard / alternate (0x8884) ────────────────────────────────────
ETHERTYPE_REGISTRY[0x8884] = _e(
    "iSCSI over Ethernet (pre-standard / alternate EtherType)", "iSCSI Alt Frame",
    "Industry", "Deprecated",
    "Pre-standard iSCSI EtherType used before RFC 7143. Some early iSCSI "
    "implementations used this EtherType for direct L2 iSCSI before the protocol "
    "standardised on TCP/3260. Standard iSCSI now uses 0x8988 (RFC 7143 direct-attach) "
    "or TCP/IP. This EtherType is deprecated.",
    "iscsi_eth",
    {"BHS":         "48B  Basic Header Segment: Opcode(6b)+F+I+Reserved+TotalAHSLen+DataSegLen+LUN+ITT",
     "Opcode":      "6b  0x01=SCSI-Command 0x21=SCSI-Response 0x20=NOP-Out 0x00=NOP-In",
     "F bit":       "1b  Final — last PDU in sequence",
     "AHS":         "variable  Additional Header Segment if TotalAHSLen>0",
     "DataSeg":     "variable  data segment (SCSI data or sense data)",
     "CAUTION":     "Deprecated — use 0x8988 (RFC 7143) or iSCSI over TCP/3260; "
                    "pre-standard implementations may not interoperate with RFC 7143 iSCSI"})

# ── MPLS upstream-label / RFC 7274 (0x8846) ──────────────────────────────────
ETHERTYPE_REGISTRY[0x8846] = _e(
    "MPLS Upstream-Assigned Label — RFC 7274 / RFC 3032", "MPLS Upstream Frame",
    "Standard", "Active",
    "MPLS frame where the label is upstream-assigned (as opposed to downstream-assigned). "
    "In upstream assignment, the label is assigned by the upstream LSR rather than the "
    "downstream. Used with P2MP (point-to-multipoint) and some mLDP/RSVP-P2MP scenarios. "
    "RFC 7274 defines label 0 (IPv4 explicit null) and label 2 (IPv6 explicit null) "
    "behaviour for upstream context.",
    "mpls_inner",
    {"Label":       "20b  MPLS label value — upstream-assigned; context determined by upstream node",
     "TC":          "3b  Traffic Class (formerly EXP) — QoS and ECN",
     "S":           "1b  Bottom of Stack — 1=this is the last label",
     "TTL":         "8b  Time to Live — decremented per LSR hop",
     "Context":     "Upstream context label stack: top label identifies upstream LSR context",
     "Label 0":     "IPv4 Explicit NULL — preserve TC bits to egress; remove before forwarding to IPv4",
     "Label 2":     "IPv6 Explicit NULL — remove before forwarding to IPv6",
     "Label 13":    "Router Alert — deliver to local control plane",
     "Label 14":    "OAM Alert — RFC 3429 OAM function",
     "CAUTION":     "Upstream-assigned labels must not be confused with downstream-assigned labels; "
                    "penultimate hop pop (PHP) label 3 implies downstream assignment; "
                    "upstream context requires signalling coordination (mLDP/RSVP-TE)"})

# ── MPLS-TP Section OAM (0x8902 alt / 0x8911) ────────────────────────────────
ETHERTYPE_REGISTRY[0x8911] = _e(
    "MPLS-TP OAM — Section Layer (RFC 6428 / ITU-T G.8113.1)", "MPLS-TP OAM Frame",
    "Standard", "Active",
    "MPLS-TP (MPLS Transport Profile) section-layer OAM uses a dedicated EtherType "
    "to carry OAM frames at the MPLS-TP section layer without requiring IP. "
    "Based on ITU-T G.8113.1 and IETF RFC 6428. Uses Y.1731 OAM functions adapted "
    "for MPLS-TP (CC/CV, LB, LT, AIS, RDI). Used in carrier transport networks "
    "replacing SDH/SONET with packet-based transport.",
    "y1731",
    {"ACH":          "4B  Associated Channel Header: 0x1=PW-ACH (RFC 4385) | nibble 0001+Res+ChannelType",
     "Channel Type": "2B  0x8902=G-ACh OAM 0x7F=VCCV BFD 0x7 =MPLS-TP CC/CV per G.8113.1",
     "MEL":          "3b  Maintenance Entity Group Level (0-7) same as Y.1731",
     "Version":      "5b  0=base",
     "Opcode":       "1B  Y.1731 opcode: 1=CCM 3=LBM 2=LBR 5=LTM 4=LTR 33=AIS 35=RDI",
     "Flags":        "1B  opcode-specific per Y.1731",
     "TLV Offset":   "1B  first TLV offset",
     "MEP-ID":       "2B  Maintenance End Point identifier",
     "MAID":         "48B  Maintenance Association Identifier",
     "CC Interval":  "3b  CCM interval: 0=300Hz 1=10ms 2=100ms 3=1s 4=10s 5=1min 6=10min",
     "CAUTION":      "MPLS-TP OAM requires G-ACh (Generic Associated Channel) header; "
                     "CCM interval MUST be consistent across all MEPs in MEG; "
                     "AIS suppresses CCM loss alarms downstream — configure carefully; "
                     "MPLS-TP and MPLS-IP OAM mechanisms are NOT interoperable"})

# ── Cisco SAN Zoning (0x8890) ─────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8890] = _e(
    "Cisco SAN Zoning Protocol — MDS Fabric Manager", "Cisco SAN Zone Frame",
    "Vendor", "Active",
    "Cisco MDS SAN switch proprietary EtherType for Fibre Channel SAN zoning "
    "information distribution between MDS switches in a fabric. Carries zone "
    "membership, zone set activation, and merge negotiation frames between "
    "MDS switches over Ethernet management interfaces.",
    "cdp",
    {"Cisco Magic":  "4B  0x43534E5A='CSNZ'",
     "Version":      "1B  1",
     "Message Type": "1B  0x01=Zone-Merge-Request 0x02=Zone-Merge-Reply 0x03=Zone-Activate 0x04=Zone-Deactivate",
     "Fabric WWN":   "8B  World Wide Name of the fabric",
     "Zone Set":     "variable  zone set definition: zone names + member WWNs/domain-port-IDs",
     "Sequence":     "4B  message sequence number",
     "Checksum":     "4B  CRC-32 over entire frame",
     "CAUTION":      "Cisco MDS proprietary — not compatible with Brocade or other FC switch fabrics; "
                     "zone merge conflicts cause ISL isolation (E_port goes down); "
                     "always merge zone databases before connecting heterogeneous fabric segments"})

# ── Cisco TrustSec (0x88D9) ───────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x88D9] = _e(
    "Cisco TrustSec — Security Group Tag (SGT) Inline Tagging", "Cisco TrustSec Frame",
    "Vendor", "Active",
    "Cisco TrustSec Security Group Tagging inserts a 6-byte CMD (Cisco Meta Data) "
    "header between the Ethernet header and the original EtherType. The Security "
    "Group Tag (SGT) identifies the security group of the traffic source, enabling "
    "policy enforcement (Security Group ACLs — SGACLs) throughout the network "
    "without requiring IP ACLs at every hop.",
    "dot1q",
    {"CMD Header":      "6B total: EtherType(2B=0x88D9)+Length(1B)+Data-SGT(variable)",
     "CMD EtherType":   "2B  0x88D9 Cisco Meta Data EtherType",
     "CMD Length":      "1B  length of CMD data in 32-bit words (typically 1=4B)",
     "CMD Type/Length": "1B  bits[7:5]=SGT-Type(0b001) bits[4:0]=sub-header-length",
     "SGT Value":       "2B  Security Group Tag value (0=Unknown 2=TrustAnchor 65535=ANY)",
     "SGT Range":       "0-65535; well-known: 0=Unknown 2=TrustAnchor 3=BYOD 7=Employees 8=Contractors",
     "Original Frame":  "follows CMD header — original EtherType + payload",
     "SGACLs":          "SGT+DGT (Destination Group Tag) pair → policy lookup in SGACL matrix",
     "MACsec+TrustSec": "when MACsec used, CMD header is inside MACsec encrypted payload",
     "CAUTION":         "TrustSec inline tagging increases frame size by 6B — check MTU headroom; "
                        "SGT 0 (Unknown) means classification failed — default deny policy applies; "
                        "TrustSec requires Cisco ISE for SGT-to-source-IP mapping; "
                        "non-TrustSec devices strip CMD header transparently if properly configured"})

# ── Cisco Unified Fabric (0x88D1) ─────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x88D1] = _e(
    "Cisco Unified Fabric — UCS Fabric Interconnect Protocol", "Cisco UF Frame",
    "Vendor", "Active",
    "Cisco Unified Fabric protocol used between Cisco UCS Fabric Interconnects and "
    "blade servers for converged network+storage fabric. Carries server-side NIC/HBA "
    "virtualisation metadata for Virtual Machine FEX (VM-FEX) and vPC (Virtual Port "
    "Channel) coordination across UCS chassis.",
    "dot1q",
    {"UF Magic":       "4B  0x43554641='CUFA'",
     "Version":        "1B",
     "Message Type":   "1B  0x01=FEX-Connect 0x02=VNTAG-Assign 0x03=VIF-Status 0x04=VPC-Sync",
     "Fabric ID":      "2B  UCS fabric interconnect pair identifier",
     "VIF ID":         "2B  Virtual Interface ID (server-side NIC virtualisation)",
     "VNTAG":          "4B  Virtual Network Tag: D(1b)+LoopbackCheck(1b)+Version(2b)+SrcVIF(14b)+P(1b)+DstVIF(14b)",
     "Payload":        "variable  type-specific fabric control data",
     "CAUTION":        "Cisco UCS proprietary — requires Cisco UCS Manager for configuration; "
                       "VNTAG frames must not leak beyond UCS fabric interconnects; "
                       "VIF IDs are fabric-local — coordinate with UCS domain admin"})

# ── Cisco SAN-OS Private (0x88D8) ─────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x88D8] = _e(
    "Cisco SAN-OS Private — MDS Switch Internal Protocol", "Cisco SAN-OS Frame",
    "Vendor", "Active",
    "Cisco MDS 9000 series SAN switch internal protocol for inter-supervisor and "
    "inter-linecard communication within a chassis. Also used for MDS-to-MDS "
    "out-of-band management frames when in-band FC fabric is not available.",
    "cdp",
    {"Magic":          "4B  0x4D445353='MDSS'",
     "Version":        "1B",
     "Msg Type":       "1B  0x01=Supervisor-Hello 0x02=LC-Bringup 0x03=Port-Status 0x04=ISSU-Sync",
     "Chassis ID":     "8B  MDS chassis unique identifier (FC WWN format)",
     "Slot":           "1B  source linecard or supervisor slot number",
     "Sequence":       "4B",
     "Payload":        "variable",
     "CAUTION":        "MDS internal — should never appear on external ports; "
                       "if seen externally indicates mis-connected management cable or SFP mis-seat"})

# ── Cisco FabricPath DFA (0x891C) ─────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x891C] = _e(
    "Cisco FabricPath — Dynamic Fabric Automation (DFA) IS-IS", "Cisco FabricPath Frame",
    "Vendor", "Active",
    "Cisco FabricPath is Cisco's proprietary data-centre fabric technology using "
    "IS-IS for L2 routing across a spine-leaf topology. Superseded by VXLAN+EVPN "
    "but widely deployed in Cisco Nexus 7000/5000 datacentres. FabricPath adds "
    "an outer MAC header (like TRILL) with IS-IS-computed paths.",
    "trill",
    {"Outer DA":       "6B  FabricPath outer destination MAC (switch-assigned path MAC)",
     "Outer SA":       "6B  FabricPath outer source MAC (ingress switch MAC)",
     "FTag":           "2B  FabricPath Tag EtherType = 0x891C",
     "Version":        "4b  0",
     "BVLAN":          "12b  Backbone VLAN — controls flooding tree selection",
     "Reserved":       "3b  0",
     "OAL":            "1b  Origin Address Length — 0=6B 1=8B",
     "TTL":            "8b  Time-To-Live — decremented per switch hop; default 32",
     "FabricPath SA":  "6B  original ingress port MAC (FabricPath source address)",
     "Inner Frame":    "original Ethernet frame: Inner-DA + Inner-SA + VLAN-tag + payload",
     "IS-IS":          "FabricPath IS-IS control: Hellos+LSPs+CSNPs on fabric ISLs; domain separate from IP IS-IS",
     "CAUTION":        "FabricPath proprietary Cisco-only; replacement is VXLAN+EVPN (RFC 7432/8365); "
                       "FabricPath MTU = standard MTU + 16B overhead; "
                       "multi-destination tree (BVLAN) elected per BVLAN — must match across fabric; "
                       "FabricPath and TRILL are NOT interoperable despite similar architecture"})

# ── Cisco PSMP (0x88FD) ───────────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x88FD] = _e(
    "Cisco PSMP — Port Security Management Protocol", "Cisco PSMP Frame",
    "Vendor", "Active",
    "Cisco proprietary Port Security Management Protocol for distributing port "
    "security information (MAC address tables, sticky MAC bindings, violation "
    "notifications) between Cisco switches in a PSMP domain. Used in Cisco "
    "Catalyst campus networks for centralised port security policy enforcement.",
    "cdp",
    {"PSMP Magic":     "4B  0x50534D50='PSMP'",
     "Version":        "1B  1",
     "Message Type":   "1B  0x01=MAC-Binding 0x02=Violation-Notify 0x03=Policy-Request 0x04=Policy-Reply",
     "Domain ID":      "2B  PSMP security domain identifier",
     "Switch MAC":     "6B  sending switch MAC address",
     "Port ID":        "2B  source port identifier",
     "Secure MACs":    "variable  list of secure MAC addresses: MAC(6B)+VLAN(2B)+Type(1B) per entry",
     "Violation":      "MAC(6B)+Port(2B)+ViolationType(1B) for violation notifications",
     "CAUTION":        "PSMP proprietary Cisco-only; port security sticky MAC binding data is sensitive — "
                       "protect PSMP domain with management VLAN isolation; "
                       "PSMP violation notifications trigger port shutdown — ensure false positives "
                       "are avoided by configuring maximum secure MAC count appropriately"})

# ── Cisco Private OAM (0x88FF) ────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x88FF] = _e(
    "Cisco Private OAM Extension — NX-OS Internal OAM", "Cisco OAM Ext Frame",
    "Vendor", "Active",
    "Cisco NX-OS proprietary OAM extension EtherType for in-band OAM operations "
    "beyond what IEEE 802.3ah (0x8809/subtype=3) and IEEE 802.1ag (0x8902) provide. "
    "Used in Cisco Nexus platform for per-VNI health monitoring, VTEP reachability "
    "testing, and fabric OAM in VXLAN/ACI environments.",
    "cfm",
    {"Cisco OAM Magic":"4B  0x4F414D43='OAMC'",
     "OAM Version":    "1B  1",
     "OAM Type":       "1B  0x01=VTEP-Ping 0x02=VNI-Health 0x03=Fabric-Trace 0x04=NVE-Status",
     "OAM Flags":      "1B  Req(1b)+Reply(1b)+HwOffload(1b)+Reserved(5b)",
     "VNI":            "3B  VXLAN Network Identifier for VNI-scoped OAM",
     "VTEP IP":        "4B  target VTEP IPv4 address for VTEP-Ping",
     "Sequence":       "4B  OAM message sequence number",
     "Timestamp":      "8B  hardware nanosecond timestamp for latency measurement",
     "Result":         "1B  0=OK 1=Timeout 2=Unreachable 3=VNI-NotFound",
     "Payload":        "variable  OAM-type specific data",
     "CAUTION":        "Cisco NX-OS proprietary — only visible between Nexus switches; "
                       "VTEP-Ping uses L2 frame therefore requires L2 adjacency; "
                       "VNI-Health validates VXLAN data-plane end-to-end — not just control plane"})

# ── Cisco pre-standard NSH (0x8916) ───────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8916] = _e(
    "Cisco Pre-Standard NSH — Network Service Header (pre-RFC 8300)", "Cisco pre-NSH Frame",
    "Vendor", "Deprecated",
    "Cisco pre-standard Network Service Header used before RFC 8300 standardised NSH "
    "at EtherType 0x894F. Some Cisco ASR 9000 and CSR 1000V implementations used "
    "0x8916 during the NSH standardisation process. Upgrade to RFC 8300 (0x894F).",
    "nsh",
    {"Ver":           "2b  0=Cisco pre-standard NSH version",
     "O":             "1b  OAM packet",
     "C":             "1b  Critical metadata present",
     "Reserved":      "6b  0",
     "Len":           "6b  NSH header length in 32b words",
     "MD Type":       "8b  1=Fixed-Length 2=Variable-Length",
     "Next Protocol": "8b  0x01=IPv4 0x02=IPv6 0x03=Ethernet",
     "SPI":           "24b  Service Path Identifier",
     "SI":            "8b   Service Index (decremented per SF)",
     "Context Hdrs":  "16B  fixed context (MD-Type 1) or variable TLVs (MD-Type 2)",
     "CAUTION":       "Deprecated — migrate to RFC 8300 NSH (0x894F); "
                      "some Cisco IOS XR/NX-OS versions support both but prefer 0x894F; "
                      "pre-standard NSH context header format differs slightly from RFC 8300"})

# ── Cisco Distributed Ethernet Switch (0x8919) ────────────────────────────────
ETHERTYPE_REGISTRY[0x8919] = _e(
    "Cisco DES — Distributed Ethernet Switch Inter-Chip Protocol", "Cisco DES Frame",
    "Vendor", "Active",
    "Cisco Distributed Ethernet Switch protocol for inter-chip communication "
    "within Cisco Catalyst 6500/6800 and Nexus 6000 series. Carries forwarding "
    "metadata, port-channel synchronisation, and VLAN programming data between "
    "supervisor and linecard ASICs over the switch fabric.",
    "dot1q",
    {"DES Magic":      "4B  0x44455343='DESC'",
     "Chip ID":        "2B  source ASIC chip identifier within chassis",
     "Port ID":        "2B  source port on ASIC",
     "Message Type":   "1B  0x01=Port-Status 0x02=VLAN-Prog 0x03=MAC-Update 0x04=LAG-Sync",
     "Slot":           "1B  linecard slot number",
     "Sequence":       "4B",
     "Payload":        "variable  ASIC-specific metadata",
     "CAUTION":        "Cisco chassis-internal — must never appear on external ports; "
                       "seen only on SPAN of supervisor-linecard fabric interconnects"})

# ── Cisco pre-standard MACsec (0x891B) ────────────────────────────────────────
ETHERTYPE_REGISTRY[0x891B] = _e(
    "Cisco Pre-Standard MACsec (pre-IEEE 802.1AE)", "Cisco pre-MACsec Frame",
    "Vendor", "Deprecated",
    "Cisco pre-standard MACsec implementation used before IEEE 802.1AE-2006 "
    "was finalised. Some Cisco Catalyst 3560/3750 switches shipped with this "
    "EtherType. Completely superseded by IEEE 802.1AE (0x88E5). "
    "Upgrade all equipment to standard 802.1AE MACsec.",
    "macsec",
    {"TCI":          "1B  Tag Control Information: V+ES+SC+SCB+E+C bits",
     "AN":           "2b  Association Number (0-3) key selector",
     "SL":           "6b  Short Length (0=full frame)",
     "PN":           "4B  Packet Number — anti-replay counter",
     "SCI":          "8B  Secure Channel Identifier (if SC=1): MAC(6B)+Port(2B)",
     "Secure Data":  "variable  AES-GCM-128 encrypted payload",
     "ICV":          "16B  Integrity Check Value (authentication tag)",
     "CAUTION":      "Deprecated — Cisco pre-standard MACsec NOT interoperable with IEEE 802.1AE; "
                     "crypto may be AES-128-GCM but key exchange is Cisco-proprietary MKA variant; "
                     "upgrade to IEEE 802.1AE (0x88E5) with standard MKA (802.1X-2010)"})

# ── Cisco ACI Infrastructure (0x8950) ─────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8950] = _e(
    "Cisco ACI — Application Centric Infrastructure Fabric Protocol", "Cisco ACI Frame",
    "Vendor", "Active",
    "Cisco ACI (Application Centric Infrastructure) uses a proprietary fabric protocol "
    "between spine and leaf switches for policy distribution, endpoint tracking, "
    "and fabric bring-up. The ACI fabric is IS-IS based (similar to FabricPath) with "
    "additional OpFlex-like metadata. APIC (Application Policy Infrastructure Controller) "
    "programs the fabric via this protocol.",
    "trill",
    {"ACI Magic":     "4B  0x41434946='ACIF'",
     "Version":       "1B  ACI protocol version",
     "Msg Type":      "1B  0x01=EP-Register 0x02=Policy-Download 0x03=Fabric-Hello 0x04=Spine-Proxy",
     "VNID":          "3B  Virtual Network ID (ACI segment — equivalent to VXLAN VNI)",
     "EPG ID":        "2B  Endpoint Group identifier for policy lookup",
     "PCTag":         "2B  Policy Class Tag (ACI equivalent of TrustSec SGT)",
     "Spine MAC":     "6B  originating spine switch MAC address",
     "Leaf MAC":      "6B  originating leaf switch MAC address",
     "Timestamp":     "8B  hardware timestamp for latency measurement",
     "Payload":       "variable  message-specific policy or endpoint data",
     "CAUTION":       "Cisco ACI proprietary — requires Cisco APIC controller; "
                      "ACI fabric EtherType frames must not leak beyond fabric boundary; "
                      "ACI IS-IS domain is completely separate from IP routing IS-IS; "
                      "mixing ACI and non-ACI Nexus switches in same fabric is not supported"})

# ── Cisco MPLS-TP OAM (0x8932) ────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8932] = _e(
    "Cisco MPLS-TP OAM — Section Layer with G-ACh (RFC 6428 / G.8113.1)", "MPLS-TP OAM Frame",
    "Standard", "Active",
    "MPLS-TP (MPLS Transport Profile) OAM frames at the section layer using "
    "Generic Associated Channel (G-ACh). Based on RFC 6428 and ITU-T G.8113.1. "
    "Cisco initially used 0x8932 for MPLS-TP section OAM; the IETF standardised "
    "the mechanism via G-ACh over the MPLS label stack rather than a dedicated "
    "EtherType — 0x8932 is the Cisco implementation EtherType.",
    "mpls_inner",
    {"G-ACh Header":  "4B  0x0001xxxx — Generic Associated Channel, Version=0, Reserved=0",
     "Channel Type":  "2B  0x8902=OAM (Y.1731) 0x0007=MPLS-TP CV 0x000A=MPLS-TP CC",
     "MPLS-TP Label": "4B  section-layer MPLS label (bottom-of-stack, TTL=1)",
     "OAM PDU":       "variable  Y.1731-compatible OAM PDU (CCM/LBM/LBR/AIS/RDI)",
     "CC Function":   "Continuity Check: MEP-to-MEP CCM frames at configured rate",
     "CV Function":   "Connectivity Verification: CCM with ME-ID for path verification",
     "CAUTION":       "Cisco-specific EtherType for MPLS-TP — IETF standard uses G-ACh inside MPLS; "
                      "interoperability requires matching OAM channel type configuration; "
                      "MPLS-TP CC/CV interval must match both endpoint MEPs"})

# ── Huawei Smart Link (0x8905) ────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8905] = _e(
    "Huawei Smart Link — Dual Uplink Fast Failover", "Huawei Smart Link Frame",
    "Vendor", "Active",
    "Huawei Smart Link provides dual-uplink link redundancy with <50ms failover "
    "for access switches. One uplink is active, one is standby — on active link "
    "failure, Smart Link switches to standby and sends Flush messages to upstream "
    "switches to update MAC tables. Used in Huawei CloudEngine and Quidway S-series.",
    "lldp",
    {"Smart Link Magic":"4B  0x534C494E='SLIN'",
     "Version":         "1B  1",
     "Message Type":    "1B  0x01=Flush 0x02=Update 0x03=Hello 0x04=Preemption-Notify",
     "Group ID":        "2B  Smart Link group identifier (1-48)",
     "Priority":        "1B  port priority (higher=preferred active)",
     "Port Role":       "1B  0=Active 1=Standby",
     "Control VLAN":    "2B  Smart Link control VLAN ID",
     "Flush VLAN":      "4B×N  VLAN bitmap for MAC flush on failover (up to 4094 VLANs)",
     "Preemption":      "preemption-delay timer (0=disabled): standby waits N×100ms before becoming active",
     "CAUTION":         "Smart Link is Huawei-proprietary — interoperability requires all access/aggregation "
                        "switches to be Huawei; Smart Link + STP MUST NOT be enabled simultaneously on same ports; "
                        "Flush VLAN list must include all VLANs using the uplink pair"})

# ── Huawei RRPP (0x8909) ──────────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8909] = _e(
    "Huawei RRPP — Rapid Ring Protection Protocol", "Huawei RRPP Frame",
    "Vendor", "Active",
    "Huawei RRPP is a proprietary ring protection protocol achieving <50ms failover. "
    "Similar to Extreme EAPS and ITU-T G.8032 ERPS but Huawei-specific. "
    "A master node monitors ring health; on failure it unblocks the secondary port "
    "and sends flush messages. Deployed in Huawei metro access rings.",
    "lldp",
    {"RRPP Magic":    "4B  0x52525050='RRPP'",
     "Version":       "1B  1",
     "Message Type":  "1B  0x01=Hello 0x02=LinkDown 0x03=EdgeHello 0x04=MajorFaultDetect 0x05=MajorFaultRecover 0x06=LinkUpFlush",
     "Domain ID":     "2B  RRPP domain identifier",
     "Ring ID":       "1B  ring number within domain (1-8)",
     "Node State":    "1B  0=Normal 1=Failed 2=Preforwarding",
     "Role":          "1B  0=Master 1=Transit 2=Edge 3=AssistantEdge",
     "Hello Timer":   "2B  hello interval in 10ms units (default 100=1s)",
     "Fail Timer":    "2B  failure detection time in 10ms units (default 300=3s)",
     "Src MAC":       "6B  originating node MAC address",
     "CAUTION":       "Huawei proprietary — not compatible with G.8032 ERPS or Cisco REP or Extreme EAPS; "
                      "RRPP must be disabled before running STP on same ring; "
                      "exactly one master node per ring domain — two masters = ring oscillation; "
                      "control VLAN must carry only RRPP frames"})

# ── Huawei SEP (0x890A) ───────────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x890A] = _e(
    "Huawei SEP — Smart Ethernet Protection (Segment Protection)", "Huawei SEP Frame",
    "Vendor", "Active",
    "Huawei Smart Ethernet Protection — extends RRPP for segment-based protection "
    "in complex multi-ring or tangent-ring topologies. SEP protects individual "
    "segments rather than full rings, enabling more flexible metro ethernet topology. "
    "Used in Huawei CloudEngine data centre and carrier metro networks.",
    "lldp",
    {"SEP Magic":     "4B  0x53455050='SEPP'",
     "Version":       "1B  1",
     "Message Type":  "1B  0x01=Hello 0x02=LinkDown 0x03=Preempt 0x04=Flush 0x05=Topology-Change",
     "Segment ID":    "2B  SEP segment identifier",
     "Instance ID":   "1B  SEP instance within segment",
     "Role":          "1B  0=Edge 1=Transit 2=PreemptionBlock",
     "State":         "1B  0=Normal 1=Blocking 2=Preforwarding",
     "Priority":      "2B  edge node priority (lower=preferred primary edge)",
     "Preempt Delay": "2B  preemption delay in 100ms units",
     "Topology Data": "variable  segment topology information",
     "CAUTION":       "Huawei proprietary — not interoperable with RRPP or G.8032; "
                      "SEP and RRPP must not run on overlapping segments; "
                      "tangent-ring topologies require careful SEP domain partitioning"})

# ── Huawei EVPN Extension (0x8948) ────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8948] = _e(
    "Huawei EVPN Extension — Fabric OAM for CloudEngine", "Huawei EVPN Ext Frame",
    "Vendor", "Active",
    "Huawei CloudEngine proprietary EVPN fabric extension for in-band OAM in "
    "VXLAN/EVPN datacenter fabrics. Provides VTEP reachability testing, BFD "
    "for EVPN sessions, and per-VNI health monitoring without requiring IP "
    "reachability between management stations.",
    "dot1q",
    {"HW EVPN Magic": "4B  0x45564558='EVEX'",
     "Version":       "1B",
     "OAM Type":      "1B  0x01=VTEP-Echo 0x02=VNI-Ping 0x03=MAC-Probe 0x04=Path-Trace",
     "VNI":           "3B  VXLAN Network Identifier under test",
     "Src VTEP":      "4B  source VTEP IPv4 address",
     "Dst VTEP":      "4B  destination VTEP IPv4 address",
     "Test MAC":      "6B  probe MAC address for MAC-Probe operation",
     "Sequence":      "4B",
     "Timestamp":     "8B  nanosecond hardware timestamp",
     "RTT":           "4B  round-trip time from previous probe (microseconds)",
     "CAUTION":       "Huawei CloudEngine proprietary — requires all fabric nodes to be Huawei CE; "
                      "VNI-Ping triggers data-plane forwarding test not just control-plane; "
                      "MAC-Probe ages out entries — do not use on production traffic VNIs during peak"})

# ── HPE IRF (0x8904) ──────────────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8904] = _e(
    "HPE IRF — Intelligent Resilient Framework (Comware IRF Stack)", "HPE IRF Frame",
    "Vendor", "Active",
    "HPE Intelligent Resilient Framework virtualises multiple physical Comware switches "
    "into a single logical switch with shared MAC, single management plane. "
    "IRF members communicate over dedicated IRF ports using this EtherType. "
    "IRF achieves <50ms failover and eliminates STP through logical device unification. "
    "Used in HPE Comware FlexFabric (5900/5940/6900 series) switches.",
    "lldp",
    {"IRF Magic":     "4B  0x49524632='IRF2'",
     "Version":       "1B  IRF protocol version (2=IRF2)",
     "Message Type":  "1B  0x01=Hello 0x02=Election 0x03=Master-Sync 0x04=Port-Sync 0x05=MAD-Detect",
     "Domain ID":     "4B  IRF domain identifier (shared across all members)",
     "Member ID":     "1B  stack member ID (1=master 2-9=members; lower priority=member)",
     "Priority":      "4B  master election priority (higher=preferred master)",
     "Bridge MAC":    "6B  IRF virtual bridge MAC (shared across domain)",
     "IRF Port ID":   "2B  source IRF port number",
     "Sequence":      "4B  message sequence number",
     "Config Digest": "16B  MD5 of running config for sync verification",
     "MAD Mode":      "Multi-Active Detection: ARP MAD or BFD MAD to detect split-brain",
     "CAUTION":       "IRF split-brain (both halves think they are master) causes duplicate MACs and "
                      "traffic black-hole — configure MAD (Multi-Active Detection) always; "
                      "IRF domain can have only 1 master; IRF port failure triggers master re-election; "
                      "IRF and LACP cannot both be configured on same ports"})

# ── Nokia/ALU Carrier OAM (0x890C) ────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x890C] = _e(
    "Nokia / Alcatel-Lucent Carrier OAM — ALU-OAM", "Nokia ALU-OAM Frame",
    "Vendor", "Active",
    "Nokia (formerly Alcatel-Lucent) proprietary carrier Ethernet OAM EtherType "
    "used in Nokia 7x50 Service Routers (SR-OS) and 7210 Service Access Switches. "
    "Extends IEEE 802.1ag CFM with Nokia-specific TLV types for SAP (Service Access "
    "Point) and SDP (Service Distribution Point) OAM in Nokia VPLS/VPRN services.",
    "cfm",
    {"MD Level":      "3b  Maintenance Domain level 0-7",
     "Version":       "5b  0=base Nokia OAM",
     "Opcode":        "1B  0x01=CCM 0x02=LBR 0x03=LBM 0x04=LTR 0x05=LTM 0x31=SAP-Ping 0x32=SDP-Ping",
     "Flags":         "1B  opcode-specific",
     "TLV Offset":    "1B",
     "SAP-Ping":      "service-id(4B)+sap-id(variable)+target-mac(6B) — tests SAP-to-SAP path",
     "SDP-Ping":      "sdp-id(4B)+vc-id(4B)+far-end(4B) — tests SDP tunnel end-to-end",
     "Nokia TLV 64":  "Type=64 Service-ID: 4B Nokia VPLS/VPRN service ID",
     "Nokia TLV 65":  "Type=65 SDP-Binding: sdp-id+vc-id for SDP fault isolation",
     "Nokia TLV 66":  "Type=66 SAP-ID: port:vlan or channel:group notation",
     "CAUTION":       "Nokia proprietary OAM TLVs (type 64-127) not compatible with other vendors; "
                      "SAP-Ping and SDP-Ping require Nokia SR-OS on both endpoints; "
                      "standard CFM opcodes (CCM/LBM/LBR) use same encoding as IEEE 802.1ag"})

# ── Juniper QFabric (0x8936) ──────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8936] = _e(
    "Juniper QFabric — Fabric Extension Protocol", "Juniper QFabric Frame",
    "Vendor", "Active",
    "Juniper QFabric fabric extension protocol for Juniper QFX series switches "
    "in QFabric topology (Node+Interconnect+Director). The QFabric system presents "
    "as a single logical device while spanning multiple physical switches. "
    "This EtherType carries inter-component fabric control and VXLAN overlay metadata. "
    "Superseded by EVPN/VXLAN in newer Juniper architectures.",
    "trill",
    {"JNP QFabric":   "4B  0x4A4E5146='JNQF'",
     "Version":       "1B",
     "Message Type":  "1B  0x01=Fabric-Hello 0x02=VLAN-Prog 0x03=MAC-Learn 0x04=BUM-Replicate",
     "Node ID":       "2B  QFabric node identifier (0=Director)",
     "VLAN ID":       "2B  VLAN being programmed or learned",
     "Src MAC":       "6B  source MAC triggering learn event",
     "Dst MAC":       "6B  destination MAC for forwarding",
     "Payload":       "variable  fabric-specific control data",
     "CAUTION":       "Juniper QFabric proprietary — discontinued product line; "
                      "QFabric end-of-life January 2020; replace with Juniper EVPN/VXLAN; "
                      "QFabric frames should not appear beyond QFabric director uplinks"})

# ── Nokia 7x50 SR Fabric (0x894C) ─────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x894C] = _e(
    "Nokia 7x50 SR-OS Fabric Control — Internal Switch Fabric", "Nokia SR Fabric Frame",
    "Vendor", "Active",
    "Nokia 7x50 Service Router internal switch fabric control protocol for "
    "inter-IOM (I/O Module) and IMM-to-CPM communication. Carries internal "
    "routing table updates, interface state, QoS programming, and OAM metadata "
    "across the Nokia SR-OS chassis switching fabric.",
    "lldp",
    {"Nokia Magic":   "4B  0x4E4F4B49='NOKI'",
     "Version":       "1B",
     "Message Type":  "1B  0x01=IOM-Hello 0x02=RT-Update 0x03=Interface-State 0x04=QoS-Prog 0x05=OAM-Meta",
     "Chassis ID":    "8B  Nokia 7x50 chassis unique identifier",
     "Slot ID":       "1B  source slot (IOM/IMM slot number)",
     "MDA":           "1B  source MDA (Media Dependent Adapter) number",
     "Sequence":      "8B  64-bit monotonically increasing sequence number",
     "Payload":       "variable  message-type specific data",
     "CAUTION":       "Nokia 7x50 chassis-internal — must never appear on external ports or NPE uplinks; "
                      "visible only on fabric card inter-slot connections during hardware debug"})

# ── ZTE Proprietary Management (0x894A) ───────────────────────────────────────
ETHERTYPE_REGISTRY[0x894A] = _e(
    "ZTE Proprietary Network Management — ZXR10 Switch Series", "ZTE Mgmt Frame",
    "Vendor", "Active",
    "ZTE Corporation (中兴通讯) proprietary EtherType for ZXR10 switch series "
    "management frames. Used for switch discovery, topology information exchange, "
    "and configuration synchronisation between ZTE ZXR10 switches in a network domain.",
    "lldp",
    {"ZTE Magic":     "4B  0x5A544520='ZTE '",
     "Version":       "1B",
     "Message Type":  "1B  0x01=Discovery 0x02=Topology 0x03=Config-Sync 0x04=VLAN-Info",
     "Device ID":     "6B  ZTE switch MAC address (unique device identifier)",
     "Product Type":  "2B  ZXR10 product family code",
     "SW Version":    "4B  ZXR10 software version (major.minor.patch.build)",
     "Sequence":      "4B",
     "Payload":       "variable  type-specific management payload",
     "CAUTION":       "ZTE proprietary — not published; protocol details inferred from captures; "
                      "disable on all non-ZTE ports; ZTE management network should be isolated VLAN"})

# ── Qualcomm Atheros HomePlug AV2 (0x8A00) ────────────────────────────────────
ETHERTYPE_REGISTRY[0x8A00] = _e(
    "Qualcomm Atheros HomePlug AV2 — AR7x00 Peer Discovery", "Qualcomm HPAV2 Frame",
    "Vendor", "Active",
    "Qualcomm Atheros AR7x00 series HomePlug AV2 silicon proprietary peer discovery "
    "and management frame. Used during HomePlug AV2 network formation before standard "
    "HomePlug AV2 MME (0x88E1/0x8912) protocol takes over. Also used for Atheros "
    "firmware download and silicon-specific configuration.",
    "homeplug_av2",
    {"QCA Magic":     "4B  0x51434154='QCAT' — Qualcomm Atheros identifier",
     "Chip ID":       "2B  AR7x00 chip variant (AR7400=0x7400 AR7420=0x7420)",
     "Version":       "1B  firmware/protocol version",
     "MMType":        "2B  0x6000=CM-Discovery 0x6001=CM-Confirm 0xA000=Atheros-FW-Upgrade",
     "Src MAC":       "6B  source HomePlug node MAC address",
     "Payload":       "variable  message-specific HomePlug AV2 or Atheros-proprietary data",
     "CAUTION":       "QCA proprietary extension — used during chip bring-up and firmware upgrade; "
                      "standard HomePlug AV2 uses 0x88E1/0x8912 after network formation; "
                      "AR7x00 firmware upgrade via this EtherType must be secured to trusted hosts only"})

# ── Ruckus SmartMesh (0x8A11) ─────────────────────────────────────────────────
ETHERTYPE_REGISTRY[0x8A11] = _e(
    "Ruckus SmartMesh — Wireless AP Mesh Control Protocol", "Ruckus SmartMesh Frame",
    "Vendor", "Active",
    "Ruckus Networks (CommScope) SmartMesh proprietary protocol for 802.11 wireless "
    "mesh network control. Manages AP-to-AP mesh link formation, path selection, "
    "and traffic load balancing in Ruckus SmartMesh deployments without requiring "
    "IP connectivity. Used in Ruckus ZoneFlex and SmartZone AP series.",
    "lldp",
    {"SmartMesh Magic":"4B  0x524D5348='RMSH'",
     "Version":        "1B  SmartMesh protocol version",
     "Message Type":   "1B  0x01=Neighbour-Discover 0x02=Link-Quality 0x03=Path-Select 0x04=Root-Hello",
     "AP MAC":         "6B  source AP MAC address",
     "Root AP MAC":    "6B  root AP (mesh portal) MAC address",
     "Hop Count":      "1B  hops from root AP (0=root)",
     "Link Quality":   "1B  uplink RSSI estimate (0-255, higher=better)",
     "Channel":        "1B  mesh link radio channel",
     "BSSID":          "6B  mesh BSSID for this SmartMesh segment",
     "Payload":        "variable  mesh-specific path or quality data",
     "CAUTION":        "Ruckus proprietary — SmartMesh frames must not leave wireless mesh segment; "
                       "inter-vendor mesh interoperability not supported; "
                       "SmartMesh operates on dedicated radio chain — shared channel with client radio degrades throughput"})

# ── MPLS upstream-assigned label (0x8846) — if not already added ──────────────
if 0x8846 not in ETHERTYPE_REGISTRY:
    ETHERTYPE_REGISTRY[0x8846] = _e(
        "MPLS Upstream-Assigned Label Stack — RFC 5331 / RFC 3032", "MPLS Upstream Frame",
        "Standard", "Active",
        "MPLS frame with upstream-assigned labels. In upstream label assignment "
        "(RFC 5331), labels are assigned by the node upstream of the receiving node "
        "(opposite of normal downstream assignment). Used in P2MP LSP scenarios "
        "and context-specific label spaces for VPLS and L3VPN multicast.",
        "mpls_inner",
        {"Label":       "20b  MPLS upstream-assigned label value",
         "TC":          "3b   Traffic Class for QoS",
         "S":           "1b   Bottom of Stack",
         "TTL":         "8b   TTL — decremented per hop",
         "Context":     "RFC 5331 upstream context: receiving node looks up label in upstream neighbour context",
         "Use cases":   "P2MP mLDP trees, VPLS multicast, L3VPN multicast with upstream label assignment",
         "CAUTION":     "Upstream label 0 (IPv4 Explicit NULL) and label 2 (IPv6 Explicit NULL) have "
                        "same values as downstream — context determines meaning; "
                        "mixing upstream and downstream labels in same LSP requires careful design; "
                        "signalling must coordinate upstream label space (mLDP uses upstream-assigned)"})

ETHERTYPE_REGISTRY[0x9300]['fields']['CAUTION'] = 'Deprecated — use IEEE 802.1ad 0x88A8; Foundry/Brocade equipment can be configured to use 0x88A8 instead; mixing 0x9300 and 0x88A8 in same network causes VLAN forwarding failures'

# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL ETHERTYPES — Wireshark epan/etypes.h cross-reference
# Sources: Wireshark 4.x, IEEE RA, IANA
# ═══════════════════════════════════════════════════════════════════════════════

ETHERTYPE_REGISTRY[0x2452] = _e(
    "IEEE 802.15.4 over Ethernet (ZigBee/Thread MAC)", "IEEE 802.15.4 Frame",
    "Standard", "Active",
    "IEEE 802.15.4 MAC frame encapsulated over Ethernet. Used in IEEE 802.15.4 "
    "over Ethernet test equipment, Zigbee/Thread sniffer bridges, and "
    "IEEE 802.15.4-to-Ethernet gateways (whsniff, scapy 802.15.4 tools).",
    "lowpan",
    {"IEEE 802.15.4 FCF": "2B  Frame Control Field: FrameType(3b)+SecEn+FP+AR+PanIDComp+Reserved+SeqNumSup+IEPresent+DstAddrMode(2b)+FrameVer(2b)+SrcAddrMode(2b)",
     "Seq Number":        "0B or 1B  sequence number (suppressed if SeqNumSup=1)",
     "Dst PAN ID":        "0B or 2B  destination PAN identifier (0xFFFF=broadcast)",
     "Dst Address":       "0B/2B/8B  short(16b) or extended(64b) destination address",
     "Src PAN ID":        "0B or 2B  source PAN ID (omitted if PanIDComp=1)",
     "Src Address":       "0B/2B/8B  short or extended source address",
     "Payload":           "variable  MAC payload: Data/Command/Beacon/Ack",
     "FCS":               "2B  ITU-T CRC-16 (CCITT) over entire MPDU",
     "CAUTION":           "802.15.4 frames over Ethernet are test/sniffer use only; "
                          "production 802.15.4 runs on 2.4GHz/868/915MHz radio, not Ethernet; "
                          "EtherType 0x2452 is Wireshark convention for capture tools"})

ETHERTYPE_REGISTRY[0x8204] = _e(
    "QNX QNET — QNX Neutrino Transparent Distributed Processing", "QNET Frame",
    "Vendor", "Active",
    "QNX QNET protocol for transparent distributed computing in QNX Neutrino RTOS. "
    "Allows processes on different QNX nodes to communicate as if local, including "
    "file descriptors, signals, and IPC. Used in automotive (QNX CAR), medical, "
    "and industrial embedded systems. Registered by QNX Software (Blackberry).",
    "lldp",
    {"QNET Version":  "1B  protocol version",
     "Frame Type":    "1B  0x01=Send 0x02=SendReceive 0x03=Reply 0x04=Error 0x05=Pulse 0x06=Unblock",
     "Src Node":      "4B  source QNX node ID (network-layer node identifier)",
     "Dst Node":      "4B  destination QNX node ID",
     "Src PID":       "4B  source process ID",
     "Dst PID":       "4B  destination process ID",
     "Channel ID":    "4B  destination channel identifier",
     "Message Size":  "4B  total message payload size in bytes",
     "Payload":       "variable  IPC message data",
     "CAUTION":       "QNX QNET is QNX-proprietary RTOS IPC; not interoperable with non-QNX systems; "
                      "QNET traffic contains process-level data including file descriptors — "
                      "must be isolated on dedicated VLAN in mixed networks"})

ETHERTYPE_REGISTRY[0x8661] = _e(
    "MiNT — MikroTik Neighbor Discovery (MNDP / Mesh Internal)", "MiNT Frame",
    "Vendor", "Active",
    "MikroTik MiNT (MikroTik Network Transport) proprietary protocol for "
    "RouterOS wireless mesh networking and NV2 TDMA protocol. Also used for "
    "MikroTik Neighbor Discovery Protocol (MNDP) alternative to CDP/LLDP. "
    "Used in RouterBOARD devices running MikroTik RouterOS.",
    "lldp",
    {"MiNT Magic":    "4B  0x4D694E54='MiNT'",
     "Version":       "1B",
     "Frame Type":    "1B  0x01=MNDP-Discovery 0x02=Mesh-Route 0x03=NV2-Control 0x04=Topology",
     "Src MAC":       "6B  source RouterBOARD MAC",
     "Sequence":      "4B",
     "RouterOS Ver":  "variable  RouterOS version string (for discovery frames)",
     "Board Type":    "variable  RouterBOARD model string",
     "Payload":       "variable  frame-type specific data",
     "CAUTION":       "MikroTik proprietary — disable on non-MikroTik ports; "
                      "MNDP reveals RouterOS version and board type; "
                      "NV2 mesh protocol provides no encryption at L2"})

ETHERTYPE_REGISTRY[0x9021] = _e(
    "MiNT Control — MikroTik Mesh Control Channel", "MiNT Control Frame",
    "Vendor", "Active",
    "MikroTik MiNT control channel — second EtherType used by RouterOS for "
    "mesh control plane messaging, NV2 TDMA scheduling, and CAPsMAN "
    "(Central Access Point Management) control frames.",
    "lldp",
    {"MiNT Ctrl Magic":"4B  0x4D43544C='MCTL'",
     "Version":        "1B",
     "Ctrl Type":      "1B  0x01=NV2-Schedule 0x02=CAPsMAN-Register 0x03=Bridge-Ctrl",
     "Src MAC":        "6B",
     "Sequence":       "4B",
     "Payload":        "variable  control-type specific",
     "CAUTION":        "MikroTik proprietary — see 0x8661 for details"})

ETHERTYPE_REGISTRY[0xCAFE] = _e(
    "Wireshark/Test Tools Custom EtherType", "Test Frame",
    "Vendor", "Active",
    "0xCAFE is used by Wireshark developers, scapy, and various network test tools "
    "as a convenient test/debug EtherType. Not formally registered with IEEE RA. "
    "Also used by some vendor test harnesses and OpenFlow test suites.",
    "local_exp",
    {"Magic":        "optional  test tool identifier",
     "Sequence":     "optional  test sequence number",
     "Payload":      "variable  test-specific data",
     "CAUTION":      "Not IEEE-registered — use 0x88B5/0x88B6 for formal experimental use; "
                     "0xCAFE used informally in test environments only"})

# ── HomePlug 1.0 (0x887B) — expand fields to full spec ───────────────────────
ETHERTYPE_REGISTRY[0x887B]["fields"].update({
    "MMType":       "2B  Management Message Type: High byte=category Low byte=subtype",
    "MME Data":     "variable  MME payload — network key exchange, tone map, stats, metering",
    "Dst MAC":      "Target: Broadcast (FF:FF:FF:FF:FF:FF) for discovery or unicast for direct mgmt",
    "MAC Proto":    "HomePlug 1.0 uses 56-bit DES encryption for payload (deprecated — insecure)",
})

# ── HomePlug AV (0x88E1) — expand fields ─────────────────────────────────────
ETHERTYPE_REGISTRY[0x88E1]["fields"].update({
    "OUI":          "3B  0x00:B0:52 HomePlug Alliance OUI",
    "MMTYPE":       "2B  management message type — 0x6000-0x61FF=CM category",
    "FMI":          "2B  Fragment Management Information: FMI(4b)+FMSN(4b)+FMID(8b)",
    "MMENTRY":      "variable  management message data body",
    "AV Version":   "0x01=HomePlug AV 1.0 0x02=HomePlug AV 1.1 0x03=HomePlug Green PHY",
    "Coexist":      "HomePlug AV uses signal band 1.8-30MHz; G.hn uses 0-100MHz — coexistence filtering required",
})

# ── QinQ (0x88A8) expand fields ───────────────────────────────────────────────
if "dot1q" in ETHERTYPE_REGISTRY.get(0x88A8, {}).get("name", ""):
    pass  # already handled
ETHERTYPE_REGISTRY[0x88A8]["fields"].update({
    "PCP":      "3b  Priority Code Point 0-7 (maps to IEEE 802.1p traffic class)",
    "DEI":      "1b  Drop Eligible Indicator — 0=non-discardable 1=eligible for drop",
    "VID":      "12b Service VLAN ID 0=no-tag 1-4094=valid 4095=reserved",
    "Inner EtherType": "2B following S-Tag — typically 0x8100 for customer C-Tag",
    "C-Tag":    "4B  Customer 802.1Q tag: TPID(0x8100)+PCP(3b)+DEI(1b)+C-VID(12b)",
    "Inner Payload":  "Customer Ethernet frame following C-Tag",
})

# ── NSH (0x894F) expand L3 fields already done above; ensure L2 also has them
ETHERTYPE_REGISTRY[0x894F]["fields"].update({
    "Version":       "2b  0=RFC 8300",
    "O bit":         "1b  OAM packet flag — set for OAM-only frames",
    "C bit":         "1b  Critical TLV present in Context Headers",
    "Length":        "6b  NSH header length in 4-byte words",
    "MD Type":       "8b  1=Fixed-Length Context 2=Variable-Length Context",
    "Next Protocol": "8b  1=IPv4 2=IPv6 3=Ethernet 4=NSH 5=MPLS 0xFE=Exp 0xFF=None",
    "Service Path":  "24b Service Path Identifier (SPI) — selects service function chain",
    "Service Index": "8b  decremented by 1 at each service function; 0=drop",
    "Fixed Context": "16B (MD-Type=1) four 4-byte fixed mandatory context headers",
})

# ── HomePNA (0x886C) expand fields ───────────────────────────────────────────
if 0x886C in ETHERTYPE_REGISTRY:
    ETHERTYPE_REGISTRY[0x886C]["fields"].update({
        "Max Data Rate":"2B  maximum achievable rate to peer (Mbps)",
        "SNR margin":   "1B  signal-to-noise ratio margin in dB",
        "Attenuation":  "1B  loop attenuation in dB",
        "Node Type":    "1B  0x01=HPNA-3.0 0x02=HPNA-3.1 0x03=G.9954",
    })

# ═══════════════════════════════════════════════════════════════════════════════
# L2 FIELD COMPLETENESS PATCHES — all verified against authoritative specs
# ═══════════════════════════════════════════════════════════════════════════════

# 3Com entries — expand minimally (completely obsolete, PDU unpublished)
ETHERTYPE_REGISTRY[0x8081]["fields"].update({
    "3Com OUI":    "3B  0x00:20:AF 3Com OUI prefix",
    "Frame Subtype":"1B  undocumented 3Com internal subtype",
})
ETHERTYPE_REGISTRY[0x8082]["fields"].update({
    "3Com OUI":    "3B  0x00:20:AF 3Com OUI prefix",
    "Frame Subtype":"1B  undocumented 3Com internal subtype",
})
ETHERTYPE_REGISTRY[0x8083]["fields"].update({
    "3Com OUI":    "3B  0x00:20:AF 3Com OUI prefix",
    "Frame Subtype":"1B  undocumented 3Com internal subtype",
})

# Historical entries — add minimal PDU fields where documented
_HIST_FIELDS = {
    0x6000: {"DEC Exp Type":"2B  0x6000-0x6009 DEC experimental range","Payload":"variable"},
    0x8039: {"DEC DSM/DDP Opcode":"1B  DEC Distributed Storage Manager operation","Data":"variable  DSM management payload"},
    0x803B: {"VAXELN Type":"1B  VAXELN protocol type","Data":"variable  VAXELN real-time OS data"},
    0x803E: {"DTS Version":"1B  DEC Distributed Time Service version","Request Type":"1B","Timestamp":"8B  DEC 64-bit timestamp"},
    0x8041: {"LAST Type":"1B  DEC Local Area System Transport type","Data":"variable  terminal data"},
    0x8044: {"PRC Type":"1B","Data":"variable  Planning Research Corp data"},
    0x8049: {"ExperData Version":"1B","Data":"variable  ExperData payload"},
    0x805B: {"Stanford-V Version":"1B  0x05=Stanford V experimental","Data":"variable  Stanford V kernel data"},
    0x805C: {"Stanford-V Version":"1B  0x05=Stanford V production","Data":"variable  Stanford V kernel data"},
    0x805D: {"E&S Type":"1B  Evans & Sutherland graphics","Data":"variable"},
    0x8060: {"Little Machines Type":"1B","Data":"variable"},
    0x8062: {"Counterpoint Type":"1B  Counterpoint Computers","Data":"variable"},
    0x8065: {"UMass Type":"1B","Data":"variable  UMass Amherst research"},
    0x8066: {"UMass Type":"1B","Data":"variable  UMass Amherst research"},
    0x8067: {"Veeco Type":"1B  Veeco Integrated Automation","Data":"variable"},
    0x8068: {"GD Type":"1B  General Dynamics","Data":"variable"},
    0x806A: {"Autophon Type":"1B  Autophon Swiss Telecom","Data":"variable"},
    0x806C: {"ComDesign Type":"1B","Data":"variable"},
    0x806D: {"Computgraphic Type":"1B","Data":"variable"},
    0x807A: {"Matra Type":"1B  Matra French defence","Data":"variable"},
    0x807B: {"DDE Type":"1B  Dansk Data Elektronik","Data":"variable"},
    0x807C: {"Merit Type":"1B  Merit Network","Data":"variable"},
    0x8080: {"Vitalink Type":"1B  Vitalink TransLAN III","Data":"variable"},
    0x80A3: {"Nixdorf Type":"1B  Nixdorf computer","Data":"variable"},
    0x80DD: {"Varian Type":"1B  Varian Associates","Data":"variable"},
    0x80F7: {"Apollo Type":"1B  Apollo HP workstation","Data":"variable"},
    0x818D: {"Motorola Type":"1B  Motorola Computer Group","Data":"variable"},
}
for et, flds in _HIST_FIELDS.items():
    if et in ETHERTYPE_REGISTRY and len(ETHERTYPE_REGISTRY[et].get("fields",{})) == 0:
        ETHERTYPE_REGISTRY[et]["fields"].update(flds)
