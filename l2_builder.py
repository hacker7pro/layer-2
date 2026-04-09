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
    0x0800: _e("IPv4", "IPv4 Packet", "Standard", "Active",
               "Internet Protocol version 4", "ipv4",
               {"Dst MAC":"6B","Src MAC":"6B","EtherType":"0x0800",
                "Payload":"IPv4 datagram","FCS":"CRC-32 4B"}),

    0x0806: _e("ARP", "ARP Frame", "Standard", "Active",
               "Address Resolution Protocol — maps IP to MAC", "arp",
               {"HW Type":"2B 1=Eth","Proto":"2B 0x0800","HW Len":"1B=6",
                "Proto Len":"1B=4","Op":"2B 1=Req 2=Rep",
                "Sender MAC":"6B","Sender IP":"4B","Target MAC":"6B","Target IP":"4B"}),

    0x0808: _e("Frame Relay ARP", "RAW", "Standard", "Deprecated",
               "Frame Relay ARP — RFC 826 extension", None, {}),

    0x86DD: _e("IPv6", "IPv6 Packet", "Standard", "Active",
               "Internet Protocol version 6", "ipv6",
               {"Ver":"4b=6","TC":"8b DSCP+ECN","Flow":"20b",
                "Payload Len":"2B","Next Hdr":"1B","Hop Limit":"1B",
                "Src":"16B","Dst":"16B"}),

    0x8035: _e("RARP", "RARP Frame", "Standard", "Deprecated",
               "Reverse ARP — maps MAC to IP (replaced by DHCP)", "rarp",
               {"Note":"Same structure as ARP, Op=3=RARP-Req 4=RARP-Rep"}),

    0x0842: _e("Wake-on-LAN", "WoL Magic Packet", "Industry", "Active",
               "Remote power-on via magic packet", None,
               {"Magic":"FF×6 + target MAC×16"}),

    # ── GROUP 2: VLAN / Stacking / Bridging ──────────────────────────────────
    0x8100: _e("IEEE 802.1Q C-Tag (Customer VLAN)", "VLAN Tagged Frame",
               "Standard", "Active",
               "Customer VLAN tag — PCP+DEI+VID (802.1Q)", None,
               {"TPID":"2B 0x8100","PCP":"3b CoS 0-7",
                "DEI":"1b drop-eligible","VID":"12b VLAN ID 0-4094",
                "Inner EtherType":"2B next protocol"}),

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

    0x88B5: _e("IEEE 802 Local Experimental EtherType (1)", "RAW",
               "Standard", "Experimental",
               "Reserved for local/experimental 802 use (RFC 9542 §3)", None, {}),

    0x88B6: _e("IEEE 802 Local Experimental EtherType (2)", "RAW",
               "Standard", "Experimental",
               "Reserved for local/experimental 802 use (RFC 9542 §3)", None, {}),

    0x88B7: _e("IEEE 802 OUI-Extended EtherType", "OUI-Extended Frame",
               "Standard", "Active",
               "OUI-extended EtherType — 3B OUI + 2B sub-protocol",
               "oui_ext",
               {"OUI":           "3B  Organisation Unique Identifier (e.g. 00:12:0F = Cisco)",
                "Ext EtherType": "2B  sub-protocol under that OUI",
                "Payload":       "variable  OUI-specific frame content",
                "CAUTION":       "OUI must be your registered IEEE OUI — misuse = protocol conflict"}),

    0x890D: _e("IEEE 802.11r / TDLS (Fast Roaming / Tunneled Direct Link)", "RAW",
               "Standard", "Active",
               "802.11r fast BSS transition and 802.11z TDLS", None, {}),

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

    0x876C: _e("IP Autonomous Systems", "RAW",
               "Standard", "Active", "IP AS routing protocol (RFC 1701)", None, {}),

    0x876D: _e("Secure Data", "RAW",
               "Standard", "Active", "Secure data framing (RFC 1701)", None, {}),

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

    0x8870: _e("Jumbo Frame EtherType (proposed/defunct)", "RAW",
               "Industry", "Deprecated",
               "Proposed to disambiguate jumbo frame length — rejected by IEEE 802.3", None,
               {"Note":"Never standardised; length field collision with EtherType range"}),

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
    0x8892: _e("PROFINET RT (IEC 61158)", "PROFINET Frame",
               "Industry", "Active",
               "PROFINET Real-Time — industrial automation (Siemens/PI-North America)", None,
               {"EtherType":"0x8892",
                "Frame ID":"2B 0x0001-BFFF=RT-CLASS1/2 0xC000-FBFF=RTC3 0xFC00-FEFF=Alarm 0xFF01=DCP",
                "Status":"2B — DataStatus+TransferStatus",
                "Cycle Counter":"2B","Payload":"IO process data bytes",
                "Note":"Bypasses TCP/IP entirely — <1ms cycle typical; PROFINET IRT <0.25ms"}),

    0x88A4: _e("EtherCAT (Ethernet for Control Automation Technology)", "EtherCAT Frame",
               "Industry", "Active",
               "EtherCAT — Beckhoff ultra-fast fieldbus (<100µs), IEC 61158-12", None,
               {"Reserved":"2b","Length":"11b total PDU chain length","Type":"3b 1=EtherCAT",
                "EtherCAT PDU Chain":"sub-PDUs each: Cmd+Idx+Addr(4B)+Len(11b)+IRQ+Data+WKC(2B)",
                "Cmd":"1B NOP=0 APRD=1 APWR=2 FPRD=4 FPWR=5 BRD=7 BWR=8 LRW=14",
                "WKC":"Working Counter — incremented by each matched slave",
                "Note":"All slaves processed in single frame traversal — on-the-fly insertion"}),

    0x88AB: _e("Ethernet POWERLINK (EPSG)", "POWERLINK Frame",
               "Industry", "Active",
               "Ethernet POWERLINK — open real-time protocol for motion control", None,
               {"Msg Type":"1B SoC=0x01 PReq=0x03 PRes=0x03 SoA=0x05 ASnd=0x06",
                "Dst Node":"1B 0xFF=broadcast","Src Node":"1B",
                "SoC":"start of cycle — BeginSyncOffset(4B) SyncModeFlags(1B)",
                "PRes":"poll response — contains process output data",
                "Note":"Slot communication with managing node — open standard EPSG DS 301"}),

    0x88B8: _e("GOOSE — IEC 61850-8-1 Generic Object Oriented Substation Event", "GOOSE PDU",
               "Industry", "Active",
               "IEC 61850 GOOSE — fast L2 multicast <4ms substation protection", None,
               {"APPID":"2B 0x0000-3FFF application identifier",
                "Length":"2B total PDU length","Reserved1":"2B","Reserved2":"2B",
                "ASN.1 BER":"goID+datSet+t+stNum+sqNum+timeAllowedToLive+simulation+ndsCom+numDatSetEntries+allData",
                "Note":"No authentication — IEC 62351-6 adds HMAC security"}),

    0x88B9: _e("GSE Management Services — IEC 61850-8-1", "GSE Management PDU",
               "Industry", "Active",
               "GOOSE/GSSE management (Enter/Leave-Group) services — IEC 61850", None,
               {"Note":"Control messages for GOOSE/GSSE group membership management"}),

    0x88BA: _e("SV / SMV — IEC 61850-9-1/9-2 Sampled Values", "Sampled Values PDU",
               "Industry", "Active",
               "Streaming instrument transformer measurements — power grid protection", None,
               {"APPID":"2B","Length":"2B",
                "ASN.1 BER":"savPdu smpCnt confRev smpSynch smpRate dataset entries",
                "Rates":"80 samples/cycle (4kHz 50Hz grid) or 256/cycle (12.8kHz)",
                "Note":"Synchronized via IEEE 1588 PTP — IEC 61869-9 extended version"}),

    0x88CD: _e("SERCOS III (Serial Real-time COmmunication System)", "SERCOS Frame",
               "Industry", "Active",
               "SERCOS III — motion control open real-time (IEC 61784-2-14)", None,
               {"Frame Type":"1B HP-Telegram=0x01 CP-Telegram=0x11 AT=0x02 MDT=0x12",
                "Topology":"Ring — primary and secondary channel",
                "Note":"Sub-1ms cycle, nanometer precision — open SERCOS Int'l standard"}),

    0x890F: _e("CC-Link IE (Control & Communication Link Industrial Ethernet)", "CC-Link IE Frame",
               "Industry", "Active",
               "Mitsubishi CC-Link IE — 1Gbps industrial fieldbus (ring topology)", None,
               {"Payload":"CC-Link IE protocol PDU",
                "Note":"Mitsubishi proprietary — token-passing ring, 0.5-1ms cycle time"}),

    0x88DC: _e("WSMP (WAVE Short Message Protocol — IEEE 802.11p)", "WSMP Frame",
               "Industry", "Active",
               "V2X / DSRC vehicle-to-everything short message protocol", None,
               {"Version":"4b=3","PSID":"variable Provider Service ID",
                "Channel Interval":"1B","Data Rate":"1B","Tx Power":"1B",
                "WSM Data":"variable application payload",
                "Note":"Used in intelligent transportation — ETSI ITS-G5 / DSRC"}),

    0x8819: _e("CobraNet (Cirrus Logic audio-over-Ethernet)", "CobraNet Frame",
               "Industry", "Active",
               "Professional audio distribution — 256 channels 48kHz/24-bit", None,
               {"Sub-Type":"Beat/Bundle audio or management",
                "Note":"100Mbps Ethernet, <1ms latency — Cirrus Logic proprietary"}),

    0x887B: _e("HomePlug 1.0 MME (Management Message Entry)", "HomePlug Frame",
               "Industry", "Active",
               "HomePlug 1.0 powerline networking management", None,
               {"MME Type":"2B","MME Data":"variable"}),

    0x88E1: _e("HomePlug AV / Green PHY", "HomePlug AV Frame",
               "Industry", "Active",
               "HomePlug AV powerline — smart grid, EV charging (ISO 15118)", None,
               {"MMType":"2B","Fragment":"fragmentation info",
                "Payload":"management message"}),

    0x8912: _e("HomePlug AV2 / MME Extended", "HomePlug AV2 Frame",
               "Industry", "Active",
               "HomePlug AV2 MIMO powerline — EV charging, smart grid, home networking", None,
               {"MMType":"2B Management Message Type (MME type code)","FMI":"2B fragment/sequence: FMI(4b)+FMSN(4b)+FMID(8b)","MMENTRY":"variable payload — AV2 station capabilities/beacons/link stats","CAUTION":"HomePlug AV2 uses powerline — no physical port isolation; all devices on same electrical circuit share traffic"}),

    0x8200: _e("BACnet/Ethernet (ASHRAE 135, Annex H)", "BACnet Frame",
               "Industry", "Active",
               "BACnet building automation directly over Ethernet", None,
               {"Length":"2B","DSAP":"1B=0x82","SSAP":"1B=0x82","Control":"1B=0x03",
                "NPDU":"Network PDU — version hopcount dest src",
                "APDU":"ConfirmedReq UnconfirmedReq ComplexAck SimpleAck Error Reject Abort"}),

    # ── GROUP 10: AT&T Private ────────────────────────────────────────────────
    0x8008: _e("AT&T / Stanford University Local Use", "RAW",
               "Private", "Legacy",
               "AT&T/Stanford local-use private EtherType (IANA Neil Sembower)", None, {}),

    0x8046: _e("AT&T Private (assignment 1)", "RAW",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    0x8047: _e("AT&T Private (assignment 2)", "RAW",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    0x8069: _e("AT&T Private (assignment 3)", "RAW",
               "Private", "Legacy",
               "AT&T private EtherType — purpose undocumented", None, {}),

    # ── GROUP 11: DEC (Digital Equipment Corporation) ────────────────────────
    0x6000: _e("DEC Unassigned / Experimental", "RAW",
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

    0x8039: _e("DEC DSM/DDP (Distributed Storage Manager)", "RAW",
               "Historical", "Legacy", "DEC DSM/DDP over Ethernet", None, {}),

    0x803A: _e("DEC Argonaut Console", "RAW",
               "Historical", "Legacy", "DEC Argonaut graphics workstation console", None, {}),

    0x803B: _e("DEC VAXELN (Real-Time OS)", "RAW",
               "Historical", "Legacy",
               "DEC VAXELN hard real-time OS network protocol", None, {}),

    0x803C: _e("DEC DNS Naming Service", "RAW",
               "Historical", "Legacy",
               "DEC DNS DECdns distributed naming protocol", None, {}),

    0x803D: _e("DEC Ethernet Encryption", "Encrypted Frame",
               "Historical", "Legacy",
               "DEC link-layer encryption (predecessor to MACsec)", None,
               {"Key ID":"2B encryption key identifier","IV":"8B init vector","Ciphertext":"variable DES-encrypted payload","CAUTION":"DES-based deprecated — treat payload as opaque"}),

    0x803E: _e("DEC Distributed Time Service (DTS)", "RAW",
               "Historical", "Legacy",
               "DEC DTS time synchronisation — predecessor to NTP/PTP", None, {}),

    0x803F: _e("DEC LAN Traffic Monitor", "RAW",
               "Historical", "Legacy",
               "DEC LAN Traffic Monitor — network management probe", None, {}),

    0x8040: _e("DEC PATHWORKS / NetBIOS Emulation", "RAW",
               "Historical", "Legacy",
               "DEC PATHWORKS DECnet NetBIOS Emulation layer", None, {}),

    0x8041: _e("DEC LAST (Local Area System Transport)", "RAW",
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

    0x8015: _e("SGI Reserved", "RAW",
               "Historical", "Legacy",
               "Silicon Graphics reserved EtherType — purpose undocumented", None, {}),

    0x8016: _e("SGI XNS NameServer / Bounce Server", "RAW",
               "Historical", "Legacy",
               "Silicon Graphics XNS NameServer and bounce server", None, {}),

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

    0x80C4: _e("Banyan Systems Private (1)", "RAW",
               "Historical", "Legacy", "Banyan Systems private protocol slot 1", None, {}),

    0x80C5: _e("Banyan Systems Private (2)", "RAW",
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

    0x8888: _e("HP LanProbe Test", "RAW",
               "Historical", "Legacy", "HP LanProbe test/diagnostic protocol", None, {}),

    # ── GROUP 20: Apollo / Various Workstation Vendors ────────────────────────
    0x8019: _e("Apollo Domain (HP Apollo)", "Apollo Domain Frame",
               "Historical", "Legacy",
               "Apollo Domain OS network protocol — later HP Apollo workstations", None,
               {"Msg Type":"2B 0x0001=RPC-call","Src UID":"8B Apollo UID","Dst UID":"8B","Seq":"4B","Data":"variable NCS payload"}),

    0x8044: _e("Planning Research Corporation", "RAW",
               "Historical", "Legacy", "Planning Research Corp. private EtherType", None, {}),

    0x802E: _e("Tymshare", "RAW",
               "Historical", "Legacy", "Tymshare timesharing service network protocol", None, {}),

    0x802F: _e("Tigan Inc.", "RAW",
               "Historical", "Legacy", "Tigan Inc. private protocol", None, {}),

    0x8036: _e("Aeonic Systems", "RAW",
               "Historical", "Legacy", "Aeonic Systems private protocol", None, {}),

    0x8049: _e("ExperData", "RAW",
               "Historical", "Legacy", "ExperData private EtherType", None, {}),

    0x805B: _e("Stanford V Kernel (Experimental)", "RAW",
               "Historical", "Legacy",
               "Stanford V distributed OS kernel — experimental network", None, {}),

    0x805C: _e("Stanford V Kernel (Production)", "RAW",
               "Historical", "Legacy",
               "Stanford V distributed OS kernel — production network", None, {}),

    0x805D: _e("Evans & Sutherland", "RAW",
               "Historical", "Legacy",
               "Evans & Sutherland 3D graphics workstation protocol", None, {}),

    0x8060: _e("Little Machines", "RAW",
               "Historical", "Legacy", "Little Machines private EtherType", None, {}),

    0x8062: _e("Counterpoint Computers", "RAW",
               "Historical", "Legacy",
               "Counterpoint Computers private protocol", None, {}),

    0x8065: _e("University of Massachusetts Amherst (1)", "RAW",
               "Historical", "Legacy",
               "UMass Amherst research network protocol (1)", None, {}),

    0x8066: _e("University of Massachusetts Amherst (2)", "RAW",
               "Historical", "Legacy",
               "UMass Amherst research network protocol (2)", None, {}),

    0x8067: _e("Veeco Integrated Automation", "RAW",
               "Historical", "Legacy",
               "Veeco Integrated Automation — scientific instruments", None, {}),

    0x8068: _e("General Dynamics", "RAW",
               "Historical", "Legacy",
               "General Dynamics defence/aerospace private protocol", None, {}),

    0x806A: _e("Autophon (Swiss Telecom)", "RAW",
               "Historical", "Legacy",
               "Autophon Swiss telephone equipment manufacturer protocol", None, {}),

    0x806C: _e("ComDesign", "RAW",
               "Historical", "Legacy", "ComDesign private protocol", None, {}),

    0x806D: _e("Computgraphic Corporation", "RAW",
               "Historical", "Legacy",
               "Computgraphic typesetting systems private protocol", None, {}),

    0x807A: _e("Matra (French defence electronics)", "RAW",
               "Historical", "Legacy",
               "Matra SA (French defence/aerospace) private protocol", None, {}),

    0x807B: _e("Dansk Data Elektronik", "RAW",
               "Historical", "Legacy",
               "Dansk Data Elektronik (Danish IT) private protocol", None, {}),

    0x807C: _e("Merit Internodal (Merit Network)", "RAW",
               "Historical", "Legacy",
               "Merit Network (Michigan) internodal routing protocol", None, {}),

    0x8080: _e("Vitalink TransLAN III", "RAW",
               "Historical", "Legacy",
               "Vitalink Communications TransLAN III bridge protocol", None, {}),

    0x80A3: _e("Nixdorf Computers", "RAW",
               "Historical", "Legacy",
               "Nixdorf Computer AG private protocol", None, {}),

    0x817D: _e("XTP (Xpress Transport Protocol)", "XTP Frame",
               "Historical", "Deprecated",
               "XTP transport protocol — combined transport+network (research)", None,
               {"Note":"XTP was an alternative to TCP — never deployed commercially"}),

    0x8180: _e("HIPPI-FP Encapsulation (High-Performance Parallel Interface)", "HIPPI-FP Frame",
               "Historical", "Legacy",
               "HIPPI-FP 800Mbps/1.6Gbps supercomputer interconnect framing", None,
               {"Note":"Precursor to InfiniBand — used in 1990s HPC/supercomputers"}),

    0x818D: _e("Motorola Computer Group", "RAW",
               "Historical", "Legacy",
               "Motorola Computer Group (68000-based workstations) private", None, {}),

    0x80F7: _e("Apollo Computer (HP)", "RAW",
               "Historical", "Legacy",
               "Apollo Computer (acquired by HP 1989) private protocol", None, {}),

    0x80DD: _e("Varian Associates", "RAW",
               "Historical", "Legacy",
               "Varian Associates (scientific instruments) private protocol", None, {}),

    # ── GROUP 21: Ungermann-Bass / BBN / Cronus ───────────────────────────────
    0x0900: _e("Ungermann-Bass Net Debugger", "RAW",
               "Historical", "Legacy",
               "Ungermann-Bass (early LAN vendor) network debugger", None, {}),

    0x7000: _e("Ungermann-Bass Download", "RAW",
               "Historical", "Legacy",
               "Ungermann-Bass firmware/config download protocol", None, {}),

    0x7002: _e("Ungermann-Bass Diagnostics / Loop", "RAW",
               "Historical", "Legacy",
               "Ungermann-Bass loopback and diagnostic protocol", None, {}),

    0x7030: _e("Proteon (Pioneer Router Vendor)", "RAW",
               "Historical", "Legacy",
               "Proteon Inc. — early internet router vendor (1972–2004)", None, {}),

    0x7034: _e("Cabletron Systems (now Extreme Networks)", "RAW",
               "Historical", "Legacy",
               "Cabletron Systems private protocol — acquired by Enterasys/Extreme", None, {}),

    0x5208: _e("BBN Simnet Private", "RAW",
               "Historical", "Legacy",
               "BBN Technologies Simnet simulation network", None, {}),

    0x8003: _e("Cronus VLN (RFC 824)", "Cronus VLN Frame",
               "Historical", "Legacy",
               "Cronus Virtual Local Network — RFC 824 (1982)", None,
               {"VLN Header":"4B msg-type+flags","VLN Data":"variable Cronus VLN payload"}),

    0x8004: _e("Cronus Direct (RFC 824)", "Cronus Direct Frame",
               "Historical", "Legacy",
               "Cronus Direct transport — RFC 824 (1982)", None,
               {"Msg Type":"1B 0x01=data 0x02=ack","Seq":"1B","Length":"2B","Data":"variable Cronus Direct payload"}),

    0xFF00: _e("BBN VITAL-LanBridge Cache Wakeup (private)", "RAW",
               "Private", "Legacy",
               "BBN VITAL-LanBridge cache wakeup — ISC Bunker Ramo range 0xFF00-FF0F", None, {}),

    0xFFFF: _e("Reserved (RFC 1701)", "RAW",
               "Standard", "Reserved",
               "Reserved EtherType — never assigned for use (RFC 1701)", None, {}),

    # ── GROUP 22: Research / Miscellaneous ────────────────────────────────────
    0x4242: _e("PCS Basic Block Protocol", "RAW",
               "Historical", "Legacy",
               "PCS (Protocol Conversion System) Basic Block Protocol", None, {}),

    0x1600: _e("Valid Systems Protocol", "RAW",
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
               "Axis Communications (network cameras) proprietary bootstrap protocol", None,
               {"Msg Type":"1B 0x01=Discovery 0x02=IPAssign","Serial":"8B Axis serial number","Current IP":"4B","New IP":"4B","Subnet":"4B","CAUTION":"Unauthenticated IP assignment — attacker on LAN can reassign camera IP"}),

    0x8820: _e("Hitachi Cable (Optoelectronic Systems Lab)", "RAW",
               "Historical", "Legacy",
               "Hitachi Cable optoelectronic lab private protocol", None, {}),

    0xAAAA: _e("DECNET / VAX 6220 DEBNI", "RAW",
               "Historical", "Legacy",
               "DEC DEBNI interface board on VAX 6220 — DECnet protocol", None, {}),

    0xFAF5: _e("Sonix Arpeggio", "RAW",
               "Historical", "Legacy",
               "Sonix Arpeggio proprietary protocol", None, {}),

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

    0x80FF: _e("Wellfleet/Bay Networks (private)", "RAW",
               "Historical", "Legacy",
               "Wellfleet Communications (later Bay Networks) private protocol", None, {}),

    # ── GROUP 24: Berkeley / Research ─────────────────────────────────────────
    0x1000: _e("Berkeley Trailer Negotiation", "Trailer Frame",
               "Historical", "Legacy",
               "BSD Berkeley Trailer encapsulation — IP header moved to end (VAX optimisation)", None,
               {"Note":"Reduced memory copies on VAX — never widely deployed"}),

    # ── GROUP 25: ETSI / GeoNetworking ────────────────────────────────────────
    0x8947: _e("GeoNetworking (ETSI EN 302 636-4-1)", "GeoNetworking PDU",
               "Industry", "Active",
               "ETSI ITS geographic routing for V2X / ITS-G5 vehicles", None,
               {"Basic Hdr":"4B Version+NH+Reserved+Lifetime+RHL",
                "Common Hdr":"8B NH+Reserved+HT+HST+TC+Flags+PL+MHL",
                "Extended Hdr":"variable based on header type GUC/GAC/GBC/TSB/SHB/BEACON",
                "Note":"ETSI ITS-G5 / IEEE 802.11p — geographic position-based routing"}),

    # ── GROUP 26: Loopback / Test ─────────────────────────────────────────────
    0x8822: _e("Wind River / Ethernet NIC Test", "Test Frame",
               "Vendor", "Active",
               "Ethernet NIC hardware and software testing (Wind River Systems)", None,
               {"Test Type":"1B 0x01=loopback 0x02=pattern","Pattern":"1B fill byte","Length":"2B payload length","Data":"variable test pattern","CAUTION":"Test frames must not reach production ports"}),

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
