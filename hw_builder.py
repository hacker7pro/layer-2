"""
hw_builder.py  —  Hardware / Motherboard Bus Frame Intelligence Engine
═══════════════════════════════════════════════════════════════════════
Covers Ethernet-encapsulated payloads that mimic or carry hardware bus
protocols traversing the same PCIe fabric as the Ethernet controller.

Concept: Every hardware bus has a frame/packet boundary detected by a
specific symbol, DLLP pattern, or bit sequence. When an Ethernet NIC
sits on PCIe, its DMA engine shares the root complex with USB, HDMI,
DisplayPort, SATA, UART, IPMI, etc. A crafted Ethernet payload whose
binary content matches a hardware bus frame boundary can:
  • Trigger DMA confusion across shared IOMMU domains
  • Appear as a valid transaction to the PCIe root complex
  • Cross protocol domains in FPGA/SoC shared-bus designs
  • Confuse hardware parsers in industrial / embedded systems

Platform categories:
  Consumer      — desktop ATX/ITX, laptop, gaming
  Server        — 1P/2P/4P Xeon/EPYC, IPMI/BMC, OCP
  Network       — Router ASIC, switch silicon, SmartNIC
  Security      — Firewall, IDS/IPS, NAC appliance
  Industrial    — PLC, embedded ARM/MIPS, real-time controller
  Embedded/IoT  — SBC, microcontroller, automotive ECU
"""

from __future__ import annotations

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — BUS PROTOCOL FRAME BOUNDARY REGISTRY
#  Each entry: delimiter/symbol that marks frame start (and end),
#  the bus width, encoding, and how it manifests inside an Ethernet payload.
# ══════════════════════════════════════════════════════════════════════════════

BUS_BOUNDARY_REGISTRY: dict[str, dict] = {

    # ── PCIe (PCI Express) ────────────────────────────────────────────────────
    "pcie_tlp": dict(
        bus="PCIe TLP (Transaction Layer Packet)",
        standard="PCI Express Base Specification 5.0",
        delimiter_start="STP symbol 0xFB (8b/10b) or SKP ordered set",
        delimiter_end="END symbol 0xFD (8b/10b) or EDB (Error Data Boundary)",
        encoding="8b/10b (Gen1/2) → 128b/130b (Gen3+) → 242b/256b (Gen6)",
        frame_bytes="12-20B header + up to 4096B data payload",
        detection="Bytes 0xFB…0xFD (8b/10b decoded) or 0x02 start-token (128b/130b)",
        fields={
            "Fmt+Type":    "1B  Fmt(2b)+Type(5b): 0x00=MRd32 0x20=MRd64 0x40=MWr32 0x60=MWr64 0x05=CplD 0x0A=IORd 0x42=IOWr 0x04=CfgRd0 0x44=CfgWr0",
            "TC":          "3b  Traffic Class 0-7",
            "TD":          "1b  TLP Digest (ECRC) present",
            "EP":          "1b  Error Poisoned",
            "Attr":        "2b  Relaxed Ordering + No Snoop",
            "Length":      "10b  payload in 32b DWORDs (0=1024 DW)",
            "Requester ID":"2B  Bus(8b)+Device(5b)+Function(3b)",
            "Tag":         "1B  transaction tag (matches Cpl/CplD)",
            "Last BE":     "4b  byte enables for last DW",
            "First BE":    "4b  byte enables for first DW",
            "Address":     "4B (32b) or 8B (64b) target MMIO/memory address",
            "ECRC":        "optional 4B end-to-end CRC",
            "LCRC":        "4B link CRC (stripped at link layer, added per hop)",
            "CAUTION":     "Address must be within a valid BAR or MMIO region — wrong address = UR (Unsupported Request) completion or system hang",
        },
        attack_surface="PCIe DMA attack: Ethernet NIC on PCIe Bus0 shares root complex — crafted TLP in Ethernet payload can be injected via IOMMU bypass in misconfigured systems",
        platforms=["Consumer desktop (ATX/ITX)", "Laptop (M.2/Thunderbolt)", "Server (OCP/HHHL)", "FPGA SmartNIC"],
    ),

    "pcie_dllp": dict(
        bus="PCIe DLLP (Data Link Layer Packet)",
        standard="PCI Express Base Specification 5.0 — Section 3",
        delimiter_start="SDP symbol 0xFC before DLLP (8b/10b encoding)",
        delimiter_end="END symbol 0xFD",
        encoding="8b/10b Gen1/2 or 128b/130b Gen3+",
        frame_bytes="6B fixed (Type+Value+CRC16)",
        detection="0xFC byte followed by DLLP type byte",
        fields={
            "Type":    "1B  0x00=Ack 0x10=Nak 0x20=PMReq_L0s 0x21=PMReq_L1 0x22=PMReq_L23 0x23=PM_Enter_L1 0x24=PM_Active_State_Request_L1 0x30=InitFC1-P 0x34=InitFC1-NP 0x38=InitFC1-Cpl 0x40=InitFC2-P 0x50=UpdateFC-P 0x54=UpdateFC-NP 0x58=UpdateFC-Cpl",
            "Value":   "3B  type-specific: AckNak=Seq(12b)+RSVD(12b); FC=HdrScale(2b)+DataScale(2b)+HdrFC(8b)+DataFC(12b)",
            "CRC-16":  "2B  DLLP CRC over Type+Value bytes",
            "CAUTION": "Injecting fake Nak DLLP causes replay of all unacknowledged TLPs — can cause avalanche retransmit and link reset",
        },
        attack_surface="Link-layer flow control poisoning — fake UpdateFC causes transmitter to over-send, triggering buffer overflow at receiver",
        platforms=["All PCIe devices", "SmartNIC", "FPGA accelerator"],
    ),

    # ── USB ───────────────────────────────────────────────────────────────────
    "usb3_packet": dict(
        bus="USB 3.x SuperSpeed Packet",
        standard="USB 3.2 Specification / USB4",
        delimiter_start="COM (Comma) symbol K28.5 — 10b pattern 1111100101 — synchronises lanes",
        delimiter_end="EOP (End of Packet): SKP or SLC ordered set",
        encoding="8b/10b USB 3.0/3.1 Gen1/2  →  128b/132b USB4",
        frame_bytes="4B header packet + up to 1024B data payload",
        detection="K28.5 comma symbol in 8b/10b stream or LMP packet type byte",
        fields={
            "DW0 Type":    "5b  0x00=LMP 0x04=TP(Transaction Packet) 0x08=DPH(Data Packet Header) 0x0C=ITP(Isochronous TP)",
            "DW0 Route String":"20b (USB4) routing through hub chain",
            "Packet Type": "5b  TP subtypes: 0x04=ACK 0x08=NRDY 0x0C=ERDY 0x10=STATUS 0x14=STRDYL 0x18=PING 0x1C=Pping",
            "Device Addr": "7b  USB device address 1-127",
            "EndpointNum": "4b  endpoint 0-15",
            "Stream ID":   "16b (USB 3.1) stream identifier for bulk streams",
            "Sequence Num":"5b  data packet sequence (ACK correlates by seq)",
            "Data Payload":"variable up to 1024B SuperSpeed, 512B HighSpeed",
            "CRC-32":      "4B over data payload",
            "CAUTION":     "Device address 0 is reserved for enumeration — injecting to addr=0 triggers re-enumeration on all hubs",
        },
        attack_surface="USB-over-Ethernet (USBoPCIe): Ethernet payload matching USB LMP/TP structure can confuse USB host controller sharing same PCIe bus",
        platforms=["Consumer desktop (USB4/TB4)", "Laptop", "Server (IPMI USB)", "Embedded SBC"],
    ),

    "usb2_packet": dict(
        bus="USB 2.0 High-Speed Packet",
        standard="USB 2.0 Specification Rev 2.0",
        delimiter_start="SYNC field: 00000001 (NRZI-encoded) — 8 bits of 0s then 1",
        delimiter_end="EOP: SE0 (both D+/D- low) for 2 bit times then J state",
        encoding="NRZI with bit stuffing (insert 0 after 6 consecutive 1s)",
        frame_bytes="3B token packet or up to 1023B data packet",
        detection="0x80 SYNC byte followed by PID byte",
        fields={
            "PID":        "1B  Packet Identifier: 0x01=SOF 0x09=IN 0x01=OUT 0xC3=DATA0 0x4B=DATA1 0xD2=ACK 0x5A=NAK 0x1E=STALL 0xA5=PRE",
            "PID Check":  "upper 4b must be bitwise complement of lower 4b",
            "Frame Num":  "11b (SOF) frame number 0-2047",
            "ADDR":       "7b  device address",
            "ENDP":       "4b  endpoint number",
            "CRC-5":      "5b over token fields",
            "CRC-16":     "16b over data payload",
            "CAUTION":    "PID check failure causes packet discard — lower nibble must = ~upper nibble",
        },
        attack_surface="USB 2.0 replay via Ethernet: SOF injection confuses USB host SOF counter timing",
        platforms=["All consumer/server hardware", "Industrial HMI", "Embedded controllers"],
    ),

    # ── HDMI / DisplayPort ────────────────────────────────────────────────────
    "hdmi_packet": dict(
        bus="HDMI Data Island Packet",
        standard="HDMI Specification 2.1 — Section 5",
        delimiter_start="Data Island period: TERC4 encoded control tokens CTL0-3 preamble",
        delimiter_end="Guardband period: TERC4 0xC or 0xD tokens on each lane",
        encoding="TMDS (Transition Minimised Differential Signalling) — 8b/10b variant",
        frame_bytes="32B per packet (4B header + 28B subpackets)",
        detection="Packet type byte 0x00-0x0F in header byte 0",
        fields={
            "Packet Type":   "1B  0x00=Null 0x01=AudioClock(ACR) 0x02=AVI-InfoFrame 0x03=SPD 0x04=Audio-InfoFrame 0x05=MPEG-Source 0x0A=Gamut-Metadata 0x0F=Audio-Sample",
            "HB1 HB2":       "2B  type-specific header bytes",
            "ECC Header":    "1B  Hamming code over HB0-HB2",
            "SubPkt0-3 Byte0-6":"7B each  4 sub-packets × 7B = 28B data",
            "SubPkt BCH":    "1B per subpacket  BCH error correction code",
            "AVI InfoFrame": "0x02: ColorSpace(2b)+Scan(2b)+Colorimetry+AspectRatio+VIC+PixelRepeat",
            "Audio Sample":  "0x0F: ChannelStatus bits + IEC60958 audio samples",
            "ACR N value":   "0x01: N(20b) for audio clock regeneration N/CTS ratio",
            "CAUTION":       "Injecting AVI InfoFrame with wrong VIC code causes display to switch resolution or go blank",
        },
        attack_surface="HDMI-over-Ethernet (HDBaseT): Ethernet frames carrying HDMI packet bytes can control downstream display behaviour when forwarded by HDBaseT extender",
        platforms=["Consumer GPU (HDMI 2.1)", "Server VGA/HDMI console", "KVM-over-IP", "Industrial HMI"],
    ),

    "displayport_packet": dict(
        bus="DisplayPort Main Stream / Sideband",
        standard="DisplayPort 2.1 UHBR — VESA Spec",
        delimiter_start="BS (Blanking Start) symbol 0x1BC (K28.5+D11.6) in 8b/10b stream",
        delimiter_end="BE (Blanking End) symbol 0x17C",
        encoding="8b/10b DP1.x → 128b/132b DP2.0 UHBR",
        frame_bytes="512B main stream frame + 64B sideband message",
        detection="K28.5 comma followed by SR (Symbol Reset) sequence",
        fields={
            "BS Symbol":     "0x1BC  Blanking Start — marks active-to-blank transition",
            "SR Symbol":     "0x154  Symbol Reset — lane alignment",
            "MSA Mvid":      "3B  M value for video clock recovery (Nvid/Mvid × link rate)",
            "MSA Nvid":      "3B  N value",
            "Htotal":        "2B  total horizontal pixels including blanking",
            "Vtotal":        "2B  total vertical lines",
            "Hstart":        "2B  horizontal active start position",
            "Vstart":        "2B  vertical active start",
            "Misc0":         "1B  color depth(3b)+colorimetry(2b)+component format(2b)+sync(1b)",
            "SB MSG Type":   "1B  sideband: 0x20=LINK_ADDRESS 0x11=CLEAR_PAYLOAD 0x12=SET_PAYLOAD 0x30=REMOTE_DPCD_READ",
            "CAUTION":       "Wrong Mvid/Nvid ratio causes pixel clock desync and display corruption on all downstream monitors",
        },
        attack_surface="DP-over-USB4/Thunderbolt: DisplayPort tunnelled in USB4 shares PCIe bandwidth — injected BS symbols can disrupt active video stream",
        platforms=["Consumer GPU (DP 2.1)", "Laptop (USB-C DP-Alt)", "USB4/Thunderbolt dock", "Workstation"],
    ),

    # ── SATA / NVMe Storage ───────────────────────────────────────────────────
    "sata_fis": dict(
        bus="SATA FIS (Frame Information Structure)",
        standard="SATA Revision 3.5 — Serial ATA International Organization",
        delimiter_start="SOF (Start of Frame) primitive: K28.5+D24.3+D24.3+D21.5",
        delimiter_end="EOF primitive: K28.5+D21.6+D21.6+D21.5  then WTRM",
        encoding="8b/10b SERDES — 1.5/3/6 Gbps",
        frame_bytes="20B Register FIS or up to 8KB data FIS",
        detection="FIS Type byte at offset 0: 0x27=H2D-Register 0x34=D2H-Register 0x39=DMA-Activate 0x41=DMA-Setup 0x46=Data 0xA1=Set-Device-Bits 0xBF=BIST-Activate",
        fields={
            "FIS Type":    "1B  0x27=Host→Dev Register 0x34=Dev→Host Register 0x46=Data 0x41=DMA-Setup 0x39=DMA-Activate 0xBF=BIST",
            "C/I/PM":      "1B  bit7=C(Command/Status) bit6=I(Interrupt) bit3:0=PM-Port",
            "Command":     "1B  ATA command: 0x25=ReadDMAExt 0x35=WriteDMAExt 0xEC=Identify 0xB0=SMART 0x60=ReadFPDMAQueued 0x61=WriteFPDMAQueued",
            "Features":    "1B  command-specific feature register",
            "LBA Low":     "1B  LBA bits 7:0",
            "LBA Mid":     "1B  LBA bits 15:8",
            "LBA High":    "1B  LBA bits 23:16",
            "Device":      "1B  bit7=1 bit6=LBA-mode=1 bit4=DEV bit3:0=LBA[27:24]",
            "LBA Low Exp": "1B  LBA bits 31:24 (48-bit addressing)",
            "LBA Mid Exp": "1B  LBA bits 39:32",
            "LBA High Exp":"1B  LBA bits 47:40",
            "Count":       "2B  sector count (0=65536 sectors = 32GB per command)",
            "Control":     "1B  bit2=SRST(soft reset) bit3=NIEN(interrupt disable)",
            "DMA Buffer ID":"8B  (DMA-Setup) host buffer descriptor address",
            "DMA Count":   "4B  (DMA-Setup) bytes to transfer",
            "CAUTION":     "SRST bit=1 in Control byte causes immediate device reset — all outstanding NCQ commands aborted",
        },
        attack_surface="SATA-over-Ethernet (eSATA bridge/IP): FIS byte sequence in Ethernet payload can trigger ATA commands on bridged storage devices",
        platforms=["Consumer desktop (AHCI/SATA)", "Server JBOD expander", "Industrial storage controller", "NAS"],
    ),

    "nvme_pcie": dict(
        bus="NVMe Admin/IO Command (PCIe MMIO)",
        standard="NVMe Base Specification 2.0 — NVM Express",
        delimiter_start="SQ (Submission Queue) doorbell write to MMIO offset 0x1008+(2y×4) triggers NVMe command",
        delimiter_end="CQ (Completion Queue) entry written by controller; interrupt or polling",
        encoding="MMIO register writes via PCIe TLP MemWr — 64B SQE written to host memory",
        frame_bytes="64B Submission Queue Entry (SQE) + 16B Completion Queue Entry (CQE)",
        detection="NVMe BAR0 offset pattern: Admin SQ at offset 0x1000 area; opcode byte at SQE[0]",
        fields={
            "CDW0 Opcode":  "1B  Admin: 0x00=DeleteSQ 0x01=CreateSQ 0x02=GetLogPage 0x05=CreateCQ 0x06=Identify 0x09=Abort 0x0A=SetFeatures 0x0B=GetFeatures 0x0C=AsyncEvent 0x7C=FormatNVM 0x7E=SecuritySend 0x7F=SecurityRecv  IO: 0x00=Flush 0x01=Write 0x02=Read 0x08=WriteZeroes 0x09=DSM",
            "CDW0 FUSE":    "2b  Fused: 00=Normal 01=First 10=Second",
            "CDW0 CID":     "2B  Command Identifier",
            "NSID":         "4B  Namespace ID (1-based; 0xFFFFFFFF=all)",
            "MPTR":         "8B  Metadata Pointer (host DMA address for metadata)",
            "PRP1":         "8B  Physical Region Page 1 — host data buffer PA",
            "PRP2/SGL":     "8B  PRP list or SGL segment pointer",
            "CDW10":        "4B  SLBA[31:0] for Read/Write; DW-specific for admin",
            "CDW11":        "4B  SLBA[63:32]",
            "CDW12":        "4B  NLB(15:0)+PRINFO(3b)+FUA(1b)+LR(1b)",
            "CDW13-15":     "4B each  command-specific",
            "SecuritySend": "CDW10: SPSP(16b)=Security Protocol Specific; CDW11: TL=transfer length",
            "FormatNVM":    "CDW10: SES(3b)=Secure-Erase-Setting(1=UserData 2=Crypto); PROT_INFO(4b); MSET(1b); PI(3b); PIL(1b); MS(1b)",
            "CAUTION":      "SecuritySend 0x7E with SPSP=0x0001 (TCG Opal) can activate locking — permanent data loss if passphrase not saved",
        },
        attack_surface="NVMe MMIO injection: PCIe peer-to-peer DMA from compromised NIC can write NVMe SQEs directly to NVMe controller BAR without CPU involvement if IOMMU misconfigured",
        platforms=["Consumer NVMe SSD (M.2)", "Server NVMe (U.2/E1.S/E3.S)", "Cloud storage (OCP NVMe-MI)", "Enterprise all-flash array"],
    ),

    # ── Network Switch Silicon ────────────────────────────────────────────────
    "broadcom_xgs": dict(
        bus="Broadcom XGS/DNX RCPU / Higig2 Header",
        standard="Broadcom BCM56xxx/88xxx internal — Higig2 IEEE 802.1 Higig2",
        delimiter_start="Higig2 start: 0xFB55 magic bytes at offset 0 of internal header",
        delimiter_end="No delimiter — length field determines boundary",
        encoding="Binary header prepended to Ethernet frame on chip-to-chip links",
        frame_bytes="16B Higig2 header + original Ethernet frame",
        detection="0xFB55 at bytes 0-1 of inter-chip Higcom link frames",
        fields={
            "Start":       "2B  0xFB55  Higig2 start marker",
            "TC":          "3b  traffic class 0-7",
            "Mirror Pkt":  "1b",
            "MH Opcode":   "3b  0=CPU 1=BC 2=UC 3=IPMC",
            "Dst Module":  "8b  destination module ID (switch chip ID)",
            "Dst Port":    "7b  destination port on that module",
            "Src Module":  "8b  source module ID",
            "Src Port":    "7b  source port",
            "LBID":        "8b  load-balance ID (for ECMP/LAG)",
            "VID":         "12b  VLAN ID",
            "PFM":         "2b  Port Flooding Mode",
            "Src T":       "1b  source is trunk",
            "PPD":         "2b  Protocol Processing Disable",
            "DONOT_LEARN": "1b  suppress MAC learning for this frame",
            "MIRROR_ONLY": "1b  frame is mirror copy — do not switch",
            "Hdr_Ext_Len": "3b  extra header words (4B each)",
            "CAUTION":     "Setting DONOT_LEARN=0 on unknown src causes MAC table pollution — use with MIRROR_ONLY to prevent switching",
        },
        attack_surface="Switch CPU injection: Ethernet frames with Higig2 header directed to switch CPU port (module=0 port=0) bypass normal forwarding and hit kernel network stack directly",
        platforms=["Broadcom Trident4/Tomahawk5 based switches", "Arista/Cisco/Juniper/HP ProCurve", "Cloud ToR (Top of Rack)"],
    ),

    "intel_fm10k": dict(
        bus="Intel FM10000 (Fulcrum) Switch Fabric Header",
        standard="Intel Ethernet Switch FM10000 Datasheet",
        delimiter_start="FM10K internal header: FTAG 0x8100+VID=0xFFF special VLAN",
        delimiter_end="End of Ethernet frame (FCS)",
        encoding="Modified Ethernet with prepended fabric tag",
        frame_bytes="4B fabric header + Ethernet frame",
        detection="EtherType 0x8100 + VID=0xFFF identifies internal fabric frame",
        fields={
            "FTAG EtherType":"2B  0x8100",
            "Fabric VID":    "12b  0xFFF = internal fabric frame (not normal VLAN)",
            "Dst Port":      "8b  destination port bitmap",
            "Src Port":      "8b  originating port",
            "Traffic Class": "3b",
            "CAUTION":       "VID=0xFFF frames must not egress to customer ports — misconfigured trunk leaks internal fabric headers",
        },
        attack_surface="Fabric tag injection: crafted Ethernet with VID=0xFFF reaching switch VLAN-unaware port processed as internal fabric frame — arbitrary port redirect",
        platforms=["Intel FM10000-based switches", "Silicom SmartNIC", "WhiteBox OCP switches"],
    ),

    # ── BMC / IPMI / Redfish ──────────────────────────────────────────────────
    "ipmi_lan": dict(
        bus="IPMI over LAN (RMCP/RMCP+) — BMC Management",
        standard="IPMI v2.0 Specification / DMTF DSP0114",
        delimiter_start="RMCP header: 0x06 (RMCP version 1) at UDP payload offset 0",
        delimiter_end="End of UDP datagram",
        encoding="Binary — RMCP(4B) + IPMI Session(10-18B) + IPMI Message",
        frame_bytes="14B minimum RMCP+Session + variable IPMI command",
        detection="0x06 0x00 0xFF 0x07 RMCP header (version+reserved+seq+class)",
        fields={
            "RMCP Version":  "1B  0x06=RMCP v1.0",
            "RMCP Reserved": "1B  0x00",
            "RMCP Seq":      "1B  sequence number (0xFF=no ACK needed)",
            "RMCP Class":    "1B  0x07=IPMI  0x06=ASF",
            "Auth Type":     "1B  0x00=None 0x01=MD2 0x02=MD5 0x04=Straight 0x06=RMCP+",
            "Session Seq":   "4B  per-session sequence number (anti-replay)",
            "Session ID":    "4B  session handle from OpenSession response",
            "Auth Code":     "16B  (if AuthType≠0) HMAC-SHA1 or MD5 of message",
            "Msg Length":    "1B",
            "Target Addr":   "1B  0x20=BMC",
            "NetFn/LUN":     "1B  NetFn(6b)+LUN(2b): 0x06/0x00=App 0x0A/0x00=Storage 0x2C/0x00=DCMI",
            "Checksum1":     "1B  2's complement of TargetAddr+NetFn",
            "Source Addr":   "1B  0x81=remote console",
            "Seq/LUN":       "1B  request seq(6b)+LUN(2b)",
            "Command":       "1B  0x01=GetChassisStatus 0x02=ChassisControl 0x37=GetSensorReading 0x2C=GetSDR 0x40=SetSystemBootOptions",
            "ChassisCtrl":   "1B  (Cmd=0x02) 0x00=PowerDown 0x01=PowerUp 0x02=PowerCycle 0x03=HardReset 0x05=SoftShutdown",
            "BootOptions":   "(Cmd=0x40) BootDevice(4b): 0x08=PXE 0x04=HDD 0x14=CDROM 0x18=BIOS-setup",
            "Checksum2":     "1B  2's complement of SourceAddr+Seq+Cmd+Data",
            "CAUTION":       "ChassisControl PowerCycle (0x02) immediately cuts power — no OS shutdown; data loss on filesystems without journaling",
        },
        attack_surface="IPMI LAN is the primary server remote-management attack surface — default creds (admin/admin or ADMIN/ADMIN), cipher0 auth bypass, and RAKP vulnerability allow unauthenticated chassis control",
        platforms=["All server BMC: Dell iDRAC, HP iLO, Supermicro IPMI, Lenovo XCC, Fujitsu iRMC", "Cisco CIMC", "HPE Synergy"],
    ),

    "redfish_frame": dict(
        bus="Redfish / MCTP over SMBus/PCIe",
        standard="DMTF DSP0236 MCTP + DSP0218 Redfish",
        delimiter_start="MCTP header: 0x01 (MCTP version 1) at SMBus/PCIe VDM offset 0",
        delimiter_end="Last packet flag (EOM bit=1) in MCTP header",
        encoding="MCTP (Management Component Transport Protocol) binary framing",
        frame_bytes="4B MCTP header + variable payload per message",
        detection="MCTP version 0x01 + Message Type 0x7E=PLDM or 0x7F=VendorDefined",
        fields={
            "MCTP Version": "4b  0x1=MCTPv1",
            "Reserved":     "4b  0",
            "Dest EID":     "1B  Endpoint ID 0x00=Null 0x01=Broadcast 0x08+=component",
            "Src EID":      "1B",
            "SOM":          "1b  Start of Message",
            "EOM":          "1b  End of Message",
            "Pkt Seq":      "2b  0-3 wrapping packet sequence",
            "TO":           "1b  Tag Owner",
            "Msg Tag":      "3b  message tag (correlates multi-packet messages)",
            "Msg Type":     "1B  0x00=MCTP-Control 0x01=PLDM 0x02=NCSI 0x03=Ethernet 0x04=NVMeMI 0x7E=SPDM 0x7F=Vendor",
            "PLDM Type":    "1B  0x00=Ctrl 0x01=SMBIOS 0x02=Platform 0x03=BIOS 0x04=FW-Update 0x05=Redfish",
            "PLDM Cmd":     "1B  Redfish: 0x01=GetTLSCert 0x02=GetToken type-specific",
            "CAUTION":      "MCTP EID 0x01 (broadcast) reaches ALL management controllers on the bus — no authentication by default in pre-SPDM implementations",
        },
        attack_surface="OOB management injection: MCTP frames via PCIe VDM (Vendor Defined Messages) reach BMC without going through host OS — Ethernet NIC can emit PCIe VDMs targeting BMC EID",
        platforms=["Server BMC (all vendors)", "CXL memory devices", "NVMe MI (Management Interface)", "OCP DC-MHS"],
    ),

    # ── Thunderbolt / USB4 ────────────────────────────────────────────────────
    "thunderbolt_tlp": dict(
        bus="Thunderbolt 3/4 Tunnelled PCIe TLP",
        standard="Thunderbolt 3 Specification / USB4 v2.0",
        delimiter_start="TB transport packet: SSP header 0x00FB (transport-layer start symbol)",
        delimiter_end="SSP EOP 0x00FD",
        encoding="USB4 128b/132b transport over USB-C cable",
        frame_bytes="16B TB transport header + PCIe TLP payload",
        detection="TB transport type field 0x00=PCIe 0x01=DisplayPort 0x02=USB3 0x03=HopID",
        fields={
            "Transport Type":"4b  0=PCIe 1=DP 2=USB3 3=HopID-only",
            "Hop ID":        "6b  identifies tunnel endpoint (path through daisy-chain)",
            "Route String":  "60b  USB4 device routing",
            "PCIe TLP":      "variable  standard PCIe TLP (MRd/MWr/Cpl) after transport header",
            "DP Bandwidth":  "(Type=1) 2B estimated bandwidth in Mbps",
            "CAUTION":       "Thunderbolt DMA attack: Type=0 (PCIe) with Hop=0 reaches host root complex — no IOMMU protection on legacy pre-VT-d systems",
        },
        attack_surface="Classic Thunderbolt DMA attack: connected Thunderbolt device gets PCIe peer-to-peer DMA access to host memory — can read RAM contents or inject code",
        platforms=["Consumer laptop (TB3/4/USB4)", "Workstation", "Mac (TB2/3/4)", "eGPU enclosure"],
    ),

    # ── Automotive / CAN / FlexRay ────────────────────────────────────────────
    "can_fd_frame": dict(
        bus="CAN FD (Controller Area Network Flexible Data-rate)",
        standard="ISO 11898-1:2015 CAN FD",
        delimiter_start="SOF (Start of Frame): dominant bit (0) after 3+ recessive (1) idle",
        delimiter_end="EOF: 7 consecutive recessive bits",
        encoding="NRZ with bit stuffing — insert opposite bit after 5 identical consecutive bits",
        frame_bytes="8-64B data + 8B header",
        detection="SOF bit + 11b or 29b arbitration ID + IDE bit (0=standard 1=extended)",
        fields={
            "SOF":        "1b  0 (dominant) — marks frame start after idle",
            "ID":         "11b standard or 29b extended identifier (priority: lower=higher priority)",
            "SRR":        "1b  (extended only) substitute remote request",
            "IDE":        "1b  0=standard 11b ID  1=extended 29b ID",
            "EDL":        "1b  Extended Data Length — 1=CAN FD mode",
            "BRS":        "1b  Bit Rate Switch — 1=data phase at higher baud rate",
            "ESI":        "1b  Error State Indicator — 1=transmitter is error-passive",
            "DLC":        "4b  Data Length Code: 0-8=0-8B  9=12B 10=16B 11=20B 12=24B 13=32B 14=48B 15=64B",
            "Data":       "0-64B  payload bytes",
            "CRC-17":     "17b (≤16B payload) or CRC-21 (>16B payload)",
            "CRC Del":    "1b  recessive delimiter",
            "ACK":        "1b  any receiver pulls dominant to acknowledge",
            "ACK Del":    "1b  recessive",
            "EOF":        "7b  all recessive — end of frame",
            "CAUTION":    "Dominant bit arbitration: lower ID wins bus — ID=0x000 always wins and can block all other nodes",
        },
        attack_surface="CAN-over-Ethernet (CANbus gateway): ECU firmware update frames in Ethernet payload forwarded to CAN gateway — ID spoofing allows engine/brake CAN message injection",
        platforms=["Automotive ECU gateway (Automotive Ethernet + CAN)", "Industrial PLC CAN bridge", "Robotics CAN master"],
    ),

    "flexray_frame": dict(
        bus="FlexRay Communication Frame",
        standard="FlexRay Protocol Specification v3.0.1",
        delimiter_start="TSS (Transmission Start Sequence): 3-15 LOW bits + BSS (Byte Start Sequence)",
        delimiter_end="FES (Frame End Sequence): static 0b + dynamic 1b + CRC(24b) + FES pattern",
        encoding="NRZ differential signalling — 10Mbps both channels",
        frame_bytes="5B header + 0-254B payload + 3B CRC",
        detection="0x01 Frame ID field MSB + Payload Length + Header CRC",
        fields={
            "Res":         "1b  reserved=0",
            "PayPream":    "1b  payload preamble indicator",
            "Null Frame":  "1b  1=null frame (no valid data)",
            "Sync Frame":  "1b  1=sync frame (used for clock sync)",
            "Startup Frame":"1b  1=startup frame",
            "Frame ID":    "11b  slot identifier 1-2047 (determines transmission time)",
            "Payload Len": "7b  words (2B each) — 0-127 words = 0-254B",
            "Header CRC":  "11b  CRC over reservation+sync+startup+ID+length",
            "Cycle Count": "6b  0-63 cycle counter",
            "Payload":     "variable  application data",
            "Frame CRC":   "24b  CRC over header+payload",
            "CAUTION":     "Sync Frame bit=1 causes all nodes to adjust clock — injecting fake sync frames desynchronises the entire FlexRay cluster",
        },
        attack_surface="FlexRay-over-Ethernet gateway: AUTOSAR adaptive platform bridges FlexRay to Ethernet — frame ID spoofing affects X-by-Wire systems (steer/brake)",
        platforms=["Automotive (BMW, Audi, Daimler X-by-Wire)", "Aerospace avionics bus", "Industrial real-time control"],
    ),

    # ── Serial / Console / UART ───────────────────────────────────────────────
    "uart_console": dict(
        bus="UART / Serial Console Frame",
        standard="RS-232 / RS-485 / UART 16550",
        delimiter_start="Start bit: line goes LOW (space) for 1 bit period",
        delimiter_end="Stop bit(s): line goes HIGH (mark) for 1 or 2 bit periods",
        encoding="NRZ async — LSB first, optional parity bit",
        frame_bytes="10-12 bits per character (1 start + 8 data + parity + 1-2 stop)",
        detection="Baud rate dependent — common: 9600/115200/1500000 bps",
        fields={
            "Start Bit":   "1b  always 0 (space/low)",
            "Data Bits":   "5-8b  LSB first (usually 8N1 = 8 data + no parity + 1 stop)",
            "Parity Bit":  "optional  0=Even 1=Odd or absent",
            "Stop Bit(s)": "1 or 2b  always 1 (mark/high)",
            "Baud Rate":   "Common: 9600 19200 38400 57600 115200 921600 1500000 3000000",
            "Flow Control":"RTS/CTS hardware or XON(0x11)/XOFF(0x13) software",
            "Console Cmds":"VT100/ANSI: ESC[2J=clear ESC[H=home ESC[1;1H=cursor ESC[0m=reset",
            "CAUTION":     "XON/XOFF: 0x11 and 0x13 bytes in data payload cause unintended flow control — use hardware RTS/CTS for binary protocols",
        },
        attack_surface="UART-over-Ethernet (SOC console): embedded Linux serial console exposed via Ethernet serial server — UART frame injection allows unauthenticated root shell access",
        platforms=["Embedded Linux (UART console)", "Router console port (RJ45→RS232)", "Industrial PLC serial", "Network switch console"],
    ),

    "sol_ipmi": dict(
        bus="Serial-over-LAN (IPMI SOL — BMC UART redirect)",
        standard="IPMI v2.0 — Serial-Over-LAN Specification",
        delimiter_start="IPMI SOL payload after RMCP+ session header",
        delimiter_end="End of UDP datagram",
        encoding="RMCP+ encrypted IPMI session carrying console byte stream",
        frame_bytes="Variable — IPMI SOL payload type 0x01 with console data",
        detection="RMCP class 0x07 + IPMI NetFn=0x34 (Transport) + Cmd=0x01(Activate SOL)",
        fields={
            "SOL PayloadType":"1B  0x01=SOL data",
            "Packet Seq":    "1B  0-15 wrapping sequence",
            "Ack/Nack Seq":  "1B  acknowledges received packet",
            "Accepted Char Count":"1B  bytes accepted from previous packet",
            "Flush Input":   "1b  discard pending input",
            "Flush Output":  "1b  discard pending output",
            "DCD":           "1b  Data Carrier Detect state",
            "CTS":           "1b  Clear To Send state",
            "Console Data":  "variable  raw UART bytes (terminal keystrokes / output)",
            "CAUTION":       "SOL gives full interactive BIOS/boot/OS console access — equivalent to physical KVM; requires RMCP+ auth but many BMCs have default credentials",
        },
        attack_surface="SOL console access: unauthenticated IPMI → SOL provides interactive server console — boot into single-user mode, edit /etc/passwd, disable SELinux",
        platforms=["Dell iDRAC SOL", "HP iLO VSP (Virtual Serial Port)", "Supermicro IPMI SOL", "Lenovo XCC SOL"],
    ),

    # ── PCIe Bus − DMA / IOMMU ───────────────────────────────────────────────
    "pcie_dma_desc": dict(
        bus="PCIe DMA Descriptor (NIC Ring Buffer)",
        standard="Intel 82599/X710/E810 DMA Descriptor Ring Format",
        delimiter_start="Head pointer register write signals new descriptor available",
        delimiter_end="DD (Descriptor Done) bit set by hardware in writeback",
        encoding="64-128B descriptor written to host memory; hardware polls via DMA read",
        frame_bytes="16B Tx descriptor or 16B Rx descriptor",
        detection="Buffer Address at 8B alignment + Command/Type field",
        fields={
            "Buffer Addr":  "8B  host physical/virtual address of data buffer",
            "Length":       "16b  buffer length in bytes",
            "CSO":          "8b  checksum offset",
            "CMD":          "8b  bit0=EOP bit1=IFCS bit3=RS(report status) bit5=DEXT",
            "STA/RSV":      "4b  bit0=DD(done) written by hardware on completion",
            "Special":      "4b  VLAN tag",
            "CSS":          "8b  checksum start offset",
            "VLAN":         "16b  VLAN tag to insert",
            "DMA_Buf_Addr": "8B  (Rx) host ring buffer address for incoming frame",
            "Advanced Tx":  "DTYP=0x03 context: MSS+HDRLEN+TUCMD (TSO/checksum offload)",
            "CAUTION":      "Buffer address must be IOMMU-mapped — unmapped PA causes DMAR fault, disables NIC, and may crash kernel",
        },
        attack_surface="DMA descriptor manipulation: if IOMMU disabled or misconfigured, a compromised NIC firmware can write DMA descriptors pointing to arbitrary host PA — read/write any physical memory",
        platforms=["Intel X710/XXV710/E810 NIC", "Mellanox ConnectX-6/7", "Broadcom BCM57XXX", "AWS ENA", "Azure MLX5"],
    ),

    # ── RAM / Memory ──────────────────────────────────────────────────────────
    "ddr5_command": dict(
        bus="DDR5 DRAM Command Bus",
        standard="JEDEC DDR5 SDRAM Standard JESD79-5B",
        delimiter_start="CA[13:0] command/address bus sampled on rising CLK edge (source-synchronous)",
        delimiter_end="CAS Latency (CL) cycles after command before data appears",
        encoding="Double Data Rate — commands on CLK rising edge only; data on both edges",
        frame_bytes="14-bit command word × 1-2 CLK cycles per command",
        detection="CS_n (Chip Select) assertion + CA[13:0] decoded command",
        fields={
            "CS_n":        "active-low chip select  0=selected  1=deselected",
            "CA[13:0]":    "14-bit command/address bus",
            "Command Decode":"(bits[2:0]): 000=MRS 001=REF 010=PRE 011=ACT 100=RD 101=WR 110=WRA 111=RDA",
            "BankGroup":   "CA[4:3] bank group select (0-3)",
            "Bank":        "CA[6:5] bank select (0-3)",
            "Row":         "CA[17:7] row address (ACT command)",
            "Column":      "CA[9:0] column address (RD/WR command)",
            "Burst Length":"CA[4] 0=BL8 1=BL16",
            "Auto Precharge":"CA[10] 1=auto-precharge after access",
            "Mode Register":"MRS command: CA[10:8]=MR number CA[7:0]=MR data",
            "MR0":         "Burst Length + CL(CAS Latency) + Burst Type",
            "MR3":         "Write Leveling + Geardown mode",
            "MR5":         "CA Parity Latency mode + DQ Parity",
            "Refresh Mode":"REF: Normal(all banks) or per-bank refresh",
            "CAUTION":     "MRS to MR0 with wrong CL setting causes all read data to be bit-shifted — system crash or silent data corruption",
        },
        attack_surface="Rowhammer via NIC DMA: repeated DRAM row activation from NIC DMA buffer access flips bits in adjacent rows — privilege escalation without code execution",
        platforms=["Consumer DDR5 (AM5/LGA1700)", "Server RDIMM/LRDIMM (LGA4677)", "LPDDR5 laptop", "HBM2E/3 on GPU/accelerator"],
    ),

    # ── Audio ─────────────────────────────────────────────────────────────────
    "aes67_rtp": dict(
        bus="AES67 / RAVENNA Audio-over-IP (RTP)",
        standard="AES67-2018 — High-performance streaming audio-over-IP",
        delimiter_start="RTP header at UDP payload offset 0: version 0x80 (V=2 P=0 X=0 CC=0)",
        delimiter_end="End of UDP datagram",
        encoding="RTP over UDP/IP — PCM/DSD audio samples",
        frame_bytes="12B RTP header + variable audio payload (typical 48-192 samples)",
        detection="RTP V=2 (bits 7-6 = 0b10) + PT (payload type) + SSRC",
        fields={
            "V":          "2b  must be 0b10 (RTP v2)",
            "P":          "1b  padding present",
            "X":          "1b  extension header present",
            "CC":         "4b  CSRC count (usually 0)",
            "M":          "1b  marker (first packet of talk spurt)",
            "PT":         "7b  payload type: 96-127=dynamic; AES67 uses 96 for L24 or L32",
            "Seq Num":    "2B  monotonic sequence — receiver detects loss",
            "Timestamp":  "4B  media time in sample units (90000Hz for 48kHz audio = 1875 per frame)",
            "SSRC":       "4B  synchronisation source identifier (unique per stream)",
            "Payload":    "variable  interleaved PCM L24/L32 samples: CH1[3B]+CH2[3B]+... per sample",
            "Sample Rate":"Common: 44100/48000/88200/96000/176400/192000 Hz",
            "Bit Depth":  "16b/24b/32b PCM or 1b DSD64/DSD128",
            "PTP Sync":   "IEEE 1588 PTPv2 synchronises media clocks to <1µs",
            "CAUTION":    "Timestamp discontinuity >1 RTP packet causes audio glitch/click — PTP sync loss = audible dropout in broadcast environment",
        },
        attack_surface="AES67 stream injection: matching SSRC of active audio stream with replayed or modified audio causes audio monitoring disruption in broadcast/live production",
        platforms=["Dante/AES67 audio network (Yamaha/Shure/Focusrite)", "Broadcast facility", "Live sound system", "Recording studio network"],
    ),

    # ── Industrial / SCADA ───────────────────────────────────────────────────
    "modbus_tcp": dict(
        bus="Modbus TCP (SCADA/PLC over Ethernet)",
        standard="Modbus Application Protocol v1.1b3 — modbus.org",
        delimiter_start="MBAP header: Transaction ID at TCP payload offset 0",
        delimiter_end="End of TCP segment (length field in MBAP)",
        encoding="Binary over TCP port 502",
        frame_bytes="6B MBAP header + variable PDU",
        detection="Protocol ID 2B = 0x0000 at offset 2 + TCP dport=502",
        fields={
            "Transaction ID":"2B  echoed in response for request matching",
            "Protocol ID":   "2B  0x0000=Modbus (always)",
            "Length":        "2B  remaining bytes (Unit ID + PDU)",
            "Unit ID":       "1B  slave address 1-247 (0xFF=broadcast)",
            "Function Code": "1B  0x01=ReadCoils 0x02=ReadDI 0x03=ReadHoldingReg 0x04=ReadInputReg 0x05=WriteSingleCoil 0x06=WriteSingleReg 0x0F=WriteMultipleCoils 0x10=WriteMultipleReg 0x17=ReadWriteMultipleReg 0x2B=EncapsulatedInterface",
            "Start Address": "2B  starting register/coil address (0-based)",
            "Quantity":      "2B  number of coils/registers to read",
            "Byte Count":    "1B  (write functions) data bytes that follow",
            "Values":        "variable  register values or coil states",
            "Exception Code":"1B  (error response: FC+0x80): 0x01=IllegalFunction 0x02=IllegalDataAddr 0x03=IllegalDataValue 0x04=SlaveDeviceFailure",
            "CAUTION":       "No authentication in Modbus TCP — any host on network can write registers; use ACL or industrial firewall to restrict TCP 502 access",
        },
        attack_surface="SCADA attack: Modbus TCP has no authentication — attacker on same VLAN can write output coils (FC=0x0F) to control physical actuators (motors, valves, relays)",
        platforms=["Schneider Modicon PLC", "Siemens S7 (via gateway)", "Allen-Bradley (via converter)", "SCADA DCS systems", "Smart grid RTU"],
    ),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PLATFORM REGISTRY
#  Maps hardware platform category → relevant bus protocols
# ══════════════════════════════════════════════════════════════════════════════

PLATFORM_REGISTRY: dict[str, dict] = {
    "consumer": dict(
        name="Consumer Motherboard (Desktop / Laptop / Gaming)",
        chipsets=["Intel Z790/Z890 + PCH", "AMD X670E/X870E", "Apple M4 (SoC)"],
        form_factors=["ATX", "mATX", "ITX", "Laptop (SO-DIMM)", "NUC"],
        buses=["pcie_tlp", "pcie_dllp", "usb3_packet", "usb2_packet",
               "displayport_packet", "hdmi_packet", "nvme_pcie",
               "sata_fis", "ddr5_command", "uart_console",
               "thunderbolt_tlp", "aes67_rtp"],
        ethernet_ports=["Intel I225/I226 2.5GbE", "Realtek RTL8125 2.5GbE", "Marvel AQC113 10GbE"],
        attack_notes="Thunderbolt DMA / Rowhammer via NIC DMA / HDMI EDID injection",
    ),
    "server": dict(
        name="Server Motherboard (1P/2P/4P Enterprise + Cloud)",
        chipsets=["Intel W790/C741 (Sapphire Rapids)", "AMD EPYC Genoa/Bergamo", "Ampere Altra"],
        form_factors=["EATX", "LGA4677", "OCP 3.0 NIC", "1U/2U rackmount"],
        buses=["pcie_tlp", "pcie_dllp", "pcie_dma_desc", "nvme_pcie",
               "ipmi_lan", "redfish_frame", "sol_ipmi", "ddr5_command",
               "usb3_packet", "uart_console", "sata_fis"],
        ethernet_ports=["Intel X710/E810 10/25GbE", "Mellanox ConnectX-7 100/400GbE", "Broadcom BCM57508 100GbE"],
        attack_notes="IPMI default creds / RAKP auth bypass / PCIe peer-to-peer DMA via OCP NIC / MCTP injection",
    ),
    "router": dict(
        name="Router / WAN Edge Appliance",
        chipsets=["Cavium OCTEON III/TX2", "Marvell OCTEON 10", "Qualcomm IPQ9574", "Intel Atom P5000"],
        form_factors=["1U/2U rackmount", "Desktop", "PoP/CPE"],
        buses=["pcie_tlp", "uart_console", "usb2_packet",
               "can_fd_frame", "modbus_tcp"],
        ethernet_ports=["Marvell 88E2110 10GbE", "Intel I350 1GbE×4", "Qualcomm QCA8081 2.5GbE"],
        attack_notes="Console UART access / JTAG via exposed header / PCIe enumeration of hidden devices",
    ),
    "switch": dict(
        name="Network Switch Silicon (Access / Distribution / Core)",
        chipsets=["Broadcom Trident4/Tomahawk5", "Marvell Prestera/Aldrin2", "Intel Tofino2", "Innovium TERALYNX8"],
        form_factors=["1U/2U fixed", "Modular chassis", "OCP SAI"],
        buses=["broadcom_xgs", "intel_fm10k", "pcie_tlp",
               "ipmi_lan", "uart_console", "usb2_packet"],
        ethernet_ports=["400GbE × 32 QSFP-DD", "100GbE × 128", "25GbE × 48 + 100GbE × 8"],
        attack_notes="Higig2 injection → arbitrary port redirect / switch CPU DoS / VLAN hopping via fabric tag leak",
    ),
    "firewall": dict(
        name="Firewall / NGFW Appliance",
        chipsets=["Intel Atom C3000 (Denverton)", "Intel Xeon D", "Cavium OCTEON TX2", "Netronome Agilio SmartNIC"],
        form_factors=["1U/2U rackmount", "Desktop SOHO", "Virtual (VFW)"],
        buses=["pcie_tlp", "pcie_dma_desc", "ipmi_lan",
               "uart_console", "usb2_packet", "redfish_frame"],
        ethernet_ports=["Intel X553 10GbE", "Chelsio T62100 100GbE", "Netronome NFP-4000"],
        attack_notes="Bypass via crafted fragmented packets / IPMI out-of-band access bypasses firewall rules / DMA descriptor manipulation on SmartNIC offload",
    ),
    "ids_ips": dict(
        name="IDS / IPS Sensor (Inline / Passive)",
        chipsets=["Intel Xeon E-2300", "Cavium NITROX V", "Netronome SmartNIC"],
        form_factors=["1U inline appliance", "TAP-based passive sensor"],
        buses=["pcie_tlp", "pcie_dma_desc", "uart_console", "ipmi_lan"],
        ethernet_ports=["Intel X710 10GbE bypass", "Silicom PE310G4BPI (bypass NIC)"],
        attack_notes="Evasion via packet fragmentation / checksum anomalies / protocol state desync / asymmetric routing bypass",
    ),
    "nac": dict(
        name="NAC Appliance (Network Access Control)",
        chipsets=["Intel Xeon D", "ARM Cortex-A72 (embedded)"],
        form_factors=["1U appliance", "VM-based"],
        buses=["pcie_tlp", "ipmi_lan", "uart_console",
               "usb2_packet"],
        ethernet_ports=["Intel I350 1GbE×4", "Intel X710 10GbE"],
        attack_notes="802.1X bypass via MAC spoofing / EAPOL-Start flooding / RADIUS shared-secret brute-force / VLAN hopping post-auth",
    ),
    "industrial": dict(
        name="Industrial Controller (PLC / DCS / RTU / HMI)",
        chipsets=["TI AM64x (Sitara)", "NXP i.MX 8M", "Xilinx Zynq UltraScale+", "Siemens S7-1500 ASIC"],
        form_factors=["DIN-rail PLC", "Panel PC HMI", "Rack RTU", "Embedded IPC"],
        buses=["can_fd_frame", "flexray_frame", "modbus_tcp",
               "uart_console", "pcie_tlp", "usb2_packet",
               "sata_fis"],
        ethernet_ports=["TI DP83867 RGMII 1GbE", "Microchip LAN9303 3-port switch", "PROFINET RT NIC"],
        attack_notes="CAN injection via Ethernet-CAN gateway / Modbus coil write to actuators / FlexRay clock desync / Serial console access via Ethernet serial server",
    ),
    "embedded": dict(
        name="Embedded / IoT / SBC / Automotive ECU",
        chipsets=["NXP S32G (AUTOSAR)", "Renesas R-Car H3/S4", "Qualcomm SA8295P", "Broadcom BCM2712 (RPi5)"],
        form_factors=["COM Express", "SODIMM module", "Custom PCB", "ECU"],
        buses=["can_fd_frame", "flexray_frame", "uart_console",
               "usb2_packet", "usb3_packet", "pcie_tlp",
               "aes67_rtp"],
        ethernet_ports=["TI DP83TC812 100BASE-T1 (automotive)", "Marvell 88Q2112 1000BASE-T1", "Broadcom BCM54210 1GbE"],
        attack_notes="ECU firmware update injection via Automotive Ethernet / UDS (ISO 14229) diagnostic session abuse / FlexRay X-by-Wire spoofing",
    ),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — ETHERNET ENCAPSULATION STRUCTURES
#  How each bus frame is encapsulated inside Ethernet for cross-protocol attacks
# ══════════════════════════════════════════════════════════════════════════════

ETH_ENCAP_REGISTRY: dict[str, dict] = {
    "pcie_tlp":         dict(eth_type="0x8999 (proprietary) or 0x88B7 OUI-Ext", wrapping="Raw TLP bytes after Ethernet header", inject_method="Direct MMIO write via DMA or NIC firmware"),
    "pcie_dllp":        dict(eth_type="0x88B7 OUI-Extended", wrapping="DLLP bytes after OUI+SubType", inject_method="PCIe link-layer packet replay"),
    "usb3_packet":      dict(eth_type="0x0800 (USB/IP RFC 3538) UDP port 3240", wrapping="USB/IP header + URB data", inject_method="USB/IP protocol over standard IP network"),
    "usb2_packet":      dict(eth_type="0x0800 UDP port 3240", wrapping="USB/IP low-speed/full-speed URB", inject_method="USB/IP redirect to remote host"),
    "hdmi_packet":      dict(eth_type="0x8100 VLAN or 0x88B7 OUI-Ext", wrapping="HDMI packet bytes in payload", inject_method="HDBaseT extender / HDMI-over-IP encoder"),
    "displayport_packet":dict(eth_type="0x0800 (DisplayPort tunnelled in USB4/IP)", wrapping="DP MST tunnel in USB4 PCIe VDM", inject_method="USB4/Thunderbolt tunnel injection"),
    "sata_fis":         dict(eth_type="0x0800 TCP port 3260 (iSCSI) or 0x88A2 (AoE)", wrapping="FIS bytes in AoE or iSCSI data segment", inject_method="AoE direct or iSCSI initiator to SATA bridge"),
    "nvme_pcie":        dict(eth_type="0x8893 (NVMe-oF L2) or 0x0800 UDP 4420 (NVMe/TCP)", wrapping="NVMe SQE in NVMe-oF capsule", inject_method="NVMe-oF fabric target injection"),
    "broadcom_xgs":     dict(eth_type="Internal — Higig2 link between switch chips", wrapping="Higig2 16B header prepended to Ethernet frame", inject_method="Physical access to inter-chip SerDes link or CPU port injection"),
    "intel_fm10k":      dict(eth_type="0x8100 with VID=0xFFF", wrapping="FM10K fabric tag as 802.1Q header", inject_method="Trunk port that fails to strip fabric VLAN"),
    "ipmi_lan":         dict(eth_type="0x0800 UDP port 623", wrapping="RMCP+IPMI payload", inject_method="Direct UDP to BMC management port"),
    "redfish_frame":    dict(eth_type="0x0800 TCP port 443 (Redfish HTTP) or PCIe VDM (MCTP)", wrapping="MCTP over PCIe VDM out-of-band", inject_method="PCIe VDM injection from NIC to BMC EID"),
    "sol_ipmi":         dict(eth_type="0x0800 UDP port 623 (RMCP+)", wrapping="IPMI SOL payload type 0x01", inject_method="Authenticated RMCP+ session → SOL activation"),
    "thunderbolt_tlp":  dict(eth_type="USB4 transport (not standard Ethernet EtherType)", wrapping="TB transport header + PCIe TLP", inject_method="Physical Thunderbolt connection or eGPU"),
    "can_fd_frame":     dict(eth_type="0x0800 UDP (SocketCAN over UDP) or 0x88B7 OUI-Ext", wrapping="CAN frame in SocketCAN netlink or UDP", inject_method="CAN-over-Ethernet gateway / SocketCAN tunnel"),
    "flexray_frame":    dict(eth_type="0x0800 UDP (AUTOSAR Ethernet adaptation)", wrapping="FlexRay PDU in SOME/IP or raw UDP", inject_method="AUTOSAR adaptive platform IP gateway"),
    "uart_console":     dict(eth_type="0x0800 TCP (Telnet/SSH/RFC2217)", wrapping="RFC2217 serial-over-TCP or raw Telnet", inject_method="Console server (Digi/Opengear) TCP 2001-2032"),
    "sol_ipmi":         dict(eth_type="0x0800 UDP 623", wrapping="RMCP+ SOL payload", inject_method="IPMI credential attack then SOL"),
    "ddr5_command":     dict(eth_type="N/A — indirect via Rowhammer", wrapping="NIC DMA buffer in DRAM row triggers bit flips", inject_method="Rowhammer: repeated NIC DMA access to same PA triggers row activation"),
    "aes67_rtp":        dict(eth_type="0x0800 UDP (multicast 239.x.x.x:5004)", wrapping="RTP header + PCM audio payload", inject_method="Multicast stream injection matching SSRC"),
    "modbus_tcp":       dict(eth_type="0x0800 TCP port 502", wrapping="MBAP header + Modbus PDU", inject_method="Direct TCP connection — no auth required by default"),
    "pcie_dma_desc":    dict(eth_type="N/A — NIC ring buffer in host memory", wrapping="DMA descriptor ring in host DRAM pointed to by NIC BAR", inject_method="Corrupt NIC firmware or IOMMU bypass → write arbitrary descriptor"),
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_bus_info(bus_class: str) -> dict:
    return BUS_BOUNDARY_REGISTRY.get(bus_class, {})

def get_platform_buses(platform: str) -> list[str]:
    p = PLATFORM_REGISTRY.get(platform, {})
    return p.get("buses", [])

def get_all_platforms() -> list[str]:
    return list(PLATFORM_REGISTRY.keys())

def get_all_buses() -> list[str]:
    return list(BUS_BOUNDARY_REGISTRY.keys())

def get_encap_info(bus_class: str) -> dict:
    return ETH_ENCAP_REGISTRY.get(bus_class, {})

def list_buses_for_platform(platform: str) -> list[dict]:
    buses = get_platform_buses(platform)
    result = []
    for b in buses:
        info = get_bus_info(b)
        if info:
            result.append(dict(
                bus_class=b,
                name=info.get("bus", b),
                standard=info.get("standard", ""),
                delimiter=info.get("delimiter_start", ""),
                frame_bytes=info.get("frame_bytes", ""),
                attack=info.get("attack_surface", ""),
                encap=ETH_ENCAP_REGISTRY.get(b, {}),
            ))
    return result

def registry_stats_hw() -> dict:
    return dict(
        buses=len(BUS_BOUNDARY_REGISTRY),
        platforms=len(PLATFORM_REGISTRY),
        encap_methods=len(ETH_ENCAP_REGISTRY),
    )
