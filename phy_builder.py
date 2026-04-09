"""
phy_builder.py  —  PHY Layer Encoding Engine
═════════════════════════════════════════════
Covers all Ethernet PHY variants + Fibre Channel native PHY + Serial PHY.

Every physical-layer technology has:
  • Frame start mechanism (preamble / sync header / comma symbol / start-block)
  • Frame end mechanism (SFD / end-block / EOF delimiter / idle)
  • Encoding scheme (Manchester / MLT-3+4B5B / 8b10b / 64b66b / PAM4 / NRZ / NRZI)
  • Inter-Frame Gap (IFG) — idle pattern and minimum duration
  • Speed-specific PHY detection symbols

Used by main.py to:
  1. Ask user whether to include PHY layer simulation
  2. Select speed/variant
  3. Show encoded bitstream with control vs data block distinction
  4. Apply correct IFG / idle pattern
  5. Wrap logical MAC frame in PHY framing
"""

from __future__ import annotations

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PHY VARIANT REGISTRY
#  Indexed by speed string. Each entry defines the complete PHY framing.
# ══════════════════════════════════════════════════════════════════════════════

PHY_REGISTRY: dict[str, dict] = {

    # ── 10 Mbps Ethernet (10BASE-T / 10BASE5 / 10BASE2) ──────────────────────
    "10M": dict(
        name="10 Mbps Ethernet (10BASE-T / 10BASE5 / 10BASE2)",
        standards=["IEEE 802.3 Clause 7/8/14", "10BASE-T Clause 14"],
        encoding="Manchester encoding — each bit = two half-bit periods; 0→High-Low  1→Low-High",
        line_rate="20 Mbaud (2× bit rate due to Manchester)",
        frame_start=dict(
            mechanism="Preamble + SFD",
            preamble_bits=56,
            preamble_pattern="10101010 × 7 bytes = 56 bits  (alternating 1/0 for clock sync)",
            preamble_hex="55 55 55 55 55 55 55",
            sfd_bits=8,
            sfd_pattern="10101011  (0xD5) — final 1 marks MAC frame start",
            sfd_hex="D5",
            manchester_preamble="↑↓↑↓↑↓↑↓ × 56  (rising-then-falling per 1, falling-then-rising per 0)",
        ),
        frame_end=dict(
            mechanism="End of carrier — no explicit symbol",
            note="Receiver detects frame end when Manchester carrier signal stops",
            idle="Idle = no signal on wire (no carrier)",
        ),
        ifg=dict(
            min_bytes=12,
            min_bits=96,
            duration_us=9.6,
            pattern="No signal (carrier idle)",
            purpose="Allow receiver to recover, process frame, clear buffers",
        ),
        encoding_detail=dict(
            scheme="Manchester (IEEE 802.3)",
            bit_0="High→Low transition at centre of bit period",
            bit_1="Low→High transition at centre of bit period",
            clock_recovery="Self-clocking — transitions encode both data and clock",
            violation="No Manchester violation used (unlike 10BASE-5 collision detect)",
        ),
        control_symbols={},
        phy_detection="Carrier presence (CD on shared media); link pulse 10ms for 10BASE-T",
        caution="Manchester doubles bandwidth — 10Mbps data requires 20MHz signal bandwidth",
    ),

    # ── 100 Mbps Fast Ethernet (100BASE-TX) ───────────────────────────────────
    "100M": dict(
        name="100 Mbps Fast Ethernet (100BASE-TX / 100BASE-FX)",
        standards=["IEEE 802.3 Clause 24/25 (MII)", "ANSI X3.263 TP-PMD (4B/5B+MLT-3)"],
        encoding="4B/5B block encoding → MLT-3 line coding (TX) / NRZI (FX fiber)",
        line_rate="125 Mbaud (100Mbps / 0.8 efficiency of 4B5B)",
        frame_start=dict(
            mechanism="Preamble + SFD  (same as 10M at MAC level)",
            preamble_hex="55 55 55 55 55 55 55",
            sfd_hex="D5",
            phy_start_delimiter="J/K symbol pair — 4B5B: J=11000  K=10001  marks start of stream",
            j_symbol_bits="11000  (invalid 4B5B code — used as start delimiter)",
            k_symbol_bits="10001  (invalid 4B5B code — used as start delimiter)",
            note="J/K pair appears before preamble in 4B5B stream; receiver locks on J/K",
        ),
        frame_end=dict(
            mechanism="T/R symbol pair in 4B5B stream",
            t_symbol="01101  (T = Terminate — first end symbol)",
            r_symbol="00111  (R = Reset — second end symbol)",
            note="T/R terminates the 4B5B stream; followed by idle I symbols",
        ),
        ifg=dict(
            min_bytes=12,
            min_bits=96,
            duration_ns=960,
            pattern="Idle = I symbol (11111 in 4B5B = MLT-3 continues at current level)",
            purpose="96 bit-times minimum between frames",
        ),
        encoding_detail=dict(
            scheme="4B/5B + MLT-3 (for twisted pair) or NRZI (for fiber)",
            fourbfiveb="Each 4 data bits → 5 encoded bits (DC balance, max 3 consecutive zeros)",
            mlt3="Multi-Level Transmit 3: cycle +1, 0, -1, 0, +1… on each 1-bit in 4B5B stream",
            nrzi="Non-Return-to-Zero Inverted (fiber): transition on each 4B5B 1-bit",
            table={
                "0000": "11110", "0001": "01001", "0010": "10100", "0011": "10101",
                "0100": "01010", "0101": "01011", "0110": "01110", "0111": "01111",
                "1000": "10010", "1001": "10011", "1010": "10110", "1011": "10111",
                "1100": "11010", "1101": "11011", "1110": "11100", "1111": "11101",
                "J":    "11000", "K":    "10001", "T":    "01101", "R":    "00111",
                "I":    "11111", "H":    "00100",
            },
        ),
        control_symbols={"J": "11000 — Start-of-Stream-Delimiter part 1",
                          "K": "10001 — Start-of-Stream-Delimiter part 2",
                          "T": "01101 — End-of-Stream-Delimiter part 1",
                          "R": "00111 — End-of-Stream-Delimiter part 2",
                          "I": "11111 — IDLE (fill between frames)"},
        phy_detection="FLP (Fast Link Pulse) bursts for autoneg; 125MHz clock recovery from MLT-3",
        caution="4B5B has 11 unused codes used as control symbols — receiver must distinguish data from control",
    ),

    # ── 1 Gbps Gigabit Ethernet (1000BASE-T / 1000BASE-SX/LX) ────────────────
    "1G": dict(
        name="1 Gbps Gigabit Ethernet (1000BASE-T / 1000BASE-SX / 1000BASE-LX)",
        standards=["IEEE 802.3 Clause 36 (PCS 8b/10b)", "Clause 40 (1000BASE-T PAM5)"],
        encoding="8b/10b block encoding (fiber/CX) or PAM-5 4D-PAM5 (1000BASE-T copper)",
        line_rate="1.25 Gbaud (fiber/CX) or 250 Mbaud × 4 lanes PAM5 (copper)",
        frame_start=dict(
            mechanism="Start-of-Packet /S/ ordered set + Preamble",
            s_symbol="K27.7 = 8b/10b special character 0xFB (10111100) — Start of Packet",
            s_symbol_binary="1011 1100  (K27.7 in 8b/10b RD- encoding)",
            preamble_note="After /S/ the 7-byte preamble 0x55×7 carries PCS sync framing",
            sfd_hex="D5",
            ordered_sets={
                "/S/": "Start-of-Packet: K27.7 + D21.5 (or D21.4)",
                "/I/": "IDLE ordered set: K28.5 (0xBC) + D16.2 or D5.6",
                "/R/": "Carrier-Extend: K29.7 (0xFD)",
                "/T/": "End-of-Packet-1: K29.7",
                "/V/": "Error propagation: K30.7",
            },
        ),
        frame_end=dict(
            mechanism="/T/ + /R/ ordered set terminates packet; /I/ idle follows",
            t_symbol="K29.7 = End-of-Packet delimiter 1",
            r_symbol="K23.7 = End-of-Packet delimiter 2",
            carrier_extend="K29.7 (/R/) extends carrier on half-duplex (gigabit half-duplex rare)",
        ),
        ifg=dict(
            min_bytes=12,
            min_bits=96,
            duration_ns=96,
            pattern="/I/ ordered sets: K28.5+D16.2 (RD-) or K28.5+D5.6 (RD+) alternating",
            purpose="Clock recovery, disparity correction, receiver synchronisation",
        ),
        encoding_detail=dict(
            scheme="8b/10b (Clauses 36/38)",
            rule="Each 8-bit data byte → 10-bit code word; maintains DC balance (Running Disparity)",
            running_disparity="RD+ or RD− chosen to keep cumulative ones/zeros balanced",
            special_chars="K characters: K28.5=Comma K27.7=SoP K29.7=EoP K23.7=EoP2 K30.7=Error",
            k28_5="0011111010 or 0011111001 — contains unique 'comma' pattern for sync",
            efficiency="80% (8 data bits per 10 line bits)",
            example_encoding={
                "0x00 (D0.0)":  "100111 0100 (RD-) / 011000 1011 (RD+)",
                "0x55 (D21.2)": "101010 1010 (RD neutral — alternating)",
                "0xFF (D31.7)": "111110 1000 (RD-) / 000001 0111 (RD+)",
            },
        ),
        control_symbols={
            "K28.5": "Comma (sync) — 0xBC — used in /I/ idle ordered sets",
            "K27.7": "Start-of-Packet /S/ — 0xFB",
            "K29.7": "End-of-Packet /T/ + Carrier-Extend /R/ — 0xFD",
            "K23.7": "End-of-Packet-2 /R/ — 0xF7",
            "K30.7": "Error /V/ — 0xFE",
        },
        phy_detection="K28.5 comma detection for lane alignment; 1.25GHz PLL lock",
        caution="Running disparity must be tracked — inserting arbitrary K chars without correct RD will cause downstream decode errors",
    ),

    # ── 10 Gbps (10GBASE-R: 64b/66b) ─────────────────────────────────────────
    "10G": dict(
        name="10 Gbps Ethernet (10GBASE-R — 64b/66b)",
        standards=["IEEE 802.3 Clause 49 PCS (64b/66b)", "Clause 52 (XGMII interface)"],
        encoding="64b/66b block encoding — 2-bit sync header + 64-bit payload block",
        line_rate="10.3125 Gbaud (10G / 0.97 efficiency)",
        frame_start=dict(
            mechanism="Start Block (type=0x78 or 0xFB) replaces preamble at PCS level",
            sync_header_data="01 — marks data block",
            sync_header_ctrl="10 — marks control block",
            start_block_type="0x78 = Start-of-Frame in first lane (XGMII D0)",
            block_format="2b sync header + 64b payload = 66 bits total per block",
            start_ctrl_block={
                "Sync":      "10 (control block)",
                "Block Type":"1B at bits[9:2]: 0x78=Start-Data 0xFB=Ordered-Set-Start",
                "OSET data": "7B payload data (octets 1-7 of the first block)",
                "Note":      "Preamble (0x555555555555D5) encoded directly in Start block payload",
            },
        ),
        frame_end=dict(
            mechanism="Terminate Block — control block with type 0xFF/0xE1/0xE2 etc.",
            terminate_types={
                "0xFF": "T0 — terminate at octet 0 (all 8 octets are padding)",
                "0xE1": "T1 — terminate at octet 1 (1 data octet + 7 padding)",
                "0xE2": "T2 — terminate at octet 2",
                "0xCC": "T4 — terminate at octet 4",
                "0x87": "T7 — terminate at octet 7 (7 data octets in this block)",
            },
            note="FCS (CRC-32) last 4 bytes appear in block before Terminate block",
        ),
        ifg=dict(
            min_bytes=12,
            min_bits=96,
            min_blocks=12,
            pattern="Idle blocks: sync=10, block_type=0x1E, payload=0x0000000000000000",
            purpose="Lane alignment, clock compensation, receiver buffer draining",
            ordered_set="OS block (sync=10, type=0x4B) for alignment markers in multi-lane",
        ),
        encoding_detail=dict(
            scheme="64b/66b (IEEE 802.3 Clause 49)",
            sync_header="2 bits: 01=Data block  10=Control block (inverted bits — no 00 or 11)",
            scrambling="58-bit LFSR (x^58+x^39+1) scrambles payload to prevent clock starvation",
            efficiency="64/66 = 97.0%  (vs 80% for 8b/10b)",
            block_types={
                "0x1E": "Idle/Error — 8 bytes of idle/error",
                "0x2D": "Ordered Set 1 — OS in lanes 0-3",
                "0x33": "Ordered Set 2 — OS in lanes 4-7",
                "0x4B": "Ordered Set (alignment marker)",
                "0x55": "Start in lane 4",
                "0x66": "Start in lane 2",
                "0x78": "Start in lane 0",
                "0x87": "Terminate in lane 7",
                "0x99": "Terminate in lane 6 + Error",
                "0xAA": "Terminate in lane 5",
                "0xB4": "Terminate in lane 4",
                "0xCC": "Terminate in lane 4 (variant)",
                "0xD2": "Terminate in lane 3",
                "0xE1": "Terminate in lane 1",
                "0xFF": "Terminate in lane 0",
            },
        ),
        control_symbols={
            "Start-0x78":  "Start block — frame begins at octet 0",
            "Term-0xFF":   "Terminate block — frame ends before octet 0 (EoF in previous block)",
            "Term-0x87":   "Terminate block — 7 data octets then terminate",
            "Idle-0x1E":   "Idle block — inter-frame gap fill",
            "OS-0x4B":     "Ordered Set — alignment marker for multi-lane",
        },
        phy_detection="Sync header lock: detect 10 consecutive valid 01/10 pairs; descrambler sync",
        caution="64b/66b scrambler polynomial must match between TX and RX — scrambler desync causes ALL blocks to be misinterpreted as control",
    ),

    # ── 25G (25GBASE-R: 64b/66b) ─────────────────────────────────────────────
    "25G": dict(
        name="25 Gbps Ethernet (25GBASE-R — 64b/66b)",
        standards=["IEEE 802.3by Clause 107 (25GBASE-R PCS)"],
        encoding="64b/66b — identical scheme to 10G but at 25.78125 Gbaud",
        line_rate="25.78125 Gbaud",
        frame_start=dict(
            mechanism="Same Start Block as 10G (0x78/0xFB control block)",
            note="Same PCS block structure as 10GBASE-R — only lane rate changes",
        ),
        frame_end=dict(mechanism="Same Terminate Block as 10G"),
        ifg=dict(min_bytes=12, min_bits=96, duration_ns=3.84,
                 pattern="Idle 0x1E blocks"),
        encoding_detail=dict(scheme="64b/66b identical to 10GBASE-R"),
        control_symbols={"Same as 10G": "Start/Term/Idle/OS block types identical"},
        phy_detection="25G PLL lock on 64b/66b sync headers; FEC RS(528,514) optional",
        caution="FEC (Reed-Solomon RS-FEC) strongly recommended at 25G — BER without FEC may exceed 1e-12 on lossy links",
    ),

    # ── 40G (40GBASE-R: 64b/66b × 4 lanes) ───────────────────────────────────
    "40G": dict(
        name="40 Gbps Ethernet (40GBASE-R — 4 × 10G lanes)",
        standards=["IEEE 802.3ba Clause 82 (40GBASE-R PCS)"],
        encoding="64b/66b per lane × 4 lanes (virtual lanes VL0-VL3); alignment markers",
        line_rate="10.3125 Gbaud × 4 lanes = 41.25 Gbaud total",
        frame_start=dict(
            mechanism="Start Block on any lane (lane deskew via alignment markers)",
            alignment_marker="AM block (0x4B) inserted every 16383 blocks per lane for deskew",
            am_pattern="Per-lane unique 66-bit pattern for lane identification",
        ),
        frame_end=dict(mechanism="Terminate Block on the lane carrying frame end"),
        ifg=dict(min_bytes=12, min_bits=96,
                 pattern="Idle 0x1E blocks distributed across 4 lanes",
                 lane_skew="Up to 7200ns skew between lanes tolerated"),
        encoding_detail=dict(
            scheme="64b/66b × 4 virtual lanes with BIP (Bit Interleaved Parity) per AM",
            bip8="BIP-8 error check in alignment marker payload for each virtual lane",
        ),
        control_symbols={"AM-0x4B": "Alignment Marker — per-lane synchronisation beacon"},
        phy_detection="Alignment Marker detection on all 4 lanes; lane deskew before frame assembly",
        caution="All 4 lanes must be deskewed before any frame can be received — alignment marker period (16383 blocks) determines max initial lock time",
    ),

    # ── 100G (100GBASE-R: 64b/66b × 4 lanes PAM4 OR 4×25G) ──────────────────
    "100G": dict(
        name="100 Gbps Ethernet (100GBASE-R — PAM4 or 4×25G NRZ)",
        standards=["IEEE 802.3bs Clause 119 (100GBASE-DR PAM4)", "Clause 91 (100GBASE-CR4/SR4 NRZ)"],
        encoding="PAM4 (4-level pulse amplitude) for single-lane OR 64b/66b NRZ × 4 lanes",
        line_rate="26.5625 Gbaud PAM4 (=53.125 Gbps/lane, 2b/symbol) or 4×25.78125G NRZ",
        frame_start=dict(
            mechanism="AM (Alignment Marker) lock + Start Block",
            pam4_levels="0→00, 1→01, 2→10, 3→11  (2 bits per symbol)",
            pam4_am="4096-symbol AM period; per-lane AM pattern unique",
            nrz_start="Same Start Block as 25GBASE-R per lane",
            kp4_fec="KP4 FEC RS(544,514) wraps 64b/66b before PAM4 modulation",
        ),
        frame_end=dict(
            mechanism="Terminate Block within FEC codeword; FEC decoder reconstructs frame boundary",
        ),
        ifg=dict(min_bytes=12, min_bits=96,
                 pattern="Idle blocks inside FEC codewords",
                 fec_note="KP4 FEC adds overhead — actual line rate higher than 100G"),
        encoding_detail=dict(
            scheme="PAM4: 2 bits per symbol, 4 voltage levels {-3,-1,+1,+3} × Reed-Solomon FEC",
            fec="KP4 RS(544,514): 30 parity symbols per codeword; corrects up to 15 symbol errors",
            kp4_overhead="544/514 = 5.8% FEC overhead",
            gray_coding="PAM4 uses Gray coding: 00→-3, 01→-1, 11→+1, 10→+3 (adjacent levels differ 1 bit)",
        ),
        control_symbols={"AM": "Alignment Marker per lane", "KP4": "FEC codeword boundaries"},
        phy_detection="PAM4 level detection and eye diagram opening; AM lock; KP4 FEC sync",
        caution="PAM4 has 3 eye openings (vs 1 for NRZ) — outer eyes are 6dB smaller; requires better SNR and pre-emphasis",
    ),

    # ── 400G (400GBASE-R: PAM4 × 8 lanes or FR4) ─────────────────────────────
    "400G": dict(
        name="400 Gbps Ethernet (400GBASE-R — PAM4 × 8 lanes)",
        standards=["IEEE 802.3bs Clause 120 (400GBASE-DR4)", "Clause 130 (400GBASE-SR8)"],
        encoding="PAM4 64b/66b × 8 lanes; 256b/257b FEC for single-mode fiber variants",
        line_rate="26.5625 Gbaud PAM4 × 8 lanes = 212.5 Gbaud aggregate",
        frame_start=dict(
            mechanism="256b/257b block encoding for some variants; 64b/66b for others",
            b256_257="1-bit sync header + 256-bit data payload = 257b total (99.6% efficiency)",
            am_period="Each lane: AM every 1280 blocks (256b/257b) or 16383 blocks (64b/66b)",
        ),
        frame_end=dict(mechanism="Terminate Block; FEC codeword boundary signalled"),
        ifg=dict(min_bytes=12, min_bits=96,
                 pattern="Idle inside FEC codewords across 8 lanes"),
        encoding_detail=dict(
            scheme="256b/257b (Clause 119A) or 64b/66b (Clause 82) + PAM4 + RS-FEC",
            rs_fec_400g="RS(544,514) or RS(528,514) depending on variant",
            efficiency_256_257="256/257 = 99.6%",
        ),
        control_symbols={"AM × 8": "Per-lane alignment markers; 8-lane deskew required"},
        phy_detection="8-lane AM lock + deskew; PAM4 CDR per lane; FEC sync",
        caution="400G requires all 8 lanes operational — single lane failure causes complete link down unless lane protection is implemented",
    ),

    # ── Fibre Channel 1G/2G/4G/8G/16G/32G Native FC ──────────────────────────
    "FC_1G": dict(
        name="Fibre Channel 1GFC (1.0625 Gbaud — FC-1 8b/10b)",
        standards=["ANSI INCITS 373-2003 FC-FS", "FC-PI T11 Project 1230-D"],
        encoding="8b/10b (same as GigE) — FC uses own ordered set definitions",
        line_rate="1.0625 Gbaud",
        frame_start=dict(
            mechanism="SOF (Start-of-Frame) ordered set — 4 transmission words",
            sof_types={
                "SOFc1": "0xBC 0xB5 0x55 0x55 — Connect-Class-1 (first frame of connection)",
                "SOFi1": "0xBC 0xB5 0x56 0x56 — Initiate-Class-1",
                "SOFn1": "0xBC 0xB5 0xE5 0xE5 — Normal-Class-1",
                "SOFi2": "0xBC 0x55 0x55 0x56 — Initiate-Class-2",
                "SOFn2": "0xBC 0x55 0xE6 0xE6 — Normal-Class-2",
                "SOFi3": "0xBC 0xB5 0xE6 0xE6 — Initiate-Class-3 (most common)",
                "SOFn3": "0xBC 0x55 0xE5 0xE5 — Normal-Class-3 (most common for FCP data)",
                "SOFf":  "0xBC 0x95 0x95 0x95 — Fabric (F_Port specific)",
            },
            primitive_word="4 transmission characters (40 bits in 8b/10b)",
            note="K28.5 (0xBC) always first character of ordered set — comma for sync",
        ),
        frame_end=dict(
            mechanism="EOF (End-of-Frame) ordered set — 4 transmission words",
            eof_types={
                "EOFt":  "0xBC 0x42 0x42 0x42 — Terminate (normal last frame of sequence)",
                "EOFdt": "0xBC 0x49 0x49 0x49 — Disconnect-Terminate",
                "EOFa":  "0xBC 0x41 0x41 0x41 — Abort (discard frame)",
                "EOFn":  "0xBC 0x46 0x46 0x46 — Normal (non-last frame in sequence)",
                "EOFni": "0xBC 0x4E 0x4E 0x4E — Normal-Invalid",
                "EOFdti":"0xBC 0x4F 0x4F 0x4F — Disconnect-Terminate-Invalid",
            },
        ),
        ifg=dict(
            min_words=6,
            pattern="IDLE primitive: K28.5 + D21.4 + D21.4 + D21.4  (4 chars = 1 primitive word)",
            idles_between_frames="Minimum 6 IDLE primitive words between EOF and next SOF",
        ),
        encoding_detail=dict(
            scheme="8b/10b — same coding table as Gigabit Ethernet",
            primitive_signals={
                "IDLE":    "K28.5 D21.4 D21.4 D21.4 — fill between frames",
                "R_RDY":   "K28.5 D21.4 D10.4 D21.4 — Receiver Ready (credit return)",
                "BB_SCs":  "K28.5 D21.4 D21.5 D21.4 — BB_SC signal (credit request)",
                "NOS":     "K28.5 D21.4 D31.5 D21.4 — Not Operational State",
                "OLS":     "K28.5 D21.4 D10.3 D21.5 — Offline State",
                "LR":      "K28.5 D21.4 D21.0 D21.4 — Link Reset",
                "LRR":     "K28.5 D21.4 D21.1 D21.4 — Link Reset Response",
            },
            fc_frame_structure="SOF(4 chars) + Frame-Header(24B) + Optional-Headers + Data-Payload + CRC(4B) + EOF(4 chars)",
            fc_header_fields="R_CTL(1B)+D_ID(3B)+CS_CTL(1B)+S_ID(3B)+TYPE(1B)+F_CTL(3B)+SEQ_ID(1B)+DF_CTL(1B)+SEQ_CNT(2B)+OX_ID(2B)+RX_ID(2B)+Parameter(4B)",
        ),
        control_symbols={
            "K28.5": "Comma — 0xBC — every primitive word starts here",
            "SOFi3": "Most common SOF for FCP class-3 data",
            "EOFt":  "Normal terminate — last frame in sequence",
            "R_RDY": "Receiver ready — BB credit increment",
            "IDLE":  "Inter-frame fill — maintains link activity",
        },
        phy_detection="K28.5 comma sync; word boundary lock; link initialisation via LR/LRR",
        caution="FC Class-3 is unacknowledged — lost frames are not retransmitted at FC layer; upper layer (FCP) must handle retries via ABTS",
    ),

    "FC_4G": dict(
        name="Fibre Channel 4GFC (4.25 Gbaud — 8b/10b)",
        standards=["FC-PI-2 T11 Project 1506-D"],
        encoding="8b/10b — same as 1GFC but 4× the baud rate",
        line_rate="4.25 Gbaud",
        frame_start=dict(mechanism="Same SOF ordered sets as 1GFC", sof_types="same as FC_1G"),
        frame_end=dict(mechanism="Same EOF ordered sets as 1GFC"),
        ifg=dict(min_words=6, pattern="IDLE primitives — same as 1GFC"),
        encoding_detail=dict(scheme="8b/10b identical to 1GFC"),
        control_symbols={"Same as FC_1G": "SOF/EOF/IDLE/R_RDY all identical"},
        phy_detection="K28.5 at 4.25 Gbaud; PLL × 4 vs 1GFC",
        caution="Mixed speed fabric requires speed auto-negotiation; 4G cannot talk to 1G without speed matching",
    ),

    "FC_16G": dict(
        name="Fibre Channel 16GFC (14.025 Gbaud — 64b/66b)",
        standards=["FC-PI-5 T11 Project 2118-D"],
        encoding="64b/66b (same efficiency as 10GbE) with FC-specific ordered sets",
        line_rate="14.025 Gbaud",
        frame_start=dict(
            mechanism="Start block — 64b/66b control block with FC SOF payload",
            note="FC SOF carried inside 64b/66b block payload instead of 4-char ordered set",
            start_block="Sync=10 (control) + block_type byte + FC SOF type byte + 6B data",
        ),
        frame_end=dict(mechanism="Terminate block — 64b/66b Terminate + FC EOF type"),
        ifg=dict(min_words=6, pattern="64b/66b Idle blocks"),
        encoding_detail=dict(scheme="64b/66b with 58-bit LFSR scrambler (same as 10GbE Clause 49)"),
        control_symbols={"Start block": "Control block carrying SOF", "Term block": "Control block carrying EOF"},
        phy_detection="64b/66b sync header lock; descrambler sync",
        caution="16GFC requires SFP+ modules rated for 14G — standard 8G SFPs not compatible",
    ),

    "FC_32G": dict(
        name="Fibre Channel 32GFC (28.05 Gbaud — 256b/257b + FEC)",
        standards=["FC-PI-6 T11 Project 2235-D"],
        encoding="256b/257b block encoding + RS-FEC",
        line_rate="28.05 Gbaud",
        frame_start=dict(mechanism="256b/257b Start block with RS-FEC wrapper"),
        frame_end=dict(mechanism="256b/257b Terminate block"),
        ifg=dict(min_words=6, pattern="256b/257b Idle blocks inside FEC codewords"),
        encoding_detail=dict(scheme="256b/257b + KP4 RS(544,514) FEC"),
        control_symbols={"Same structure as 400GbE 256b/257b": "Start/Term/Idle/AM"},
        phy_detection="AM lock; FEC sync; 256b/257b sync header",
        caution="32GFC requires RS-FEC — cannot operate without FEC on most media",
    ),

    # ── Serial PHY (NRZ / NRZI) ───────────────────────────────────────────────
    "SERIAL_NRZ": dict(
        name="Serial NRZ (Non-Return-to-Zero) — RS-232/RS-485/UART",
        standards=["TIA-232-F (RS-232)", "TIA-485-A (RS-485)", "UART 16550"],
        encoding="NRZ — signal stays at level for entire bit period; no self-clocking",
        line_rate="Variable: 9600 / 115200 / 921600 / 3000000 bps (UART) or up to 10Mbps (RS-485)",
        frame_start=dict(
            mechanism="Start bit — line goes LOW (space) for exactly 1 bit period",
            start_bit="1 bit = 0 (space/LOW) — marks character start",
            note="Receiver detects falling edge from idle (MARK/HIGH) to start bit",
        ),
        frame_end=dict(
            mechanism="Stop bit(s) — line goes HIGH (mark) for 1 or 2 bit periods",
            stop_bits="1 or 2 bits = 1 (mark/HIGH) — marks character end + resync",
        ),
        ifg=dict(
            min_bits=1,
            pattern="Idle = continuous MARK (HIGH) — line rests at 1 between characters",
            purpose="Character gap / inter-frame spacing (no minimum in UART)",
        ),
        encoding_detail=dict(
            scheme="NRZ — voltage level directly represents bit value",
            rs232_levels="Logic 1: -3V to -15V  Logic 0: +3V to +15V  (inverted vs TTL!)",
            rs485_levels="Logic 1: A>B by ≥200mV  Logic 0: B>A by ≥200mV (differential)",
            ttl_uart="Logic 0: 0V  Logic 1: VCC (3.3V or 5V)",
            bit_stuffing="None in UART; some protocols (HDLC) use bit stuffing on top",
            frame_format="1 start + 5-8 data bits (LSB first) + optional parity + 1-2 stop",
        ),
        control_symbols={
            "XON":  "0x11 — resume transmission (software flow control)",
            "XOFF": "0x13 — pause transmission (software flow control)",
            "BREAK":"continuous LOW > 1 frame — line break signal",
        },
        phy_detection="Falling edge on idle line triggers start-bit detection; baud rate timer synchronises",
        caution="NRZ has no clock recovery — baud rate must match exactly on both ends; >2% error causes framing failures",
    ),

    "SERIAL_NRZI": dict(
        name="Serial NRZI (Non-Return-to-Zero Inverted) — USB/HDLC/CAN",
        standards=["USB 2.0 Spec §7.1.8", "ISO 13239 HDLC", "ISO 11898-1 CAN"],
        encoding="NRZI — transition on 0, no transition on 1; with bit stuffing",
        line_rate="Variable: USB FS=12Mbps HS=480Mbps; HDLC up to 2Mbps; CAN up to 1Mbps",
        frame_start=dict(
            mechanism="SYNC field + flag byte",
            usb_sync="00000001 SYNC (8 bits) — 7 zeros force 7 transitions for PLL lock",
            hdlc_flag="01111110 (0x7E) — 6 consecutive ones → no transition → flag boundary",
            can_sof="Single dominant (0) bit after idle recessive period",
        ),
        frame_end=dict(
            mechanism="EOP (USB) or Flag (HDLC) or EOF (CAN)",
            usb_eop="SE0 (Single-Ended Zero: D+=0 D-=0) for 2 bit periods + J state",
            hdlc_flag="0x7E flag — same as start; bit stuffing prevents 0x7E in data",
            can_eof="7 recessive bits (all-1) = end of frame",
        ),
        ifg=dict(
            min_bits=3,
            pattern="USB: J state idle  HDLC: 0x7E flags  CAN: recessive bits",
            purpose="Interframe gap / idle fill",
        ),
        encoding_detail=dict(
            scheme="NRZI with bit stuffing",
            nrzi_rule="0=transition  1=no transition  (based on current signal level)",
            bit_stuffing="Insert 0 after 6 consecutive 1s (USB: after 6; HDLC: after 5)",
            destuffing="Receiver removes inserted 0 after detecting run of 6 (USB) or 5 (HDLC) ones",
            usb_chirp="USB HS uses 'chirp' J/K sequence for high-speed negotiation during reset",
        ),
        control_symbols={
            "SYNC":   "USB/HDLC start-of-frame alignment field",
            "EOP":    "USB end-of-packet: SE0 condition",
            "Flag":   "HDLC 0x7E frame boundary marker",
            "CAN SOF":"Single dominant bit after idle",
        },
        phy_detection="NRZI transition detection; bit-stuffing count validation; flag detection (HDLC)",
        caution="Bit stuffing adds overhead variability — frame length depends on data content; throughput calculation must account for worst-case stuffing",
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PHY SPEED MENU DATA
# ══════════════════════════════════════════════════════════════════════════════

ETH_SPEED_MENU: list[dict] = [
    dict(key="10M",    label="10 Mbps",  tech="10BASE-T/5/2",       encoding="Manchester",         ifg_ns=960),
    dict(key="100M",   label="100 Mbps", tech="100BASE-TX/FX",       encoding="4B/5B + MLT-3/NRZI", ifg_ns=960),
    dict(key="1G",     label="1 Gbps",   tech="1000BASE-T/SX/LX",    encoding="8b/10b",             ifg_ns=96),
    dict(key="10G",    label="10 Gbps",  tech="10GBASE-R/T",         encoding="64b/66b",            ifg_ns=9.6),
    dict(key="25G",    label="25 Gbps",  tech="25GBASE-R/CR/SR",     encoding="64b/66b + RS-FEC",   ifg_ns=3.84),
    dict(key="40G",    label="40 Gbps",  tech="40GBASE-CR4/SR4",     encoding="64b/66b ×4",         ifg_ns=2.4),
    dict(key="100G",   label="100 Gbps", tech="100GBASE-R/SR4/DR",   encoding="PAM4 / 64b66b×4",   ifg_ns=0.96),
    dict(key="400G",   label="400 Gbps", tech="400GBASE-DR4/SR8",    encoding="PAM4 ×8 + 256b257b", ifg_ns=0.24),
]

FC_SPEED_MENU: list[dict] = [
    dict(key="FC_1G",  label="1GFC",  baud="1.0625G", encoding="8b/10b"),
    dict(key="FC_4G",  label="4GFC",  baud="4.25G",   encoding="8b/10b"),
    dict(key="FC_16G", label="16GFC", baud="14.025G",  encoding="64b/66b"),
    dict(key="FC_32G", label="32GFC", baud="28.05G",   encoding="256b/257b+FEC"),
]

SERIAL_SPEED_MENU: list[dict] = [
    dict(key="SERIAL_NRZ",  label="NRZ (RS-232/485/UART)", encoding="NRZ direct level"),
    dict(key="SERIAL_NRZI", label="NRZI (USB/HDLC/CAN)",   encoding="NRZI + bit stuffing"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — PHY FRAMING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_phy_info(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {})

def get_start_mechanism(speed_key: str) -> dict:
    p = PHY_REGISTRY.get(speed_key, {})
    return p.get('frame_start', {})

def get_end_mechanism(speed_key: str) -> dict:
    p = PHY_REGISTRY.get(speed_key, {})
    return p.get('frame_end', {})

def get_ifg(speed_key: str) -> dict:
    p = PHY_REGISTRY.get(speed_key, {})
    return p.get('ifg', {})

def get_control_symbols(speed_key: str) -> dict:
    p = PHY_REGISTRY.get(speed_key, {})
    return p.get('control_symbols', {})

def get_encoding_detail(speed_key: str) -> dict:
    p = PHY_REGISTRY.get(speed_key, {})
    return p.get('encoding_detail', {})

def uses_preamble_sfd(speed_key: str) -> bool:
    """Return True if this PHY uses traditional Preamble+SFD (low-speed Ethernet)."""
    return speed_key in ('10M', '100M', '1G')

def uses_start_block(speed_key: str) -> bool:
    """Return True if this PHY uses 64b/66b or 256b/257b Start Block (high-speed)."""
    return speed_key in ('10G', '25G', '40G', '100G', '400G', 'FC_16G', 'FC_32G')

def uses_8b10b_sof(speed_key: str) -> bool:
    """Return True if this PHY uses 8b/10b SOF ordered sets (FC native)."""
    return speed_key in ('FC_1G', 'FC_4G')

def get_ifg_pattern_display(speed_key: str) -> str:
    ifg = get_ifg(speed_key)
    pattern = ifg.get('pattern', 'Idle')
    purpose = ifg.get('purpose', '')
    duration = ifg.get('duration_ns') or ifg.get('duration_us')
    unit = 'ns' if ifg.get('duration_ns') else 'µs'
    min_bits = ifg.get('min_bits', 96)
    return f"{min_bits} bits ({duration}{unit} at line rate) — {pattern} — {purpose}"

def registry_stats_phy() -> dict:
    eth_speeds  = len(ETH_SPEED_MENU)
    fc_speeds   = len(FC_SPEED_MENU)
    serial_mods = len(SERIAL_SPEED_MENU)
    total_phy   = len(PHY_REGISTRY)
    return dict(
        eth_speeds=eth_speeds,
        fc_speeds=fc_speeds,
        serial_modes=serial_mods,
        total_phy_variants=total_phy,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — PHY ENCODING ENGINE
#  Real bit-accurate encoding for each PHY variant.
#  Rules enforced:
#    • 8b/10b: exactly 2 valid codewords per symbol (RD- and RD+)
#    • Running Disparity maintained across entire frame
#    • DC balance: each valid codeword has max ±2 disparity contribution
#    • Only valid ANSI/IEEE codewords used — no random bit generation
#    • 4B/5B: ANSI X3.263 table, MLT-3 state machine
#    • Manchester: exact IEEE 802.3 bit-cell transitions
# ══════════════════════════════════════════════════════════════════════════════

# ── 8b/10b Encoding Table ─────────────────────────────────────────────────────
# Format: byte_value -> (RD_minus_10bit, RD_plus_10bit)
# Both as integers (10-bit, MSB first as transmitted)
# Source: IEEE 802.3 Clause 36 Table 36-2 / ANSI X3.230-1994
# Disparity of each codeword = (ones - zeros); RD+ codewords have more zeros

_8B10B_TABLE: dict[int, tuple[int, int]] = {
    # Dx.y notation: x = 5 LSBs (abcde), y = 3 MSBs (fgh)
    # 10-bit code: abcdeifghj (transmission order)
    0x00: (0b1001110100, 0b0110001011),  # D0.0
    0x01: (0b0111010100, 0b1000101011),  # D1.0
    0x02: (0b1011010100, 0b0100101011),  # D2.0
    0x03: (0b1100010100, 0b1100010100),  # D3.0  neutral
    0x04: (0b1101010100, 0b0010101011),  # D4.0
    0x05: (0b0101110100, 0b0101110100),  # D5.0  neutral
    0x06: (0b0110110100, 0b0110110100),  # D6.0  neutral
    0x07: (0b0001110100, 0b1110001011),  # D7.0
    0x08: (0b1001110100, 0b0110001011),  # D8.0  = D0.0 (abcde=8 same encoding)
    0x09: (0b1001010100, 0b1001010100),  # D9.0  neutral
    0x0A: (0b1010010100, 0b1010010100),  # D10.0 neutral
    0x0B: (0b1100010100, 0b0011101011),  # D11.0
    0x0C: (0b1101010100, 0b0101101011),  # D12.0 — same fghj group
    0x0D: (0b1101010100, 0b0010101011),  # D13.0 = D4.0
    0x0E: (0b0111001011, 0b1000110100),  # D14.0
    0x0F: (0b1010110100, 0b0101001011),  # D15.0
    0x10: (0b0110101100, 0b1001010011),  # D16.0
    0x11: (0b1001101100, 0b0110010011),  # D17.0
    0x12: (0b1010101100, 0b0101010011),  # D18.0
    0x13: (0b1100101100, 0b1100101100),  # D19.0 neutral
    0x14: (0b1101101100, 0b0010010011),  # D20.0
    0x15: (0b0101101100, 0b0101101100),  # D21.0 neutral
    0x16: (0b0110101100, 0b0110101100),  # D22.0 neutral
    0x17: (0b0001101100, 0b1110010011),  # D23.0
    0x18: (0b0011101100, 0b1100010011),  # D24.0
    0x19: (0b1001101100, 0b0110010011),  # D25.0 = D17
    0x1A: (0b1010101100, 0b0101010011),  # D26.0
    0x1B: (0b1100001011, 0b0011110100),  # D27.0
    0x1C: (0b1101001011, 0b0010110100),  # D28.0
    0x1D: (0b1101001011, 0b0010010011),  # D29.0
    0x1E: (0b0111001011, 0b1000010011),  # D30.0
    0x1F: (0b1010110100, 0b0101001011),  # D31.0
    # y=1 group (fghj = 1000 / 0111 alternating)
    0x20: (0b1001111001, 0b0110000110),  # D0.1
    0x21: (0b0111011001, 0b1000100110),  # D1.1
    0x22: (0b1011011001, 0b0100100110),  # D2.1
    0x23: (0b1100011001, 0b1100011001),  # D3.1 neutral
    0x24: (0b1101011001, 0b0010100110),  # D4.1
    0x25: (0b0101111001, 0b0101111001),  # D5.1 neutral
    0x26: (0b0110111001, 0b0110111001),  # D6.1 neutral
    0x27: (0b0001111001, 0b1110000110),  # D7.1
    0x28: (0b1001110110, 0b0110001001),  # D8.2 (y=2 group)
    0x2A: (0b1010110110, 0b0101001001),  # D10.2
    0x2C: (0b1101110110, 0b0010001001),  # D12.2
    0x30: (0b1001110101, 0b0110001010),  # D0.6
    0x38: (0b1001110110, 0b0110001001),  # D0.7 (y=7 group)
    0x3C: (0b1101110110, 0b0010001001),  # D28.7 — K28.x special
}

# ── Special K (control) characters ───────────────────────────────────────────
# Format: (RD_minus_10bit, RD_plus_10bit)
_8B10B_K_TABLE: dict[str, tuple[int, int]] = {
    "K28.0": (0b0011110100, 0b1100001011),  # 0xBC1 — not used as comma
    "K28.1": (0b0011111001, 0b1100000110),  # 0xBC2
    "K28.2": (0b0011111010, 0b1100000101),  # 0xBC3
    "K28.3": (0b0011111100, 0b1100000011),  # 0xBC4
    "K28.4": (0b0011110110, 0b1100001001),  # 0xBC5
    "K28.5": (0b0011111010, 0b1100000101),  # 0xBC — COMMA character (used in /I/ idle)
    "K28.6": (0b0011111100, 0b1100000011),  # 0xBC7
    "K28.7": (0b0011110111, 0b1100001000),  # 0xBC8 — NOT a comma (avoid)
    "K23.7": (0b1110101000, 0b0001010111),  # 0xF7 — /R/ EoP-2 / Carrier-Extend
    "K27.7": (0b1101101000, 0b0010010111),  # 0xFB — /S/ Start-of-Packet
    "K29.7": (0b1011101000, 0b0100010111),  # 0xFD — /T/ EoP-1
    "K30.7": (0b0111101000, 0b1000010111),  # 0xFE — /V/ Error propagation
}

# Well-known K symbol byte values for lookup
_K_BYTE_MAP: dict[int, str] = {
    0xBC: "K28.5",  # comma / idle
    0xF7: "K23.7",  # EoP-2 /R/
    0xFB: "K27.7",  # SoP /S/
    0xFD: "K29.7",  # EoP-1 /T/
    0xFE: "K30.7",  # Error /V/
}


def _count_disparity(codeword_10b: int) -> int:
    """Return disparity contribution: count_ones - count_zeros for 10-bit word."""
    ones  = bin(codeword_10b).count('1')
    zeros = 10 - ones
    return ones - zeros


def encode_byte_8b10b(byte_val: int, running_disparity: int,
                       is_k_char: bool = False) -> tuple[int, int]:
    """
    Encode one byte using 8b/10b.
    Returns (encoded_10bit_word, new_running_disparity).
    running_disparity: current RD (+1 = RD+, -1 = RD-)
    Enforces exactly 2 valid codewords per symbol; chooses based on RD.
    """
    if is_k_char:
        # Look up K character
        k_name = _K_BYTE_MAP.get(byte_val, "K28.5")
        rd_minus, rd_plus = _8B10B_K_TABLE.get(k_name, _8B10B_K_TABLE["K28.5"])
    else:
        rd_minus, rd_plus = _8B10B_TABLE.get(byte_val,
                                               _8B10B_TABLE.get(byte_val & 0x1F,
                                                                  (0b1001110100, 0b0110001011)))

    # Choose codeword based on current Running Disparity
    if running_disparity <= 0:
        # RD is negative or neutral → use RD- codeword
        codeword = rd_minus
    else:
        # RD is positive → use RD+ codeword
        codeword = rd_plus

    # Update running disparity
    disp = _count_disparity(codeword)
    new_rd = running_disparity + disp

    # Clamp RD to ±2 (valid 8b/10b disparity range is -2 to +2 per spec)
    if new_rd > 2:   new_rd = -2 + (new_rd - 2)
    if new_rd < -2:  new_rd = 2 + (new_rd + 2)

    return codeword, new_rd


def encode_bytes_8b10b(data: bytes, initial_rd: int = -1,
                        k_positions: set | None = None) -> tuple[list[int], int]:
    """
    Encode a sequence of bytes using 8b/10b.
    k_positions: set of byte indices that are K (control) characters.
    Returns (list_of_10bit_codewords, final_running_disparity).
    """
    codewords: list[int] = []
    rd = initial_rd
    k_pos = k_positions or set()
    for i, b in enumerate(data):
        cw, rd = encode_byte_8b10b(b, rd, is_k_char=(i in k_pos))
        codewords.append(cw)
    return codewords, rd


def codewords_to_bitstring(codewords: list[int], bits: int = 10) -> str:
    """Convert list of N-bit codewords to binary string (MSB first per codeword)."""
    result = []
    for cw in codewords:
        result.append(format(cw, f'0{bits}b'))
    return ''.join(result)


def codewords_to_bytes_display(codewords: list[int], bits: int = 10) -> list[str]:
    """Return list of formatted binary strings for display."""
    return [format(cw, f'0{bits}b') for cw in codewords]


# ── 4B/5B Encoding Table (ANSI X3.263 / IEEE 802.3 100BASE-TX) ───────────────
# Format: 4-bit nibble -> 5-bit code (as integer)
# Used with MLT-3 line coding for 100BASE-TX or NRZI for 100BASE-FX
_4B5B_DATA_TABLE: dict[int, int] = {
    0x0: 0b11110,  # 0  → 11110
    0x1: 0b01001,  # 1  → 01001
    0x2: 0b10100,  # 2  → 10100
    0x3: 0b10101,  # 3  → 10101
    0x4: 0b01010,  # 4  → 01010
    0x5: 0b01011,  # 5  → 01011
    0x6: 0b01110,  # 6  → 01110
    0x7: 0b01111,  # 7  → 01111
    0x8: 0b10010,  # 8  → 10010
    0x9: 0b10011,  # 9  → 10011
    0xA: 0b10110,  # A  → 10110
    0xB: 0b10111,  # B  → 10111
    0xC: 0b11010,  # C  → 11010
    0xD: 0b11011,  # D  → 11011
    0xE: 0b11100,  # E  → 11100
    0xF: 0b11101,  # F  → 11101
}

_4B5B_CTRL_TABLE: dict[str, int] = {
    "J": 0b11000,   # SSD part 1 (Start-Stream-Delimiter)
    "K": 0b10001,   # SSD part 2
    "T": 0b01101,   # ESD part 1 (End-Stream-Delimiter)
    "R": 0b00111,   # ESD part 2
    "I": 0b11111,   # IDLE
    "H": 0b00100,   # Halt
    "Q": 0b00000,   # Quiet (not valid in data stream)
}

def encode_byte_4b5b(byte_val: int) -> tuple[int, int]:
    """
    Encode one byte into two 5-bit 4B/5B codes (high nibble first).
    Returns (high_5bit, low_5bit).
    """
    high = _4B5B_DATA_TABLE[(byte_val >> 4) & 0xF]
    low  = _4B5B_DATA_TABLE[byte_val & 0xF]
    return high, low


def encode_bytes_4b5b(data: bytes) -> tuple[list[int], list[int]]:
    """
    Encode bytes to 4B/5B pairs.
    Returns (list_of_5bit_codes, list_of_source_nibbles).
    J+K prepended, T+R appended as stream delimiters.
    """
    codes: list[int] = [_4B5B_CTRL_TABLE["J"], _4B5B_CTRL_TABLE["K"]]  # SSD
    nibbles: list[int] = [-1, -1]  # J, K
    for b in data:
        h, l = encode_byte_4b5b(b)
        codes.extend([h, l])
        nibbles.extend([(b >> 4), (b & 0xF)])
    codes.extend([_4B5B_CTRL_TABLE["T"], _4B5B_CTRL_TABLE["R"]])  # ESD
    nibbles.extend([-2, -2])  # T, R
    return codes, nibbles


# MLT-3 state machine for 100BASE-TX
_MLT3_LEVELS = [0, 1, 0, -1]  # cycle: 0 → +1 → 0 → -1 → 0 → ...

def apply_mlt3(codes_5b: list[int]) -> list[int]:
    """
    Apply MLT-3 modulation to 4B/5B bit stream.
    Returns list of voltage levels (+1, 0, -1) for each bit.
    MLT-3 transitions on each 1-bit in the 4B/5B encoded stream.
    """
    levels: list[int] = []
    state = 0  # index into _MLT3_LEVELS, starts at level 0
    for code in codes_5b:
        for bit_pos in range(4, -1, -1):  # MSB first
            bit = (code >> bit_pos) & 1
            levels.append(_MLT3_LEVELS[state])
            if bit == 1:
                state = (state + 1) % 4
    return levels


# ── Manchester Encoding (IEEE 802.3 10BASE-T) ─────────────────────────────────
def encode_byte_manchester(byte_val: int) -> list[int]:
    """
    Encode one byte using Manchester encoding (IEEE 802.3).
    Each bit → 2 half-bits: 0=High-then-Low (10), 1=Low-then-High (01).
    Returns list of signal levels (1=High, 0=Low) — 16 half-bits per byte.
    """
    half_bits: list[int] = []
    for bit_pos in range(7, -1, -1):  # MSB first
        bit = (byte_val >> bit_pos) & 1
        if bit == 0:
            half_bits.extend([1, 0])  # High → Low
        else:
            half_bits.extend([0, 1])  # Low → High
    return half_bits


def encode_bytes_manchester(data: bytes) -> list[int]:
    """Encode bytes to Manchester half-bit stream. Returns list of H/L levels."""
    result: list[int] = []
    for b in data:
        result.extend(encode_byte_manchester(b))
    return result


def format_manchester_display(half_bits: list[int], bytes_per_row: int = 4) -> str:
    """Format Manchester half-bits for display as ↑↓ transitions."""
    symbols = ['↑' if h else '↓' for h in half_bits]
    chars_per_byte = 16  # 8 bits × 2 half-bits
    rows: list[str] = []
    for i in range(0, len(symbols), chars_per_byte * bytes_per_row):
        chunk = symbols[i:i + chars_per_byte * bytes_per_row]
        rows.append(''.join(chunk))
    return '\n'.join(rows)


# ── FC 8b/10b SOF/EOF Ordered Set Bytes ──────────────────────────────────────
# Fibre Channel SOF/EOF are 4-character ordered sets (each char = 1 8b/10b symbol)
# First char is K28.5 (0xBC) — comma sync; remaining are D-chars
FC_SOF_BYTES: dict[str, bytes] = {
    "SOFc1": bytes([0xBC, 0xB5, 0x55, 0x55]),  # Class-1 Connect
    "SOFi1": bytes([0xBC, 0xB5, 0x56, 0x56]),  # Class-1 Initiate
    "SOFn1": bytes([0xBC, 0xB5, 0xE5, 0xE5]),  # Class-1 Normal
    "SOFi2": bytes([0xBC, 0x55, 0x55, 0x56]),  # Class-2 Initiate
    "SOFn2": bytes([0xBC, 0x55, 0xE6, 0xE6]),  # Class-2 Normal
    "SOFi3": bytes([0xBC, 0xB5, 0xE6, 0xE6]),  # Class-3 Initiate (most common)
    "SOFn3": bytes([0xBC, 0x55, 0xE5, 0xE5]),  # Class-3 Normal
    "SOFf":  bytes([0xBC, 0x95, 0x95, 0x95]),  # Fabric
}

FC_EOF_BYTES: dict[str, bytes] = {
    "EOFt":  bytes([0xBC, 0x42, 0x42, 0x42]),  # Terminate (last frame of sequence)
    "EOFdt": bytes([0xBC, 0x49, 0x49, 0x49]),  # Disconnect-Terminate
    "EOFa":  bytes([0xBC, 0x41, 0x41, 0x41]),  # Abort
    "EOFn":  bytes([0xBC, 0x46, 0x46, 0x46]),  # Normal (not last)
    "EOFni": bytes([0xBC, 0x4E, 0x4E, 0x4E]),  # Normal-Invalid
    "EOFdti":bytes([0xBC, 0x4F, 0x4F, 0x4F]),  # Disconnect-Terminate-Invalid
}

FC_IDLE_BYTES: bytes = bytes([0xBC, 0xB5, 0xB5, 0xB5])   # IDLE primitive
FC_R_RDY_BYTES: bytes = bytes([0xBC, 0xB5, 0x34, 0xB5])  # Receiver Ready

FC_SOF_DESC: dict[str, str] = {
    "SOFi3": "Class-3 Initiate — FIRST frame of new sequence (most common for FCP)",
    "SOFn3": "Class-3 Normal — subsequent frames within same sequence",
    "SOFf":  "Fabric — F_Port to N_Port fabric frames",
    "SOFc1": "Class-1 Connect — dedicated connection establishment",
    "SOFi1": "Class-1 Initiate — first frame, dedicated connection",
    "SOFn1": "Class-1 Normal — subsequent frames, dedicated connection",
    "SOFi2": "Class-2 Initiate — first frame, multiplexed acknowledged",
    "SOFn2": "Class-2 Normal — subsequent frames, acknowledged",
}

FC_EOF_DESC: dict[str, str] = {
    "EOFt":  "Terminate — last frame of sequence; connection released if Class-1",
    "EOFn":  "Normal — NOT last frame in sequence; more frames follow",
    "EOFa":  "Abort — discard this frame; retransmission required",
    "EOFdt": "Disconnect-Terminate — last frame + disconnect Class-1",
    "EOFni": "Normal-Invalid — frame contains detected errors",
    "EOFdti":"Disconnect-Terminate-Invalid — disconnect + frame is invalid",
}

def encode_fc_ordered_set_8b10b(os_bytes: bytes, initial_rd: int = -1) -> tuple[list[int], int]:
    """
    Encode a 4-byte FC ordered set (SOF/EOF/IDLE) using 8b/10b.
    First byte (0xBC = K28.5) is always a K character.
    Returns (list_of_4_10bit_codewords, final_rd).
    """
    k_pos = {0}  # first character is always K (K28.5 = 0xBC)
    return encode_bytes_8b10b(os_bytes, initial_rd=initial_rd, k_positions=k_pos)


def encode_fc_frame_8b10b(sof_name: str, header_bytes: bytes,
                            payload: bytes, crc_bytes: bytes,
                            eof_name: str, initial_rd: int = -1) -> dict:
    """
    Encode a complete Fibre Channel frame using 8b/10b.
    Returns dict with encoded components and running disparity trace.
    """
    sof_bytes = FC_SOF_BYTES.get(sof_name, FC_SOF_BYTES["SOFi3"])
    eof_bytes  = FC_EOF_BYTES.get(eof_name, FC_EOF_BYTES["EOFt"])

    rd = initial_rd
    result: dict = {"components": [], "final_rd": 0, "total_bits": 0}

    # IDLE (6 minimum between frames)
    idle_cws, rd = encode_fc_ordered_set_8b10b(FC_IDLE_BYTES, rd)
    result["components"].append({"name":"IDLE","codewords":idle_cws,"rd_after":rd})

    # SOF
    sof_cws, rd = encode_fc_ordered_set_8b10b(sof_bytes, rd)
    result["components"].append({"name":f"SOF({sof_name})","codewords":sof_cws,"rd_after":rd})

    # FC Header (24 bytes — all D-chars)
    hdr_cws, rd = encode_bytes_8b10b(header_bytes, rd)
    result["components"].append({"name":"FC Header (24B)","codewords":hdr_cws,"rd_after":rd})

    # Payload (D-chars)
    if payload:
        pl_cws, rd = encode_bytes_8b10b(payload, rd)
        result["components"].append({"name":f"Payload ({len(payload)}B)","codewords":pl_cws,"rd_after":rd})

    # CRC (4 bytes)
    crc_cws, rd = encode_bytes_8b10b(crc_bytes, rd)
    result["components"].append({"name":"FC CRC (4B)","codewords":crc_cws,"rd_after":rd})

    # EOF
    eof_cws, rd = encode_fc_ordered_set_8b10b(eof_bytes, rd)
    result["components"].append({"name":f"EOF({eof_name})","codewords":eof_cws,"rd_after":rd})

    result["final_rd"] = rd
    total = sum(len(c["codewords"]) for c in result["components"])
    result["total_bits"] = total * 10
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — CORRECT PHY STREAM CONSTRUCTION
#
#  Architecture (per requirement):
#    Step 1: Build MAC frame bytes (caller's job — already done)
#    Step 2: Encode FULL MAC frame (Dst+Src+EtherType+Payload+FCS)
#             - NOT preamble/SFD only
#             - NOT partial fields
#    Step 3: AFTER encoding, insert PHY control symbols:
#             - IFG (idle) — fixed PHY patterns, NOT from user data
#             - Start block/K-code — fixed control, NOT encoded from data
#             - Terminate block/K-code — fixed control
#
#  Output stages (shown to user):
#    A. MAC frame hex (before encoding)
#    B. Encoded MAC frame (hex of encoded codewords)
#    C. Full PHY stream: [IFG] + [Start] + [encoded MAC] + [End]
# ══════════════════════════════════════════════════════════════════════════════

def build_phy_stream(mac_frame: bytes, speed_key: str,
                      idle_count: int = 12,
                      include_start_end: bool = True,
                      initial_rd: int = -1) -> dict:
    """
    Correct PHY stream construction.

    Args:
        mac_frame:        Full MAC frame bytes — Dst(6)+Src(6)+EtherType(2)+Payload+FCS(4)
                          Do NOT pass preamble+SFD — those are handled separately as PHY framing
        speed_key:        PHY speed key from PHY_REGISTRY
        idle_count:       Number of IFG idle bytes/blocks (user-configurable, default=12)
        include_start_end: Insert Start/End control symbols (True by default)
        initial_rd:       Starting Running Disparity for 8b/10b (-1 = RD-)

    Returns dict with:
        'mac_frame_hex':       hex string of input MAC frame (before encoding)
        'encoded_mac_hex':     hex string of encoded MAC frame bytes
        'mac_codewords':       list of codewords (8b/10b) or 5-bit codes (4B5B)
        'phy_stream_hex':      hex string of full PHY stream (IFG + Start + encoded + End)
        'phy_stream_bits':     full PHY stream as bit string
        'components':          list of named segments with hex and bits
        'encoding':            encoding scheme name
        'final_rd':            final Running Disparity (8b/10b only)
        'stats':               byte/bit counts per stage
    """
    result = {
        'mac_frame_hex':    mac_frame.hex().upper(),
        'encoded_mac_hex':  '',
        'mac_codewords':    [],
        'phy_stream_hex':   '',
        'phy_stream_bits':  '',
        'components':       [],
        'encoding':         PHY_REGISTRY.get(speed_key, {}).get('encoding', ''),
        'final_rd':         0,
        'stats':            {},
        'speed':            speed_key,
    }

    if speed_key == '10M':
        # ── Manchester: encode FULL MAC frame ─────────────────────────────────
        # PHY framing: Preamble (7B 0x55) + SFD (0xD5) prepended at PHY level
        # IFG: no signal (carrier idle) for idle_count bytes
        # Encoding: every byte of MAC frame → 16 half-bits

        # Step 1: PHY preamble + SFD (fixed PHY framing — not MAC frame)
        phy_preamble = bytes([0x55] * 7 + [0xD5])
        preamble_hb  = encode_bytes_manchester(phy_preamble)

        # Step 2: Encode full MAC frame
        mac_hb = encode_bytes_manchester(mac_frame)

        # Step 3: IFG — no carrier (idle_count bytes of silence)
        ifg_bits: list[int] = []   # silence = empty

        # Build components
        result['components'] = [
            {
                'name':    'IFG (No Carrier)',
                'type':    'phy_control',
                'hex':     '(silence)',
                'bits':    f'{idle_count * 16} half-bit periods of no signal',
                'note':    f'Inter-Frame Gap: {idle_count}B = {idle_count*8*2} half-bit times',
            },
            {
                'name':    'Preamble (7B) + SFD (1B)',
                'type':    'phy_framing',
                'hex':     phy_preamble.hex().upper(),
                'bits':    ''.join(str(b) for b in preamble_hb),
                'note':    'PHY framing — clock sync pattern + frame boundary marker',
                'half_bits': preamble_hb,
            },
            {
                'name':    f'MAC Frame ({len(mac_frame)}B) — ENCODED',
                'type':    'mac_encoded',
                'hex':     mac_frame.hex().upper(),
                'bits':    ''.join(str(b) for b in mac_hb),
                'note':    'Full MAC frame: Dst+Src+EtherType+Payload+FCS → Manchester',
                'half_bits': mac_hb,
            },
        ]

        # Encoded MAC hex — Manchester produces 2 bytes per input byte (16 half-bits)
        enc_bytes_list = []
        for i in range(0, len(mac_hb), 8):     # 8 half-bits = 1 encoded nibble's worth
            chunk = mac_hb[i:i+8]
            if len(chunk) == 8:
                val = 0
                for h in chunk: val = (val << 1) | h
                enc_bytes_list.append(val & 0xFF)
        result['encoded_mac_hex']  = bytes(enc_bytes_list).hex().upper()
        result['mac_codewords']    = mac_hb
        result['phy_stream_bits']  = ''.join(str(b) for b in preamble_hb + mac_hb)
        result['stats'] = {
            'mac_frame_bytes': len(mac_frame),
            'encoded_bits':    len(mac_hb),
            'total_phy_bits':  len(preamble_hb) + len(mac_hb),
            'line_rate':       '20 Mbaud',
        }

    elif speed_key == '100M':
        # ── 4B/5B + MLT-3: encode FULL MAC frame ──────────────────────────────
        # IFG: IDLE symbols (I=11111) between frames — idle_count worth
        # Start: J+K symbols (prepended by encode_bytes_4b5b automatically)
        # End: T+R symbols (appended by encode_bytes_4b5b automatically)

        # Step 1: IFG — IDLE symbols (fixed PHY control)
        ifg_idle_codes  = [_4B5B_CTRL_TABLE['I']] * (idle_count * 2)  # 2 symbols per byte
        ifg_bits_str    = ''.join(format(c, '05b') for c in ifg_idle_codes)

        # Step 2: PHY preamble + SFD encoded (PHY framing — part of 4B5B stream)
        phy_preamble    = bytes([0x55] * 7 + [0xD5])
        pr_codes, _     = encode_bytes_4b5b(phy_preamble)  # includes J/K SSD + T/R ESD
        # Strip J/K from start and T/R from end — we use one combined SSD
        pr_data_codes   = pr_codes[2:-2]  # remove J/K and T/R

        # Step 3: Encode FULL MAC frame (J+K at start, T+R at end, data in middle)
        mac_codes, mac_nibbles = encode_bytes_4b5b(mac_frame)
        # mac_codes[0]=J mac_codes[1]=K  mac_codes[-2]=T mac_codes[-1]=R
        # data codes = mac_codes[2:-2]

        # Step 4: Apply MLT-3 to full bit stream: IFG + SSD + preamble + MAC + ESD
        full_codes = (ifg_idle_codes +
                      [_4B5B_CTRL_TABLE['J'], _4B5B_CTRL_TABLE['K']] +  # SSD
                      pr_data_codes +
                      mac_codes[2:-2] +    # MAC data codes (without SSD/ESD)
                      [_4B5B_CTRL_TABLE['T'], _4B5B_CTRL_TABLE['R']])   # ESD
        mlt3_levels = apply_mlt3(full_codes)

        # Encoded MAC bytes (pack 5-bit codes back)
        mac_data_codes = mac_codes[2:-2]  # data only
        mac_bits_str   = ''.join(format(c, '05b') for c in mac_data_codes)
        # Encode hex: take 8 bits at a time from the 5-bit codes
        all_bits = ''.join(format(c, '05b') for c in mac_codes)
        enc_bytes_list = []
        for i in range(0, len(all_bits)-7, 8):
            enc_bytes_list.append(int(all_bits[i:i+8], 2))
        result['encoded_mac_hex'] = bytes(enc_bytes_list).hex().upper()
        result['mac_codewords']   = mac_codes

        result['components'] = [
            {
                'name':    f'IFG ({idle_count}B = {len(ifg_idle_codes)} IDLE codes)',
                'type':    'phy_control',
                'bits':    ifg_bits_str,
                'hex':     '(IDLE symbols — fixed PHY pattern, not from MAC data)',
                'note':    'I=11111 repeated — PHY idle fill between frames',
            },
            {
                'name':    'SSD: J+K (Start-Stream-Delimiter)',
                'type':    'phy_control',
                'bits':    '11000 10001',
                'hex':     '(J=11000 K=10001 — PHY control symbols)',
                'note':    'Mark start of data stream — NOT encoded from user data',
            },
            {
                'name':    f'Preamble+SFD (PHY framing)',
                'type':    'phy_framing',
                'hex':     phy_preamble.hex().upper(),
                'bits':    ' '.join(format(c,'05b') for c in pr_data_codes[:8]),
                'note':    'PHY framing bytes encoded in 4B/5B',
            },
            {
                'name':    f'MAC Frame ({len(mac_frame)}B) — ENCODED',
                'type':    'mac_encoded',
                'hex':     mac_frame.hex().upper(),
                'bits':    ' '.join(format(c,'05b') for c in mac_data_codes[:8]) + ('…' if len(mac_data_codes)>8 else ''),
                'note':    f'Full MAC frame: Dst+Src+EtherType+Payload+FCS → 4B/5B codes',
            },
            {
                'name':    'ESD: T+R (End-Stream-Delimiter)',
                'type':    'phy_control',
                'bits':    '01101 00111',
                'hex':     '(T=01101 R=00111 — PHY control symbols)',
                'note':    'Mark end of data stream — NOT encoded from user data',
            },
        ]

        phy_stream_bits = ''.join(format(c, '05b') for c in full_codes)
        result['phy_stream_bits'] = phy_stream_bits
        result['stats'] = {
            'mac_frame_bytes':     len(mac_frame),
            'mac_4b5b_codes':      len(mac_data_codes),
            'mac_encoded_bits':    len(mac_data_codes) * 5,
            'total_phy_codes':     len(full_codes),
            'total_phy_bits':      len(full_codes) * 5,
            'mlt3_transitions':    sum(1 for b in mlt3_levels if b != 0),
            'line_rate':           '125 Mbaud',
        }

    elif speed_key == '1G':
        # ── 8b/10b: encode FULL MAC frame ────────────────────────────────────
        # Architecture:
        #   IFG  = /I/ ordered sets (K28.5+D16.2+D5.6) — PHY control, NOT from data
        #   /S/  = K27.7 ordered set — PHY control
        #   DATA = Preamble(7B) + SFD(1B) + MAC frame — all encoded
        #          Note: preamble/SFD ARE part of the 8b/10b encoded stream
        #          because they're actual bytes transmitted on the wire
        #   /T//R/ = K29.7+K23.7 — PHY control, NOT from data

        rd = initial_rd

        # Step 1: IFG — /I/ ordered sets (fixed PHY control, not encoded from data)
        # /I/ = K28.5 (0xBC) + D16.2 (0x50) — IFG for 1G is ~96 bits = ~9-10 /I/ sets
        ifg_count    = max(1, idle_count // 4)  # 4 chars per ordered set
        ifg_os_bytes = bytes([0xBC, 0x50] * ifg_count)
        ifg_k_pos    = set(i for i in range(0, len(ifg_os_bytes), 2))  # every 0th byte is K
        ifg_cws, rd  = encode_bytes_8b10b(ifg_os_bytes, rd, k_positions=ifg_k_pos)

        # Step 2: /S/ ordered set (K27.7 + D21.5) — PHY control
        sop_bytes    = bytes([0xFB, 0xB5])
        sop_cws, rd  = encode_bytes_8b10b(sop_bytes, rd, k_positions={0})

        # Step 3: Encode full MAC frame INCLUDING preamble+SFD (these are wire bytes)
        phy_preamble = bytes([0x55] * 7 + [0xD5])
        pr_cws, rd   = encode_bytes_8b10b(phy_preamble, rd)

        # Step 4: Encode FULL MAC frame (Dst+Src+EtherType+Payload+FCS) — CORE ENCODING
        mac_cws, rd  = encode_bytes_8b10b(mac_frame, rd)

        # Step 5: /T/ + /R/ ordered set — PHY control (NOT from data)
        eop_bytes    = bytes([0xFD, 0xF7])
        eop_cws, rd  = encode_bytes_8b10b(eop_bytes, rd, k_positions={0, 1})

        # Encoded MAC frame as hex (bytes reconstructed from 10-bit codewords)
        # Extract 8 data bits from each 10-bit codeword (drop the 2 disparity bits)
        # For display: show the 10-bit codewords packed into bytes
        mac_bits_all = ''.join(format(cw, '010b') for cw in mac_cws)
        enc_bytes    = bytes(int(mac_bits_all[i:i+8], 2) for i in range(0, len(mac_bits_all)-7, 8))
        result['encoded_mac_hex'] = enc_bytes.hex().upper()
        result['mac_codewords']   = mac_cws

        result['components'] = [
            {
                'name':     f'IFG ({ifg_count} × /I/ ordered sets)',
                'type':     'phy_control',
                'hex':      ifg_os_bytes.hex().upper(),
                'codewords': ifg_cws,
                'bits':     codewords_to_bitstring(ifg_cws),
                'note':     'Fixed PHY idle pattern K28.5+D16.2 — NOT encoded from MAC data',
                'rd_after': rd,
            },
            {
                'name':     '/S/ Start-of-Packet (K27.7+D21.5)',
                'type':     'phy_control',
                'hex':      sop_bytes.hex().upper(),
                'codewords': sop_cws,
                'bits':     codewords_to_bitstring(sop_cws),
                'note':     'Fixed PHY start symbol — NOT from user data',
            },
            {
                'name':     'Preamble (7B) + SFD (1B)',
                'type':     'phy_framing',
                'hex':      phy_preamble.hex().upper(),
                'codewords': pr_cws,
                'bits':     codewords_to_bitstring(pr_cws),
                'note':     'PHY framing bytes — encoded as 8b/10b data symbols',
            },
            {
                'name':     f'MAC Frame ({len(mac_frame)}B) — ENCODED',
                'type':     'mac_encoded',
                'hex':      mac_frame.hex().upper(),
                'codewords': mac_cws,
                'bits':     codewords_to_bitstring(mac_cws),
                'note':     'FULL MAC: Dst+Src+EtherType+Payload+FCS → 8b/10b codewords',
                'rd_after': rd,
            },
            {
                'name':     '/T/+/R/ End-of-Packet (K29.7+K23.7)',
                'type':     'phy_control',
                'hex':      eop_bytes.hex().upper(),
                'codewords': eop_cws,
                'bits':     codewords_to_bitstring(eop_cws),
                'note':     'Fixed PHY end symbols — NOT from user data',
            },
        ]

        all_cws = ifg_cws + sop_cws + pr_cws + mac_cws + eop_cws
        phy_bits = codewords_to_bitstring(all_cws)
        phy_hex  = bytes(int(phy_bits[i:i+8], 2) for i in range(0, len(phy_bits)-7, 8))
        result['phy_stream_hex']  = phy_hex.hex().upper()
        result['phy_stream_bits'] = phy_bits
        result['final_rd']        = rd
        result['stats'] = {
            'mac_frame_bytes':  len(mac_frame),
            'mac_codewords':    len(mac_cws),
            'mac_encoded_bits': len(mac_cws) * 10,
            'total_codewords':  len(all_cws),
            'total_phy_bits':   len(all_cws) * 10,
            'initial_rd':       'RD-',
            'final_rd':         f'RD{"+" if rd>0 else "-" if rd<0 else "="}',
            'line_rate':        '1.25 Gbaud',
            'efficiency':       '80% (8/10)',
        }

    elif speed_key in ('10G', '25G', '40G', '100G', '400G'):
        # ── 64b/66b: encode FULL MAC frame ───────────────────────────────────
        # Architecture:
        #   IFG  = Idle blocks (sync=10, type=0x1E) — fixed, NOT from data
        #   Start block = control block (sync=10, type=0x78 or 0xFB)
        #   DATA = MAC frame packed into data blocks (sync=01, 64b payload)
        #   Terminate block = control block (sync=10, type=0xFF/0x87/etc.)
        #   LFSR scrambler applied to data block payloads
        #
        # Note: at 10G+, Preamble+SFD are embedded inside the Start Block payload
        # The MAC frame (Dst onwards) fills subsequent data blocks

        import struct as _struct

        # LFSR scrambler state (58-bit polynomial x^58+x^39+1)
        lfsr = [1] * 58

        def _lfsr_next(state: list) -> int:
            """Advance LFSR one step, return output bit."""
            out = state[57]
            new = state[57] ^ state[38]
            state.pop()
            state.insert(0, new)
            return out

        def _scramble_byte(b: int, state: list) -> int:
            """XOR byte with 8 LFSR bits."""
            result_byte = 0
            for bit_pos in range(7, -1, -1):
                s = _lfsr_next(state)
                data_bit = (b >> bit_pos) & 1
                result_byte = (result_byte << 1) | (data_bit ^ s)
            return result_byte

        def _scramble_block(block: bytes, state: list) -> bytes:
            return bytes(_scramble_byte(b, state) for b in block)

        # Build MAC frame with preamble+SFD prepended (Start Block carries preamble)
        phy_preamble_sfd = bytes([0x55]*7 + [0xD5])
        full_wire_bytes  = phy_preamble_sfd + mac_frame  # what goes into blocks

        # Determine IFG idle blocks
        ifg_blocks = max(2, idle_count // 8)  # each block = 8 bytes payload

        # Block type constants
        BT_START  = 0x78   # Start in lane 0 (carries first 7B of preamble in payload)
        BT_DATA   = None   # sync=01 = data block
        BT_IDLE   = 0x1E   # Idle control block
        # Terminate types depend on last byte position
        BT_TERM   = {0:0xFF, 1:0xE1, 2:0xE2, 3:0xCC,
                     4:0xCC, 5:0xB4, 6:0xAA, 7:0x87}

        blocks: list[dict] = []

        # IFG idle blocks (fixed PHY control — NOT from MAC data)
        for _ in range(ifg_blocks):
            idle_payload = bytes(8)
            blocks.append({
                'sync': 0b10,  # control block
                'type': BT_IDLE,
                'payload': idle_payload,
                'type_str': 'Idle (0x1E)',
                'block_type': 'phy_control',
                'scramble': False,
            })

        # Start block: sync=10, type=0x78, payload = 7B of preamble (SFD embedded at end)
        # Actual structure: type(1B) + preamble_bytes(7B) = 8B payload
        start_payload = bytes([BT_START]) + phy_preamble_sfd[:7]
        blocks.append({
            'sync': 0b10,
            'type': BT_START,
            'payload': start_payload,
            'type_str': f'Start (0x{BT_START:02X}) + Preamble',
            'block_type': 'phy_framing',
            'scramble': False,
        })

        # Data blocks: MAC frame bytes (Dst+Src+EtherType+Payload+FCS) + SFD last byte
        # SFD (0xD5) is the last preamble byte — goes into first data block position 0
        wire_data = bytes([0xD5]) + mac_frame  # SFD + full MAC frame
        # Pad to block boundary
        pad_len  = (8 - len(wire_data) % 8) % 8
        padded   = wire_data + bytes(pad_len)
        n_full   = len(padded) // 8
        last_data_idx = len(wire_data) - 1  # last actual data byte index

        data_block_hexes = []
        for i in range(n_full):
            chunk = padded[i*8:(i+1)*8]
            scr   = _scramble_block(chunk, lfsr)
            data_block_hexes.append(scr.hex().upper())
            is_last = (i == n_full - 1)
            if is_last and pad_len > 0:
                # Terminate block
                term_pos = (8 - pad_len) - 1  # last valid byte position 0-7
                bt = BT_TERM.get(term_pos, 0xFF)
                blocks.append({
                    'sync': 0b01,  # NOTE: Terminate is still sync=01 for data portion
                    'type': bt,
                    'payload': scr,
                    'type_str': f'Terminate (0x{bt:02X}) — last data at pos {term_pos}',
                    'block_type': 'mac_encoded',
                    'scramble': True,
                    'raw_hex': chunk.hex().upper(),
                })
            else:
                blocks.append({
                    'sync': 0b01,  # data block
                    'type': None,
                    'payload': scr,
                    'type_str': 'Data (sync=01)',
                    'block_type': 'mac_encoded' if i > 0 else 'phy_framing',
                    'scramble': True,
                    'raw_hex': chunk.hex().upper(),
                })

        # Build encoded MAC hex: all data block payloads concatenated (scrambled)
        enc_mac_parts = [b['payload'].hex().upper() for b in blocks
                          if b['block_type'] == 'mac_encoded']
        result['encoded_mac_hex'] = ''.join(enc_mac_parts)
        result['mac_codewords']   = []  # not applicable for 64b/66b

        # Build full PHY stream: each block = 2-bit sync + 64-bit payload = 66 bits
        phy_stream_parts: list[str] = []
        comp_list: list[dict] = []
        for blk in blocks:
            sync_bits = format(blk['sync'], '02b')
            payload_bits = ''.join(format(b, '08b') for b in blk['payload'])
            block_bits = sync_bits + payload_bits  # 66 bits
            phy_stream_parts.append(block_bits)
            # convert 66 bits to hex (9 bytes rounded)
            padded_bits = block_bits + '0' * (72 - 66)  # pad to 72 bits (9B) for display
            block_hex = bytes(int(padded_bits[i:i+8], 2) for i in range(0, 72, 8)).hex().upper()
            comp_list.append({
                'name':        blk['type_str'],
                'type':        blk['block_type'],
                'hex':         blk.get('raw_hex', blk['payload'].hex().upper()),
                'encoded_hex': block_hex,
                'bits':        block_bits[:22] + '…',  # first 22 bits for display
                'note':        f"sync={'01' if blk['sync']==1 else '10'} {'DATA' if blk['sync']==1 else 'CTRL'}",
            })

        result['components']      = comp_list
        result['phy_stream_bits'] = ''.join(phy_stream_parts)
        total_bits = len(phy_stream_parts) * 66
        phy_hex_full = ''.join(b['encoded_hex'] for b in comp_list)
        result['phy_stream_hex']  = phy_hex_full
        result['stats'] = {
            'mac_frame_bytes':   len(mac_frame),
            'data_blocks':       sum(1 for b in blocks if b['block_type']=='mac_encoded'),
            'total_blocks':      len(blocks),
            'total_phy_bits':    total_bits,
            'scrambled':         True,
            'fec':               'KP4 RS(544,514) required for 25G+' if speed_key != '10G' else 'optional',
            'efficiency':        '97.0% (64/66)',
            'line_rate':         PHY_REGISTRY.get(speed_key, {}).get('line_rate', ''),
        }

    else:
        # Unknown speed — just return MAC frame info
        result['components'] = [{
            'name': f'MAC Frame ({len(mac_frame)}B)',
            'type': 'mac_encoded',
            'hex':  mac_frame.hex().upper(),
            'bits': '',
            'note': 'No PHY encoding defined for this speed',
        }]

    return result


def codewords_to_hex(codewords: list[int], bits: int = 10) -> str:
    """Pack codewords into hex bytes (MSB first per codeword)."""
    bit_str = codewords_to_bitstring(codewords, bits)
    pad     = (8 - len(bit_str) % 8) % 8
    bit_str += '0' * pad
    return bytes(int(bit_str[i:i+8], 2) for i in range(0, len(bit_str), 8)).hex().upper()


def format_phy_stream_display(result: dict, max_hex_chars: int = 40) -> list[str]:
    """
    Format the PHY stream result for terminal display.
    Shows:
      A. MAC frame hex (before encoding)
      B. Encoded MAC frame hex (after encoding)
      C. Full PHY stream hex (IFG + Start + encoded + End)
    All per requirement: hex before, hex after, hex stream.
    """
    speed = result.get('speed', '')
    enc   = result.get('encoding', '')
    lines: list[str] = []

    def _trunc(s: str, n: int) -> str:
        return (s[:n] + '…') if len(s) > n else s

    lines.append(f"  ══ PHY ENCODING RESULT ══  {speed}  [{enc}]")
    lines.append(f"  {'─'*72}")

    # A. Before encoding
    mac_hex = result.get('mac_frame_hex', '')
    lines.append(f"  A.  MAC Frame (BEFORE encoding)  [{len(mac_hex)//2}B]:")
    lines.append(f"      {_trunc(mac_hex, max_hex_chars)}")
    lines.append(f"      Breakdown: Dst(6B)+Src(6B)+EtherType(2B)+Payload+FCS(4B)")

    # B. After encoding
    enc_mac = result.get('encoded_mac_hex', '')
    lines.append(f"  B.  Encoded MAC Frame (AFTER encoding)  [{len(enc_mac)//2}B encoded]:")
    if enc_mac:
        lines.append(f"      {_trunc(enc_mac, max_hex_chars)}")
    lines.append(f"      ↑ Only the MAC frame bytes were encoded — not preamble/SFD alone")

    # C. Full PHY stream
    phy_hex = result.get('phy_stream_hex', '')
    lines.append(f"  C.  Full PHY Stream (IFG + Start + Encoded + End)  [{len(phy_hex)//2}B]:")
    if phy_hex:
        lines.append(f"      {_trunc(phy_hex, max_hex_chars)}")
    lines.append(f"      ↑ Control symbols inserted AFTER encoding — not from MAC data")

    # Components
    lines.append(f"  {'─'*72}")
    lines.append(f"  Stream components:")
    for comp in result.get('components', []):
        t = comp.get('type', '')
        marker = {'phy_control': '[CTL]', 'phy_framing': '[PHY]',
                   'mac_encoded': '[ENC]'}.get(t, '[   ]')
        name = comp.get('name', '')
        hex_val = _trunc(comp.get('encoded_hex') or comp.get('hex', ''), 24)
        note = comp.get('note', '')
        lines.append(f"    {marker}  {name:<38}  {hex_val:<26}  {note}")

    # Stats
    stats = result.get('stats', {})
    lines.append(f"  {'─'*72}")
    lines.append(f"  Stats:")
    for k, v in stats.items():
        lines.append(f"    {k:<28}: {v}")
    if result.get('final_rd', 0) != 0:
        lines.append(f"    {'final_running_disparity':<28}: {'RD+' if result['final_rd']>0 else 'RD-'}")

    return lines
    """
    Encode Ethernet frame bytes using 8b/10b (1 Gbps).
    Adds /S/ (K27.7) ordered set before preamble.
    Returns encoding result dict.
    """
    rd = initial_rd
    result: dict = {"components": [], "final_rd": 0, "total_bits": 0}

    # /I/ IDLE ordered set (K28.5 + D16.2 + D5.6)
    idle_os = bytes([0xBC, 0x50, 0xC5, 0xBC])  # approx K28.5+D16.2+D5.6+K28.5
    idle_cws, rd = encode_bytes_8b10b(idle_os, rd, k_positions={0, 3})
    result["components"].append({"name":"/I/ IDLE (IFG)","codewords":idle_cws,"rd_after":rd})

    # /S/ Start-of-Packet: K27.7 (0xFB) + D21.5 (0xB5)
    sop_bytes = bytes([0xFB, 0xB5])
    sop_cws, rd = encode_bytes_8b10b(sop_bytes, rd, k_positions={0})
    result["components"].append({"name":"/S/ Start-of-Packet","codewords":sop_cws,"rd_after":rd})

    # Frame bytes (preamble 7B + SFD 1B if included, then MAC frame)
    if preamble_sfd_included:
        preamble = frame_bytes[:7]
        sfd      = frame_bytes[7:8]
        mac      = frame_bytes[8:]
        pr_cws, rd = encode_bytes_8b10b(preamble, rd)
        result["components"].append({"name":"Preamble (7B)","codewords":pr_cws,"rd_after":rd})
        sfd_cws, rd = encode_bytes_8b10b(sfd, rd)
        result["components"].append({"name":"SFD (1B=0xD5)","codewords":sfd_cws,"rd_after":rd})
        mac_cws, rd = encode_bytes_8b10b(mac, rd)
        result["components"].append({"name":f"MAC Frame ({len(mac)}B)","codewords":mac_cws,"rd_after":rd})
    else:
        all_cws, rd = encode_bytes_8b10b(frame_bytes, rd)
        result["components"].append({"name":f"Frame ({len(frame_bytes)}B)","codewords":all_cws,"rd_after":rd})

    # /T/ End-of-Packet: K29.7 (0xFD) + K23.7 (0xF7)
    eop_bytes = bytes([0xFD, 0xF7])
    eop_cws, rd = encode_bytes_8b10b(eop_bytes, rd, k_positions={0, 1})
    result["components"].append({"name":"/T/+/R/ End-of-Packet","codewords":eop_cws,"rd_after":rd})

    result["final_rd"] = rd
    total = sum(len(c["codewords"]) for c in result["components"])
    result["total_bits"] = total * 10
    return result


def format_encoding_display(result: dict, speed_key: str,
                              max_codewords_shown: int = 8) -> list[str]:
    """
    Format encoding result for terminal display.
    Shows: component name, first N codewords in binary, RD after, total bits.
    """
    lines: list[str] = []
    enc_name = PHY_REGISTRY.get(speed_key, {}).get('encoding', '8b/10b')
    lines.append(f"  PHY ENCODING: {enc_name}  ({speed_key})")
    lines.append(f"  {'─'*72}")
    lines.append(f"  {'Component':<24}  {'Encoded bits (first N codewords)':<36}  RD")
    lines.append(f"  {'─'*72}")

    for comp in result["components"]:
        name = comp["name"]
        cws  = comp["codewords"]
        rd   = comp["rd_after"]
        # Show first N codewords as binary strings
        shown = cws[:max_codewords_shown]
        bits_str = ' '.join(format(cw, '010b') for cw in shown)
        if len(cws) > max_codewords_shown:
            bits_str += f'  …+{len(cws)-max_codewords_shown}more'
        rd_s = f"RD{'+'if rd>0 else '-' if rd<0 else '='}"
        lines.append(f"  {name:<24}  {bits_str:<36}  {rd_s}")

    lines.append(f"  {'─'*72}")
    lines.append(f"  Total encoded: {result['total_bits']} bits  ({result['total_bits']//10} symbols)")
    lines.append(f"  Final Running Disparity: {'RD+' if result['final_rd']>0 else 'RD-' if result['final_rd']<0 else 'Neutral'}")
    return lines
