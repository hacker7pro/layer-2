"""
Network Frame Builder
Layered input flow:  L1 (Physical) -> L2 (Data Link) -> L3 (Network) -> L4 (Transport/Control)
Every field is labelled with its layer in the final output table.
"""
import struct, zlib, socket

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

W   = 118           # total print width
SEP = "═" * W
DIV = "─" * W
HDR = "─" * W

# Layer colour tags used in the field table
LAYER_TAG = {
    1: "[L1-PHY ]",
    2: "[L2-DL  ]",
    3: "[L3-NET ]",
    4: "[L4-CTRL]",
    0: "[TRAILER]",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def get(prompt, default=""):
    """Simple prompted input with default."""
    val = input(f"    {prompt} [{default}]: ").strip()
    return val if val else default

def get_hex(prompt, default_hex, byte_len=None):
    """Prompt for hex bytes, validate length."""
    while True:
        raw = input(f"    {prompt} [{default_hex}]: ").strip().lower()
        if not raw:
            print(f"      -> using default: {default_hex}")
            return bytes.fromhex(default_hex.replace(" ","").replace(":",""))
        try:
            cleaned = raw.replace(":","").replace("-","").replace(" ","")
            b = bytes.fromhex(cleaned)
            if byte_len and len(b) != byte_len:
                print(f"      -> need exactly {byte_len} bytes ({byte_len*2} hex chars)")
                continue
            return b
        except ValueError:
            print("      -> invalid hex, try again")

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

def inet_cksum(data):
    """RFC 1071 one's-complement checksum."""
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

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

# ═══════════════════════════════════════════════════════════════════════════════
#  PRINT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def banner(title, subtitle=""):
    print(f"\n{SEP}")
    print(f"  {title}")
    if subtitle: print(f"  {subtitle}")
    print(SEP)

def section(title):
    print(f"\n  {'▌ '+title}")
    print(f"  {DIV}")

def print_frame_table(records):
    """
    records: list of dicts with keys:
        layer   : int  (1/2/3/4/0)
        name    : str  field name
        raw     : bytes
        note    : str  human-readable value / description
        user_val: str  the exact value the user entered (or auto)
    """
    print(f"\n{SEP}")
    print(f"  {'COMPLETE FRAME  –  FIELD-BY-FIELD TABLE':^{W-2}}")
    print(SEP)
    hdr = (f"  {'Byte':>6}  "
           f"{'Layer':<11}  "
           f"{'Field Name':<28}  "
           f"{'Size':>8}  "
           f"{'Hex Value':<30}  "
           f"{'User Input / Note'}")
    print(hdr)
    print(f"  {DIV}")

    offset = 0
    prev_layer = None
    for r in records:
        lay  = r['layer']
        name = r['name']
        raw  = r['raw']
        note = r.get('note', '')
        uval = r.get('user_val', '')

        # separator when layer changes
        if lay != prev_layer and prev_layer is not None:
            print(f"  {'·'*114}")
        prev_layer = lay

        sz   = len(raw)
        hexs = ' '.join(f'{b:02x}' for b in raw)
        # truncate hex display if very long
        if len(hexs) > 29: hexs = hexs[:27] + '..'

        # Build user-input annotation
        annotation = uval if uval else note
        # show note separately if both exist
        if uval and note and uval != note:
            annotation = f"{uval}  ({note})"

        tag = LAYER_TAG.get(lay, "        ")
        print(f"  {offset:5d}-{offset+sz-1:<4d}  "
              f"{tag}  "
              f"  {name:<28}  "
              f"{sz:3d}B/{sz*8:4d}b  "
              f"  {hexs:<30}  "
              f"  {annotation}")
        offset += sz

    print(f"  {DIV}")
    print(f"  {'Total':>5}: {offset} bytes  /  {offset*8} bits")
    print(SEP)

def print_encapsulation(records, frame):
    """
    Print three things:
    1. Nested encapsulation box diagram showing which bytes belong to which layer
    2. Annotated hex dump with layer markers
    3. Plain final hex (no gaps) + total bytes
    """
    W2 = 110

    # ── collect layer spans ────────────────────────────────────────────────────
    # Each span: (start_byte, end_byte_inclusive, layer, group_name)
    layer_spans = []   # list of (start, end, layer, label)
    offset = 0
    for r in records:
        sz = len(r['raw'])
        layer_spans.append((offset, offset+sz-1, r['layer'], r['name']))
        offset += sz
    total_bytes = offset

    # ── group spans by layer into contiguous blocks ────────────────────────────
    # We want: L1 block, L2 block, L3 block, L4 block, Trailer block
    # Build: layer -> (first_byte, last_byte, display_label)
    layer_groups = {}
    for (s, e, lay, name) in layer_spans:
        if lay not in layer_groups:
            layer_groups[lay] = [s, e, name]
        else:
            layer_groups[lay][1] = e   # extend end
    # Assign group labels
    LAYER_LABELS = {
        1: "LAYER 1  Physical  (Preamble + SFD / Flags)",
        2: "LAYER 2  Data Link  (MAC / Serial header)",
        3: "LAYER 3  Network   (IP / ARP / BPDU / DTP / PAgP / LACP)",
        4: "LAYER 4  Transport (TCP / UDP / ICMP)",
        0: "TRAILER  (FCS / CRC)",
    }

    # ── determine protocol names per layer from records ────────────────────────
    def proto_names(layer):
        seen = []
        for r in records:
            if r['layer'] == layer:
                n = r['name'].split()[0]
                if n not in seen:
                    seen.append(n)
        return ' | '.join(seen[:4])

    # ── Print encapsulation diagram ────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  {'FRAME ENCAPSULATION  —  STRUCTURE DIAGRAM':^{W-2}}")
    print(SEP)
    print()

    sorted_layers = sorted(layer_groups.keys(), key=lambda x: (x if x != 0 else 99))

    # Box drawing chars
    TL='╔'; TR='╗'; BL='╚'; BR='╝'; H='═'; V='║'
    ITL='╠'; ITR='╣'; IH='─'; IML='├'; IMR='┤'

    indent_map = {1:0, 2:2, 3:4, 4:6, 0:0}

    for lay in sorted_layers:
        s, e, _ = layer_groups[lay]
        ind   = ' ' * indent_map.get(lay, 0)
        width = W2 - indent_map.get(lay, 0) - 2
        label = LAYER_LABELS.get(lay, f"Layer {lay}")
        proto = proto_names(lay)
        bytes_count = e - s + 1

        # Top border
        print(f"  {ind}{TL}{H*width}{TR}")
        # Label line
        content = f"  {label}"
        print(f"  {ind}{V}{content:<{width}}{V}")
        # Protocol line
        if proto:
            pcontent = f"  Protocols: {proto}"
            print(f"  {ind}{V}{pcontent:<{width}}{V}")
        # Byte range line
        bcontent = f"  Bytes {s}–{e}  ({bytes_count} bytes / {bytes_count*8} bits)"
        print(f"  {ind}{V}{bcontent:<{width}}{V}")
        # Fields line — list all field names
        fnames = [r['name'] for r in records if r['layer'] == lay]
        # wrap field names into lines of ~width-4 chars
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
            print(f"  {ind}{V}{fl:<{width}}{V}")
        # Hex preview (first 24 bytes of this layer)
        layer_bytes = frame[s:e+1]
        hex_preview = ' '.join(f'{b:02x}' for b in layer_bytes[:24])
        if len(layer_bytes) > 24:
            hex_preview += ' ..'
        hcontent = f"  Hex: {hex_preview}"
        print(f"  {ind}{V}{hcontent:<{width}}{V}")
        # Bottom border (no close for layers that nest inside)
        if lay == 0:
            print(f"  {ind}{BL}{H*width}{BR}")
        elif lay == max(sorted_layers[:-1] if 0 in sorted_layers else sorted_layers):
            print(f"  {ind}{BL}{H*width}{BR}")
        else:
            # partial close — inner layer will continue
            print(f"  {ind}{BL}{H*width}{BR}")
        print()

    # ── Nesting summary ────────────────────────────────────────────────────────
    print(f"  {DIV}")
    print(f"  ENCAPSULATION SUMMARY  (outermost → innermost)")
    print(f"  {DIV}")
    nesting = []
    for lay in sorted(layer_groups.keys()):
        if lay == 0: continue
        s, e, _ = layer_groups[lay]
        proto = proto_names(lay)
        nesting.append(f"L{lay}({proto})")
    nesting_str = '  ──encapsulates──>  '.join(nesting)
    if 0 in layer_groups:
        s, e, _ = layer_groups[0]
        nesting_str += f"  ──trailer──>  FCS/CRC({e-s+1}B)"
    print(f"  {nesting_str}")
    print()
    # total sizes
    for lay in sorted(layer_groups.keys(), key=lambda x: x if x != 0 else 99):
        s, e, _ = layer_groups[lay]
        lname = LAYER_LABELS.get(lay, f"Layer {lay}")
        print(f"    {lname:<55}  {e-s+1:4d} bytes  /  {(e-s+1)*8:5d} bits  [byte {s}–{e}]")
    print(f"  {DIV}")
    print(f"  {'TOTAL FRAME':<55}  {total_bytes:4d} bytes  /  {total_bytes*8:5d} bits")
    print(f"  {DIV}")

    # ── Annotated hex dump ─────────────────────────────────────────────────────
    print()
    print(f"  {'─'*W2}")
    print(f"  {'ANNOTATED HEX DUMP  (16 bytes per row)':^{W2}}")
    print(f"  {'─'*W2}")
    print(f"  {'Offset':>6}  {'Hex (16 bytes per row)':<48}  {'ASCII':<16}  Layer annotation")
    print(f"  {'─'*W2}")

    # Build per-byte layer map
    byte_layer = {}
    byte_field  = {}
    for (s, e, lay, fname) in layer_spans:
        for b in range(s, e+1):
            byte_layer[b] = lay
            byte_field[b]  = fname

    LAYER_ABBR = {1:'PHY', 2:'DL ', 3:'NET', 4:'TRP', 0:'TRL'}

    row_size = 16
    for row_start in range(0, total_bytes, row_size):
        row_bytes = frame[row_start:row_start+row_size]
        hex_part  = ' '.join(f'{b:02x}' for b in row_bytes)
        asc_part  = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row_bytes)

        # determine dominant layer annotation for this row
        layers_in_row = []
        for i, b_idx in enumerate(range(row_start, row_start+len(row_bytes))):
            lay = byte_layer.get(b_idx, -1)
            if not layers_in_row or layers_in_row[-1][0] != lay:
                layers_in_row.append([lay, b_idx, b_idx])
            else:
                layers_in_row[-1][2] = b_idx

        # build annotation: "PHY[0-7] DL[8-21] NET[22-41]"
        ann_parts = []
        for (lay, bs, be) in layers_in_row:
            abbr = LAYER_ABBR.get(lay, '???')
            ann_parts.append(f"{abbr}[{bs}-{be}]")
        annotation = '  '.join(ann_parts)

        print(f"  {row_start:6d}  {hex_part:<48}  {asc_part:<16}  {annotation}")

    print(f"  {'─'*W2}")

    # ── Final hex no gaps ──────────────────────────────────────────────────────
    print()
    print(f"  {'─'*W2}")
    print(f"  {'FINAL HEX  (continuous, no gaps)':^{W2}}")
    print(f"  {'─'*W2}")
    hex_str = ''.join(f'{b:02x}' for b in frame)
    for i in range(0, len(hex_str), 64):
        print(f"  {hex_str[i:i+64]}")
    print(f"  {'─'*W2}")
    print(f"  Total bytes : {total_bytes}")
    print(f"  Total bits  : {total_bytes * 8}")
    print(SEP + "\n")

def ask_fcs_eth(fcs_input_bytes):
    """Ask user for Ethernet FCS preference, return (fcs_bytes, fcs_note)."""
    print(f"\n  ▌ ETHERNET FCS  (CRC-32 over {len(fcs_input_bytes)} bytes: Dst MAC → end of payload)")
    print(f"  {DIV}")
    ch = input("    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    if ch == '2':
        fcs_hex = input("    Enter 8 hex digits: ").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == 4: return fcs, "custom"
        except: pass
        print("    -> invalid, using auto")
    fcs = crc32_eth(fcs_input_bytes)
    return fcs, f"CRC-32 auto over {len(fcs_input_bytes)}B"

def ask_serial_crc(crc_input_bytes, crc_type, byte_order='big'):
    """Ask user for serial CRC preference."""
    print(f"\n  ▌ {crc_type}  (covers {len(crc_input_bytes)} bytes)")
    print(f"  {DIV}")
    ch = input(f"    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    crc_val = crc16_ccitt(crc_input_bytes)
    fcs_auto = crc_val.to_bytes(2, byte_order)
    if ch == '2':
        fcs_hex = input("    Enter hex: ").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == len(fcs_auto): return fcs, f"{crc_type} custom"
        except: pass
        print("    -> invalid, using auto")
    return fcs_auto, f"{crc_type} auto over {len(crc_input_bytes)}B"

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 1  –  PHYSICAL
# ═══════════════════════════════════════════════════════════════════════════════

def ask_layer1_eth():
    """Preamble + SFD for Ethernet."""
    section("LAYER 1 — Physical (Preamble + SFD)")
    preamble = get_hex("Preamble  7 bytes (14 hex)", "55555555555555", 7)
    sfd      = get_hex("SFD       1 byte  ( 2 hex)", "d5", 1)
    return preamble, sfd

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 2  –  DATA LINK
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  L2-A  Ethernet II / 802.3
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

    dst = get("Destination MAC", "ff:ff:ff:ff:ff:ff")
    src = get("Source MAC",      "00:11:22:33:44:55")

    llc_b = b''; snap_b = b''

    if v == '1':
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2)
        variant_name = "Ethernet II"
        type_len_b = et
    elif v == '2':
        variant_name = "IEEE 802.3 Raw"
        type_len_b = None   # computed after payload known
    elif v == '3':
        variant_name = "IEEE 802.3 + LLC"
        dsap = get_hex("DSAP (2 hex)", "42", 1)
        ssap = get_hex("SSAP (2 hex)", "42", 1)
        ctl  = get_hex("Control (2 hex)", "03", 1)
        llc_b = dsap + ssap + ctl
        type_len_b = None
    elif v == '4':
        variant_name = "IEEE 802.3 + LLC + SNAP"
        dsap = get_hex("DSAP (2 hex, SNAP=aa)", "aa", 1)
        ssap = get_hex("SSAP (2 hex, SNAP=aa)", "aa", 1)
        ctl  = get_hex("Control (2 hex)", "03", 1)
        llc_b = dsap + ssap + ctl
        oui  = get_hex("SNAP OUI (6 hex)", "000000", 3)
        pid  = get_hex("SNAP Protocol ID (4 hex)", ethertype_hint, 2)
        snap_b = oui + pid
        type_len_b = None
    else:
        v = '1'
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2)
        variant_name = "Ethernet II"
        type_len_b = et

    return mac_b(dst), mac_b(src), type_len_b, llc_b, snap_b, variant_name, dst, src, v

# ──────────────────────────────────────────────────────────────────────────────
#  L2-B  Serial / WAN protocols
# ──────────────────────────────────────────────────────────────────────────────

SERIAL_TYPES = {
    '1': "Raw",
    '2': "SLIP",
    '3': "PPP",
    '4': "HDLC",
    '5': "COBS (placeholder)",
    '6': "KISS",
    '7': "Modbus RTU",
    '8': "HDLC + Bit-Stuffing",
    '9': "ATM AAL5",
   '10': "Cisco HDLC",
}

def ask_l2_serial():
    section("LAYER 2 — Serial / WAN  (choose protocol)")
    for k,v in SERIAL_TYPES.items():
        print(f"      {k:>2} = {v}")
    ch = input("    Select [3]: ").strip() or '3'
    if ch not in SERIAL_TYPES: ch = '3'
    return ch, SERIAL_TYPES[ch]

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3  –  NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  ARP
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_arp():
    section("LAYER 3 — ARP")
    hw_type    = get("Hardware Type (1=Ethernet)", "1")
    proto_type = get("Protocol Type hex (0800=IPv4)", "0800")
    hw_len     = get("HW Address Length", "6")
    proto_len  = get("Protocol Address Length", "4")
    opcode     = get("Opcode  1=Request  2=Reply", "1")
    sender_ha  = get("Sender MAC", "00:11:22:33:44:55")
    sender_pa  = get("Sender IP",  "192.168.1.10")
    target_ha  = get("Target MAC", "00:00:00:00:00:00")
    target_pa  = get("Target IP",  "192.168.1.100")
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

# ──────────────────────────────────────────────────────────────────────────────
#  IPv4
# ──────────────────────────────────────────────────────────────────────────────

L3_PROTO_NAMES = {1:"ICMP", 6:"TCP", 17:"UDP", 41:"IPv6", 89:"OSPF", 47:"GRE"}

def ask_l3_ipv4():
    section("LAYER 3 — IPv4")
    src_ip  = get("Source IP",                  "192.168.1.10")
    dst_ip  = get("Destination IP",             "192.168.1.20")
    ttl     = get("TTL",                        "64")
    ip_id   = get("Identification (decimal)",   "4660")
    dscp    = get("DSCP/ECN (decimal, usu. 0)", "0")
    df      = get("DF flag? (y/n)",             "y")
    return src_ip, dst_ip, int(ttl), int(ip_id), int(dscp), df.lower().startswith('y'), 0

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

# ──────────────────────────────────────────────────────────────────────────────
#  STP / RSTP BPDU   (L2/L3 hybrid – uses 802.3 + LLC wrapper)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_stp():
    section("LAYER 3 — STP / RSTP BPDU")
    version   = get("Version  0=STP  2=RSTP", "2")
    bpdu_type = get("BPDU Type  00=Config  80=TCN", "00")
    flags     = get("Flags (hex)", "00")
    root_prio = get("Root Priority", "32768")
    root_mac  = get("Root MAC",     "00:00:00:00:00:00")
    path_cost = get("Root Path Cost", "0")
    br_prio   = get("Bridge Priority", "32768")
    br_mac    = get("Bridge MAC",      "00:11:22:33:44:55")
    port_id   = get("Port ID (hex)",   "8001")
    msg_age   = get("Message Age (sec)","0")
    max_age   = get("Max Age (sec)",   "20")
    hello     = get("Hello Time (sec)","2")
    fwd_delay = get("Forward Delay (sec)","15")
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

# ──────────────────────────────────────────────────────────────────────────────
#  DTP  (Cisco proprietary – carried in 802.3+SNAP frame)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_dtp():
    section("LAYER 3 — DTP  (Dynamic Trunking Protocol)")
    print("    Modes:  02=desirable  03=auto  04=on  05=off")
    mode = get("DTP Mode (hex)", "02")
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

# ──────────────────────────────────────────────────────────────────────────────
#  PAgP  (Cisco proprietary)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_pagp():
    section("LAYER 3 — PAgP  (Port Aggregation Protocol)")
    print("    Port State flags: 0x01=Active 0x04=Consistent 0x05=Active+Consistent")
    state = get("Port State (hex)", "05")
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

# ──────────────────────────────────────────────────────────────────────────────
#  LACP  (IEEE 802.3ad)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_lacp():
    section("LAYER 3 — LACP  (802.3ad Link Aggregation)")
    actor_mac   = get("Actor System MAC",  "00:11:22:33:44:55")
    actor_key   = get("Actor Key (hex)",   "0001")
    actor_state = get("Actor State (hex)  [3d=Active+Short+Aggregating+Sync+Col+Dist]", "3d")
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

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 4  –  TRANSPORT / CONTROL
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  ICMP
# ──────────────────────────────────────────────────────────────────────────────

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
    icmp_type = int(get("ICMP Type  (default=8 Echo Request)", "8"))
    if icmp_type in ICMP_TABLE:
        codes = ICMP_TABLE[icmp_type][1]
        code_hint = "  ".join(f"{c}={d}" for c,d in sorted(codes.items()))
        print(f"    Valid codes: {code_hint}")
    icmp_code = int(get("ICMP Code", "0"))
    icmp_id   = int(get("ICMP Identifier (decimal)", "1"))
    icmp_seq  = int(get("ICMP Sequence   (decimal)", "1"))
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

# ═══════════════════════════════════════════════════════════════════════════════
#  WELL-KNOWN PORT TABLE
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
#  TCP PSEUDO-HEADER CHECKSUM  (RFC 793)
# ═══════════════════════════════════════════════════════════════════════════════

def tcp_checksum(src_ip, dst_ip, tcp_segment):
    """RFC 793: checksum over pseudo-header + TCP segment."""
    pseudo = (ip_b(src_ip) + ip_b(dst_ip) +
              b'\x00' + b'\x06' +
              struct.pack("!H", len(tcp_segment)))
    return inet_cksum(pseudo + tcp_segment)

def udp_checksum(src_ip, dst_ip, udp_datagram):
    """RFC 768: checksum over pseudo-header + UDP datagram."""
    pseudo = (ip_b(src_ip) + ip_b(dst_ip) +
              b'\x00' + b'\x11' +
              struct.pack("!H", len(udp_datagram)))
    return inet_cksum(pseudo + udp_datagram)

# ═══════════════════════════════════════════════════════════════════════════════
#  TCP  –  3-WAY HANDSHAKE BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

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

    src_port = int(get("Source Port",      "49152"))
    dst_port = int(get("Destination Port", "80"))
    pn = port_note(dst_port) or port_note(src_port)
    if pn: print(f"    -> Port note: {pn}")

    seq_num  = int(get("Sequence Number  (ISN for SYN, else continuation)", "1000"))
    ack_num  = int(get("Acknowledgement Number  (0 if SYN, else peer_seq+1)", "0" if step=='1' else "1001"))
    data_off = 5     # header length = 5 * 4 = 20 bytes (no options)
    flags_val = default_flags
    print(f"    TCP Flags (hex, default={default_flags:#04x} = {step_name})")
    flags_in = get("Flags hex (Enter=default)", f"{default_flags:02x}")
    try:    flags_val = int(flags_in, 16)
    except: flags_val = default_flags

    window   = int(get("Window Size (bytes)", "65535"))
    urg_ptr  = int(get("Urgent Pointer      (0 unless URG set)", "0"))

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

# ═══════════════════════════════════════════════════════════════════════════════
#  UDP  –  DATAGRAM BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

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

def ask_l4_udp(src_ip, dst_ip):
    print_port_table()
    section("LAYER 4 — UDP")
    print("    UDP is connectionless – single datagram, no handshake.")
    print("    Common uses: DNS (53), DHCP (67/68), NTP (123), SNMP (161), TFTP (69)")

    src_port = int(get("Source Port",      "49152"))
    dst_port = int(get("Destination Port", "53"))
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

# ═══════════════════════════════════════════════════════════════════════════════
#  FRAME ASSEMBLERS
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
#  CHECKSUM VERIFY REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def verify_report(checks):
    """checks: list of (name, stored_val, verify_fn, pass_cond, pass_str)"""
    print(f"\n  {'─'*80}")
    print(f"  CHECKSUM / CRC VERIFICATION")
    print(f"  {'─'*80}")
    for name, stored, result, passed in checks:
        status = "PASS ✓" if passed else "FAIL ✗"
        print(f"  {name:<30}  stored={stored}   verify={result}   {status}")
    print(f"  {'─'*80}")

# ═══════════════════════════════════════════════════════════════════════════════
#  TOP-LEVEL FLOW CONTROLLERS
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + ARP
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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + IPv4 + ICMP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_ip_icmp():
    banner("ETHERNET  +  IPv4  +  ICMP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: ICMP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp,
     df, _) = ask_l3_ipv4()
    # L4
    icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
    icmp_msg, icmp_fields, icmp_ck = build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
    ip_hdr, ip_fields, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + STP/RSTP
# ──────────────────────────────────────────────────────────────────────────────

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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + DTP
# ──────────────────────────────────────────────────────────────────────────────

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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + PAgP
# ──────────────────────────────────────────────────────────────────────────────

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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + LACP
# ──────────────────────────────────────────────────────────────────────────────

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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + IPv4 + TCP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_ip_tcp():
    banner("ETHERNET  +  IPv4  +  TCP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: TCP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp, df, _) = ask_l3_ipv4()
    # Force protocol=6 (TCP) regardless of user proto input
    (step, step_name, src_port, dst_port, seq_num, ack_num,
     data_off, flags_val, window, urg_ptr, tcp_data,
     sip, dip) = ask_l4_tcp(src_ip, dst_ip)

    tcp_seg, tcp_fields, tcp_ck = build_tcp(
        step, step_name, src_port, dst_port, seq_num, ack_num,
        data_off, flags_val, window, urg_ptr, tcp_data, src_ip, dst_ip)

    ip_hdr, ip_fields, ip_ck = build_ipv4(
        tcp_seg, src_ip, dst_ip, ttl, ip_id, dscp, df, 6)

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

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + IPv4 + UDP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_ip_udp():
    banner("ETHERNET  +  IPv4  +  UDP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: UDP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp, df, _) = ask_l3_ipv4()

    (src_port, dst_port, udp_data,
     sip, dip) = ask_l4_udp(src_ip, dst_ip)

    udp_dgram, udp_fields, udp_ck = build_udp(
        src_port, dst_port, udp_data, src_ip, dst_ip)

    ip_hdr, ip_fields, ip_ck = build_ipv4(
        udp_dgram, src_ip, dst_ip, ttl, ip_id, dscp, df, 17)

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



def flow_serial():
    banner("SERIAL / WAN FRAME BUILDER",
           "L2: PPP | HDLC | SLIP | Modbus RTU | ATM AAL5 | Cisco HDLC | KISS | COBS")
    ch, proto_name = ask_l2_serial()

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

    # L3 inside serial
    l3_payload = b''
    l3_fields  = []
    if ch in ('3','4','8','10'):
        section("LAYER 3 — Payload inside Serial frame")
        print("    Options:  1=None (empty)   2=Raw hex   3=IPv4+ICMP")
        l3ch = input("    Choose [1]: ").strip() or '1'
        if l3ch == '2':
            phex = get("Payload hex", "")
            try:    l3_payload = bytes.fromhex(phex.replace(" ",""))
            except: l3_payload = b''
        elif l3ch == '3':
            (src_ip, dst_ip, ttl, ip_id, dscp, df, _) = ask_l3_ipv4()
            icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
            icmp_msg, icmp_flds, icmp_ck = build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
            ip_hdr, ip_flds, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
            l3_payload = ip_hdr + icmp_msg
            l3_fields  = ip_flds + icmp_flds

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
        cx = input("    1=Auto  2=Custom  [1]: ").strip() or '1'
        if cx == '2':
            fh = input("    Enter 8 hex digits: ").strip()
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
        records.append({"layer":1,"name":"Start Flag","raw":start_flag,"user_val":start_flag.hex(),"note":""})
    if address:
        records.append({"layer":2,"name":"Address","raw":address,"user_val":address.hex(),"note":""})
    if control:
        records.append({"layer":2,"name":"Control","raw":control,"user_val":control.hex(),"note":""})
    records += l3_fields
    if fcs:
        records.append({"layer":0,"name":f"CRC/FCS","raw":fcs,"user_val":"auto/custom","note":fcs_desc})
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"End Flag","raw":end_flag,"user_val":end_flag.hex(),"note":""})

    banner(f"SERIAL FRAME — {proto_name}")
    print_frame_table(records)
    print_encapsulation(records, full_frame)

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3 MENU  (what runs inside Ethernet)
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
#  ETHERNET PAUSE FRAME  (IEEE 802.3x / 802.3-2015 Clause 31)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  PURPOSE
#  ───────
#  An Ethernet Pause Frame is a MAC Control frame defined in IEEE 802.3x (now
#  part of IEEE 802.3-2015, Clause 31).  It implements *symmetric* (link-level)
#  flow control between two directly connected full-duplex Ethernet stations
#  (usually a NIC and a switch port, or two switch ports).
#
#  When a receiver's buffer is filling up it transmits a Pause frame toward the
#  sender, asking it to STOP sending for a given time quantum.  The sender MUST
#  honour the request and halt its transmission for that many quanta, after which
#  it may resume.  A Pause value of 0 means "resume immediately".
#
#  FIELD MAP  (64-byte minimum frame on the wire)
#  ──────────────────────────────────────────────
#  Byte  Field                  Size    Value / Notes
#  ────  ─────────────────────  ──────  ──────────────────────────────────────
#    0   Preamble               7 B     0x55 × 7  — synchronisation pattern
#    7   SFD                    1 B     0xD5       — marks start of frame
#    8   Dst MAC (multicast)    6 B     01:80:C2:00:00:01  (PAUSE reserved addr)
#          OR unicast dest MAC  6 B     peer's MAC when sent point-to-point
#   14   Src MAC                6 B     sender's own MAC
#   20   EtherType              2 B     0x8808  (MAC Control)
#   22   Opcode                 2 B     0x0001  (PAUSE opcode — only defined one)
#   24   Pause Quanta           2 B     0x0000–0xFFFF
#          1 quanta = 512 bit-times at the link speed
#          @ 1 Gbps  → 1 quanta ≈ 512 ns
#          @ 10 Gbps → 1 quanta ≈  51.2 ns
#          Max 0xFFFF = 65535 quanta
#   26   Pad                   42 B     0x00 × 42  — IEEE 802.3 min frame = 64 B
#   64   FCS                    4 B     CRC-32 over bytes 8–67 (DST MAC → Pad)
#  ────
#  Total on wire: 8 (L1) + 42 (MAC hdr+payload) + 4 (FCS) + 10 (IFG) = 64 B frame
#
#  OPCODE — only ONE opcode is defined for basic Pause:
#    0x0001 = PAUSE  (stop sending for Quanta × 512 bit-times)
#    0x0101 = PFC PAUSE  (Priority-based Flow Control, IEEE 802.1Qbb — extended)
#
#  QUANTA EXAMPLES
#  ───────────────
#    Speed     1 quanta   0xFFFF quanta    Typical use
#    100 Mbps  5.12 µs    335 ms           Legacy Fast Ethernet
#    1 Gbps    512 ns     33.5 ms          GbE NICs / switches
#    10 Gbps   51.2 ns    3.35 ms          Data-centre / storage
#    25 Gbps   20.5 ns    1.34 ms          High-speed uplinks
#
#  HOW FLOW CONTROL WORKS
#  ─────────────────────────────────────────────────────────────────────────────
#   Receiver (buffer near full)
#     1. Generates a Pause frame with Quanta = X
#     2. Transmits it toward the sender on the same full-duplex link
#
#   Sender (receives Pause)
#     1. Finishes current frame in progress (cannot abort mid-frame)
#     2. Halts NEW frame transmission for X × 512 bit-times
#     3. May re-enable early if a Pause(0) arrives
#
#   Receiver (buffer drained)
#     1. Sends Pause(0) to cancel remaining pause time immediately
#
#  NEGOTIATION
#  ───────────
#  Both ends MUST advertise "Symmetric PAUSE" capability in Auto-Negotiation
#  (Fast Link Pulses, Base Page bit C8 = PAUSE, bit C9 = ASM_DIR).
#  If not negotiated, Pause frames are silently discarded.
#
#  DESTINATION MAC
#  ───────────────
#  IEEE 802.3x defines the reserved multicast address 01:80:C2:00:00:01.
#  Switches do NOT forward this address (it is a "slow protocols" address).
#  Unicast Pause to the peer MAC is also valid (some implementations use this).
#
# ═══════════════════════════════════════════════════════════════════════════════

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

    link = get("Link speed for quanta display  1=100M  2=1G  3=10G  4=25G", "2")
    speed_map = {'1':100e6,'2':1e9,'3':10e9,'4':25e9}
    speed_bps = speed_map.get(link, 1e9)
    speed_label = {'1':'100 Mbps','2':'1 Gbps','3':'10 Gbps','4':'25 Gbps'}.get(link,'1 Gbps')

    quanta_hex = get("Pause Quanta  (hex, 0000–FFFF)", "00ff")
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

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3 MENU  (what runs inside Ethernet)
# ═══════════════════════════════════════════════════════════════════════════════

L3_ETH_MENU = """
  ┌─────────────────────────────────────────────────────────────────────┐
  │           LAYER 3  —  Choose protocol to carry in Ethernet          │
  ├───┬─────────────────────────────────────────────────────────────────┤
  │ 1 │ ARP                      (EtherType 0x0806)                     │
  │ 2 │ IPv4 + ICMP              (EtherType 0x0800)                     │
  │ 3 │ IPv4 + TCP               (EtherType 0x0800, proto=6)            │
  │ 4 │ IPv4 + UDP               (EtherType 0x0800, proto=17)           │
  │ 5 │ STP / RSTP BPDU          (802.3 + LLC wrapper)                  │
  │ 6 │ DTP  – Cisco Trunking    (802.3 + SNAP)                         │
  │ 7 │ PAgP – Cisco Port Agg.   (802.3 + SNAP)                         │
  │ 8 │ LACP – 802.3ad           (EtherType 0x8809)                     │
  │ 9 │ Pause Frame  – IEEE 802.3x  (EtherType 0x8808, flow control)    │
  └───┴─────────────────────────────────────────────────────────────────┘"""

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

MAIN_MENU = """
╔═══════════════════════════════════════════════════════════════════════════╗
║           NETWORK FRAME BUILDER  —  LAYERED INPUT FLOW                   ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  SELECT LAYER 2 TECHNOLOGY FIRST                                          ║
╠═══╦═══════════════════════════════════════════════════════════════════════╣
║ 1 ║ Ethernet / 802.3  →  then choose Layer 3 protocol                    ║
║   ║  ARP|ICMP|TCP|UDP|STP|DTP|PAgP|LACP|Pause(802.3x)                   ║
╠═══╬═══════════════════════════════════════════════════════════════════════╣
║ 2 ║ Serial / WAN  →  then choose L2 protocol + optional L3/L4 payload    ║
║   ║   PPP | HDLC | SLIP | Modbus RTU | ATM AAL5 | Cisco HDLC | KISS     ║
╚═══╩═══════════════════════════════════════════════════════════════════════╝"""

L3_DISPATCH = {
    '1': flow_eth_arp,
    '2': flow_eth_ip_icmp,
    '3': flow_eth_ip_tcp,
    '4': flow_eth_ip_udp,
    '5': flow_eth_stp,
    '6': flow_eth_dtp,
    '7': flow_eth_pagp,
    '8': flow_eth_lacp,
    '9': flow_eth_pause,
}

def main():
    print(MAIN_MENU)
    top = input("  Choose L2 technology  (1=Ethernet  2=Serial): ").strip()

    if top == '1':
        print(L3_ETH_MENU)
        l3ch = input("  Choose L3 protocol (1-9): ").strip()
        fn = L3_DISPATCH.get(l3ch)
        if fn: fn()
        else:  print("  Invalid choice.")

    elif top == '2':
        flow_serial()
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
