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

        # zero-length raw = annotation/breakdown row only
        if sz == 0:
            annotation = uval if uval else note
            if uval and note and uval != note:
                annotation = f"{uval}  ({note})"
            tag = LAYER_TAG.get(lay, "        ")
            print(f"  {'':10}  {tag}    {name:<28}  {'':>8}   {'':30}    {annotation}")
            continue

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
        if sz == 0:
            continue   # skip annotation-only rows
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

def ask_l2_serial():
    section("LAYER 2 — Serial / WAN  (choose protocol)")
    for k,v in SERIAL_TYPES.items():
        marker = "  ←  full 3-type builder" if k == '11' else ""
        print(f"      {k:>2} = {v}{marker}")
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



# ═══════════════════════════════════════════════════════════════════════════════
#  HDLC — HIGH-LEVEL DATA LINK CONTROL  (ISO 13239 / ITU-T Q.921 / Q.922)
#  Full 3-Frame-Type Builder:  I-frame  |  S-frame  |  U-frame
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHAT IS HDLC?
#  ─────────────
#  HDLC is the foundational synchronous data-link protocol used in:
#    WAN links (leased lines, X.25), ISDN (Q.921 = LAPD), Frame Relay (Q.922),
#    PPP (uses HDLC framing), Cisco HDLC, SS7 MTP2, GSM Um interface,
#    SDLC (IBM SNA), LAPB (X.25 layer 2), LAPF (Frame Relay).
#
#  FRAME STRUCTURE  (every HDLC frame)
#  ────────────────────────────────────────────────────────────────────────────
#  Flag     Address    Control       Information    FCS        Flag
#  0x7E     1–N bytes  1 or 2 bytes  0+ bytes       2 or 4 B   0x7E
#  ────────────────────────────────────────────────────────────────────────────
#  • Flag (0x7E) : start/end of frame — same as in PPP
#  • Address     : station or DLCI address (1 byte basic, ext with EA bit=0)
#  • Control     : frame type + sequence numbers (THE KEY FIELD)
#  • Information : user data payload (present only in I-frames)
#  • FCS         : CRC-16/CCITT (2 bytes) or CRC-32 (4 bytes)
#
#  THE CONTROL FIELD — 3 FRAME TYPES
#  ────────────────────────────────────────────────────────────────────────────
#
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │  TYPE 1:  I-FRAME  (Information Frame)                                  │
#  │  Carries user data.  Uses sliding-window ARQ for reliable delivery.     │
#  │                                                                         │
#  │  1-byte control (modulo 8):                                             │
#  │  Bit  7  6  5  4  3  2  1  0                                            │
#  │       N(S)3 N(S)2 N(S)1 N(S)0  P/F  N(R)2 N(R)1 N(R)0  0              │
#  │       └──────N(S)──────┘  │   └──────N(R)──────┘  └─ 0 = I-frame      │
#  │                            └─ P/F: Poll(cmd) / Final(resp)              │
#  │                                                                         │
#  │  2-byte control (modulo 128):                                           │
#  │  Byte 0: N(S)(7 bits) + 0                                               │
#  │  Byte 1: N(R)(7 bits) + P/F                                             │
#  │                                                                         │
#  │  N(S) = Send sequence number (0–7 or 0–127)                             │
#  │  N(R) = Receive sequence number (= next expected from peer)             │
#  └─────────────────────────────────────────────────────────────────────────┘
#
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │  TYPE 2:  S-FRAME  (Supervisory Frame)                                  │
#  │  Flow/error control.  NO information field.  4 subtypes:               │
#  │                                                                         │
#  │  1-byte control (modulo 8):                                             │
#  │  Bit  7  6  5  4  3  2  1  0                                            │
#  │       N(R)2 N(R)1 N(R)0  P/F  S1 S0  1  0                              │
#  │       └──────N(R)──────┘  │  └──┘  └─── 10 = S-frame                  │
#  │                            │    └─ Supervisory function bits            │
#  │                            └─ P/F                                       │
#  │                                                                         │
#  │  S1 S0  Subtype  Meaning                                                │
#  │  ─────  ───────  ──────────────────────────────────────────────────── │
#  │   0  0   RR     Receive Ready    — ready, ACK up to N(R)-1             │
#  │   0  1   REJ    Reject           — go-back-N retransmit from N(R)      │
#  │   1  0   RNR    Receive Not Ready— busy, stop sending                  │
#  │   1  1   SREJ   Selective Reject — retransmit only frame N(R)          │
#  └─────────────────────────────────────────────────────────────────────────┘
#
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │  TYPE 3:  U-FRAME  (Unnumbered Frame)                                   │
#  │  Link management.  NO sequence numbers.  Many subtypes:                │
#  │                                                                         │
#  │  Control byte (always 1 byte):                                          │
#  │  Bit  7  6  5  4  3  2  1  0                                            │
#  │       M4 M3 M2  P/F  M1 M0  1  1                                       │
#  │       └─────┘   │   └──┘  └─── 11 = U-frame                           │
#  │       modifier   └─ P/F    modifier bits (M4-M0)                       │
#  │                                                                         │
#  │  Common U-frame commands/responses:                                     │
#  │  M4 M3 M2 M1 M0   Mnemonic  C/R  Meaning                               │
#  │  ─────────────    ────────  ───  ──────────────────────────────────── │
#  │  0  0  0  0  0    UI        C/R  Unnumbered Information (datagram)     │
#  │  0  0  1  0  0    UP        C    Unnumbered Poll                        │
#  │  0  0  0  0  1    RR(U)     C    Disconnect Mode (DM-like)              │
#  │  0  1  1  0  0    SABM      C    Set Async Balanced Mode (connect)      │
#  │  0  1  1  0  1    SABME     C    SABM Extended (modulo 128)             │
#  │  0  0  0  1  1    DM        R    Disconnect Mode (not connected)        │
#  │  0  0  1  0  1    UA        R    Unnumbered Acknowledgment              │
#  │  1  0  0  0  1    FRMR      R    Frame Reject (error)                   │
#  │  1  1  0  0  0    XID       C/R  Exchange Identification                │
#  │  1  1  1  0  0    TEST      C/R  Test frame                             │
#  │  0  1  0  0  0    DISC      C    Disconnect                             │
#  └─────────────────────────────────────────────────────────────────────────┘
#
#  ADDRESS FIELD  (EA = Extension Address bit)
#  ────────────────────────────────────────────────────────────────────────────
#  Basic (1 byte):  bit 0 = 1  (EA=1 = last byte of address)
#  Extended:        byte has EA=0, next byte continues, last byte EA=1
#  In LAPD (Q.921): address = SAPI(6b)+C/R(1b)+EA(1b)  |  TEI(7b)+EA(1b)
#  In LAPB (X.25):  address = 0x01 (DTE command) or 0x03 (DCE command)
#  In basic HDLC:   0xFF = broadcast (all stations)
#
#  FCS COVERAGE
#  ────────────────────────────────────────────────────────────────────────────
#  FCS covers:  Address + Control + Information  (NOT the flags)
#  CRC-16/CCITT (default): polynomial x^16+x^12+x^5+1, init=0xFFFF
#  CRC-32       (optional): same as Ethernet CRC-32, little-endian
#
# ═══════════════════════════════════════════════════════════════════════════════

# ── HDLC U-frame subtype table ────────────────────────────────────────────────
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

def flow_hdlc():
    banner("HDLC FRAME BUILDER — ISO 13239",
           "3 Frame Types:  I-frame (data+seq)  |  S-frame (supervisory)  |  U-frame (link mgmt)")
    print_hdlc_education()

    # ── Flags ──────────────────────────────────────────────────────────────────
    section("FLAGS  (frame delimiters)")
    print("    Standard HDLC flag = 0x7E.  Both start and end use same value.")
    flag_hex = get("Flag byte (hex)", "7e")
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
        mod128 = get("Use Modulo-128 extended control? (y/n)", "n").lower().startswith("y")

    # ── P/F bit ───────────────────────────────────────────────────────────────
    section("POLL/FINAL (P/F) BIT")
    print("    P=1 in a COMMAND means: 'respond now' (poll)")
    print("    F=1 in a RESPONSE means: 'this is my final response'")
    pf = int(get("P/F bit (0 or 1)", "0")) & 1

    # ─────────────────────────────────────────────────────────────────────────
    if ftype == '1':
        # I-FRAME
        section("I-FRAME — SEQUENCE NUMBERS")
        print("    N(S) = Send Sequence Number (sequence of THIS frame)")
        print("    N(R) = Receive Sequence Number (acknowledges receipt up to N(R)-1)")
        ns_max = 127 if mod128 else 7
        ns = int(get(f"N(S) Send Sequence  (0–{ns_max})", "0")) & (0x7F if mod128 else 0x7)
        nr = int(get(f"N(R) Receive/ACK Seq (0–{ns_max})", "0")) & (0x7F if mod128 else 0x7)
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
        nr = int(get(f"N(R) Receive/ACK Sequence (0–{nr_max})", "0")) & (0x7F if mod128 else 0x7)
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
    fcs_mode = get("FCS type (1=CRC-16  2=CRC-32)", "1")

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
    do_stuff = get("Apply bit-stuffing to content? (y/n)", "n").lower().startswith("y")

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

# ═══════════════════════════════════════════════════════════════════════════════
#  PFC — PRIORITY FLOW CONTROL  (IEEE 802.1Qbb)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHAT IS PFC?
#  ────────────
#  Priority Flow Control extends the basic Pause frame (802.3x) to support
#  per-priority (per-CoS class) flow control instead of pausing ALL traffic.
#  Defined in IEEE 802.1Qbb (merged into 802.1Q-2018).
#  Used heavily in Data Centre Bridging (DCB) for RoCE, iSCSI, FCoE.
#
#  KEY DIFFERENCE FROM BASIC PAUSE
#  ────────────────────────────────
#  Basic Pause (0x0001) : pauses ALL 8 priorities simultaneously
#  PFC       (0x0101)   : per-priority bitmask — pause only specific CoS queues
#
#  PFC FRAME STRUCTURE
#  ───────────────────
#  Byte  Field                   Size   Fixed?  Value / Notes
#  ────  ──────────────────────  ─────  ──────  ────────────────────────────────
#    0   Preamble                7 B    Fixed   0x55 × 7
#    7   SFD                     1 B    Fixed   0xD5
#    8   Dst MAC                 6 B    Semi    01:80:C2:00:00:01  (MAC Ctrl mcast)
#   14   Src MAC                 6 B    User    Sender MAC
#   20   EtherType               2 B    Fixed   0x8808  (MAC Control)
#   22   Opcode                  2 B    Fixed   0x0101  (PFC opcode)
#   24   Priority Enable Vector  2 B    USER    Bitmask: bit N = 1 means pause P(N)
#                                                bit 0 = Priority 0 (Best Effort)
#                                                bit 1 = Priority 1
#                                                ...
#                                                bit 7 = Priority 7 (Network Control)
#   26   Quanta[0]               2 B    USER    Pause time for Priority 0
#   28   Quanta[1]               2 B    USER    Pause time for Priority 1
#   30   Quanta[2]               2 B    USER    ...
#   32   Quanta[3]               2 B    USER    ...
#   34   Quanta[4]               2 B    USER    Commonly mapped to FCoE
#   36   Quanta[5]               2 B    USER    Commonly mapped to iSCSI / RoCE
#   38   Quanta[6]               2 B    USER    ...
#   40   Quanta[7]               2 B    USER    0x0000 = not pausing this priority
#   42   Pad                    26 B    Auto    0x00 × 26  (pad to 64 B minimum)
#   68   FCS                     4 B    Auto    CRC-32
#
#  PRIORITY → TRAFFIC CLASS TYPICAL MAPPING (DCB / RoCE)
#  ──────────────────────────────────────────────────────
#  Priority 0  Best Effort (default)        → most TCP/IP traffic
#  Priority 1  Background / Scavenger       → bulk backup, low-priority
#  Priority 2  Spare / Video                → video streaming
#  Priority 3  Critical Apps / Call Signal  → VoIP signalling
#  Priority 4  Video Conferencing           → interactive video
#  Priority 5  Voice / iSCSI / RoCE        → lossless storage/RDMA
#  Priority 6  Internetwork Control         → routing protocols (OSPF/BGP)
#  Priority 7  Network Control              → spanning-tree, LLDP
#
#  ENABLE VECTOR EXAMPLES
#  ──────────────────────
#  0x0020 = 0b00100000 → pause only Priority 5  (RoCE / iSCSI)
#  0x00E0 = 0b11100000 → pause Priority 5,6,7
#  0x00FF = 0b11111111 → pause all 8 priorities (same effect as basic Pause)
#  0x0001 = 0b00000001 → pause only Priority 0
#
# ═══════════════════════════════════════════════════════════════════════════════

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
    vec_hex = get("Priority Enable Vector (hex 0000-00FF)", "0020")
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


# ═══════════════════════════════════════════════════════════════════════════════
#  LLDP — LINK LAYER DISCOVERY PROTOCOL  (IEEE 802.1AB)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHAT IS LLDP?
#  ─────────────
#  LLDP is a vendor-neutral L2 discovery protocol.  Devices advertise their
#  identity, capabilities, and management addresses to directly connected
#  neighbours.  Neighbours store the info in an MIB (LLDP-MIB, RFC 2922).
#  Sent to the multicast address 01:80:C2:00:00:0E every 30s (default).
#  NOT forwarded by bridges/switches (link-local multicast).
#
#  TLV STRUCTURE (Type-Length-Value)
#  ───────────────────────────────────────────────────────────────────────────
#  Every LLDP PDU is a sequence of TLVs.  Each TLV:
#    Bits 15-9 : Type  (7 bits)
#    Bits  8-0 : Length (9 bits) — number of value bytes following
#    Bytes  …  : Value (0–511 bytes)
#
#  MANDATORY TLVs (must appear, in this order)
#  ────────────────────────────────────────────────────────────────────────────
#  Type  Name                    Description
#  ────  ──────────────────────  ──────────────────────────────────────────────
#    0   End of LLDPDU           Length=0, marks end of PDU. MUST be last TLV.
#    1   Chassis ID              Identifies the sending chassis.
#                                  Subtype 4 = MAC address  (6 B value)
#                                  Subtype 5 = Network Address
#                                  Subtype 7 = Locally Assigned (string)
#    2   Port ID                 Identifies the sending port.
#                                  Subtype 3 = MAC address  (6 B value)
#                                  Subtype 5 = Interface Name (string)
#                                  Subtype 7 = Locally Assigned (string)
#    3   TTL                     Seconds neighbours should retain this info.
#                                  0 = remove immediately (device leaving)
#                                  120 = default; max 65535
#
#  OPTIONAL TLVs
#  ─────────────────────────────────────────────────────────────────────────────
#  Type  Name                    Description
#  ────  ──────────────────────  ──────────────────────────────────────────────
#    4   Port Description        Human-readable port description string
#    5   System Name             sysName MIB object (hostname)
#    6   System Description      sysDescr MIB object (OS, version, platform)
#    7   System Capabilities     2-byte bitmask + 2-byte enabled bitmask
#                                  bit 0=Other  bit 1=Repeater  bit 2=Bridge
#                                  bit 3=WLAN   bit 4=Router    bit 5=Telephone
#                                  bit 6=DOCSIS bit 7=Station
#    8   Management Address      IP or MAC address for SNMP/mgmt access
#  127   Org-Specific (OUID+Sub) Used by 802.1 / 802.3 / Cisco extensions
#
#  LLDP FRAME STRUCTURE
#  ─────────────────────
#  Byte  Field               Size    Value
#  ────  ──────────────────  ──────  ──────────────────────────────────────────
#    0   Preamble            7 B     0x55 × 7
#    7   SFD                 1 B     0xD5
#    8   Dst MAC             6 B     01:80:C2:00:00:0E  (LLDP multicast)
#   14   Src MAC             6 B     Sender MAC
#   20   EtherType           2 B     0x88CC  (LLDP)
#   22   LLDPDU              var     Sequence of TLVs
#   ??   FCS                 4 B     CRC-32
#
# ═══════════════════════════════════════════════════════════════════════════════

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
    ttl_val = int(get("TTL (seconds)", "120")) & 0xFFFF
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


# ═══════════════════════════════════════════════════════════════════════════════
#  VLAN TAGGED FRAME  (IEEE 802.1Q)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHAT IS 802.1Q?
#  ───────────────
#  IEEE 802.1Q inserts a 4-byte VLAN tag between the Source MAC and EtherType.
#  It allows a single physical link to carry traffic for multiple VLANs.
#  Used on trunk ports between switches and between switches and routers.
#
#  THE 802.1Q TAG  (4 bytes inserted at offset 12)
#  ─────────────────────────────────────────────────────────────────────────────
#  Bytes  Field               Size   Value / Notes
#  ─────  ──────────────────  ─────  ─────────────────────────────────────────
#   +0    TPID (Tag Protocol  2 B    0x8100  (standard 802.1Q)
#           Identifier)               0x88A8  (802.1ad Q-in-Q outer tag)
#                                     0x9100  (Cisco proprietary Q-in-Q)
#   +2    TCI (Tag Control    2 B    Combined: PCP(3b) + DEI(1b) + VID(12b)
#           Information)
#           PCP  bits 15-13   3 b    Priority Code Point = CoS 0–7
#                                     0=BestEffort  1=Background  2=Excellent
#                                     3=CritApp     4=Video       5=Voice
#                                     6=Internetwork-Ctrl   7=Network-Ctrl
#           DEI  bit 12       1 b    Drop Eligible Indicator (0=keep, 1=drop)
#           VID  bits 11-0   12 b    VLAN ID  0–4095
#                                     0    = priority-tagged only (no VLAN)
#                                     1    = default native VLAN
#                                     1–4094 = user VLANs
#                                     4095 = reserved, not used
#
#  DOUBLE TAGGING (Q-in-Q / 802.1ad)
#  ───────────────────────────────────
#  Outer tag TPID = 0x88A8  (provider tag / S-Tag)
#  Inner tag TPID = 0x8100  (customer tag / C-Tag)
#  Used by Metro Ethernet providers to tunnel customer VLANs.
#
#  PCP → PRIORITY MAPPING
#  ────────────────────────
#  PCP 0  Best Effort (default)      PCP 4  Controlled Load
#  PCP 1  Background (low priority)  PCP 5  Video <100ms latency
#  PCP 2  Excellent Effort           PCP 6  Voice <10ms latency
#  PCP 3  Critical Applications      PCP 7  Network Control
#
# ═══════════════════════════════════════════════════════════════════════════════

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
    tpid_hex = get("TPID (hex)", "8100")
    try:    tpid_val = int(tpid_hex.replace("0x",""), 16) & 0xFFFF
    except: tpid_val = 0x8100

    print("    PCP (Priority Code Point):  0=BestEffort  3=CritApps  5=Voice  7=NetCtrl")
    pcp = int(get("PCP  (0-7)", "0")) & 0x7
    print("    DEI (Drop Eligible):  0=keep  1=may be dropped first during congestion")
    dei = int(get("DEI  (0 or 1)", "0")) & 0x1
    print("    VID:  0=priority-only  1=native  2-4094=user VLANs  4095=reserved")
    vid = int(get("VID  (0-4094)", "100")) & 0x0FFF

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


# ═══════════════════════════════════════════════════════════════════════════════
#  JUMBO FRAME  (vendor extension — no IEEE standard number)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHAT IS A JUMBO FRAME?
#  ──────────────────────
#  Jumbo frames are Ethernet frames with an MTU larger than the standard 1500B.
#  They are NOT defined in any IEEE standard — they are a vendor extension.
#  Common jumbo MTU values: 9000B (most switches), 9216B, 9600B, 16110B.
#
#  KEY BENEFIT
#  ───────────
#  Larger frames = fewer frames for same data = less CPU overhead per byte.
#  For 1 GbE with 9000B jumbo vs 1500B standard:
#    Efficiency gain ≈ 9000/1500 = 6× fewer frame headers, interrupts, checksums.
#  Used in: NFS, iSCSI, Ceph, Hadoop, HPC clusters, storage networks.
#
#  REQUIREMENTS
#  ────────────
#  • ALL devices on the path must support and have jumbo frames enabled.
#  • One misconfigured switch/NIC causes silent frame drops or fragmentation.
#  • Must be configured consistently: same MTU on both ends of every link.
#  • Jumbo frames do NOT fragment if the IP DF (Don't Fragment) bit is set.
#
#  STANDARD vs JUMBO SIZE COMPARISON
#  ────────────────────────────────────────────────────────────────────────────
#  Frame type      Max payload   Total frame   Use case
#  ─────────────── ─────────────  ────────────  ─────────────────────────────
#  Standard        1500 B        1518 B         General LAN
#  Baby Giant      1600 B        1618 B         MPLS labels (+4B per label)
#  Jumbo (typical) 9000 B        9018 B         NFS/iSCSI/Ceph/HPC
#  Jumbo (extended)9216 B        9234 B         Some storage switches
#  Super Jumbo     16110 B       16128 B        InfiniBand bridging
#
#  FIELD STRUCTURE  (same as standard Ethernet II — only payload size differs)
#  ─────────────────────────────────────────────────────────────────────────────
#  Byte  Field        Size   Value
#  ────  ───────────  ─────  ──────────────────────────────────────────────────
#    0   Preamble     7 B    0x55 × 7
#    7   SFD          1 B    0xD5
#    8   Dst MAC      6 B    destination MAC
#   14   Src MAC      6 B    source MAC
#   20   EtherType    2 B    0x0800(IPv4) / 0x86DD(IPv6) / etc.
#   22   Payload      up to 9000 B  (or more depending on NIC config)
#   ??   FCS          4 B    CRC-32
#
#  NOTE ON VLAN-TAGGED JUMBO
#  ─────────────────────────
#  With a 802.1Q tag, the tag itself (+4B) does not reduce the payload limit.
#  The NIC sees 9000B payload + 4B tag = 9004B payload space needed.
#  Known as "9004-byte jumbo" in some vendor documentation.
#
# ═══════════════════════════════════════════════════════════════════════════════

JUMBO_PRESETS = {
    '1': (1500,  "Standard Ethernet (baseline)"),
    '2': (1600,  "Baby Giant  (MPLS +1 label)"),
    '3': (4470,  "FDDI over Ethernet bridging"),
    '4': (9000,  "Typical Jumbo (NFS/iSCSI/Ceph/HPC)"),
    '5': (9216,  "Extended Jumbo (storage switches)"),
    '6': (16110, "Super Jumbo (InfiniBand bridging)"),
    '7': (0,     "Custom"),
}

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


# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3 MENU
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  WiFi FRAME  —  IEEE 802.11  (Wi-Fi MAC Layer)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  OVERVIEW
#  ────────
#  IEEE 802.11 defines the MAC and PHY for wireless LAN (Wi-Fi).
#  Unlike Ethernet, 802.11 frames carry up to FOUR MAC addresses, a sequence
#  number, duration/NAV, QoS control, and HT/VHT control fields.
#
#  THREE FRAME TYPES
#  ─────────────────
#  Type 00 = Management  — BSS administration (Beacon, Probe, Auth, Assoc)
#  Type 01 = Control     — Medium access (RTS, CTS, ACK, Block Ack)
#  Type 10 = Data        — Actual data payload (Data, QoS Data, Null)
#
#  FRAME CONTROL FIELD  (2 bytes — the very first field)
#  ──────────────────────────────────────────────────────
#  Bits  Field             Description
#  ────  ───────────────── ────────────────────────────────────────────────────
#  1-0   Protocol Version  Always 0b00 (only version defined)
#  3-2   Type              00=Mgmt  01=Ctrl  10=Data  11=Reserved
#  7-4   Subtype           Depends on Type (see tables below)
#  8     To DS             1 = frame going TO the distribution system (AP)
#  9     From DS           1 = frame coming FROM distribution system
#  10    More Fragments    1 = more fragments follow
#  11    Retry             1 = retransmission of earlier frame
#  12    Power Mgmt        1 = STA going into power-save mode after this frame
#  13    More Data         1 = AP has more buffered frames for sleeping STA
#  14    Protected Frame   1 = frame body is encrypted (WEP/TKIP/CCMP/GCMP)
#  15    +HTC/Order        1 = HT Control field present (HT/VHT frames)
#
#  DS BITS → ADDRESS INTERPRETATION  (crucial!)
#  ──────────────────────────────────────────────────────────────────────────
#  ToDS  FromDS  Addr1(RA)    Addr2(TA)    Addr3       Addr4
#  ────  ──────  ───────────  ───────────  ─────────── ────────────────────
#    0     0     Destination  Source       BSSID       not present
#    0     1     Destination  BSSID        Source      not present
#    1     0     BSSID        Source       Destination not present
#    1     1     RA (nexthop) TA (sender)  DA (dest)   SA (source)  ← WDS
#
#  ToDS=0 FromDS=0 → IBSS/Ad-Hoc direct  (STA↔STA, no AP)
#  ToDS=1 FromDS=0 → Infrastructure uplink  (STA → AP → DS)
#  ToDS=0 FromDS=1 → Infrastructure downlink (DS → AP → STA)
#  ToDS=1 FromDS=1 → WDS / Mesh (AP ↔ AP bridge)
#
#  SEQUENCE CONTROL  (2 bytes, present in most frames)
#  ────────────────────────────────────────────────────
#  Bits 15-4 : Sequence Number (12 bits, 0–4095, wraps)
#  Bits  3-0 : Fragment Number (4 bits, 0 = unfragmented)
#
#  QoS CONTROL  (2 bytes, present when subtype has QoS bit set)
#  ──────────────────────────────────────────────────────────────
#  Bits  3-0 : TID  (Traffic ID / UP — User Priority 0–7)
#  Bit   4   : EOSP (End of Service Period)
#  Bits  6-5 : Ack Policy  0=Normal  1=No-Ack  2=No-Explicit  3=Block-Ack
#  Bit   7   : A-MSDU Present
#  Bits 15-8 : TXOP Limit / Queue Size / AP PS Buffer State
#
#  MANAGEMENT FRAME SUBTYPES
#  ─────────────────────────────────────────────────────────────────────────
#  Sub  Name               Direction     Purpose
#  ───  ─────────────────  ────────────  ──────────────────────────────────
#   0   Association Req    STA→AP        STA requests to join BSS
#   1   Association Resp   AP→STA        AP grants/denies association
#   2   Reassociation Req  STA→new-AP    STA roams to new AP
#   3   Reassociation Resp new-AP→STA    New AP responds to roam
#   4   Probe Request      STA→all/AP    STA scans for APs / networks
#   5   Probe Response     AP→STA        AP responds to probe
#   8   Beacon             AP→all        AP announces BSS periodically
#  10   Disassociation     either        Terminate association
#  11   Authentication     either        Open/SAE auth exchange
#  12   Deauthentication   either        Terminate authentication
#  13   Action             either        Management actions (BA, RM, etc.)
#
#  CONTROL FRAME SUBTYPES
#  ─────────────────────────────────────────────────────────────────────────
#  Sub  Name               Size     Purpose
#  ───  ─────────────────  ───────  ─────────────────────────────────────
#   8   Block Ack Req      24+ B    Request block acknowledgment
#   9   Block Ack          32+ B    Block acknowledgment bitmap
#  10   PS-Poll            20 B     Power-save station polls for buffered data
#  11   RTS                20 B     Request To Send (collision avoidance)
#  12   CTS                14 B     Clear To Send (response to RTS)
#  13   ACK                14 B     Acknowledgment of received frame
#  14   CF-End             20 B     End of contention-free period
#
#  DATA FRAME SUBTYPES
#  ─────────────────────────────────────────────────────────────────────────
#  Sub  Name               QoS?  Notes
#  ───  ─────────────────  ────  ──────────────────────────────────────────
#   0   Data               No    Basic data frame
#   4   Null               No    No data — used for power management signalling
#   8   QoS Data           Yes   Data with QoS Control field  (Wi-Fi Multimedia)
#  12   QoS Null           Yes   QoS power-save signalling, no payload
#
#  LLCSNAP HEADER  (8 bytes — bridges 802.11 payload to Ethernet)
#  ──────────────────────────────────────────────────────────────
#  Bytes  Value        Field
#  ─────  ─────────── ─────────────────────────────────────
#   0     0xAA         LLC DSAP  (SNAP indicator)
#   1     0xAA         LLC SSAP  (SNAP indicator)
#   2     0x03         LLC Control (Unnumbered Information)
#   3-5   0x00 0x00 0x00  SNAP OUI  (0x000000 for Ethernet-mapped)
#   6-7   EtherType    Protocol (0x0800=IPv4  0x0806=ARP  0x86DD=IPv6)
#
#  FCS  (Frame Check Sequence — 4 bytes, CRC-32)
#  ────────────────────────────────────────────────
#  802.11 FCS = CRC-32 over the entire MPDU (MAC Protocol Data Unit):
#  Frame Control + Duration + all Address fields + Seq Ctrl + QoS +
#  HTC (if present) + Frame Body.
#  NOTE: In most captures (pcap) the FCS is stripped by the driver.
#        This builder includes it as transmitted on air.
#
# ═══════════════════════════════════════════════════════════════════════════════

# ── Frame type/subtype definitions ───────────────────────────────────────────

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

def wifi_crc32(data: bytes) -> bytes:
    """802.11 FCS = CRC-32 same polynomial as Ethernet, little-endian."""
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')

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


# ── PHY preamble builders ─────────────────────────────────────────────────────

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


# ── Inputs ────────────────────────────────────────────────────────────────────

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
        to_ds   = int(get("ToDS   (0 or 1)", "1")) & 1
        from_ds = int(get("FromDS (0 or 1)", "0")) & 1

    more_frag = int(get("More Fragments (0/1)", "0")) & 1
    retry     = int(get("Retry          (0/1)", "0")) & 1
    pwr_mgmt  = int(get("Power Mgmt     (0/1)", "0")) & 1
    more_data = int(get("More Data      (0/1)", "0")) & 1
    protected = int(get("Protected Frame (0/1, 1=encrypted)", "0")) & 1
    htc_order = int(get("+HTC/Order     (0/1)", "0")) & 1

    fc_byte0 = (subtype_val << 4) | (type_bits << 2) | 0x00
    fc_byte1 = (to_ds | (from_ds<<1) | (more_frag<<2) | (retry<<3) |
                (pwr_mgmt<<4) | (more_data<<5) | (protected<<6) | (htc_order<<7))
    fc_bytes = bytes([fc_byte0, fc_byte1])

    # ── Duration / ID ──────────────────────────────────────────────────────────
    section("DURATION / ID  (2 bytes)")
    print("    NAV duration in microseconds (Network Allocation Vector).")
    print("    For ACK/CTS: time for remaining exchange.  PS-Poll: AID value.")
    dur_val   = int(get("Duration µs  (0–32767) or AID for PS-Poll", "0")) & 0x7FFF
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
        seq_num  = int(get("Sequence Number  (0–4095)", "100")) & 0xFFF
        frag_num = int(get("Fragment Number  (0=unfragmented)", "0")) & 0xF
        seq_ctrl_val   = (seq_num << 4) | frag_num
        seq_ctrl_bytes = struct.pack("<H", seq_ctrl_val)

    # ── QoS Control ────────────────────────────────────────────────────────────
    qos_bytes = b''
    if has_qos:
        section("QoS CONTROL")
        for tid,(name) in WIFI_TID_NAMES.items():
            print(f"      TID {tid} = {name}")
        tid     = int(get("TID  Traffic ID (0–7)", "0")) & 0xF
        eosp    = int(get("EOSP (0/1)", "0")) & 0x1
        print("    Ack Policy:  0=Normal  1=No-Ack  2=No-Explicit  3=Block-Ack")
        ack_pol = int(get("Ack Policy (0–3)", "0")) & 0x3
        amsdu   = int(get("A-MSDU Present (0/1)", "0")) & 0x1
        txop    = int(get("TXOP Limit (0–255)", "0")) & 0xFF
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

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

MAIN_MENU = """
╔════════════════════════════════════════════════════════════════════════════════╗
║           NETWORK FRAME BUILDER  —  LAYERED INPUT FLOW                        ║
╠════════════════════════════════════════════════════════════════════════════════╣
║  SELECT LAYER 2 TECHNOLOGY                                                     ║
╠═══╦════════════════════════════════════════════════════════════════════════════╣
║ 1 ║ Ethernet / 802.3  →  choose L3 protocol (13 options)                      ║
║   ║  ARP | ICMP | TCP | UDP | STP | DTP | PAgP | LACP                         ║
║   ║  Pause(802.3x) | PFC(802.1Qbb) | LLDP(802.1AB) | VLAN(802.1Q) | Jumbo    ║
╠═══╬════════════════════════════════════════════════════════════════════════════╣
║ 2 ║ Serial / WAN  →  choose L2 protocol (11 options)                          ║
║   ║  Raw | SLIP | PPP | HDLC-basic | HDLC-Full(I/S/U) | KISS | Modbus        ║
║   ║  HDLC+BitStuff | ATM AAL5 | Cisco HDLC | COBS                             ║
╠═══╬════════════════════════════════════════════════════════════════════════════╣
║ 3 ║ WiFi / 802.11  →  choose frame type (Management / Control / Data)         ║
║   ║  Beacon | Probe | Auth | Assoc | RTS | CTS | ACK | Data | QoS | Null      ║
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
    top = input("  Choose technology  (1=Ethernet  2=Serial  3=WiFi): ").strip()

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
