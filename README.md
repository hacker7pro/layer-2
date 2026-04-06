🌐 PacketCraft: Protocol & EtherType Mapper

🔍 Generate hex payload values and explore mappings between EtherTypes, protocols, and network layers (L2 → L7)

🎯 About

PacketCraft is a reference + utility project that helps you:

🧩 Map EtherTypes → Payload Protocols
📡 Understand WiFi & Serial protocol encapsulation
🌍 Work with Standalone IPv4 packet structures
🧱 Identify Hardware (MAC/PHY) types
🔗 Connect L2 → L3 → L4 → Application layers
🔢 Generate hexadecimal payload outputs
🎨 Features

✨ Color-coded protocol mappings
✨ Hex payload generator
✨ Layer-wise breakdown (OSI + TCP/IP)
✨ Ethernet, WiFi, Serial support
✨ Clean developer-friendly tables

🧱 Layer Mapping Overview
+-------------------+
| Application Layer |
+-------------------+
| Transport (L4)    |
+-------------------+
| Network (L3)      |
+-------------------+
| Data Link (L2)    |
+-------------------+
| Physical (L1)     |
+-------------------+

🛠️ Example: Generate Payload Hex
Input:
Protocol: IPv4 + TCP + HTTP

▶️ Running the Script
🐍 Requirements
Python 3.x recommended (works best)
Python 2.x (legacy support, optional)


🚀 Run Command
# Python 3 (recommended)
        python3 main.py

# OR (if python maps to Python 3)
        python main.py

# Python 2 (only if your script supports it)
        python2 main.py
⚠️ Notes
     ✔️ Use Python 3 for full feature compatibility
⚠️ Python 2 is deprecated and may break newer modules
💡 On Linux, you may need:
                      python3 main.py


🖥️ Main Menu Interface

When you run the script, you’ll see:


   ╔══════════════════════════════════════════════════════════════════════════════╗
║               NETWORK FRAME BUILDER  ─  COMPLETE PROTOCOL SUITE              ║
║                            Engines: L2✓ L3✓ L4✓ HW✓                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 1  Ethernet / 802.3          11 full builders | 174 EtherTypes | 35 L3 stacks | 77 L4 handlers
║     ARP · IPv4(→L4 sub-menu) · STP · DTP · PAgP · LACP · Pause · PFC · LLDP · VLAN · Jumbo
║     Storage: FCoE FIP AoE RoCE iSCSI NVMe  Switch: EAPOL MACSec CFM Y.1731 PTP MRP TRILL
╠══════════════════════════════════════════════════════════════════════════════╣
║ 2  Serial / WAN              11 protocols  (Raw·SLIP·PPP·HDLC·Cisco-HDLC·Modbus·ATM·KISS·COBS)
║     HDLC: I-frame(data) · S-frame(supervisory) · U-frame(link mgmt)
╠══════════════════════════════════════════════════════════════════════════════╣
║ 3  WiFi / 802.11             21 PHY standards  ·  4 frame categories
║     802.11a/b/g/n/ac/ax/be · ad/ay(60GHz) · p(V2X) · s(Mesh) · ah(HaLow) · j/r/u/v/w/k/y
╠══════════════════════════════════════════════════════════════════════════════╣
║ 4  Standalone IPv4           Full RFC 791  ·  24 protocols  ·  options  ·  L4 payload
║     ICMP(19 types) · TCP(11 states) · UDP(41 ports) · GRE · ESP · AH · OSPF · SCTP
╠══════════════════════════════════════════════════════════════════════════════╣
║ 5  Hardware / Bus Frame      21 bus protocols  ·  9 platform categories
║     Consumer · Server · Router · Switch · Firewall · IDS/IPS · NAC · Industrial · Embedded
║     PCIe TLP/DLLP · USB3/2 · HDMI · DisplayPort · SATA FIS · NVMe · IPMI/SOL · Thunderbolt
║     CAN FD · FlexRay · UART · DDR5 · AES67 · Modbus TCP · Broadcom Higig2 · DMA Desc
╚══════════════════════════════════════════════════════════════════════════════╝



📦 Use Cases
🧪 Network packet crafting
🔐 Security research
📡 Protocol debugging
📚 Learning networking deeply
🤝 Contributing

Pull requests welcome!
Add more protocols, mappings, or payload generators 🚀
