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

Output:
0x0800 4500003C...0600...474554202F
📦 Use Cases
🧪 Network packet crafting
🔐 Security research
📡 Protocol debugging
📚 Learning networking deeply
🤝 Contributing

Pull requests welcome!
Add more protocols, mappings, or payload generators 🚀
