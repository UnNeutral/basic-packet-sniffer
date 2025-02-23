🚀 Packet Sniffer in Python

This project is a Packet Sniffer built using Python and raw sockets to capture and analyze network packets at multiple layers, including Ethernet, IPv4, ICMP, TCP, and UDP.

📊 Key Feature
* Ethernet Frame Parsing: Captures and decodes Ethernet frames to extract source/destination MAC addresses and protocol type.
* IPv4 Packet Parsing: Extracts critical header details like version, header length, TTL, protocol, and IP addresses.
* ICMP Packet Handling: Parses ICMP packets, displaying key fields like type, code, checksum, and payload data.
* TCP Segment Handling: Decodes TCP headers, including source/destination ports, sequence/acknowledgment numbers, header length, and essential flags (SYN, ACK, FIN, etc.).
* UDP Segment Handling: Extracts UDP headers, providing details like source/destination ports and packet length.
* Hex Dump of Payload: Enables in-depth packet inspection with a formatted hex dump of the packet payload. 

⚙️ Under the Hood
* Uses raw sockets and AF_PACKET to capture network traffic (Linux only).
* Processes packets dynamically for real-time network analysis and security monitoring.
* Designed for learning, debugging, and cybersecurity research. 

🔧 Requirements
* Python 3.x
* Root/Admin Privileges (Required for raw socket operations)
* Linux OS (Not compatible with Windows due to AF_PACKET dependency) 

🔗 Explore the Project

Check out the code, documentation, and usage examples on GitHub. Contributions and feedback are welcome!

#CyberSecurity #Networking #PacketSniffer #Python #EthicalHacking
