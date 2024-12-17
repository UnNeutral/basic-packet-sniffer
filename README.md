Packet Sniffer in Python
This project is a Packet Sniffer implemented in Python. It captures and analyzes network packets at the Ethernet, IPv4, ICMP, TCP, and UDP levels using raw sockets.


Features:

Ethernet Frame Parsing: Captures and decodes Ethernet frames to extract source and destination MAC addresses and protocol type.

IPv4 Packet Parsing: Extracts header details like version, header length, TTL, protocol, source, and destination IP addresses.

ICMP Packet Handling: Parses ICMP packets to display type, code, checksum, and payload data.

TCP Segment Handling: Decodes TCP headers, including source/destination ports, sequence/acknowledgment numbers, header length, and flags (SYN, ACK, FIN, etc.).

UDP Segment Handling: Extracts UDP headers, including source/destination ports and packet length.

Hex Dump of Payload: Provides a formatted hex dump of the packet payload for deeper inspection.


Requirements:
Python 3.x
Elevated privileges (root access) to run raw sockets.
The code won't work on Windows because it uses AF_PACKET sockets, which are specific to Linux for capturing raw Ethernet frames.

Notes:
Ensure you have sufficient privileges to execute raw socket operations.
This tool is for educational and debugging purposes. Use it responsibly.
