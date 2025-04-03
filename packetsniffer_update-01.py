import socket
import struct
import time
import os
import threading
import dpkt
from collections import defaultdict

LOG_FILE = "packet_log.txt"
PCAP_FILE = "captured_traffic.pcap"
PACKET_THRESHOLD = 100  # Flood threshold (packets per second per IP)

detected_attacks = set()
packet_count = defaultdict(int)
timestamp_track = defaultdict(float)
pcap_writer = dpkt.pcap.Writer(open(PCAP_FILE, "wb"))


def main():
    os.system("clear")
    print("[*] Starting Advanced Packet Sniffer...")
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffing_thread = threading.Thread(target=sniff_packets, args=(conn,))
    sniffing_thread.start()


def sniff_packets(conn):
    while True:
        raw_data, addr = conn.recvfrom(65536)
        timestamp = time.time()
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        log_data = f"\n[+] Ethernet Frame:\n\tDestination: {dest_mac}, Source: {src_mac}, Protocol:{eth_proto}"

        if eth_proto == 8:
            version, header_len, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            log_data += f"\n\t[IPV4 Packet] Source: {src_ip}, Destination: {dest_ip}, Protocol: {proto}"

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                log_data += f"\n\t[ICMP Packet] Type: {icmp_type}, Code: {code}, Checksum: {checksum}"
                detect_flood(src_ip, "ICMP")

            elif proto == 6:
                src_port, dest_port, seq, ack, offset, flags, payload = tcp_segment(data)
                log_data += f"\n\t[TCP Segment] Src Port: {src_port}, Dest Port: {dest_port}, Flags: {flags}"
                detect_flood(src_ip, "TCP")
                detect_suspicious_activity(src_ip, dest_ip, src_port, dest_port, flags)

                if src_port == 80 or dest_port == 80:
                    http_data = parse_http(payload)
                    if http_data:
                        log_data += f"\n\t[HTTP Data] {http_data}"

            elif proto == 17:
                src_port, dest_port, length, payload = udp_segment(data)
                log_data += f"\n\t[UDP Segment] Src Port: {src_port}, Dest Port: {dest_port}, Length: {length}"
                detect_flood(src_ip, "UDP")

                if src_port == 53 or dest_port == 53:
                    dns_query = parse_dns(payload)
                    if dns_query:
                        log_data += f"\n\t[DNS Query] {dns_query}"
                        detect_flood(src_ip, "DNS")

        log_packet(log_data)
        pcap_writer.writepkt(raw_data, timestamp)


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]


def get_mac_address(bytes_addr):
    return ":".join(f"{b:02x}" for b in bytes_addr).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack("!8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(dest), data[header_length:]


def ipv4(addr):
    return ".".join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    src_port, dest_port, seq, ack, offset_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        "URG": (offset_flags & 32) >> 5,
        "ACK": (offset_flags & 16) >> 4,
        "PSH": (offset_flags & 8) >> 3,
        "RST": (offset_flags & 4) >> 2,
        "SYN": (offset_flags & 2) >> 1,
        "FIN": offset_flags & 1,
    }
    return src_port, dest_port, seq, ack, offset, flags, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def log_packet(packet_data):
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()} {packet_data}\n")


def detect_flood(ip, attack_type):
    global packet_count, timestamp_track
    if time.time() - timestamp_track[ip] > 1:
        packet_count[ip] = 0
        timestamp_track[ip] = time.time()
    packet_count[ip] += 1
    if packet_count[ip] > PACKET_THRESHOLD and (ip, attack_type) not in detected_attacks:
        print(f"[!] {attack_type} Flood Attack from {ip}")
        log_packet(f"[!] {attack_type} Flood detected from {ip}")
        detected_attacks.add((ip, attack_type))


def detect_suspicious_activity(src_ip, dest_ip, src_port, dest_port, flags):
    if flags["SYN"] == 1 and flags["ACK"] == 0:
        print(f"[!] Possible SYN Flood Attack from {src_ip}:{src_port} to {dest_ip}:{dest_port}")
        log_packet(f"[!] SYN Flood detected from {src_ip}:{src_port} to {dest_ip}:{dest_port}")


def parse_http(data):
    try:
        http_request = data.decode(errors="ignore")
        if "GET" in http_request or "POST" in http_request:
            return http_request.split("\r\n")[0]
    except:
        return None


def parse_dns(data):
    try:
        if len(data) < 12:
            return None
        query_section = data[12:]
        domain = []
        i = 0
        while True:
            length = query_section[i]
            if length == 0:
                break
            domain.append(query_section[i + 1:i + 1 + length].decode(errors="ignore"))
            i += length + 1
        return ".".join(domain)
    except:
        return None


main()
