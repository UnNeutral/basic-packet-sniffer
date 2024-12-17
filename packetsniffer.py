import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connection.recvfrom(65536)
        destination_mac, source_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print('\tDestination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, eth_protocol))

        if eth_protocol == 8:  # IPv4
            if len(data) >= 20:  # Ensure the data is sufficient for an IPv4 header
                try:
                    version, header_length, ttl, protocol, source, target, data = ipv4_packet(data)
                    print('\tIPV4 Packet:')
                    print('\t\tVersion: {} Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print('\t\tProtocol: {}, Source: {}, Target: {}'.format(protocol, source, target))

                    # Handle ICMP packets
                    if protocol == 1:
                        if len(data) >= 4:  # Ensure enough data for ICMP header
                            icmp_type, code, checksum, data = icmp_packet(data)
                            print('\tICMP Packet: ')
                            print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                            print('\t\tData: ')
                            print(format_multi_line('\t\t\t\t', data))
                        else:
                            print('\t\tData too short for ICMP packet.')

                    # Handle TCP packets
                    elif protocol == 6:  # Protocol number 6 corresponds to TCP
                        if len(data) >= 20:  # Ensure enough data for TCP header
                            source_port, destination_port, sequence, acknowledgement, offset, flags = tcp_segment(data)
                            print('\tTCP Segment:')
                            print('\t\tSource Port: {}, Destination Port: {}'.format(source_port, destination_port))
                            print('\t\tSequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                            print('\t\tHeader Length: {} bytes'.format(offset))
                            print('\t\tFlags:')
                            for flag, value in flags.items():
                                print('\t\t\t{}: {}'.format(flag, value))
                            print('\t\tData:')
                            print(format_multi_line('\t\t\t\t', data[offset:]))  # Data starts after the header length
                        else:
                            print('\t\tData too short for TCP segment.')

                    # Handle UDP packets
                    elif protocol == 17:
                        if len(data) >= 8:  # Ensure enough data for UDP header
                            source_port, destination_port, length, data = udp_segment(data)
                            print('\tUDP Segment: ')
                            print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(
                                source_port, destination_port, length))
                        else:
                            print('\t\tData too short for UDP segment.')

                    else:
                        print('\tUnknown Protocol. Data:')
                        print(format_multi_line('\t\t', data))
                except struct.error as e:
                    print(f'\tError unpacking IPv4 packet: {e}')
            else:
                print('\tData too short for IPv4 packet.')
        else:
            print('\tNon-IPv4 Protocol. Data:')
            print(format_multi_line('\t', data))


def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(protocol), data[14:]


def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()


def ipv4(address):
    return '.'.join(map(str, address))


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(source), ipv4(target), data[header_length:]


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',
                                                                                                      data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return source_port, destination_port, sequence, acknowledgement, offset, {
        'URG': flag_urg,
        'ACK': flag_ack,
        'PSH': flag_psh,
        'RST': flag_rst,
        'SYN': flag_syn,
        'FIN': flag_fin,
    }


def udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
