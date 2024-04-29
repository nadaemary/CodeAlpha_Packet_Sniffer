import socket
import struct
import textwrap

# constants:
ONE_TAB = '\t - '
TWO_TABS = '\t\t - '
THREE_TABS = '\t\t\t - '
FOUR_TABS = '\t\t\t\t - '


## slicing the data into frames and packets
## first, upack the ethernet frame
### TODO: explain how upack works first
def unpack_ethernet_frame(data):
     dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
     return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

## formating from b'\x00\x11\x22\x33\x44\x55' to 00:11:22:33:44:55
def get_mac_address(address_in_bytes):
    str = map('{:02x}'.format, address_in_bytes)
    mac_address = ':'.join(str).upper()
    return mac_address

## a helpler function to return properly formatted upv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


## second we unpack the ipv4 packet
def unpack_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) *4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

## unpacking imcp segement
def unpack_icmp_segment(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

## unpacking tcp segement
def unpack_tcp_segement(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12) *4
    flag_urg = (offset_reserved_flags & 32) >>5
    flag_ack = (offset_reserved_flags & 16) >>4
    flag_psh = (offset_reserved_flags & 8) >>3
    flag_rst = (offset_reserved_flags & 4) >>2
    flag_syn = (offset_reserved_flags & 2) >>1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


## unpacking udp segement
def unpack_udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, size, data[8:]

## Creating the connection:
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
while True: # to capture several packets


    ## getting the data
    raw_data, addr = conn.recvfrom(65536)
    ## printing the ethernet frame
    dest_mac, src_mac, eth_protocol, eth_data = unpack_ethernet_frame(raw_data)
    print('/nEthernet Frame:')
    print(ONE_TAB + 'destination: {}, source: {}, protocol: {}'.format(dest_mac, src_mac, eth_protocol))

    ## protocol 8 for ipv4
    if eth_protocol == 8:
        ## printing the ipv4 packet
        version, header_length, ttl, protocol, src, target, mid_data = unpack_ipv4_packet(eth_data)
        print(TWO_TABS + 'ipv4 Packet: ')
        print(THREE_TABS + 'version: {}, Header lenght: {}, TTL: {}'.format(version, header_length, ttl))
        print(THREE_TABS + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, src, target))

        ## which protocl we are using?
        ## 1 represents icmp
        if protocol == 1:
            ## printing icmp packet
            icmp_type, code, checksum, data = unpack_icmp_segment(mid_data)
            print(TWO_TABS + 'ICMP Packet: ')
            print(THREE_TABS + 'Type: {}, Code: {}, checksum: {}'.format(icmp_type, code, checksum))
            print(THREE_TABS + 'Data: ')
            print(FOUR_TABS + 'actual data: {}'.format(data))

        ## 6 represents tcp
        elif protocol == 6:
            ## printing tcp packet
            src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = unpack_tcp_segement(mid_data)
            print(TWO_TABS + 'TCP Segment: ')
            print(THREE_TABS + 'Source Port: {}, Destination Port: {}'. format(src_port, dest_port))
            print(THREE_TABS + 'sequence: {}, acknowledgement: {}'. format(sequence, acknowledgement))
            print(THREE_TABS+ 'Flags: ')
            print(FOUR_TABS + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'. format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
            print(THREE_TABS + 'Data: ')
            print(FOUR_TABS + 'actual data: {}'.format(data))

        ## 17 represents udp
        elif protocol == 17:
            ## printing udp segement
            src_port, dest_port, lenght, data = unpack_udp_segment(mid_data)
            print(TWO_TABS + 'UDP segment: ')
            print(THREE_TABS + 'Source Port: {}, Destination Port: {}, Lenght: {}'.format(src_port, dest_port, lenght))
            print(FOUR_TABS + 'actual data: {}'.format(data))
        else:
            ## other protocols
            print(THREE_TABS + 'Data: ')
            print(FOUR_TABS + 'actual data: {}'.format(data))

    print('-'*100)
