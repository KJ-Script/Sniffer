from scapy.layers.inet import IP, TCP, UDP, ICMP
def ip_address(packet):
    if 'IP' in packet:
        source = packet['IP'].src
        destination = packet['IP'].dst
        return source, destination
    else:
        return None, None


def port(packet, protocol):
    if packet.haslayer(protocol) and protocol != 'ICMP' and protocol is not None:
        sport = packet[protocol].sport
        dport = packet[protocol].dport
        return sport, dport
    else:
        return None, None


def get_protocol(packet):
    if packet.haslayer(TCP):
        return 'TCP'
    elif packet.haslayer(UDP):
        return 'UDP'
    elif packet.haslayer(ICMP):
        print("icmp detected")
        return 'ICMP'
    else:
        print('Unsupported protocol found')
        return None
