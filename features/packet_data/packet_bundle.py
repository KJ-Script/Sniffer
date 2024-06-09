from features.packet_data.get_address import get_protocol, ip_address, port


def packet_obj(packet):
    src, dst = ip_address(packet)
    protocol = get_protocol(packet)
    sport, dport = port(packet, protocol)
    return {
        'source_ip': src,
        'destination_ip': dst,
        'protocol': protocol,
        'source_port': sport,
        'destination_port': dport,
        'timestamp': packet.time,
    }


