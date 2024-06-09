def get_length(packet):
    if packet.haslayer('IP'):
        return packet['IP'].len


def get_header_length(packet):
    if packet.haslayer('IP'):
        return packet['IP'].ihl * 4


def for_packet_std(item):
    packet_array = item['forward_packet_length']
    mean = sum(packet_array)/len(packet_array)
