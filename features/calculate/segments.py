def packet_segment(packet, protocol):
    if protocol in packet:
        segment = bytes(packet[protocol].payload)
        return len(segment)
    else:
        print("unsupported protocol")
        return None

