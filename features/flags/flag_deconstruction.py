def deconstruct(packet):
    if packet.haslayer('TCP'):
        flags = packet['TCP'].flags
        flags_array = []

        if flags & 0x01:
            flags_array.append("FIN")
        if flags & 0x02:
            flags_array.append("SYN")
        if flags & 0x04:
            flags_array.append("RST")
        if flags & 0x08:
            flags_array.append("PSH")
        if flags & 0x10:
            flags_array.append("ACK")
        if flags & 0x20:
            flags_array.append("URG")
        if flags & 0x40:
            flags_array.append("ECE")
        if flags & 0x80:
            flags_array.append("CWR")

        return flags_array
    else:
        return None
