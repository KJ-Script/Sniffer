from features.flow.packet_direction import packet_direction


def packet_list(packet):
    # fetch to handle getting list

    black_listed_ip = ["95.168.168.143", "192.168.188.102"]
    if 'IP' in packet:
        ip = packet['IP'].dst if packet_direction(packet['IP'].src, packet['IP'].dst) else packet['IP'].src
        for item in black_listed_ip:
            if ip == item:
                print("ip: ", ip)
                print("blacklisted ip detected")
                return ip
            else:
                return None

    else:
        print("no ip packet yet")
