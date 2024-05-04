from helper.ip_address import get_ip_address


def packet_direction(source, destination):
    if get_ip_address() == source:
        return True
    elif get_ip_address() == destination:
        return False


def flow_direction(packet, item, protocol):
    return 'Working on it'
