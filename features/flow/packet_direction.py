from helper.ip_address import get_ip_address
import ipaddress


def packet_direction(source, destination):
    src_bytes = ipaddress.ip_address(source).packed
    dst_bytes = ipaddress.ip_address(destination).packed

    for src_byte, dst_byte in zip(src_bytes, dst_bytes):
        if src_byte != dst_byte:
            if src_byte > dst_byte:
                return False
            break

    return True


def flow_direction(packet, item, protocol):
    return 'Working on it'
