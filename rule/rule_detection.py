from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from constants import THRESH_HOLD_COUNT, THRESH_HOLD_SECONDS
from collections import defaultdict
from helper.ip_address import get_ip_address
import time

# HOME_NET = get_ip_address()
HOME_NET = '192.168.188.102'

syn_count = defaultdict(int)
syn_reset_time = defaultdict(float)

ack_count = defaultdict(int)
ack_reset_time = defaultdict(float)

rst_count = defaultdict(int)
rst_reset_time = defaultdict(float)

fin_count = defaultdict(int)
fin_reset_time = defaultdict(float)

udp_count = defaultdict(int)
udp_last_reset_time = defaultdict(float)

icmp_count = defaultdict(int)
last_reset_time = defaultdict(float)


def syn_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print("checking for flags")
        if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'S':
            current_time = time.time()
            dst_ip = packet[IP].dst
            if current_time - syn_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                syn_count[dst_ip] = 0
                syn_reset_time[dst_ip] = current_time

            syn_count[dst_ip] += 1

            if syn_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"possible syn dos attack from {packet[IP].src} on {dst_ip}")
                rule_result = 'syn_flood'
                return True


def ack_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print("checking for flags")
        if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'A':
            current_time = time.time()
            dst_ip = packet[IP].dst
            if current_time - ack_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                ack_count[dst_ip] = 0
                ack_reset_time[dst_ip] = current_time

            ack_count[dst_ip] += 1

            if ack_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"possible ack dos attack from {packet[IP].src} on {dst_ip}")
                rule_result = 'ack'
                return True


def fin_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print("checking for flags")
        if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'F':
            current_time = time.time()
            dst_ip = packet[IP].dst
            if current_time - fin_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                fin_count[dst_ip] = 0
                fin_reset_time[dst_ip] = current_time

            fin_count[dst_ip] += 1
            if fin_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"possible fin dos attack from {packet[IP].src} on {dst_ip}")
                rule_result = 'fin'
                return True


def rst_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print("checking for flags")
        if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'R':
            current_time = time.time()
            dst_ip = packet[IP].dst
            if current_time - fin_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                fin_count[dst_ip] = 0
                fin_reset_time[dst_ip] = current_time

            syn_count[dst_ip] += 1

            if fin_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"possible rst dos attack from {packet[IP].src} on {dst_ip}")
                rule_result = 'rst'
                return True


def detect_udp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        if ip_layer.dst in HOME_NET:
            current_time = time.time()
            dst_ip = ip_layer.dst

            # Reset count if the time window has passed
            if current_time - udp_last_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                udp_count[dst_ip] = 0
                udp_last_reset_time[dst_ip] = current_time

            # Increment the UDP packet count
            udp_count[dst_ip] += 1

            # Check if the threshold is exceeded
            if udp_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"Possible UDP DoS attack detected on {dst_ip}")
                # Reset the counter after detection to avoid spamming
                udp_count[dst_ip] = 0
                return True


def detect_icmp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        ip_layer = packet.getlayer(IP)
        icmp_layer = packet.getlayer(ICMP)

        if ip_layer.dst in HOME_NET:
            current_time = time.time()
            dst_ip = ip_layer.dst

            # Reset count if the time window has passed
            if current_time - last_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                icmp_count[dst_ip] = 0
                last_reset_time[dst_ip] = current_time

                # Increment the ICMP packet count
            icmp_count[dst_ip] += 1

            # Check if the threshold is exceeded
            if icmp_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"Possible ICMP DoS attack detected on {dst_ip}")
                icmp_count[dst_ip] = 0
                return True


def return_rule(packet):
    if syn_flood(packet):
        return 'syn_flood'
    elif ack_flood(packet):
        return 'ack_flood'
    elif fin_flood(packet):
        return 'fin_flood'
    elif rst_flood(packet):
        return 'rst_flood'
    elif detect_udp_flood(packet):
        return 'udp_flood'
    elif detect_icmp_flood(packet):
        return 'icmp_flood'
    else:
        return 'pass'


# def syn_rule(packet):
#     if syn_flood(packet):
#         return 'syn_flood'
#     else:
#         return 'pass'
#
#
# def ack_rule(packets):
#     if ack_flood(packets):
#         return 'ack_flood'
#     else:
#         return 'pass'
#
#
# def fin_rule(packet):
#     if fin_flood(packet):
#         return 'fin_flood'
#     else:
#         return 'pass'
#
#
# def rst_rule(packet):
#     if rst_flood(packet):
#         return 'rst_flood'
#     else:
#         return 'pass'
#
#
# def udp_rule(packet):
#     if detect_udp_flood(packet):
#         return 'udp_flood'
#     else:
#         return 'pass'
#
#
# def icmp_rule(packet):
#     if detect_icmp_flood(packet):
#         return 'icmp_flood'
#     else:
#         return 'pass'

# sniff(prn=return_rule)
