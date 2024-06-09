from helper.ip_address import get_ip_address
from constants import THRESH_HOLD_COUNT, THRESH_HOLD_SECONDS
from collections import defaultdict
import time
from scapy.all import *

# HOME_NET = get_ip_address()
HOME_NET = '192.168.188.105'

syn_count = defaultdict(int)
syn_reset_time = defaultdict(float)

ack_count = defaultdict(int)
ack_reset_time = defaultdict(float)

icmp_count = defaultdict(int)
last_reset_time = defaultdict(float)

black_listed_ip = []


def check_black_list(array, item):
    if item in array:
        print("Already in blacklist but here's a ping: ", array)
        return True
    else:
        return False


def syn_flood(packet):
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        tcp_layer = packet.getlayer("TCP")
        if check_black_list(black_listed_ip, packet['IP'].src):
            return None
        else:
            if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'S':
                current_time = time.time()
                dst_ip = packet['IP'].dst

                if current_time - syn_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                    syn_count[dst_ip] = 0
                    syn_reset_time[dst_ip] = current_time

                syn_count[dst_ip] += 1
                if syn_count[dst_ip] > THRESH_HOLD_COUNT:
                    black_listed_ip.append(packet['IP'].src)
                    print(f"possible syn dos attack from {packet['IP'].src} on {dst_ip}")
                    return True


def ack_flood(packet):
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        tcp_layer = packet.getlayer("TCP")

        if packet['IP'].dst in HOME_NET and tcp_layer.flags == 'A':
            current_time = time.time()
            dst_ip = packet['IP'].dst

            if current_time - ack_reset_time[dst_ip] > THRESH_HOLD_SECONDS:
                ack_count[dst_ip] = 0
                ack_reset_time[dst_ip] = current_time

            ack_count[dst_ip] += 1

            if ack_count[dst_ip] > THRESH_HOLD_COUNT:
                print(f"possible syn dos attack from {packet['IP'].src} on {dst_ip}")
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
                black_listed_ip.append(packet['IP'].src)
                print(f"Possible ICMP DoS attack detected on {dst_ip}")
                # Reset the counter after detection to avoid spamming
                icmp_count[dst_ip] = 0
                return True


def attack_test(packet):
    if packet.haslayer('IP') and packet.getlayer('IP') is not None:
        if syn_flood(packet):
            return "syn_flood"
        elif ack_flood(packet):
            return "ack_flood"
        elif detect_icmp_flood(packet):
            return "icmp_flood"
        else:
            return "pass"
    else:
        return None

    # Sniffing for ICMP packets


# sniff(filter='tcp', prn=attack_test)
