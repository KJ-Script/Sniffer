from scapy.all import *
from features.generator import generate_flow
from call import call

flow = {}
i = 0


def engine(packet):
    global i
    generate_flow(packet, i, flow)



sniff(prn=engine)
