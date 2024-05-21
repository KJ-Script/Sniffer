from scapy.all import *
from features.generator import generate_flow
import multiprocessing

flow = {}
i = 0


def engine(packet):
    global i
    generate_flow(packet, i, flow)


def sniff_interface():
    sniff(prn=engine)


sniff_interface()

