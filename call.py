from scapy.all import *
from features.generator import generate_flow
import multiprocessing

flow = {}
i = 0


def engine(packet, queue):
    global i
    item = generate_flow(packet, i, flow)
    i += 1
    queue.put(item)


def packet_sniffer(queue):
    def sniff_callback(packet):
        engine(packet, queue)
    sniff(prn=sniff_callback)


def packet_consumer(queue):
    while True:
        thing = queue.get()

        print("scannable", thing)


if __name__ == "__main__":
    queue = multiprocessing.Queue()

    sniffer_process = multiprocessing.Process(target=packet_sniffer, args=(queue,))
    consumer_process = multiprocessing.Process(target=packet_consumer, args=(queue,))

    sniffer_process.start()
    consumer_process.start()

    sniffer_process.join()
    consumer_process.join()
