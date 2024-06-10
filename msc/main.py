from scapy.all import *
from features.generator import generate_flow
from features.pipeline import calculate_features, scan_input, classify_prediction
from rule.packet_rule import packet_list
from rule.flow_rules import syn_attack, icmp_flood
from helper.call import send_model_prediction
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
        if packet_list(packet) is None:
            engine(packet, queue)
        else:
            print("Banned IP detected")

    sniff(prn=sniff_callback)


def packet_consumer(queue):
    while True:
        print("Before pop", queue.qsize())
        thing = queue.get()
        print("after pop", queue.qsize())

        if thing is not None:
            # if syn_attack(thing):
            #     print("Suspected Syn flood")
            # if icmp_flood(thing):
            #     print("Suspected ping flood")
            # else:
            #     result, column_mapping = calculate_features(thing)
            #     scan_result = scan_input(result, column_mapping)
            #     prediction = classify_prediction(scan_result)
            #     print("Features", prediction)
            #     # data = send_model_prediction(prediction, thing)
            print("Ueeue ----------", thing)

if __name__ == "__main__":
    queue = multiprocessing.Queue()

    sniffer_process = multiprocessing.Process(target=packet_sniffer, args=(queue,))
    consumer_process = multiprocessing.Process(target=packet_consumer, args=(queue,))

    sniffer_process.start()
    consumer_process.start()

    sniffer_process.join()
    consumer_process.join()
