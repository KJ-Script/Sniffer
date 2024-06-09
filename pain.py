import customtkinter as ctk
import multiprocessing
from scapy.all import *
from features.generator import generate_flow
from features.pipeline import calculate_features, scan_input, classify_prediction
from rule.packet_rule import attack_test
from helper.call import send_prediction, send_log
from features.packet_data.packet_bundle import packet_obj
import time

flow = {}
i = 0


def engine(packet, queue, token):
    rule_result = attack_test(packet)
    print("rule: ", rule_result)

    if rule_result != "pass" and rule_result is not None:
        print(f"suspected {rule_result} attack")
        bundle = packet_obj(packet)
        print(bundle)
        # pass token here
        send_prediction(rule_result, bundle, 'rule', token)
    elif rule_result == 'pass':
        print(f"safe, {rule_result}")
    else:
        print("No ip found")
    global i
    item = generate_flow(packet, i, flow)
    if item is not None:
        i += 1
        send_log(item, token)
        queue.put(item)


def packet_sniffer(queue, token):
    def sniff_callback(packet):
        engine(packet, queue, token)

    sniff(prn=sniff_callback)


def packet_consumer(queue, token):
    while True:
        thing = queue.get()
        if thing is not None:
            result, column_mapping = calculate_features(thing)
            scan_result = scan_input(result, column_mapping)
            prediction = classify_prediction(scan_result)
            print("Features", prediction)
            guard = "Model"
            print("THING___________________________________________", thing)

            packet_list = {
                    'source_ip': thing['source_ip'],
                    'destination_ip': thing['destination_ip'],
                    'protocol': thing['protocol'],
                    'source_port': thing['source_port'],
                    'destination_port': thing['destination_port'],
                    'timestamp': time.time(),
            }
            if prediction is None:
                prediction = "Conflicted"
            send_prediction(prediction, packet_list, guard, token)


def start_sniffer_and_consumer(token):
    queue = multiprocessing.Queue()

    sniffer_process = multiprocessing.Process(target=packet_sniffer, args=(queue, token))
    consumer_process = multiprocessing.Process(target=packet_consumer, args=(queue, token))

    sniffer_process.start()
    consumer_process.start()

    sniffer_process.join()
    consumer_process.join()


def open_box(token):
    app = ctk.CTk()
    app.geometry('300x200')
    app.title("CustomTkinter Interface")

    def pass_token():
        start_sniffer_and_consumer(token)

    # Create a button
    button = ctk.CTkButton(app, text="Start Processes", command=pass_token)
    button.pack(pady=20)

    # Start the Tkinter event loop
    app.mainloop()
