import customtkinter as ctk
from functools import partial
import multiprocessing
from scapy.all import *
from features.generator import generate_flow
from features.pipeline import calculate_features, scan_input, classify_prediction
from rule.packet_rule import packet_list
from rule.flow_rules import syn_attack, icmp_flood
from helper.call import send_model_prediction

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
        thing = queue.get()
        if thing is not None:
            if icmp_flood(thing):
                print("Suspected Syn flood")
            # elif syn_attack(flow):
            #     print("Suspected ping flood")
            else:
                result, column_mapping = calculate_features(thing)
                scan_result = scan_input(result, column_mapping)
                prediction = classify_prediction(scan_result)
                print("Features", prediction)
                guard = "Model"
                data = send_model_prediction(prediction, thing, guard)


def start_sniffer_and_consumer():
    queue = multiprocessing.Queue()

    sniffer_process = multiprocessing.Process(target=packet_sniffer, args=(queue,))
    consumer_process = multiprocessing.Process(target=packet_consumer, args=(queue,))

    sniffer_process.start()
    consumer_process.start()

    sniffer_process.join()
    consumer_process.join()


# def start_processes():
#     start_sniffer_and_consumer()
#
#
# # Define a function to handle button click event
# def on_button_click():
#     start_processes()


# Create the main application window
def open_box():
    app = ctk.CTk()
    app.geometry('300x200')
    app.title("CustomTkinter Interface")

    # Create a button
    button = ctk.CTkButton(app, text="Start Processes", command=start_sniffer_and_consumer)
    button.pack(pady=20)

# Start the Tkinter event loop
    app.mainloop()


open_box()