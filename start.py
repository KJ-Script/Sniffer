import customtkinter as ctk
from functools import partial
import multiprocessing
import queue
import threading

# Import your existing code here
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

def packet_consumer(queue, ui_queue):
    while True:
        thing = queue.get()
        if thing is not None:
            if syn_attack(thing):
                print("Suspected Syn flood")
                ui_queue.put("Suspected Syn flood")
            elif icmp_flood(thing):
                print("Suspected ping flood")
                ui_queue.put("Suspected ping flood")
            else:
                result, column_mapping = calculate_features(thing)
                scan_result = scan_input(result, column_mapping)
                prediction = classify_prediction(scan_result)
                print("Features", prediction)
                data = send_model_prediction(prediction, thing)
                ui_queue.put(data)

# Function to update data in the UI
def update_data(data_frame, ui_queue):
    try:
        while True:
            data = ui_queue.get_nowait()
            data_label = ctk.CTkLabel(data_frame, text=str(data), text_color='black')
            data_label.pack(anchor="w", padx=10, pady=5)
            data_frame.update_idletasks()
    except queue.Empty:
        pass
    data_frame.after(1000, partial(update_data, data_frame, ui_queue))

def open_new_window():
    # Create a new window
    app = ctk.CTk()
    app.geometry('1000x800')
    app.title("Safenet IDS")

    outfit_large = ctk.CTkFont(family='Outfit', size=34, weight='bold')
    outfit_small = ctk.CTkFont(family='Outfit', size=18, weight='normal')
    outfit_smallest = ctk.CTkFont(family='Outfit', size=16, weight='normal')

    left_frame = ctk.CTkFrame(app, width=350, height=800, fg_color="Indigo")
    left_frame.grid(row=0, column=0, sticky="nsew")

    app.grid_rowconfigure(0, weight=1)

    def switch_tab(tab_index):
        # Hide all content frames
        for frame in tab_content_frames:
            frame.grid_remove()
        # Show the selected tab content
        tab_content_frames[tab_index].grid(row=0, column=0, sticky="nsew")

    bg_label = ctk.CTkLabel(left_frame, text="Safenet", font=outfit_smallest)
    bg_label.pack(pady=(20, 25))

    # Create tab buttons in the left frame
    tab_buttons = []
    tab_names = ["Flows", "Blacklisted IPs", "Logs"]
    for i, tab_name in enumerate(tab_names):
        tab_button = ctk.CTkButton(left_frame, width=200, height=50, text=tab_name, font=outfit_small,
                                   command=lambda i=i: switch_tab(i))
        tab_button.pack(fill='x', padx=20, pady=5)
        tab_buttons.append(tab_button)

    # Create the right frame for tab content
    right_frame = ctk.CTkFrame(app, width=650, height=800, fg_color='lightgray')
    right_frame.grid(row=0, column=1, sticky="nsew")
    app.grid_columnconfigure(1, weight=1)
    app.grid_rowconfigure(0, weight=1)

    # Create frames for tab content in the right frame
    tab_content_frames = []
    for i in range(len(tab_buttons)):
        tab_content_frame = ctk.CTkFrame(right_frame, width=600, height=800, fg_color="lightgray")
        tab_content_frame.grid(row=0, column=0, sticky="ns")
        tab_content_frame.grid_remove()
        tab_content_frames.append(tab_content_frame)

    # Add content to each tab
    ctk.CTkLabel(tab_content_frames[0], text="Content for Flows").grid(row=0, column=0, padx=20, pady=20)

    button = ctk.CTkButton(tab_content_frames[0], text='Scan', width=200, height=45, fg_color='Indigo', text_color='white', font=outfit_small, hover=False,
                           command=lambda: start_sniffer_and_consumer(data_frame))
    button.grid(row=0, column=0, padx=20, pady=20)

    # Create a scrollable frame for the data
    data_frame = ctk.CTkScrollableFrame(tab_content_frames[0], width=700, height=700, fg_color='white', border_width=2,
                                        border_color='lightgray')
    data_frame.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

    ctk.CTkLabel(tab_content_frames[1], text="Content for Blacklisted IPs").grid(row=0, column=0, padx=20, pady=20)
    ctk.CTkLabel(tab_content_frames[2], text="Content for Logs").grid(row=0, column=0, padx=20, pady=20)

    # Initially show the first tab content
    switch_tab(0)

    app.mainloop()

def start_sniffer_and_consumer(data_frame):
    queue = multiprocessing.Queue()
    ui_queue = queue.Queue()

    sniffer_thread = threading.Thread(target=packet_sniffer, args=(queue,))
    consumer_process = multiprocessing.Process(target=packet_consumer, args=(queue, ui_queue))
    update_thread = threading.Thread(target=update_data, args=(data_frame, ui_queue))

    sniffer_thread.start()
    consumer_process.start()
    update_thread.start()

if __name__ == "__main__":
    open_new_window()
