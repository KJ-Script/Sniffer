from features.calculate.math import *
from features.flags.get_flags import flag_count
import tensorflow as tf
import pandas as pd


def calculate_features(flow):
    if flow is not None:
        print(flow)
        for_seg_min = min(flow['for_segment']) if len(flow['for_segment']) > 0 else 0
        for_pkt_len_std = std(flow['forward_packet_length']) if len(flow['forward_packet_length']) > 0 else 0
        back_iat_mean = iat_mean(flow['backward_packet_time']) if len(flow['backward_packet_time']) > 0 else 0
        init_for_win_bytes = 0
        destination_port = flow['destination_port']
        back_packets = len(flow['backward_packet_flag']) if flow['protocol'] == 'TCP' else 0
        back_len_max = max(flow['backward_packet_length']) if len(flow['backward_packet_length']) > 0 else 0
        FIN_flag_count = flag_count(flow['flags'], 'FIN') if flow['protocol'] == 'TCP' else 0
        for_header_len = max(flow['forward_packet_ihl']) if len(flow['forward_packet_ihl']) > 0 else 0
        for_PSH_flag = flag_count(flow['forward_packet_flag'], 'PSH') if flow['protocol'] == 'TCP' else 0
        SYN_flag_count = flag_count(flow['flags'], 'SYN') if flow['protocol'] == 'TCP' else 0
        flow_iat_std = iat_std(flow['forward_packet_time'], flow['backward_packet_time'])
        tot_back_pkt = len(flow['backward_packet_flag'])
        flow_iat_mean = concatenated_mean(flow['forward_packet_time'], flow['backward_packet_time'])
        tot_len_back_pkt = sum(flow['backward_packet_length'])
        URG_flag_count = flag_count(flow['forward_packet_flag'], 'URG') if flow['protocol'] == 'TCP' else 0
        init_back_win_bytes = 0
        back_pkt_len_std = std(flow['backward_packet_length']) if len(flow['backward_packet_length']) > 0 else 0
        back_pkt_len_mean = mean(flow['backward_packet_length']) if len(flow['backward_packet_length']) > 0 else 0
        back_pkt_len_mean = mean(flow['backward_packet_length']) if len(flow['backward_packet_length']) > 0 else 0

        to_model = {
            "for_seg_min": for_seg_min, "for_pkt_len_std": for_pkt_len_std, "back_iat_mean": back_iat_mean,
            "init_for_win_bytes": init_for_win_bytes, "destination_port": destination_port,
            "back_packets": back_packets,
            "back_len_max": back_len_max, "FIN_flag_count": FIN_flag_count, "for_header_len": for_header_len,
            "for_PSH_flag": for_PSH_flag, "SYN_flag_count": SYN_flag_count, "flow_iat_std": flow_iat_std,
            "tot_back_pkt": tot_back_pkt, "flow_iat_mean": flow_iat_mean, "tot_len_back_pkt": tot_len_back_pkt,
            "URG_flag_count": URG_flag_count, "init_back_win_bytes": init_back_win_bytes,
            "back_pkt_len_std": back_pkt_len_std,
            "back_pkt_len_mean": back_pkt_len_mean
        }

        column_mapping = {
            'for_seg_min': 'Fwd Seg Size Min',
            'for_pkt_len_std': 'Fwd Pkt Len Std',
            'back_iat_mean': 'Bwd IAT Mean',
            'init_for_win_bytes': 'Init Fwd Win Byts',
            'destination_port': 'Dst Port',
            'back_packets': 'Bwd Pkts/s',
            'back_len_max': 'Bwd Pkt Len Max',
            'FIN_flag_count': 'FIN Flag Cnt',
            'for_header_len': 'Fwd Header Len',
            'for_PSH_flag': 'Fwd PSH Flags',
            'SYN_flag_count': 'SYN Flag Cnt',
            'flow_iat_std': 'Flow IAT Std',
            'tot_back_pkt': 'Tot Bwd Pkts',
            'flow_iat_mean': 'Flow IAT Mean',
            'tot_len_back_pkt': 'TotLen Bwd Pkts',
            'URG_flag_count': 'URG Flag Cnt',
            'init_back_win_bytes': 'Init Bwd Win Byts',
            'back_pkt_len_std': 'Bwd Pkt Len Std',
            'back_pkt_len_mean': 'Bwd Pkt Len Mean'
        }

        renamed_data = {column_mapping[k]: v for k, v in to_model.items()}
        print(renamed_data, "-----", column_mapping)
        return renamed_data, column_mapping

    else:
        print("still gathering flow...")


def classify_prediction(predictions):
    for prediction in predictions:
        if prediction[0] == 1:
            return "Benign"
        elif prediction[1] == 1:
            return "DDOS_GE"
        elif prediction[2] == 1:
            return "DDOS_SL"


def scan_input(input_data, mapping_check):
    model = tf.keras.models.load_model("../model/FFP_0.keras")
    df = pd.DataFrame([input_data])

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.fillna(0, inplace=True)

    check = df[list(mapping_check.values())].values

    check = check.astype(float)

    predictions = model.predict(check)
    print("predictions", predictions)
    return predictions
