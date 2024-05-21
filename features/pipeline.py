from features.calculate.math import *
from features.flags.get_flags import flag_count



def calculate_features(flow):
    if flow is not None:
        print(flow)
        for_seg_min = min(flow['for_segment'])
        for_pkt_len_std = std(flow['forward_packet_length'])
        back_iat_mean = iat_mean(flow['backward_packet_time'])
        init_for_win_bytes = 0
        destination_port = flow['destination_port']
        back_packets = len(flow['backward_packet_flag']) if flow['protocol'] == 'TCP' else 0
        back_len_max = max(flow['backward_packet_length'])
        FIN_flag_count = flag_count(flow['flags'], 'FIN') if flow['protocol'] == 'TCP' else 0
        for_header_len = max(flow['forward_packet_ihl'])
        for_PSH_flag = flag_count(flow['forward_packet_flag'], 'PSH') if flow['protocol'] == 'TCP' else 0
        SYN_flag_count = flag_count(flow['flags'], 'SYN')
        flow_iat_std = iat_std(flow['forward_packet_time'], flow['backward_packet_time'])
        tot_back_pkt = len(flow['backward_packet_flag'])
        flow_iat_mean = concatenated_mean(flow['forward_packet_time'], flow['backward_packet_time'])
        tot_len_back_pkt = sum(flow['backward_packet_length'])
        URG_flag_count = flag_count(flow['forward_packet_flag'], 'URG') if flow['protocol'] == 'TCP' else 0
        init_back_win_bytes = 0
        back_pkt_len_std = std(flow['backward_packet_length'])
        back_pkt_len_mean = mean(flow['backward_packet_length'])

        to_model = {
            for_seg_min, for_pkt_len_std, back_iat_mean, init_for_win_bytes, destination_port, back_packets,
            back_len_max, FIN_flag_count, for_header_len, for_PSH_flag, SYN_flag_count, flow_iat_std, tot_back_pkt,
            flow_iat_mean, tot_len_back_pkt, URG_flag_count, init_back_win_bytes, back_pkt_len_std, back_pkt_len_mean
        }

        return to_model

    else:
        print("Gathering flow...")


def scan(input):
    print("Input code goes here")