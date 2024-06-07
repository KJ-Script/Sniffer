from features.flow.packet_direction import packet_direction
from constants import AVERAGE_PACKET_COUNT
from helper.call import send_model_prediction


def syn_attack(flow):
    # check ip
    syn_flood, ack_flood = False, False
    if flow['protocol'] == 'TCP':
        if packet_direction(flow['source_ip'], flow['destination_ip']):
            if all(all(flag == "SYN" for flag in flags) for flags in flow['backward_packet_flag']):
                print("flags", flow['backward_packet_flag'])
                syn_flood = True

            if all(all(flag == "ACK" for flag in flags) for flags in flow['backward_packet_flag']):
                print("ACK")
                ack_status = True
        else:
            if all(all(flag == "SYN" for flag in flags) for flags in flow['forward_packet_flag']):
                print("SYN")
                syn_flood = True

            if all(all(flag == "ACK" for flag in flags) for flags in flow['forward_packet_flag']):
                print("ACK")
                ack_status = True

        if syn_flood or ack_flood:
            print("Suspected syn flood attack")
            send_model_prediction("ACK_FLOOD", flow, "RULE_ENGINE")
            return True
        else:
            return False


def icmp_flood(flow):
    if flow['protocol'] == 'ICMP':
        if len(flow['flags']) > AVERAGE_PACKET_COUNT:
            print("Suspected ICMP flood attack")
            send_model_prediction("ICMP_FLOOD", flow, "RULE_ENGINE")
            return True
    else:
        return False
