from features.packet_data.get_address import ip_address, get_protocol, port
from features.packet_data.get_timestamp import timestamp
from features.flags.flag_deconstruction import deconstruct
from features.flow.packet_direction import packet_direction
from features.flow.flow_session import end_flow
from helper.timeout import activity_timeout, inactivity_timeout
from helper.match import protocol_match, ip_match, port_match
from features.calculate.segments import packet_segment
from features.calculate.length import get_length, get_header_length


def generate_flow(packet, i, flow):

    time_array, flags, forward_packet_flag, backward_packet_flag = [], [], [], []
    back_time, for_time, for_len, back_len, for_ihl, back_ihl = [], [], [], [], [], []
    packet_dir, packet_ihl, packet_seg = [], [], []
    for_segment, back_segment = [], []

    if 'IP' in packet:
        protocol = get_protocol(packet)
        source, destination = ip_address(packet)
        sport, dport = port(packet, protocol)
        time_array.append(timestamp(packet))
        flags.append(deconstruct(packet))
        isComplete = False
        get_length(packet)

        if len(flow) == 0:
            i = 1
            flow[i] = {'source_ip': source, 'destination_ip': destination, 'protocol': protocol, 'source_port': sport,
                       'destination_port': dport, 'flags': flags, 'isComplete': isComplete,
                       'forward_packet_flag': forward_packet_flag, 'backward_packet_flag': backward_packet_flag,
                       'timestamp': time_array, 'forward_packet_time': for_time, 'backward_packet_time': back_time,
                       'forward_packet_length': for_len, 'backward_packet_length': back_len,
                       'forward_packet_ihl': for_ihl, 'backward_packet_ihl': back_ihl, 'for_segment': for_segment,
                       'back_segment': back_segment, 'packet_dir': packet_dir, 'packet_ihl': packet_ihl,
                       "packet_seg": packet_seg}

            if packet_direction(source, destination):
                flow[i]['forward_packet_flag'].append(deconstruct(packet))
                flow[i]['forward_packet_time'].append(timestamp(packet))
                flow[i]['forward_packet_length'].append(get_length(packet))
                flow[i]['forward_packet_ihl'].append(get_header_length(packet))
                flow[i]['for_segment'].append(packet_segment(packet, protocol))
                flow[i]['packet_dir'].append("FOR")
                flow[i]['packet_ihl'].append(get_header_length(packet))
                flow[i]['packet_seg'].append(packet_segment(packet, protocol))
            else:
                flow[i]['backward_packet_flag'].append(deconstruct(packet))
                flow[i]['backward_packet_time'].append(timestamp(packet))
                flow[i]['backward_packet_length'].append(get_length(packet))
                flow[i]['backward_packet_ihl'].append(get_header_length(packet))
                flow[i]['for_segment'].append(packet_segment(packet, protocol))
                flow[i]['packet_dir'].append("BACK")
                flow[i]['packet_ihl'].append(get_header_length(packet))
                flow[i]['packet_seg'].append(packet_segment(packet, protocol))

            if end_flow(deconstruct(packet)):
                flow[i]['isComplete'] = True

                print("done flag", flow[i])
                return flow[i]

        else:
            global foundanItem
            foundanItem = False
            for item in flow.values():
                if protocol_match(protocol, item) and ip_match(source, destination, item) and port_match(sport, dport,
                                                                                                         item) and not \
                        item['isComplete']:
                    # activity timeout
                    if activity_timeout(timestamp(packet), item['timestamp'][0]):
                        print("activity")
                        item['isComplete'] = True
                        return item

                    else:
                        item['flags'].append(deconstruct(packet))
                        item['isComplete'] = True if end_flow(deconstruct(packet)) else False
                        item['timestamp'].append(timestamp(packet))

                        if packet_direction(source, destination):
                            item['forward_packet_flag'].append(deconstruct(packet))
                            item['forward_packet_time'].append(timestamp(packet))
                            item['forward_packet_length'].append(get_length(packet))
                            item['forward_packet_ihl'].append(get_header_length(packet))
                            item['for_segment'].append(packet_segment(packet, protocol))
                            item['packet_dir'].append("FOR")
                            item['packet_ihl'].append(get_header_length(packet))
                            item['packet_seg'].append(packet_segment(packet, protocol))

                        else:
                            item['backward_packet_flag'].append(deconstruct(packet))
                            item['backward_packet_time'].append(timestamp(packet))
                            item['backward_packet_length'].append(get_length(packet))
                            item['backward_packet_ihl'].append(get_header_length(packet))
                            item['for_segment'].append(packet_segment(packet, protocol))
                            item['packet_dir'].append("FOR")
                            item['packet_ihl'].append(get_header_length(packet))
                            item['packet_seg'].append(packet_segment(packet, protocol))

                        foundanItem = True
                        break
                else:
                    # inactivity timeout
                    if inactivity_timeout(timestamp(packet), item['timestamp'][-1]):
                        print("inactivity")
                        item['isComplete'] = True
                        return item

            if not foundanItem:
                i = list(flow)[-1] + 1
                flow[i] = {'source_ip': source, 'destination_ip': destination, 'protocol': protocol,
                           'source_port': sport,
                           'destination_port': dport, 'flags': flags, 'isComplete': isComplete,
                           'forward_packet_flag': forward_packet_flag, 'backward_packet_flag': backward_packet_flag,
                           'timestamp': time_array, 'forward_packet_time': for_time, 'backward_packet_time': back_time,
                           'forward_packet_length': for_len, 'backward_packet_length': back_len,
                           'forward_packet_ihl': for_ihl, 'backward_packet_ihl': back_ihl, 'for_segment': for_segment,
                           'back_segment': back_segment, 'packet_dir': packet_dir, 'packet_ihl': packet_ihl,
                           "packet_seg": packet_seg}

                if packet_direction(source, destination):
                    flow[i]['forward_packet_flag'].append(deconstruct(packet))
                    flow[i]['forward_packet_time'].append(timestamp(packet))
                    flow[i]['forward_packet_length'].append(get_length(packet))
                    flow[i]['forward_packet_ihl'].append(get_header_length(packet))
                    flow[i]['for_segment'].append(packet_segment(packet, protocol))
                    flow[i]['packet_dir'].append("BACK")
                    flow[i]['packet_ihl'].append(get_header_length(packet))
                    flow[i]['packet_seg'].append(packet_segment(packet, protocol))

                else:
                    flow[i]['backward_packet_flag'].append(deconstruct(packet))
                    flow[i]['backward_packet_time'].append(timestamp(packet))
                    flow[i]['backward_packet_length'].append(get_length(packet))
                    flow[i]['backward_packet_ihl'].append(get_header_length(packet))
                    flow[i]['for_segment'].append(packet_segment(packet, protocol))
                    flow[i]['packet_dir'].append("BACK")
                    flow[i]['packet_ihl'].append(get_header_length(packet))
                    flow[i]['packet_seg'].append(packet_segment(packet, protocol))

                flow[i]['timestamp'].append(timestamp(packet))

                if end_flow(deconstruct(packet)):
                    # Flag finish
                    flow[i]['isComplete'] = True
                    return flow[i]
