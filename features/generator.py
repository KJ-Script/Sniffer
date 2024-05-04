from features.packet_data.get_address import ip_address, get_protocol, port
from features.packet_data.get_timestamp import timestamp
from features.flags.flag_deconstruction import deconstruct
from features.flow.packet_direction import packet_direction
from features.flow.flow_session import end_flow
from helper.timeout import activity_timeout, inactivity_timeout
from helper.match import protocol_match, ip_match, port_match


def generate_flow(packet, i, flow):
    time_array, flags, forward_packet_flag, backward_packet_flag = [], [], [], []

    if 'IP' in packet:
        protocol = get_protocol(packet)
        source, destination = ip_address(packet)
        sport, dport = port(packet, protocol)
        time_array.append(timestamp(packet))
        flags.append(deconstruct(packet))
        isComplete = False

        if len(flow) == 0:
            i = 1
            flow[i] = {'source_ip': source, 'destination_ip': destination, 'protocol': protocol, 'source_port': sport,
                       'destination_port': dport, 'flags': flags, 'isComplete': isComplete,
                       'forward_packet_flag': forward_packet_flag, 'backward_packet_flag': backward_packet_flag,
                       'timestamp': time_array}

            flow[i]['forward_packet_flag'].append(deconstruct(packet)) if packet_direction(source,
                                                                                           destination) else flow[i][
                'backward_packet_flag'].append(
                deconstruct(packet))

            if end_flow(deconstruct(packet)):
                flow[i]['isComplete'] = True
        else:
            global foundanItem
            foundanItem = False
            for item in flow.values():
                if protocol_match(protocol, item) and ip_match(source, destination, item) and port_match(sport, dport,
                                                                                                         item) and not \
                        item['isComplete']:
                    if activity_timeout(timestamp(packet), item['timestamp'][0]):
                        item['isComplete'] = True
                        break
                    else:
                        item['flags'].append(deconstruct(packet))
                        item['isComplete'] = True if end_flow(deconstruct(packet)) else False
                        item['timestamp'].append(timestamp(packet))
                        item['forward_packet_flag'].append(deconstruct(packet)) if packet_direction(source,
                                                                                                    destination) else \
                            item['backward_packet_flag'].append(deconstruct(packet))
                        foundanItem = True

                        break
                else:
                    if inactivity_timeout(timestamp(packet), item['timestamp'][-1]):
                        item['isComplete'] = True
                        break

            if not foundanItem:
                i = list(flow)[-1] + 1
                flow[i] = {'source_ip': source, 'destination_ip': destination, 'protocol': protocol,
                           'source_port': sport,
                           'destination_port': dport, 'flags': flags, 'isComplete': isComplete,
                           'forward_packet_flag': forward_packet_flag, 'backward_packet_flag': backward_packet_flag,
                           'timestamp': time_array}
                flow[i]['forward_packet_flag'].append(deconstruct(packet)) if packet_direction(source, destination) else \
                    flow[i]['backward_packet_flag'].append(
                        deconstruct(packet))
                flow[i]['timestamp'].append(timestamp(packet))
                if end_flow(deconstruct(packet)):
                    flow[i]['isComplete'] = True
