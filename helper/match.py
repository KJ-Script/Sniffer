def protocol_match(protocol, item):
    if protocol == item['protocol']:
        return True
    else:
        return False


def ip_match(source, destination, item):
    if source == item['source_ip'] or source == item['destination_ip'] and destination == item[
        'source_ip'] or destination == item['destination_ip']:
        return True
    else:
        return False


def port_match(sport, dport, item):
    if sport == item['source_port'] or sport == item['destination_port'] and dport == item[
        'source_port'] or dport == item['destination_port']:
        return True
    else:
        return False
