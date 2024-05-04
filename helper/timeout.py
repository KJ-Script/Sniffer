from constants import ACTIVE_TIMEOUT, INACTIVITY_TIMEOUT


def activity_timeout(packet, stored_packet):
    if packet - stored_packet >= ACTIVE_TIMEOUT:
        return True
    else:
        return False


def inactivity_timeout(packet, stored_packet):
    if packet - stored_packet >= INACTIVITY_TIMEOUT:
        return True
    else:
        return False
