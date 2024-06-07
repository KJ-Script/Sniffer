import socket


def get_ip_address():
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        return ip_address
    except socket.error:
        return "Could not get IP address"
