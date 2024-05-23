import requests


def send_data(result, attack_type, packet_list):
    url = 'https://example.com/api/endpoint'

    data = {
        'key1': 'value1',
        'key2': 'value2'
    }
    response = requests.post(url, json=data)

    if response.status_code == 200:
        print("POST request successful!")
    else:
        print("POST request failed!")