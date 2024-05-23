import requests


def send_model_prediction(attack_type, packet_list):
    url = 'https://localhost:3000/api/flow'

    data = {
        "Flow": packet_list,  # this is a python dictionary - js object
        "Attack_type": attack_type,
        "Mechanism": "Model"
    }
    print("Data", data)
    response = requests.post(url, json=data)

    if response.status_code == 200:
        print("POST request successful!")
    else:
        print("POST request failed!")
