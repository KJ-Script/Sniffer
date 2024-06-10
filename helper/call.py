import requests
import time

# Function to send model prediction
# ip = '192.168.188.102'
ip = '127.0.0.1'


def send_prediction(attack_type, packet_list, guard, token):
    url = f'http://{ip}:4000/api/blacklist'
    access_token = token
    session = requests.Session()
    session.cookies.set('accessToken', access_token)
    data = {
        "Flow": packet_list,
        "attack_type": attack_type,
        "mechanism": guard,
        "time": time.time()
    }

    response = session.post(url, json=data)
    print(response.status_code)

    if response.status_code == 200:
        print("POST request successful!")
        print("Response: ", response.json())
    else:
        print("POST request failed!")
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")


def auth_call(email, password):
    url = f'http://{ip}:4000/api/auth/login'

    account = {
        'email': email,
        'password': password,
    }

    response = requests.post(url, json=account)

    if response.status_code == 200:
        token = response.json()
        print(token['accessToken'])
        return token['accessToken']
    else:
        print(f"error encountered: {response.status_code}")
        print(response)
        return None


def send_log(packet_list, token):
    print("Sending logs here")
    url = f'http://{ip}:4000/api/flows'
    access_token = token
    session = requests.Session()
    session.cookies.set('accessToken', access_token)

    data = {
        "Flow": packet_list,
        "time": time.time()
    }

    print("Data", data)

    response = session.post(url, json=data)
    print(response.status_code)

    if response.status_code == 200:
        print("POST request for log successful!")
        print("Response: ", response.json())
    else:
        print("POST request for log failed!")
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")
