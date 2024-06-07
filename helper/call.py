import requests


# Function to send model prediction
def send_model_prediction(attack_type, packet_list, guard):
    url = 'http://192.168.188.100:4000/api/flows'
    access_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NjYxNTJjODQ5YmFiMzVmYjZkYTljZjUiLCJmaXJzdE5hbWUiOiJOYXRhbiIsImxhc3ROYW1lIjoiTWVrZWJpYiIsImVtYWlsIjoiZ2ZAZ21haWwuY29tIiwiaWF0IjoxNzE3NjU0MzYwLCJleHAiOjE3MTc5MTM1NjB9.CkNU5-F6F12OSRn7dyNchulPRf9KN79FfucgRb6dQ9E'

    session = requests.Session()
    session.cookies.set('accessToken', access_token)

    data = {
        "Flow": packet_list,
        "Attack_type": attack_type,
        "Mechanism": guard
    }
    print("Data", data)

    response = session.post(url, json=data)

    if response.status_code == 200:
        print("POST request successful!")
        print("Response _____________________________", response.json())
    else:
        print("POST request failed!")
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")


# Example call to the function
