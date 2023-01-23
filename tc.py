from flask import Flask, jsonify, request
import requests

app = Flask(__name__)
server_list = ["http://127.0.0.1:5000", "http://127.0.0.1:6000", "http://127.0.0.1:7000"]


@app.route('/' , methods=['GET', 'POST'])
def handle():
    username = request.headers.get('username')
    received_encoding = request.headers.get('received_encoding')
    saved_encoding = request.headers.get('saved_encoding')
    # print(f"Received with encoding {encoding}, saved_encoding: {saved_encoding}")

    result = []
    for server in server_list:
        try:
            if(saved_encoding == None):
                r = requests.get(
                    f'{server}/server',
                    headers={
                    'username': username
                    }
                )
            else:
                r = requests.get(
                    f'{server}/server',
                    headers={
                    'username': username,
                    'saved_encoding': saved_encoding,
                    'received_encoding': received_encoding
                    }
                )
        except:
            print(f"Error in server {server}")
            continue
        if r.status_code == 200:
            print(f"Server {server} is working")
            result.append(r.json())
        else:
            print(f"Error in server {server}")
    print(f"Result: {(result)}")
    return(jsonify(result))

if __name__ == "__main__":
    app.run()

