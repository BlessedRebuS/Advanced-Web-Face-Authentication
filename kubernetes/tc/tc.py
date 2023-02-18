from flask import Flask, jsonify, request
import requests
import os

app = Flask(__name__)
server_list = []
try:
        parse_list = os.environ['TRUSTED_SERVERS']
        for i in parse_list.split("-"):
            i = i.strip('\n')
            i = i.strip(' ')
            server_list.append(i)
        server_list.remove("")
except: 
        print("ERROR FETCHING SERVER LIST")
        server_list.append('http://ts1:5000')
        server_list.append('http://ts2:6000')

print("Server list: ", server_list)

@app.route('/' , methods=['GET', 'POST'])
def handle():
    username = request.headers.get('username')
    received_encoding = request.headers.get('received_encoding')
    saved_encoding = request.headers.get('saved_encoding')

    result = []
    for server in server_list:
        try:
            if(saved_encoding == None):
                r = requests.get(
                    f'{server}/server',
                    headers={
                    'username': username
                    }, timeout=2
                )
            else:
                r = requests.get(
                    f'{server}/server',
                    headers={
                    'username': username,
                    'saved_encoding': saved_encoding,
                    'received_encoding': received_encoding
                    }, timeout=2
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

