from flask import Flask, jsonify
import requests

app = Flask(__name__)
server_list = ["http://127.0.0.1:5000/server1", "http://127.0.0.1:6000/server2", "http://127.0.0.1:7000/server3"]


@app.route('/' , methods=['GET', 'POST'])
def handle():
    
    result = []
    for server in server_list:
        try:
            r = requests.get(
                f'{server}',
                headers={
                'signature': "sign"
                }
            )
        except:
            print(f"Error in server {server}")
            continue
        if r.status_code == 200:
            # print(r.json())
            print(f"Server {server} is working")
            result.append(r.json())
        else:
            print(f"Error in server {server}")
    print(f"Result: {(result)}")
    return(jsonify(result))

if __name__ == "__main__":
    app.run()

