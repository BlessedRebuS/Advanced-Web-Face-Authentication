from flask import Flask, request, jsonify
import requests
import base64

app = Flask(__name__)

with open('key.pem', 'rb') as f:
        private_key = f.read()

BASE_URL = b'http://127.0.0.1:6000/server2'

@app.route('/server2', methods=['GET', 'POST'])
def handle():
        # rsa_private_key = RSA.importKey(open('key.pem', "rb").read())
        # encrypted_text = rsa_private_key.encrypt(b'test')
        base64_private_key = base64.b64encode(private_key)
        base64_BASE_URL = base64.b64encode(BASE_URL)
        data = base64_BASE_URL.decode("utf-8") +"|"+base64_private_key.decode("utf-8")
        headers = request.headers
        signature = headers['signature']
        if(signature == "sign"):
                print(jsonify(data))
                return jsonify(data)
        else:
                return "Signature non valida"

if __name__ == "__main__":
    app.run()