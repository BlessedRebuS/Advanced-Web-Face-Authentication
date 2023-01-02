from flask import Flask, request, jsonify
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

SERVER_NAME= os.getenv('SERVER_NAME')
SERVER_PORT = os.getenv('SERVER_PORT')

app = Flask(__name__)

with open('public.pem', 'rb') as f:
        public_key = f.read()

BASE_URL = f"{SERVER_NAME}:{SERVER_PORT}"

def decript_message(public_key, encrypted_text):
    rsa_private_key = RSA.importKey(open('key.pem', "rb").read())
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)

    # print('debug encrypted text: {}'.format(encrypted_text))

    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)
    result = (decrypted_text)
    print("Decrypted text: ", result)
    return(result)

@app.route('/server', methods=['GET', 'POST'])
def handle():
        # rsa_private_key = RSA.importKey(open('key.pem', "rb").read())
        # encrypted_text = rsa_private_key.encrypt(b'test')
        base64_public_key = base64.b64encode(public_key)
        base64_BASE_URL = base64.b64encode(BASE_URL.encode())
        data = base64_BASE_URL.decode("utf-8") +"|"+base64_public_key.decode("utf-8")
        headers = request.headers
        signature = headers['signature']
        if(signature == "sign"):
                print(jsonify(data))
                return jsonify(data)
        else:
                return "Signature non valida"

@app.route('/sign', methods=['GET', 'POST'])
def prove():
        headers = request.headers
        base64_message = headers['message']
        message = base64.b64decode(base64_message)
        return decript_message(public_key, message)

if __name__ == "__main__":
    app.run()