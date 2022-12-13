from flask import Flask, request, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode

app = Flask(__name__)

@app.route('/handle' , methods=['GET'])
def handle():
    # get action parameter
    action = request.args.get("action")
    if action is None:
        return "No action specified"
    if action == "validate":
        rsa_key = RSA.importKey(open('private.txt', "rb").read())
        # decrypt text with private key
