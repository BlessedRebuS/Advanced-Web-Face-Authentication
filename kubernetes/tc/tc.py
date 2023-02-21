from flask import Flask, jsonify, request
import requests
from blspy import (PopSchemeMPL, G1Element, G2Element)
from jwtoken import base64url_decode, aggregate_signature
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
        server_list.append('http://tsbls1:5000')
        server_list.append('http://tsbls2:6000')


@app.route('/' , methods=['GET', 'POST'])
def handle():

    username = request.headers.get('username')
    received_encoding = request.headers.get('received_encoding')
    saved_encoding = request.headers.get('saved_encoding')
    verification_results = []
    pop_sig = []
    encodings = []
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
            if(r.json().split("|")[1] == "ERR"):
                print("Error in server")
                result.append(r.json())
                continue
            token_encoded = r.json().split("|")[1]
            pk_encoded = r.json().split("|")[2]
            pop_encoded = r.json().split("|")[3]
            token = base64url_decode(token_encoded)
            token_bytes = bytes(token)
            pk = G1Element.from_bytes(base64url_decode(pk_encoded))
            pop = G2Element.from_bytes(base64url_decode(pop_encoded))
            print(f"Received pk: {pk} and pop: {pop}")
            print(f"Received token: {token}")
            verification_results.append(PopSchemeMPL.pop_verify(pk, pop))
            pop_sig.append(token_bytes)
            encodings.append(pk_encoded)
            print("Result signature: ", verification_results)
            result.append(r.json())
        else:
            print(f"Error in server {server}")
    print(f"Result: {(result)}")
    if False in verification_results:
        print("Proof of possession failed")
    else:
        try:
            signed_token = aggregate_signature(pop_sig)
            print(f"Signed token: {signed_token}")
        except:
            print("Error in signing token")
    return(jsonify(result))

if __name__ == "__main__":
    app.run()

