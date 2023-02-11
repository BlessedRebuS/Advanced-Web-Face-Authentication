from flask import Flask, request, jsonify
import base64
import face_recognition
import numpy 
from jwtoken import bls_signature
from datetime import datetime
from blspy import (PopSchemeMPL, G1Element)

app = Flask(__name__)
private_bls_key = None

with open('public.pem', 'rb') as f:
        public_key = f.read()

BASE_URL = b'http://127.0.0.1:6000'


# check if the received encoding is valid
def checkEncodings(saved_encoding, received_encoding):
        base64decoded_saved_encoding = base64.b64decode(saved_encoding).decode("utf-8")
        base64decoded_received_encoding = base64.b64decode(received_encoding).decode("utf-8")
        saved_encoding_to_array = numpy.fromstring(base64decoded_saved_encoding.strip('[]'),dtype=float, sep = ' ')
        received_encoding_to_array = numpy.fromstring(base64decoded_received_encoding.strip('[]'),dtype=float, sep = ' ')

        #print(f"Received encoding: {str(received_encoding_to_array)}")
        #print(f"Saved encoding: {str(saved_encoding_to_array)}")

        saved_encoding_to_array = [saved_encoding_to_array]
        matches = face_recognition.compare_faces(saved_encoding_to_array, received_encoding_to_array, tolerance=0.6)

        if(matches[0]):
                return True
        else:
                return False

def generate_sk():
    # print("\n*** TEST BLS SIGNATURE ***\n")
    seed: bytes = bytes([0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                        19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                        12, 62, 89, 110, 182, 9,   44, 20,  254, 22])
    seed = bytes([1]) + seed[1:]
    sk = PopSchemeMPL.key_gen(seed)
    #sk1: PrivateKey = AugSchemeMPL.key_gen(seed)
    return sk

def generate_pk_pop(sk):
        pk: G1Element = sk.get_g1()
        pop = PopSchemeMPL.pop_prove(sk)
        pk_base64_encoded = base64.urlsafe_b64encode(bytes(pk)).decode('utf-8')
        pop_base64_encoded = base64.urlsafe_b64encode(bytes(pop)).decode('utf-8')
        return pk_base64_encoded + "|" + pop_base64_encoded

def bls_token(username, received_encoding):
    global private_bls_key
    print("Private key: ", private_bls_key)
    # print("\n*** TEST BLS SIGNATURE ***\n")
    exp_time = datetime(2022, 10, 13, 12, 4, 46)
    nbf_time = datetime.now()        
    claims = {"username": username, "received_encoding": received_encoding[:10], "exp":exp_time, "nbf":nbf_time}   
    token = bls_signature(claims, private_bls_key)
    print(f"Generated token: {token}")
    return token

@app.route('/server', methods=['GET', 'POST'])
def handle():
        global private_bls_key
        private_bls_key = generate_sk()
        base64_BASE_URL = base64.b64encode(BASE_URL)
        headers = request.headers
        username = headers['username']
        saved_encoding = headers['saved_encoding']
        received_encoding = headers['received_encoding']
        token = bls_token(username, received_encoding)
        base64_token = base64.b64encode(token)
        data = base64_BASE_URL.decode("utf-8") +"|"+base64_token.decode("utf-8")+"|"+generate_pk_pop(private_bls_key)+"|"+username
        print("Data: ", data)
        
        if(saved_encoding is None):
                return jsonify(data)
        else:
                check = checkEncodings(saved_encoding, received_encoding)
                if(check is True):
                        print(jsonify(data))
                        return jsonify(data)
                else:   
                        error = "ERR"
                        return jsonify(base64_BASE_URL.decode("utf-8")+"|"+error+"|"+username)

@app.route('/sign', methods=['GET', 'POST'])
def prove():
    global private_bls_key
    pk_pop = generate_pk_pop(private_bls_key)
    print("Public key and pop ", pk_pop)
    return str(pk_pop)

if __name__ == "__main__":
    app.run()