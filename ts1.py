from flask import Flask, request, jsonify
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import face_recognition
import numpy 

app = Flask(__name__)

with open('public.pem', 'rb') as f:
        public_key = f.read()

BASE_URL = b'http://127.0.0.1:5000'

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

@app.route('/server', methods=['GET', 'POST'])
def handle():
        # rsa_private_key = RSA.importKey(open('key.pem', "rb").read())
        # encrypted_text = rsa_private_key.encrypt(b'test')
        base64_public_key = base64.b64encode(public_key)
        base64_BASE_URL = base64.b64encode(BASE_URL)
        headers = request.headers
        username = headers['username']
        saved_encoding = headers['saved_encoding']
        received_encoding = headers['received_encoding']
        data = base64_BASE_URL.decode("utf-8") +"|"+base64_public_key.decode("utf-8")+"|"+username

        # print("Ricevuta richiesta da: ", username)
        # print(f"Received encoding: {received_encoding} and saved encoding: {saved_encoding}")
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
        headers = request.headers
        base64_message = headers['message']
        message = base64.b64decode(base64_message)
        return decript_message(public_key, message)

if __name__ == "__main__":
    app.run()