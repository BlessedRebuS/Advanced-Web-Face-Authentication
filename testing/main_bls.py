from flask import Flask, session, request, redirect, abort, Response, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from os import environ
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import CollectedClientData
from fido2.server_multichallenge import Fido2ServerMultichallenge
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from blspy import (PrivateKey, Util, AugSchemeMPL, PopSchemeMPL,
                   G1Element, G2Element)
from jwtoken import bls_signature, encode_ES256, base64url_decode
from datetime import datetime, timedelta
import requests
import json
import sys
import base64
import platform
import os
import secrets

from werkzeug.wrappers import response

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32)
MODE = environ['MODE']

DEBUG_PORT_ENV_VAR = 'DEBUG_PORT'
NBF_TOLERANCE = timedelta(minutes=1)

rp = PublicKeyCredentialRpEntity("example.com", "Demo server")
server = Fido2ServerMultichallenge(rp)

sk: PrivateKey = None
token_authn_key: ec.EllipticCurvePrivateKey = None

credentials = []

whitelist_origins = ['https://login.example.com:8080']

def set_private_key_if_none():
    global sk
    global token_authn_key

    if MODE == "BLS" and sk is None:     
        seed: bytes = secrets.token_bytes(32)
        sk = PopSchemeMPL.key_gen(seed)
    elif MODE == 'LIST' and token_authn_key is None:
        token_authn_key = ec.generate_private_key(ec.SECP256K1)

set_private_key_if_none()

@app.route('/api/signature_mode', methods=['POST'])
def set_signature_mode():
    received_mode = request.get_data().decode('utf-8')

    resp = Response()
    if not received_mode in ['BLS', 'LIST']:
        resp.status_code = 400
    else:
        global MODE
        MODE = received_mode
        resp.status_code = 200
        set_private_key_if_none()
    
    return resp

@app.route("/api/pk/ecdsa", methods=['GET'])
def get_ecdsa_pk() -> bytes:
    if token_authn_key is None:
        resp = Response()
        resp.status_code = 404
    else:    
        resp = token_authn_key \
            .public_key() \
            .public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )

    return resp


@app.route("/api/pk/bls", methods=['GET'])
def get_bls_pk() -> bytes:
    
    if sk is None:
        resp = Response()
        resp.status_code = 404
    else:
        pk = sk.get_g1()
        pop = PopSchemeMPL.pop_prove(sk)

        resp = {
            'pk': base64.urlsafe_b64encode(bytes(pk)).decode('utf-8'),
            'pop': base64.urlsafe_b64encode(bytes(pop)).decode('utf-8')
        }
    
    return resp

@app.route("/api/register/begin", methods=['GET', 'POST'])
def begin_registration():
    
    registration_data, state = server.register_begin(
        {
            "id": b"user_id",
            "name": "a_user",
            "displayName": "A. User",
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    session['state'] = state
    print(session['state'])
    print("\n\n\n\n")
    print(registration_data)
    print("\n\n\n\n")

    resp = Response()
    resp.data = cbor.encode(registration_data) 
    if request.headers['Origin'] in whitelist_origins:
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp
    
@app.route("/api/register/complete", methods=["OPTIONS"])
def register_complete_preflight():
    resp = Response()
    print('%s got options request from %s' % (request.host, request.headers['Origin']))
    if request.headers['Origin'] in whitelist_origins and request.headers['Access-Control-Request-Method'] == 'POST':
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Methods'] = 'POST'
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'content-type'

        resp.status_code = 204

    return resp

@app.route("/api/register/complete", methods=["POST"])
def register_complete():

    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    challenges = data["challengesVector"]
    print("clientData: ", client_data)
    print("\n")
    print("AttestationObject: ", att_obj)

    auth_data = server.register_complete(session.get('state'), client_data, att_obj,challenges)

    credentials.append(auth_data.credential_data)
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)

    resp = Response()
    resp.data = cbor.encode({"status": "OK"})
    if request.headers['Origin'] in whitelist_origins:
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp


@app.route("/api/authenticate/complete", methods=["OPTIONS"])
def authenticate_complete_preflight():
    resp = Response()
    print('%s got options request from %s' % (request.host, request.headers['Origin']))
    if request.headers['Origin'] in whitelist_origins and request.headers['Access-Control-Request-Method'] == 'POST':
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Methods'] = 'POST'
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'content-type'

        resp.status_code = 204

    return resp

@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials)
    session["state"] = state

    resp = Response()
    resp.data = cbor.encode(auth_data) 
    if request.headers['Origin'] in whitelist_origins:
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    if not credentials:
        abort(404)

    data = cbor.decode(request.get_data())
    credential_id = base64url_decode(data["credentialId"])
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    challenge_vec = data["challengesVector"]
    not_before = data["nbf"]
    print("clientData", client_data)
    print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
        challenge_vec
    )
    print("ASSERTION OK")
    
    nbf_time = datetime.fromtimestamp(not_before / 1000)

    now = datetime.now()
    if nbf_time <= now - NBF_TOLERANCE:
        raise Exception('nbf time is too far in the past')
    if nbf_time >= now + NBF_TOLERANCE:
        raise Exception('nbf time is too far in the future')

    exp_time = nbf_time + timedelta(minutes=1)

    claims = {"iss": 'example.com', "exp":exp_time, "nbf":nbf_time, "subj":"user_id", "aud":"test"}
    
    if MODE == "BLS":
        token = bls_signature(claims, sk)
    else:
        token = encode_ES256(claims, token_authn_key)

    resp = Response()
    resp.data = cbor.encode({"status": "OK", "jwt": token})
    if request.headers['Origin'] in whitelist_origins:
        resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp

@app.route("/")
def hello() -> str:
    """
    Returns a diagnostic information message.
    """
    name = platform.node()

    if MODE == 'BLS':
        public_key = get_bls_pk()['pk']
    else:
        public_key = base64.b64encode(get_ecdsa_pk()).decode('ascii')
    
    message = "I'm Identity Server: {name}\n".format(name=name)
    message += "My token verification key is: {pk}".format(pk=public_key)
    return message

def main(host: str, port: int): 
    app.run(host=host, port=port, debug=True)

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(os.environ[DEBUG_PORT_ENV_VAR])
    main(host, port)