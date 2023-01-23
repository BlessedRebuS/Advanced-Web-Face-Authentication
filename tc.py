from flask import Flask, jsonify, request
import requests
from jwtoken import bls_signature, aggregate_signature, verify_aggregate_signature
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from blspy import PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element

app = Flask(__name__)
server_list = ["http://127.0.0.1:5000", "http://127.0.0.1:6000", "http://127.0.0.1:7000"]

def bls_token(username, received_encoding):
    # print("\n*** TEST BLS SIGNATURE ***\n")
    seed: bytes = bytes([0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                        19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                        12, 62, 89, 110, 182, 9,   44, 20,  254, 22])
    exp_time = datetime(2022, 10, 13, 12, 4, 46)
    nbf_time = datetime.now()        
    claims = {"username": username, "received_encoding": received_encoding[:10], "exp":exp_time, "nbf":nbf_time}
    # Generate some more private keys
    seed = bytes([1]) + seed[1:]
    sk1: PrivateKey = AugSchemeMPL.key_gen(seed)
    seed = bytes([2]) + seed[1:]
    sk2: PrivateKey = AugSchemeMPL.key_gen(seed)
    seed = bytes([3]) + seed[1:]
    sk3: PrivateKey = AugSchemeMPL.key_gen(seed)
    
    # Generate public keys
    pk1: G1Element = sk1.get_g1()
    pk2: G1Element = sk2.get_g1()
    pk3: G1Element = sk3.get_g1()
    # Obtain proofs of possession
    pop_sig = []
    pop_sig.append(bls_signature(claims, sk1))
    pop_sig.append(bls_signature(claims, sk2))
    pop_sig.append(bls_signature(claims, sk3))
    pop1: G2Element = PopSchemeMPL.pop_prove(sk1)
    pop2: G2Element = PopSchemeMPL.pop_prove(sk2)
    pop3: G2Element = PopSchemeMPL.pop_prove(sk3)
    # Verify proofs of possession
    verification_results = []
    verification_results.append(PopSchemeMPL.pop_verify(pk1, pop1))
    verification_results.append(PopSchemeMPL.pop_verify(pk2, pop2))
    verification_results.append(PopSchemeMPL.pop_verify(pk3, pop3))
    
    if False in verification_results:
        return "Proof of possession failed"
    # Aggregate signatures
    # print("---Aggregating signatures---\n")
    # print("Signature aggregation:")
    signed_token = aggregate_signature(pop_sig)
    # print(signed_token)
    # Verify aggregate signature
    # print("\n---Verifying signatures---\n")
    # print("Verification result:")
    # print(verify_aggregate_signature([pk1, pk2, pk3], signed_token))
    return signed_token


@app.route('/' , methods=['GET', 'POST'])
def handle():

    username = request.headers.get('username')
    received_encoding = request.headers.get('received_encoding')
    saved_encoding = request.headers.get('saved_encoding')
    token = bls_token(username, received_encoding)
    print(f"Token: {token}")
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
            result.append(r.json()  + "|" + token.decode("utf-8"))
        else:
            print(f"Error in server {server}")
    print(f"Result: {(result)}")
    return(jsonify(result))

if __name__ == "__main__":
    app.run()

