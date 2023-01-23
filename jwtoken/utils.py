from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import ec as ec_public
from typing import List, Tuple, Union
from calendar import timegm
from datetime import datetime
import base64
import json 
from blspy import PrivateKey, PopSchemeMPL, G1Element, G2Element

def base64url_decode(input: Union[str, bytes]) -> bytes:
    if isinstance(input, str):
        input = input.encode("ascii")

    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)

def encode_ES256(claims: dict, priv_key: ec.EllipticCurvePrivateKey) -> bytes:
    """"
    Returns a JWT token signed with ES256
    """

    header = {"type":"JWT", "alg":"ES256"}

    for time_claim in ["exp", "nbf"]:
        if isinstance(claims.get(time_claim), datetime):
            claims[time_claim] = timegm(claims[time_claim].utctimetuple())

    partial_token = []
    json_header  = json.dumps(header, separators=(",", ":")).encode("utf-8")
    json_claims = json.dumps(claims, separators=(",", ":")).encode("utf-8")

    partial_token.append(base64.urlsafe_b64encode(json_header).replace(b"=", b""))
    partial_token.append(base64.urlsafe_b64encode(json_claims).replace(b"=", b""))

    token = b".".join(partial_token)
    
    signature = priv_key.sign(
        token,
        ec.ECDSA(hashes.SHA256())
    )

    partial_token.append(base64.urlsafe_b64encode(signature))
    signed_token = b".".join(partial_token)
 
    return signed_token

def decode_ES256(token_authn_key: ec_public._EllipticCurvePublicKey, token: bytes) -> Tuple[dict, dict, bytes] or str:
    """"
    Verify the signature of a JWT. If the siganture is verified, it returns header,
    claims, and signature
    """

    signed_token = []

    header_segment, claims_segment, signature_segment = token.rsplit(b".", 2)
    signed_token.append(header_segment)
    signed_token.append(claims_segment)
    signed_token = b".".join(signed_token)
    signature = base64url_decode(signature_segment)

    try:
        token_authn_key.verify(signature, signed_token, ec.ECDSA(hashes.SHA256()))
    except:
        return "Invalid signature"
    
    header_data = base64url_decode(header_segment)
    header = json.loads(header_data)
    claims_data = base64url_decode(claims_segment)
    claims = json.loads(claims_data)

    for time_claim in ["exp", "nbf"]:
        if isinstance(claims.get(time_claim), int):
            claims[time_claim] = datetime.utcfromtimestamp(claims[time_claim])
    
    return header, claims, signature

def bls_signature(claims: dict, priv_key: PrivateKey) -> bytes:
    """"
    Returns a JWT token signed with BLS scheme
    """

    header = {"type":"JWT", "alg":"ES256"}

    for time_claim in ["exp", "nbf"]:
        if isinstance(claims.get(time_claim), datetime):
            claims[time_claim] = timegm(claims[time_claim].utctimetuple())

    partial_token = []
    json_header  = json.dumps(header, separators=(",", ":")).encode("utf-8")
    json_claims = json.dumps(claims, separators=(",", ":")).encode("utf-8")

    partial_token.append(base64.urlsafe_b64encode(json_header).replace(b"=", b""))
    partial_token.append(base64.urlsafe_b64encode(json_claims).replace(b"=", b""))

    token = b".".join(partial_token)
    signature: G2Element = PopSchemeMPL.sign(priv_key, token)
    partial_token.append(base64.urlsafe_b64encode(bytes(signature)))
    signed_token = b".".join(partial_token)
   
    return signed_token

def aggregate_signature(signatures: List[bytes]) -> bytes:
    """
    Returns a JWT token signed with an aggregate signature
    """
    signed_token = []
    pop_sig = []

    header_segment, claims_segment, signature_segment = signatures[0].rsplit(b".", 2)
    
    for token in signatures:
        signature_segment = token.rsplit(b".", 2)[2]
        signature = base64url_decode(signature_segment)
        pop_sig.append(G2Element(signature))
        
    aggregate_signature = PopSchemeMPL.aggregate(pop_sig)
    signed_token.append(header_segment)
    signed_token.append(claims_segment)
    signed_token.append(base64.urlsafe_b64encode(bytes(aggregate_signature)))
    signed_token = b".".join(signed_token)
    
    return signed_token

def verify_aggregate_signature(public_keys: List[G1Element], token: bytes) -> Tuple[dict, dict, bytes] or str:
    """"
    Verify the aggregate signature of a JWT. If the siganture is verified, it returns header,
    claims, and signature
    """
    signed_token  = []
    header_segment, claims_segment, pop_sig_agg = token.rsplit(b".", 2)
    signed_token.append(header_segment)
    signed_token.append(claims_segment)
    signed_token = b".".join(signed_token)
    signature = base64url_decode(pop_sig_agg)
    pop_sig_agg = G2Element(signature)
    
    if not PopSchemeMPL.fast_aggregate_verify(public_keys, signed_token, pop_sig_agg):
        return "Invalid signature"
    
    header_data = base64url_decode(header_segment)
    header = json.loads(header_data)
    claims_data = base64url_decode(claims_segment)
    claims = json.loads(claims_data)

    for time_claim in ["exp", "nbf"]:
        if isinstance(claims.get(time_claim), int):
            claims[time_claim] = datetime.utcfromtimestamp(claims[time_claim])

    return header, claims, signature
