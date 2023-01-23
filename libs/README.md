# JWToken.py
This library provides five functions that manage and create a standard JWT token composed of header, claims, and signature.
<br/>

## Requirements
This library has been tested on:

* Ubuntu 18.04

* Python 3.8.10

* Visual Studio Code
<br/>

## Dependencies
This library relies upon some primitives provided by the [bls-signatures](https://github.com/Chia-Network/bls-signatures) and [cryptography](https://github.com/pyca/cryptography) libraries.
<br/>

Before using it, ensure that you have already installed them. These libraries can be installed by executing the following commands:

```cmd
$ pip intsall blspy
$ pip install cryptography
```
<br/>

## Function Documentation
The current version of the library enables to manage and create a JWT token in two different ways:

* ECDSA with P-256 and SHA256
* BLS signatures
<br/>
<br/>

### **encode_ES256**

**Input parameters**: 
- `claims: a dict containing standard JTW claims (iss, exp, nbf, subj, aud)`
- `priv_key: elliptic curve private key`

**Output parameters**: 
- `signed_token: JWT bytes `

This method generates a JWT composed of a header({"type":"JWT", "alg":"ES256"}), JWT claims provided as input, and a signature obtained with *ES256* (SHA256 with ECDSA).
<br/>
<br/>

### **decode_ES256**

**Input parameters**: 
- `token_authn_key: the elliptic curve public key needed to verify the signature`
- `signed_token: JTW bytes`

**Output parameters**: 

If the signature is verified, the method returns:
- `header: dict containting the singature algorithm used`
- `claims: dict containing standard JTW claims (iss, exp, nbf, subj, aud)`
- `signature: the JWT signature `

Otherwise, an error message is displayed:

- `Invalid signature`

This method verifies that a JWT has been correctly signed with *ES256*.
<br/>
<br/>

### **bls_signature**

**Input parameters**: 
- `claims: dict`
- `priv_key: BLS private key`

**Output parameters**: 
- `signed_token: JWT bytes `

This method generates a JWT composed of a header({"type":"JWT", "alg":"ES256"}), JWT claims provided as input, and a signature obtained with the *BLS* scheme.
<br/>
<br/>

### **aggregate_signature**

**Input parameters**: 
- `signatures: list of JTW bytes`
- `priv_key: BLS private key`

**Output parameters**: 
- `signed_token: JWT bytes`

This method receives a list of JTWs and generates a new JWT token with the same header, claims, and with an aggregate signature obtained by means of the *BLS* scheme.
<br/>
<br/>

### **verify_aggregate_signature**

**Input parameters**
- `public_keys: list of public keys `
- `signed_token: JWT bytes `

**Output parameters**: 

If the signature is verified, the method returns:
- `header: dict containting the singature algorithm used`
- `claims: dict containing standard JTW claims (iss, exp, nbf, subj, aud)`
- `signature: the JWT signature `

Otherwise, an error message is displayed:

- `Invalid signature`

This method uses a list of public keys to verify the authenticity of the aggregate signature of a JWT.
<br/>
<br/>



