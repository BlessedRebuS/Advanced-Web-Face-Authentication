from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


public_key = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvTKvZlQdWwyH7X4YgFDl
WCYEe5UELS1W84WotKyGij1CNQ/KaEX4ifVdidenlR5KFQ7zCMr8m4bBw8K+OTmG
P6+pkh65ykpnSC1jRWREFceHntfGwkF7QKOHPDRC6wXhREcfJrVt7CKjQ0eTYC+L
KcuVdJZktXq2Ibzd/nA/NeyKFPsXWFHk/7Ar+oFMsH7kFihM6OoqC13kDHvxET/L
Vx/ltJjSpRDqv+b54s5gzeAPKckG26bt9kLmeKB7rsI0sJrFmgMwT/HLbqfjwMKQ
0oR6v2sCorMpITK9nCAGttNat93C7l/EiDC2tIfEr0Yb3FSdXtfqesrv6WuspKVo
eQIDAQAB
-----END PUBLIC KEY-----"""

def decript_message(public_key, encrypted_text):
    rsa_private_key = RSA.importKey(open('key.pem', "rb").read())
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    # print('debug encrypted text: {}'.format(encrypted_text))

    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)
    result = (decrypted_text)

    return(result)

# invio il testo cifrato 
encrypted_text = b'xX|\x16\xf3g-m\x98\x82\xbc/K~A\xd4e\xb7\xacV\xaez\xb3\t-\x99>\xc7\x02M\x82\xaf\xbc\xabG\xc6l`\xbbER\x86w+\x82\x81\xeaW,\x95\x80\xa8\x9a\x19\r\x95\xcf\xf9 \xd01A\xf7\xab\xb9W\x98+\xa9\x92\x96\x01\xff(\xb9\xb8\x0c\'\xe0e;i\x11\xa8\xb7\x1f\x08\x0f\xae>\xf3\x10\xa0Zd\xaa\xc7F\x8fN)\x97~"\x02\x91\xed\xe8\xc0\x02\xbd\xe9T\xf7\xc1M;%\xd2\xfd\x13\xcfs\xe8\x99\xc3\xff\x84\xb1psG\x95\xd5\xcb\x1b\xdfo\xa3q\xe5\x02\xa9\x85\x14\xee\x94bV\xcb\xa2\xbf\xf8\xdcW\x98\xb3\xbd\xa1\x82\xb0\x8d\xb0jfIsc.6\x04\xab\xd7t-S\xfaI\xaa\xc8-\xd7\xfcY\x81\x82\xd3~\x89iu\x84\x86\x9b\xf9\xeakR\xd1\x1f$7\xdd/\x06\x91\xd7g\xbe\xf4\x85k\xfc\xa3{Oi\x1eTp\xb0{L\xdfAp\xc9\xdc\x13\\\xe0\xfe\x1bM\xa84b\x19-w0\xbf\x1e\xe8?\x868\xe0\xff<\x1b\xbd\x86\xa8\xe3\xa3'
res = decript_message(public_key, encrypted_text)
print(res)