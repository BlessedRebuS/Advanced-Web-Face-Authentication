from jwtoken import encode_ES256, decode_ES256, bls_signature, aggregate_signature, verify_aggregate_signature
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
import unittest
from blspy import PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element


class TestJWToken(unittest.TestCase):


    def test_bls_signatures(self):
        print("\n*** TEST BLS SIGNATURE ***\n")
        seed: bytes = bytes([0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                            19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                            12, 62, 89, 110, 182, 9,   44, 20,  254, 22])
        message: bytes = bytes([1, 2, 3, 4, 5])
        exp_time = datetime(2022, 10, 13, 12, 4, 46)
        nbf_time = datetime.now()        
        claims = {"iss":"ids.example", "exp":exp_time, "nbf":nbf_time, "subj":"s1.example.com", "aud":"test"}

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
        print("---Aggregating signatures---\n")
        print("Signature aggregation:")
        signed_token = aggregate_signature(pop_sig)
        print(signed_token)

        # Verify aggregate signature
        print("\n---Verifying signatures---\n")
        print("Verification result:")
        print(verify_aggregate_signature([pk1, pk2, pk3], signed_token))

if __name__ == "__main__":
    unittest.main()