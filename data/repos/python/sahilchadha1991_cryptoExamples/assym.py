from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from pprint import pprint

private_key = dsa.generate_private_key(key_size=1024,
                                       backend=default_backend())

private_key1 = dsa.generate_private_key(key_size=1024,
                                        backend=default_backend())


print("private key is", private_key)
print("one more key", repr(private_key))
print("zzz", private_key.__str__())
signer = private_key.signer(hashes.SHA256())
data = b"this is some data I'd like to sign"
signer.update(data)
signature = signer.finalize()

public_key = private_key.public_key()
print("public key is", public_key)
verifier = public_key.verifier(signature, hashes.SHA256())
verifier.update(data)
verifier.verify()

