from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

digest.update(b"abc")
hash1 = digest.finalize()
print("hash of \"abc\" is\n", hash1)

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"1234567890")
hash2 = digest.finalize()
print("hash of \"1234567890\" is\n", hash2)