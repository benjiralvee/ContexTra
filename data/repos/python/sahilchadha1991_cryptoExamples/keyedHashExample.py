from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
key = b'1234567812345678'
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(b"message to hash")
print(h.finalize())

