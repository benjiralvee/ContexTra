import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
key = os.urandom(32)

# iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret messagea secret message")
print(ct)
decryptor = cipher.decryptor()
x = decryptor.update(ct)
y = ct[0:16]
z = ct[16:32]
print("\n\n\n\n")
print("1st block ", y, "\t", x[0:16])
print("2nd block ", z, "\t", x[16:32])

