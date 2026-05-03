import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret messagea secret message")
print("IV1 used is ", iv) 
print(ct)
decryptor = cipher.decryptor()
x = decryptor.update(ct)
y = ct[0:16]
z = ct[16:32]
print("\n\n\n\n")
print("1st block ", y, "\t", x[0:16])
print("2nd block ", z, "\t", x[16:32])

print("\n\n\n")
iv2 = os.urandom(16)
print("IV2 used is ", iv2)
cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv2), backend=backend)
encryptor = cipher2.encryptor()
ct2 = encryptor.update(b"a secret messagea secret message")
print(ct2)
decryptor = cipher2.decryptor()
x = decryptor.update(ct2)
y = ct2[0:16]
z = ct2[16:32]
print("\n\n\n\n")
print("1st block ", y, "\t", x[0:16])
print("2nd block ", z, "\t", x[16:32])

