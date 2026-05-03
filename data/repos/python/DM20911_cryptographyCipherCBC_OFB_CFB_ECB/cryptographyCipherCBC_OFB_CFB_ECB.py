import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


backend = default_backend()
key = (12345678901234567890123456789012).to_bytes(32, sys.byteorder)
#iv = os.urandom(16) #Usado en el primer ejercicio
iv = b'\xcbz)\xaf) \xce\xdd\xbb\x0e\xe0\x80\xab`n\xf7'
#print(iv) Usado para capturar un iv diferente
cipherCBC = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
cipherOFB = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
cipherCFB = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
cipherECB = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

encryptor = cipherCBC.encryptor()
encrip = encryptor.update(b"a secret messagea secret message") + encryptor.finalize()
print('\nMensaje encriptado:\n')
print(encrip)
decryptor = cipherCBC.decryptor()
decrip =decryptor.update(encrip) + decryptor.finalize()
print('\nMensaje desencriptado:\n')
print (decrip)

print('\n:::::::OFB:::::::::::')

encryptor2 = cipherOFB.encryptor()
encrip2 = encryptor2.update(b"a secret messagea secret message") + encryptor2.finalize()
print('\nMensaje encriptado:\n')
print(encrip2)
decryptor2 = cipherOFB.decryptor()
decrip2 =decryptor2.update(encrip) + decryptor2.finalize()
print('\nMensaje desencriptado:\n')
print (decrip2)

print('\n:::::::CFB:::::::::::')

encryptor3 = cipherCFB.encryptor()
encrip3 = encryptor3.update(b"a secret messagea secret message") + encryptor3.finalize()
print('\nMensaje encriptado:\n')
print(encrip3)
decryptor3 = cipherCFB.decryptor()
decrip3 =decryptor3.update(encrip) + decryptor3.finalize()
print('\nMensaje desencriptado:\n')
print (decrip3)

print('\n:::::::ECB:::::::::::')

encryptor4 = cipherECB.encryptor()
encrip4 = encryptor4.update(b"a secret messagea secret message") + encryptor4.finalize()
print('\nMensaje encriptado:\n')
print(encrip4)
decryptor4 = cipherECB.decryptor()
decrip4 =decryptor4.update(encrip) + decryptor4.finalize()
print('\nMensaje desencriptado:\n')
print (decrip4)


print('\nComparación Encrip:')
print(encrip)
print(encrip2)
print(encrip3)
print(encrip4)
print('\nComparación Decrip:')
print (decrip)
print (decrip2)
print (decrip3)
print (decrip4)