from cryptography.fernet import Fernet


def keygeneration():
    key = Fernet.generate_key()
    f = Fernet(key)
    print("the key is ", key)
    return f


def encryption(f, textToEncrypt):
    encryptedText = f.encrypt(textToEncrypt)
    print("the encrypted text is ", encryptedText)
    return encryptedText


def decryption(f, encryptedText):
    decryptedText = f.decrypt(encryptedText)
    print("the decrypted text is ", decryptedText)


print("Enter text to encrypt")
textToEncrypt = input()
bytes('example', encoding='utf-8')
textToEncrypt = bytes(textToEncrypt, encoding='utf-8')
f = keygeneration()
encryptedText = encryption(f, textToEncrypt)
decryption(f, encryptedText)


# print("Decrypting with different key now")


# x = keygeneration()
# decryption(x, encryptedText)
