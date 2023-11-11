from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_BLOCK_SIZE = AES.block_size
AES_KEY_SIZE = 32

def pad_key(key):
    if len(key) > AES_KEY_SIZE:
        return key[:AES_KEY_SIZE]
    return key.ljust(AES_KEY_SIZE, b' ')

def encrypt(key, data):
    iv = b'\x00' * AES_BLOCK_SIZE
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return encrypted_data

def decrypt(key, encrypted_data):
    iv = encrypted_data[:AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(encrypted_data[AES_BLOCK_SIZE:]), AES_BLOCK_SIZE)
    return data
