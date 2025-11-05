from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(data: bytes) -> bytes:
    padding_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_length]) * padding_length

def unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt(data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted)

def decrypt(enc_data: bytes, key: bytes) -> bytes:
    data = base64.b64decode(enc_data)
    iv = data[:AES.block_size]
    encrypted = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted)
    return unpad(decrypted_padded)
