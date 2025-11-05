from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key_bytes: bytes, data: bytes) -> bytes:
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted)

def decrypt_with_rsa(private_key_bytes: bytes, encrypted_data: bytes) -> bytes:
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)
    decoded_data = base64.b64decode(encrypted_data)
    decrypted = cipher.decrypt(decoded_data)
    return decrypted
