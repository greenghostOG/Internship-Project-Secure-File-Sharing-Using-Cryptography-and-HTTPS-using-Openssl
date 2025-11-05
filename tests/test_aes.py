import unittest
from crypto_utils.aes_crypto import encrypt, decrypt
import os

class TestAES(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        data = b"Test data for AES encryption"
        encrypted_data = encrypt(data, key)
        decrypted_data = decrypt(encrypted_data, key)
        self.assertEqual(data, decrypted_data)

if __name__ == '__main__':
    unittest.main()
