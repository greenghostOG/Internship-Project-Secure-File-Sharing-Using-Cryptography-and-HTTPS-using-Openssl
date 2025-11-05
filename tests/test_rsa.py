import unittest
from crypto_utils.rsa_crypto import generate_rsa_keypair, encrypt_with_rsa, decrypt_with_rsa

class TestRSA(unittest.TestCase):
    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keypair()
        data = b"Test RSA encryption data"
        encrypted = encrypt_with_rsa(public_key, data)
        decrypted = decrypt_with_rsa(private_key, encrypted)
        self.assertEqual(data, decrypted)

if __name__ == '__main__':
    unittest.main()
