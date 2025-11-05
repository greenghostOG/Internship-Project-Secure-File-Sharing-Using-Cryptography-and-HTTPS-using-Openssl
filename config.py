import os

# Directory to store uploaded/encrypted files
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')

# Ensure uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# RSA key size in bits
RSA_KEY_SIZE = 2048

# AES block size and key size
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32
