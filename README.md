Secure File Transfer System

This project implements a secure file transfer system demonstrating key concepts in cryptography including AES symmetric encryption and RSA asymmetric encryption. It provides a simple web interface to upload files, encrypt them securely, and download the decrypted original files using key management.
Features

    AES-256 encryption for file content confidentiality

    RSA-2048 encryption for secure AES key exchange

    Easy-to-use Flask web interface for file upload and download

    Separation of cryptographic logic for better maintainability and testing

    Unit tests for AES and RSA encryption modules
    
    Uses HTTPS protocol for secure communication.

    No Docker dependency; runs on standard Python environment

Project Structure

secure_file_transfer/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md              # This documentation
├── config.py              # Configuration constants
│
├── crypto_utils/          # Cryptographic utilities package
│   ├── aes_crypto.py      # AES encryption/decryption functions
│   ├── rsa_crypto.py      # RSA key generation, encryption, decryption
│   └── __init__.py        
│
├── templates/             # HTML templates for upload/download pages
│   ├── index.html
│   └── download.html
│
├── static/                # Static assets (CSS/JS) if needed
│
├── uploads/               # Encrypted files and encrypted keys storage
│
└── tests/                 # Unit tests for crypto modules
    ├── test_aes.py
    └── test_rsa.py

Setup Instructions For Linux :

    Clone or download this repository.

Create Virtual Environment : 

python3 -m venv .venv
source .venv/bin/activate

    Install required packages:

pip install -r requirements.txt

Generate self-signed SSL certificates for local HTTPS in your root project folder :

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -keyout key.pem -out cert.pem -subj "/CN=localhost"

Run the Flask application:

    python app.py

    Open a web browser and navigate to https://127.0.0.1:5000.

Setup Instructions For Windows :

Go To the Project Folder :

Run these Commands :

python -m venv .venv
.venv\Scripts\activate

Install require packages:

pip install -r requirements.txt

Install OPENSSL via cmd :

	winget install openssl
	
	C:\Program Files\OpenSSL-Win64\bin
	
	This is the default path add this into your Environment Varibale PATH.

	Press Win + R, type sysdm.cpl, and hit Enter.

	Go to the Advanced tab → click Environment Variables.

	Under “System variables”, find the one called Path and click Edit.

	Click New, then paste your OpenSSL bin folder path, e.g.:

Generate self-signed SSL certificates for local HTTPS in your root project folder :

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -keyout key.pem -out cert.pem -subj "/CN=localhost"

Run the Flask application:

    python app.py

    Open a web browser and navigate to https://127.0.0.1:5000.

Usage

    Upload: Select a file and upload it via the homepage. The file will be encrypted using AES with a randomly generated key.

    Key Encryption: The AES key is encrypted with RSA to secure key exchange.

    Download: On the download page, click the download button to decrypt the file on the server and retrieve the original file.

    Storage: Encrypted files and keys are stored securely in the uploads/ folder.

Testing

Run unit tests for AES and RSA modules using:

python -m unittest discover tests

Notes

    This is a demonstration project and intended for educational and internship purposes.

