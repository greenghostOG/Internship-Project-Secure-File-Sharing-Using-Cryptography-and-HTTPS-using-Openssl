from flask import Flask, request, render_template, send_file, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from crypto_utils.aes_crypto import encrypt, decrypt
from crypto_utils.rsa_crypto import generate_rsa_keypair, encrypt_with_rsa, decrypt_with_rsa
import base64
import config

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.secret_key = 'supersecretkey'

# Generate RSA keys at start (for demo only; store securely in production)
private_key, public_key = generate_rsa_keypair(config.RSA_KEY_SIZE)

@app.after_request
def set_secure_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    if file:
        filename = secure_filename(file.filename)
        data = file.read()

        # Generate AES key for this file
        aes_key = os.urandom(config.AES_KEY_SIZE)

        # Encrypt the file with AES
        enc_file_data = encrypt(data, aes_key)

        # Encrypt AES key with RSA public key
        enc_aes_key = encrypt_with_rsa(public_key, aes_key)

        # Save encrypted file and encrypted AES key
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
        enc_key_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.key')

        with open(enc_file_path, 'wb') as f_enc:
            f_enc.write(enc_file_data)

        with open(enc_key_path, 'wb') as f_key:
            f_key.write(enc_aes_key)

        flash('File encrypted and saved successfully.')
        return render_template('download.html', filename=filename)

@app.route('/download/<filename>')
def download_file(filename):
    enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    enc_key_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.key')

    if not (os.path.exists(enc_file_path) and os.path.exists(enc_key_path)):
        flash('File or key not found!')
        return redirect(url_for('index'))

    # Read encrypted AES key and decrypt it with private RSA key
    with open(enc_key_path, 'rb') as f_key:
        enc_aes_key = f_key.read()
    aes_key = decrypt_with_rsa(private_key, enc_aes_key)

    # Read encrypted file data
    with open(enc_file_path, 'rb') as f_enc:
        enc_file_data = f_enc.read()

    # Decrypt file with AES key
    decrypted_data = decrypt(enc_file_data, aes_key)

    # Send decrypted file as attachment
    from io import BytesIO
    return send_file(
        BytesIO(decrypted_data),
        download_name=filename,
        as_attachment=True
    )

if __name__ == '__main__':
    # Run with HTTPS using self-signed certificates (cert.pem, key.pem)
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))

