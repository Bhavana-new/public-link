import os
import io
import logging
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from stegano import lsb
from PIL import Image

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Store tokens against filenames (consider external DB or cache for prod)
token_store = {}

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_bytes, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return salt + nonce + ciphertext

def decrypt_file(blob, password):
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        if request.method == 'POST':
            secret_file = request.files.get('secretfile')
            cover_image = request.files.get('coverimage')
            if not secret_file or not cover_image:
                flash("Both secret file and cover image must be uploaded.")
                return redirect(url_for('index'))

            token = secrets.token_urlsafe(12)
            file_bytes = secret_file.read()
            encrypted_blob = encrypt_file(file_bytes, token)
            encrypted_hex = encrypted_blob.hex()

            try:
                hidden_image = lsb.hide(cover_image, encrypted_hex)
            except Exception as e:
                logging.error(f"Steganography hide error: {e}")
                flash("Failed to hide data inside the image. Please use a different image.")
                return redirect(url_for('index'))

            filename = secure_filename(cover_image.filename) + "_stego.png"
            filepath = os.path.join(UPLOAD_DIR, filename)
            hidden_image.save(filepath)

            token_store[filename] = token
            link = url_for('decrypt_prompt', filename=filename, _external=True)

            return render_template('result.html', token=token, link=link)
        return render_template('index.html')
    except Exception as e:
        logging.exception("Error in index route")
        return render_template('500.html'), 500

@app.route('/decrypt/<filename>', methods=['GET', 'POST'])
def decrypt_prompt(filename):
    try:
        if request.method == 'POST':
            entered_token = request.form.get('token')
            if not entered_token:
                flash("Token is required.")
                return redirect(request.url)

            real_token = token_store.get(filename)
            if real_token != entered_token:
                flash("Invalid token.")
                return redirect(request.url)

            filepath = os.path.join(UPLOAD_DIR, filename)
            if not os.path.exists(filepath):
                flash("File not found.")
                return redirect(url_for('index'))

            try:
                img = Image.open(filepath)
                hex_blob = lsb.reveal(img)
                if not hex_blob:
                    flash("No hidden data found in the image.")
                    return redirect(url_for('index'))
                decrypted_bytes = decrypt_file(bytes.fromhex(hex_blob), entered_token)
            except Exception as e:
                logging.error(f"Decryption error: {e}")
                flash("Decryption failed. Invalid token or corrupted data.")
                return redirect(request.url)

            return send_file(
                io.BytesIO(decrypted_bytes),
                as_attachment=True,
                download_name="secret_file"
            )
        return render_template('token_prompt.html', filename=filename)
    except Exception as e:
        logging.exception("Error in decrypt route")
        return render_template('500.html'), 500

# Define custom error pages
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
