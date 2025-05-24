import os
from flask import Flask, request, render_template, send_from_directory
import math
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['STEGO_FOLDER'] = 'static/stego'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['STEGO_FOLDER'], exist_ok=True)

MARKER = b'--EOF--'

def embed_eof(carrier_path, part_data, output_path, original_filename, part_index, total_parts):
    with open(carrier_path, 'rb') as img:
        image_data = img.read()

    metadata = (
        MARKER + original_filename.encode() +
        MARKER + str(part_index).encode() +
        MARKER + str(total_parts).encode() +
        MARKER + part_data
    )

    with open(output_path, 'wb') as out:
        out.write(image_data + metadata)

def extract_parts(data):
    parts = data.split(MARKER)
    if len(parts) < 5:
        return None
    filename = parts[-4].decode()
    index = int(parts[-3].decode())
    total_parts = int(parts[-2].decode())
    part_data = parts[-1]
    return {
        'filename': filename,
        'index': index,
        'total': total_parts,
        'data': part_data
    }

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: bytes, password: str) -> (bytes, bytes):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data, salt

def decrypt_data(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        secret = request.files['secret_file']
        carriers = request.files.getlist('carrier_images')
        password = request.form.get("password")

        if not password:
            return render_template("result.html", error="Password diperlukan untuk enkripsi.")

        secret_data = secret.read()

        # Enkripsi file + simpan salt
        encrypted_data, salt = encrypt_data(secret_data, password)

        total_parts = len(carriers)

        # Bagi data terenkripsi (ciphertext + salt)
        data_with_salt = salt + encrypted_data
        chunk_size = math.ceil(len(data_with_salt) / total_parts)
        chunks = [data_with_salt[i:i + chunk_size] for i in range(0, len(data_with_salt), chunk_size)]

        output_files = []
        for i, img in enumerate(carriers):
            filename = img.filename
            in_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            out_path = os.path.join(app.config['STEGO_FOLDER'], filename)

            img.save(in_path)
            embed_eof(in_path, chunks[i], out_path, secret.filename, i, total_parts)
            output_files.append(f"/static/stego/{filename}")
        return render_template('result.html', output_files=output_files)
    return render_template('index.html')


@app.route('/extract', methods=['GET', 'POST'])
def extract():
    if request.method == 'POST':
        stegofiles = request.files.getlist('stego_files')
        password = request.form.get("password")

        if not password:
            return render_template("extract.html", error="Password diperlukan untuk dekripsi.")

        extracted = []

        for f in stegofiles:
            data = f.read()
            part = extract_parts(data)
            if not part:
                return render_template('extract.html', error="Gagal ekstraksi: format tidak valid.")
            extracted.append(part)

        total_parts = extracted[0]['total']
        filename = extracted[0]['filename']
        parts_data = [None] * total_parts

        try:
            for part in extracted:
                parts_data[part['index']] = part['data']
        except IndexError:
            return render_template('extract.html', error="Gagal: indeks bagian tidak valid!")

        if None in parts_data:
            return render_template('extract.html', error="Gagal: tidak semua bagian ditemukan.")

        encrypted_full = b''.join(parts_data)

        # Pisahkan salt (16 byte pertama)
        salt = encrypted_full[:16]
        ciphertext = encrypted_full[16:]

        # Dekripsi
        try:
            decrypted_data = decrypt_data(ciphertext, password, salt)
        except Exception:
            return render_template("extract.html", error="Gagal dekripsi: password salah atau data rusak")

        output_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        return render_template("extract.html", status="✅ Dekripsi berhasil", download=filename)

    return render_template('extract.html')



@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)


