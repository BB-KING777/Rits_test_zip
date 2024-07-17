import tkinter as tk
from tkinter import filedialog, messagebox
import zipfile
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def derive_key_from_salt(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def decrypt_file(input_file, output_file, passphrase):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
        hmac_value = encrypted_data[-32:]
        encrypted_data = encrypted_data[:-32]

    key = derive_key_from_salt(passphrase, salt)

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(hmac_value)
    except:
        return False

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
    except:
        return False

    with open(output_file, 'wb') as f:
        f.write(data)
    return True

def extract_zip(zip_filename, extract_to):
    with zipfile.ZipFile(zip_filename, 'r') as zipf:
        zipf.extractall(extract_to)

def select_file():
    global encrypted_filename
    encrypted_filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.dat")])
    if encrypted_filename:
        selected_file_label.config(text=f"選択されたファイル: {encrypted_filename}")

def decrypt():
    passphrase = passphrase_entry.get()
    if not passphrase:
        messagebox.showerror("Error", "パスフレーズを入力してください")
        return

    if not encrypted_filename:
        messagebox.showerror("Error", "ファイルを選択してください")
        return

    decrypted_filename = 'temp.zip'
    success = decrypt_file(encrypted_filename, decrypted_filename, passphrase)

    if not success:
        messagebox.showerror("Error", "パスワードが違うか、ファイルが改ざんされています")
        return

    extract_to = filedialog.askdirectory()
    if not extract_to:
        return

    extract_zip(decrypted_filename, extract_to)
    os.remove(decrypted_filename)
    messagebox.showinfo("Success", "ファイルが復号化されました")

def toggle_password():
    if show_password_var.get():
        passphrase_entry.config(show="")
    else:
        passphrase_entry.config(show="*")

app = tk.Tk()
app.title("ファイル復号化")

tk.Label(app, text="パスフレーズ:").pack()
passphrase_entry = tk.Entry(app, show="*")
passphrase_entry.pack()

show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(app, text="パスフレーズを表示", variable=show_password_var, command=toggle_password)
show_password_check.pack()

tk.Button(app, text="ファイル選択", command=select_file).pack()
selected_file_label = tk.Label(app, text="選択されたファイル: なし")
selected_file_label.pack()

tk.Button(app, text="復号化", command=decrypt).pack()

app.mainloop()
