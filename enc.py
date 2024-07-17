import tkinter as tk
from tkinter import filedialog, messagebox
import zipfile
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def derive_key_and_salt(passphrase):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key, salt

def encrypt_file(input_file, output_file, passphrase):
    key, salt = derive_key_and_salt(passphrase)
    iv = os.urandom(16)
    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    hmac_value = h.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted_data + hmac_value)

def create_zip(zip_filename, files):
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for file in files:
            zipf.write(file, os.path.basename(file))

def select_files():
    files = filedialog.askopenfilenames()
    if files:
        file_list.delete(0, tk.END)
        for file in files:
            file_list.insert(tk.END, file)

def encrypt():
    passphrase = passphrase_entry.get()
    if not passphrase:
        messagebox.showerror("Error", "パスフレーズを入力してください")
        return

    files = file_list.get(0, tk.END)
    if not files:
        messagebox.showerror("Error", "ファイルを選択してください")
        return

    zip_filename = 'temp.zip'
    encrypted_filename = filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("Encrypted files", "*.dat")])
    if not encrypted_filename:
        return

    create_zip(zip_filename, files)
    encrypt_file(zip_filename, encrypted_filename, passphrase)
    os.remove(zip_filename)
    messagebox.showinfo("Success", "ファイルが暗号化されました")

def toggle_password():
    if show_password_var.get():
        passphrase_entry.config(show="")
    else:
        passphrase_entry.config(show="*")

app = tk.Tk()
app.title("ファイル暗号化")

tk.Label(app, text="パスフレーズ:").pack()
passphrase_entry = tk.Entry(app, show="*")
passphrase_entry.pack()

show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(app, text="パスフレーズを表示", variable=show_password_var, command=toggle_password)
show_password_check.pack()

tk.Button(app, text="ファイル選択", command=select_files).pack()

file_list = tk.Listbox(app)
file_list.pack()

tk.Button(app, text="暗号化", command=encrypt).pack()

app.mainloop()
