import os
import time
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import sys

# Définir un dossier spécifique pour stocker les fichiers
USER_APPDATA = os.getenv('APPDATA')  # Pour Windows
BASE_DIR = os.path.join(USER_APPDATA, "MonApplication")

if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

# Dossier de stockage des fichiers
PASSWORD_FILE = os.path.join(BASE_DIR, "password.hash")
SEED_FILE = os.path.join(BASE_DIR, "seeds.json")

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_seed(seed, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_seed = encryptor.update(seed.encode()) + encryptor.finalize()
    return {
        "ciphertext": base64.b64encode(encrypted_seed).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8')
    }

def decrypt_seed(encrypted_data, password):
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    tag = base64.b64decode(encrypted_data["tag"])
    salt = base64.b64decode(encrypted_data["salt"])
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_seed = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_seed.decode('utf-8')

def init(password_file):
    if not os.path.exists(password_file) or os.stat(password_file).st_size == 0:
        print("Create password.")
        pw = input("New password: ")
        confirm = input("Confirm password: ")
        if pw != confirm:
            print("Passwords do not match.")
            exit()
        hashed_pw = hash_sha256(pw)
        encrypted_hash = encrypt_seed(hashed_pw, pw)
        with open(password_file, "w") as f:
            json.dump(encrypted_hash, f)
        print("Password saved.")
        return pw
    else:
        pw = input("Password: ")
        with open(password_file, "r") as f:
            try:
                encrypted_hash = json.load(f)
            except json.JSONDecodeError:
                print("Password file is corrupted or empty.")
                exit()
        try:
            decrypted_hash = decrypt_seed(encrypted_hash, pw)
        except Exception:
            print("Invalid password.")
            exit()
        if hash_sha256(pw) != decrypted_hash:
            print("Invalid password.")
            exit()
        return pw

def load_data(file_path):
    return json.load(open(file_path, "r")) if os.path.exists(file_path) else []

def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def add_seed(seed_file, password):
    seed = input("Add seed or key: ")
    encrypted_seed = encrypt_seed(seed, password)
    data = load_data(seed_file)
    data.append(encrypted_seed)
    save_data(seed_file, data)
    print("Seed phrase or Private key saved.")
    input("Press enter...")

def view_seeds(seed_file, password):
    seeds = load_data(seed_file)
    if not seeds:
        print("No seed or Private key.")
        input("Press enter...")        
    else:
        print("Seed phrases or Private key:")
        for idx, encrypted in enumerate(seeds, 1):
            try:
                print(f"{idx}. {decrypt_seed(encrypted, password)}")
                input("Press enter...")
            except Exception as e:
                print(f"{idx}. Decryption error: {e}")
                input("Press enter...")

def change_password(password_file):
    old = input("Current password: ")
    with open(password_file, "r") as f:
        encrypted_hash = json.load(f)
    try:
        decrypted_hash = decrypt_seed(encrypted_hash, old)
    except Exception:
        print("Incorrect password.")
        return
    if hash_sha256(old) != decrypted_hash:
        print("Incorrect password.")
        return
    new = input("New password: ")
    confirm = input("Confirm new password: ")
    if new != confirm:
        print("The passwords do not match.")
        return
    new_hash = hash_sha256(new)
    encrypted_new_hash = encrypt_seed(new_hash, new)
    with open(password_file, "w") as f:
        json.dump(encrypted_new_hash, f)
    print("Password changed.")
    input("Press enter...")

def delete_seed(seed_file, password, password_file):
    seeds = load_data(seed_file)
    if not seeds:
        print("No seed to delete.")
        return
    print("Seed phrases or Private keys:")
    for idx, encrypted in enumerate(seeds, 1):
        try:
            print(f"{idx}. {decrypt_seed(encrypted, password)}")
        except Exception as e:
            print(f"{idx}. Decryption error: {e}")
    seed_num = int(input("Enter the number of the seed to delete: ").strip()) - 1
    if seed_num < 0 or seed_num >= len(seeds):
        print("Invalid seed number.")
        return
    confirm = input("Are you sure you want to delete this seed? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Seed deletion canceled.")
        return
    password_check = input("Enter your password to confirm deletion: ")
    with open(password_file, "r") as f:
        encrypted_hash = json.load(f)
    try:
        decrypted_hash = decrypt_seed(encrypted_hash, password_check)
    except Exception:
        print("Incorrect password.")
        return
    if hash_sha256(password_check) != decrypted_hash:
        print("Incorrect password.")
        return
    seeds.pop(seed_num)
    save_data(seed_file, seeds)
    print("Seed deleted successfully.")
    input("Press enter...")

def main():
    print("""
██╗      █████╗ ██╗  ██╗ █████╗ ██╗   ██╗    ███████╗██╗  ██╗███████╗██╗  ████████╗███████╗██████╗ 
██║     ██╔══██╗██║ ██╔╝██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██║  ╚══██╔══╝██╔════╝██╔══██╗
██║     ███████║█████╔╝ ███████║ ╚████╔╝     ███████╗███████║█████╗  ██║     ██║   █████╗  ██████╔╝
██║     ██╔══██║██╔═██╗ ██╔══██║  ╚██╔╝      ╚════██║██╔══██║██╔══╝  ██║     ██║   ██╔══╝  ██╔══██╗
███████╗██║  ██║██║  ██╗██║  ██║   ██║       ███████║██║  ██║███████╗███████╗██║   ███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝                                                                                          
""")
    password = init(PASSWORD_FILE)

    while True:
        print("""\n           
███╗   ███╗███████╗███╗   ██╗██╗   ██╗
████╗ ████║██╔════╝████╗  ██║██║   ██║
██╔████╔██║█████╗  ██╔██╗ ██║██║   ██║
██║╚██╔╝██║██╔══╝  ██║╚██╗██║██║   ██║
██║ ╚═╝ ██║███████╗██║ ╚████║╚██████╔╝
╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ 
                                       \n""")
        print("1. Add seed phrase or Public key\n")
        print("2. View seeds\n")
        print("3. Change password\n")
        print("4. Delete seed\n")
        print("0. Exit\n")
        choice = input("Pick an option: ").strip()
        if choice == "1":
            add_seed(SEED_FILE, password)
        elif choice == "2":
            view_seeds(SEED_FILE, password)
        elif choice == "3":
            change_password(PASSWORD_FILE)
        elif choice == "4":
            delete_seed(SEED_FILE, password, PASSWORD_FILE)
        elif choice == "0":
            print("Cia, crypto-bro")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
