import os
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ======================= PATH =======================
USER_APPDATA = input("Files path: ").strip()
BASE_DIR = os.path.join(USER_APPDATA, "Shelter")
PASSWORD_FILE = os.path.join(BASE_DIR, "password.hash")
SEED_FILE = os.path.join(BASE_DIR, "seeds.json")

os.makedirs(BASE_DIR, exist_ok=True)
print(f"Path selected={BASE_DIR}")

# ======================= TOOL =======================
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

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
        "salt": base64.b64encode(salt).decode()
    }

def decrypt_data(enc, password):
    try:
        ciphertext = base64.b64decode(enc["ciphertext"])
        nonce = base64.b64decode(enc["nonce"])
        tag = base64.b64decode(enc["tag"])
        salt = base64.b64decode(enc["salt"])
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        return f"Decryption error: {e}"

# ======================= INIT =======================
def init_password():
    if not os.path.exists(PASSWORD_FILE):
        pw = input("New password: ")
        confirm = input("Confirm password: ")
        if pw != confirm:
            print("Passwords do not match.")
            exit()
        hashed_pw = hash_sha256(pw)
        encrypted = encrypt_data(hashed_pw, pw)
        with open(PASSWORD_FILE, "w") as f:
            json.dump(encrypted, f)
        return pw
    else:
        pw = input("Password: ")
        with open(PASSWORD_FILE, "r") as f:
            encrypted = json.load(f)
        decrypted_hash = decrypt_data(encrypted, pw)
        if not decrypted_hash or hash_sha256(pw) != decrypted_hash:
            print("Invalid password.")
            exit()
        return pw

# ======================= SEED =======================
def load_data(file_path):
    return json.load(open(file_path, "r")) if os.path.exists(file_path) else []

def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def add_seed(password):
    seed = input("Add seed or key: ")
    encrypted = encrypt_data(seed, password)
    data = load_data(SEED_FILE)
    data.append(encrypted)
    save_data(SEED_FILE, data)
    print("Saved.")
    input("Press enter...")

def view_seeds(password):
    data = load_data(SEED_FILE)
    if not data:
        print("No seeds found.")
    for i, enc in enumerate(data, 1):
        print(f"{i}. {decrypt_data(enc, password)}")
    input("Press enter...")

def delete_seed(password):
    data = load_data(SEED_FILE)
    if not data:
        print("No seed to delete.")
        input("Press enter...")
        return
    for i, enc in enumerate(data, 1):
        try:
            print(f"{i}. {decrypt_data(enc, password)}")
        except Exception:
            print(f"{i}. (Decryption error)")
    try:
        num = int(input("Number to delete: ").strip()) - 1
    except ValueError:
        print("Invalid input.")
        return
    if 0 <= num < len(data):
        confirm = input("Delete this seed ? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            return
        pw_check = input("Password: ").strip()
        with open(PASSWORD_FILE, "r") as f:
            encrypted_pw = json.load(f)
        try:
            decrypted_hash = decrypt_data(encrypted_pw, pw_check)
        except Exception:
            print("Incorrect password.")
            return

        if hash_sha256(pw_check) != decrypted_hash:
            print("Incorrect password.")
            return
        data.pop(num)
        save_data(SEED_FILE, data)
        print("Seed deleted.")
    else:
        print("Invalid choice.")
    input("Press enter...")
    
# ======================= MAIN =======================
def main():
    print("""
    ██╗      █████╗ ██╗  ██╗ █████╗ ██╗   ██╗    ███████╗██╗  ██╗███████╗██╗  ████████╗███████╗██████╗ 
    ██║     ██╔══██╗██║ ██╔╝██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██║  ╚══██╔══╝██╔════╝██╔══██╗
    ██║     ███████║█████╔╝ ███████║ ╚████╔╝     ███████╗███████║█████╗  ██║     ██║   █████╗  ██████╔╝
    ██║     ██╔══██║██╔═██╗ ██╔══██║  ╚██╔╝      ╚════██║██╔══██║██╔══╝  ██║     ██║   ██╔══╝  ██╔══██╗
    ███████╗██║  ██║██║  ██╗██║  ██║   ██║       ███████║██║  ██║███████╗███████╗██║   ███████╗██║  ██║
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝ 
    """)
    password = init_password()
    while True:
        print("""
1. Add seed phrase or Private key

2. View stored seeds

3. Delete a seed

0. Exit
""")
        choice = input("Option: ").strip()
        if choice == "1":
            add_seed(password)
        elif choice == "2":
            view_seeds(password)
        elif choice == "3":
            delete_seed(password)
        elif choice == "0":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
