import os
import json
import hashlib
import base64
import time
import logging
import tempfile
import shutil
from typing import List, Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import bcrypt
import re

# ======================= CONSTANTES =======================
BANNER = """
===================================================================================================

██╗      █████╗ ██╗  ██╗ █████╗ ██╗   ██╗    ███████╗██╗  ██╗███████╗██╗  ████████╗███████╗██████╗ 
██║     ██╔══██╗██║ ██╔╝██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██║  ╚══██╔══╝██╔════╝██╔══██╗
██║     ███████║█████╔╝ ███████║ ╚████╔╝     ███████╗███████║█████╗  ██║     ██║   █████╗  ██████╔╝
██║     ██╔══██║██╔═██╗ ██╔══██║  ╚██╔╝      ╚════██║██╔══██║██╔══╝  ██║     ██║   ██╔══╝  ██╔══██╗
███████╗██║  ██║██║  ██╗██║  ██║   ██║       ███████║██║  ██║███████╗███████╗██║   ███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝

===================================================================================================
"""

# ======================= EXCEPTIONS =======================
class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

class ValidationError(Exception):
    pass

# ======================= CRYPTO MANAGER =======================
class CryptoManager:
    ITERATIONS = 500_000
    KEY_LENGTH = 32
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT = 300  # 5 minutes in seconds
    
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        """Verify password against bcrypt hash"""
        return bcrypt.checkpw(password.encode(), hashed)
    
    @staticmethod
    def hash_sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoManager.KEY_LENGTH,
            salt=salt,
            iterations=CryptoManager.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_data(data: str, password: str) -> dict:
        salt = os.urandom(16)
        key = CryptoManager.derive_key(password, salt)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        try:
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            return {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(encryptor.tag).decode(),
                "salt": base64.b64encode(salt).decode()
            }
        except Exception as e:
            raise EncryptionError(f"Error during encryption: {str(e)}")
    
    @staticmethod
    def decrypt_data(enc: dict, password: str) -> str:
        try:
            ciphertext = base64.b64decode(enc["ciphertext"])
            nonce = base64.b64decode(enc["nonce"])
            tag = base64.b64decode(enc["tag"])
            salt = base64.b64decode(enc["salt"])
            
            key = CryptoManager.derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        except Exception:
            raise DecryptionError("Decryption error")

# ======================= PASSWORD POLICY =======================
class PasswordPolicy:
    MIN_LENGTH = 8
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL = True
    REQUIRE_UPPER = True
    REQUIRE_LOWER = True
    
    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        if len(password) < PasswordPolicy.MIN_LENGTH:
            return False, f"Password must contain at least {PasswordPolicy.MIN_LENGTH} characters"
        
        if PasswordPolicy.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
            
        if PasswordPolicy.REQUIRE_SPECIAL and not any(not c.isalnum() for c in password):
            return False, "Password must contain at least one special character"
            
        if PasswordPolicy.REQUIRE_UPPER and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if PasswordPolicy.REQUIRE_LOWER and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        return True, "Valid password"

# ======================= UTILS =======================
def clear_console():
    """Clears the console"""
    # For Windows
    if os.name == 'nt':
        os.system('cls')
    # For Linux/Mac
    else:
        os.system('clear')

def atomic_write(filepath: str, data: dict) -> None:
    """Write data to a file atomically"""
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    try:
        json.dump(data, temp_file, indent=2)
        temp_file.close()
        shutil.move(temp_file.name, filepath)
    except Exception as e:
        os.unlink(temp_file.name)
        raise e

def validate_seed_format(seed: str) -> Tuple[bool, str]:
    """Validate seed phrase or private key format"""
    seed = seed.strip()
    
    # Check if it's a private key in various formats
    
    # 1. Hex format (64 characters)
    if re.match(r'^[0-9a-fA-F]{64}$', seed):
        return True, "Valid private key (hex format)"
    
    # 2. Base58 format (variable length)
    if re.match(r'^[1-9A-HJ-NP-Za-km-z]{40,90}$', seed):
        return True, "Valid private key (base58 format)"
    
    # 3. WIF format (starts with 5, K, or L)
    if re.match(r'^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$', seed):
        return True, "Valid private key (WIF format)"
    
    # 4. WIF compressed format (starts with 5, K, or L)
    if re.match(r'^[5KL][1-9A-HJ-NP-Za-km-z]{51,52}$', seed):
        return True, "Valid private key (WIF compressed format)"
    
    # 5. Mini private key format (starts with 'S')
    if re.match(r'^S[1-9A-HJ-NP-Za-km-z]{21,30}$', seed):
        return True, "Valid private key (mini format)"
    
    # 6. BIP38 encrypted private key
    if re.match(r'^6P[1-9A-HJ-NP-Za-km-z]{38,39}$', seed):
        return True, "Valid private key (BIP38 encrypted format)"
    
    # 7. Extended private key (xprv)
    if re.match(r'^xprv[1-9A-HJ-NP-Za-km-z]{107,108}$', seed):
        return True, "Valid private key (extended format)"
    
    # 8. BIP39 mnemonic phrase (12 or 24 words)
    words = seed.split()
    if len(words) in [12, 24] and all(word.isalpha() for word in words):
        return True, "Valid mnemonic phrase"
    
    return False, """Invalid seed format. Must be one of:
- A 64-character hex private key
- A base58 private key (40-90 characters)
- A WIF private key (starts with 5, K, or L)
- A WIF compressed private key
- A mini private key (starts with S)
- A BIP38 encrypted private key (starts with 6P)
- An extended private key (starts with xprv)
- A 12/24 word mnemonic phrase"""

# ======================= SHELTER APP =======================
class ShelterApp:
    def __init__(self):
        clear_console()
        print(BANNER)
        
        # Setup logging
        logging.basicConfig(
            filename='shelter.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Get default path
        default_path = os.path.expanduser("~/.lakayshelter")
        self.user_appdata = input(f"Files path (default: {default_path}): ").strip() or default_path
        self.base_dir = os.path.join(self.user_appdata, "Shelter")
        self.password_file = os.path.join(self.base_dir, "password.hash")
        self.seed_file = os.path.join(self.base_dir, "seeds.json")
        self.attempts_file = os.path.join(self.base_dir, "login_attempts.json")
        
        os.makedirs(self.base_dir, exist_ok=True)
        print(f"Selected path={self.base_dir}")
        
        self.password = None
        self.login_attempts = self._load_login_attempts()
        
        # Show warning about data loss
        print("\nWARNING: If you forget your password, all stored seeds will be permanently lost.")
        print("Make sure to keep your password safe and consider backing up your seeds.")
        input("\nPress Enter to continue...")
    
    def _load_login_attempts(self) -> dict:
        if not os.path.exists(self.attempts_file):
            return {"attempts": 0, "last_attempt": 0}
        try:
            with open(self.attempts_file, "r") as f:
                return json.load(f)
        except:
            return {"attempts": 0, "last_attempt": 0}
    
    def _save_login_attempts(self) -> None:
        atomic_write(self.attempts_file, self.login_attempts)
    
    def _check_login_timeout(self) -> bool:
        current_time = time.time()
        if self.login_attempts["attempts"] >= CryptoManager.MAX_LOGIN_ATTEMPTS:
            time_passed = current_time - self.login_attempts["last_attempt"]
            if time_passed < CryptoManager.LOGIN_TIMEOUT:
                remaining = int(CryptoManager.LOGIN_TIMEOUT - time_passed)
                print(f"\nToo many failed attempts. Please wait {remaining} seconds.")
                return True
            else:
                self.login_attempts["attempts"] = 0
        return False
    
    def _load_data(self) -> List[dict]:
        if not os.path.exists(self.seed_file):
            return []
        try:
            with open(self.seed_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading data: {str(e)}")
            return []
    
    def _save_data(self, data: List[dict]) -> None:
        try:
            atomic_write(self.seed_file, data)
        except Exception as e:
            logging.error(f"Error saving data: {str(e)}")
            raise
    
    def login(self) -> bool:
        try:
            if self._check_login_timeout():
                return False
                
            if not os.path.exists(self.password_file):
                print("\nCreating new password")
                print("Password must contain:")
                print("- At least 8 characters")
                print("- At least one uppercase letter")
                print("- At least one lowercase letter")
                print("- At least one digit")
                print("- At least one special character")
                
                while True:
                    password = input("\nNew password: ")
                    confirm = input("Confirm password: ")
                    
                    if password != confirm:
                        print("Passwords do not match.")
                        continue
                    
                    is_valid, message = PasswordPolicy.validate(password)
                    if not is_valid:
                        print(f"Error: {message}")
                        continue
                    
                    hashed_pw = CryptoManager.hash_password(password)
                    encrypted = CryptoManager.encrypt_data(hashed_pw.decode(), password)
                    
                    atomic_write(self.password_file, encrypted)
                    self.password = password
                    return True
            else:
                password = input("Password: ")
                with open(self.password_file, "r") as f:
                    encrypted = json.load(f)
                
                try:
                    decrypted_hash = CryptoManager.decrypt_data(encrypted, password)
                    if CryptoManager.verify_password(password, decrypted_hash.encode()):
                        self.password = password
                        self.login_attempts["attempts"] = 0
                        self._save_login_attempts()
                        return True
                except DecryptionError:
                    pass
                
                self.login_attempts["attempts"] += 1
                self.login_attempts["last_attempt"] = time.time()
                self._save_login_attempts()
                
                print("Invalid password.")
                return False
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            print(f"Authentication error: {str(e)}")
            return False
    
    def add_seed(self):
        label = input("Enter a label for this seed (optional): ").strip()
        seed = input("Add seed or key: ")
        
        is_valid, message = validate_seed_format(seed)
        if not is_valid:
            print(message)
            return
        
        encrypted = CryptoManager.encrypt_data(seed, self.password)
        if label:
            encrypted["label"] = label
            
        data = self._load_data()
        data.append(encrypted)
        self._save_data(data)
        print("Saved successfully.")
    
    def view_seeds(self):
        data = self._load_data()
        if not data:
            print("No seeds found.")
            return
        
        print()  # Just an empty line at the start
        for i, enc in enumerate(data, 1):
            try:
                seed = CryptoManager.decrypt_data(enc, self.password)
                label = enc.get("label", "No label")
                print(f"Seed #{i} ({label}):")
                print(f"{seed}")
                print()  # Empty line between seeds
            except DecryptionError:
                print(f"Seed #{i}:")
                print("(Decryption error)")
                print()  # Empty line between seeds
    
    def delete_seed(self):
        data = self._load_data()
        if not data:
            print("No seeds to delete.")
            return
        
        print()  # Just an empty line at the start
        for i, enc in enumerate(data, 1):
            try:
                seed = CryptoManager.decrypt_data(enc, self.password)
                label = enc.get("label", "No label")
                print(f"Seed #{i} ({label}):")
                print(f"{seed}")
                print()  # Empty line between seeds
            except DecryptionError:
                print(f"Seed #{i}:")
                print("(Decryption error)")
                print()  # Empty line between seeds
        
        try:
            num = int(input("Enter number to delete: ").strip()) - 1
            if not (0 <= num < len(data)):
                print("Invalid number.")
                return
            
            confirm = input("Delete this seed? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("Deletion cancelled.")
                return
            
            data.pop(num)
            self._save_data(data)
            print("Seed deleted successfully.")
        except ValueError:
            print("Invalid input.")
    
    def change_password(self):
        old_password = input("Current password: ")
        if not self.verify_password(old_password):
            print("Invalid current password.")
            return
        
        new_password = input("New password: ")
        confirm = input("Confirm new password: ")
        
        if new_password != confirm:
            print("Passwords do not match.")
            return
        
        is_valid, message = PasswordPolicy.validate(new_password)
        if not is_valid:
            print(f"Error: {message}")
            return
        
        # Re-encrypt all seeds with the new password
        data = self._load_data()
        new_data = []
        for enc in data:
            try:
                seed = CryptoManager.decrypt_data(enc, old_password)
                new_enc = CryptoManager.encrypt_data(seed, new_password)
                if "label" in enc:
                    new_enc["label"] = enc["label"]
                new_data.append(new_enc)
            except DecryptionError:
                print("Error while re-encrypting seeds.")
                return
        
        # Save the new password
        hashed_pw = CryptoManager.hash_password(new_password)
        encrypted = CryptoManager.encrypt_data(hashed_pw.decode(), new_password)
        
        atomic_write(self.password_file, encrypted)
        self._save_data(new_data)
        self.password = new_password
        print("Password changed successfully.")
    
    def verify_password(self, password: str) -> bool:
        with open(self.password_file, "r") as f:
            encrypted = json.load(f)
        try:
            decrypted_hash = CryptoManager.decrypt_data(encrypted, password)
            return CryptoManager.verify_password(password, decrypted_hash.encode())
        except DecryptionError:
            return False
    
    def show_menu(self):
        while True:
            clear_console()
            print(BANNER)
            print("""
1. Add seed phrase or private key

2. View stored seeds

3. Delete a seed

4. Change password

0. Exit
""")
            choice = input("\nOption: ").strip()
            clear_console()
            print(BANNER)
            
            try:
                if choice == "1":
                    print("\n=== ADD NEW SEED ===\n")
                    self.add_seed()
                elif choice == "2":
                    print("\n=== STORED SEEDS ===\n")
                    self.view_seeds()
                elif choice == "3":
                    print("\n=== DELETE SEED ===\n")
                    self.delete_seed()
                elif choice == "4":
                    print("\n=== CHANGE PASSWORD ===\n")
                    self.change_password()
                elif choice == "0":
                    print("\nGoodbye!")
                    break
                else:
                    print("\nInvalid option.")
            except Exception as e:
                logging.error(f"Error in menu: {str(e)}")
                print(f"\nError: {str(e)}")
            
            input("\nPress Enter to continue...")

def main():
    clear_console()
    print(BANNER)
    app = ShelterApp()
    
    if app.login():
        app.show_menu()
    else:
        print("\nAuthentication failed.")
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()