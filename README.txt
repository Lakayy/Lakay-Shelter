README.txt - LakayShelter - Secure management of seeds and private keys

===================================================================================================

██╗      █████╗ ██╗  ██╗ █████╗ ██╗   ██╗    ███████╗██╗  ██╗███████╗██╗  ████████╗███████╗██████╗ 
██║     ██╔══██╗██║ ██╔╝██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██║  ╚══██╔══╝██╔════╝██╔══██╗
██║     ███████║█████╔╝ ███████║ ╚████╔╝     ███████╗███████║█████╗  ██║     ██║   █████╗  ██████╔╝
██║     ██╔══██║██╔═██╗ ██╔══██║  ╚██╔╝      ╚════██║██╔══██║██╔══╝  ██║     ██║   ██╔══╝  ██╔══██╗
███████╗██║  ██║██║  ██╗██║  ██║   ██║       ███████║██║  ██║███████╗███████╗██║   ███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝

===================================================================================================

LakayShelter is a Python console application designed to securely store, manage, and protect your seed phrases and private keys.

---

Main Features:

1. Creation of a secure folder to store encrypted files.
2. Password management with validation (length, complexity).
3. AES-GCM encryption of seeds and private keys.
4. Add, view, and delete seeds via a simple console interface.
5. Change the main password with re-encryption of all data.
6. Secure authentication verification at startup.

---

Requirements:

- Python 3.6 or higher
- Cryptography library (installable via `pip install cryptography`)

---

Installation:

1. Clone or copy the program files.
2. Install the cryptography library if not already installed:

---

Getting Started:

1. On first launch, you will be asked to provide a path to store the secured files.
2. If no password exists, you will be prompted to create one.
- The password must contain:
  * At least 8 characters
  * At least one uppercase letter
  * At least one lowercase letter
  * At least one number
  * At least one special character
3. Once authenticated, a menu allows you to:
- Add a seed phrase or private key (stored encrypted)
- View stored seeds (decrypted on the fly)
- Delete a seed
- Change the main password
- Exit the application
4. Data is stored inside a "Shelter" subfolder in the chosen path.
5. The password is stored in an encrypted file for security.

---

Security:

- Data is encrypted with AES-GCM 256-bit encryption.
- Passwords are strengthened using PBKDF2 + SHA256 key derivation.
- Seeds are never stored in plain text on disk.
- If the password is lost, data recovery is impossible.

---

Notes:

- Console-based application only.
- Basic seed validation (no advanced format checks).
- Designed for single-user use.

---

Purpose and Use Case:

LakayShelter is designed to allow you to store your private keys securely on a USB drive or any external storage device, enabling you to access them safely from any computer without leaving unencrypted traces.
This portability ensures that your sensitive data stays protected while remaining easily accessible wherever you go.

---

Support:

For questions or bug reports, please contact @Lakay1733 on Telegram or on GitHub.

---

Thank you for using LakayShelter to keep your seeds safe !
