README.txt - LakayShelter v1.2 - Secure management of seeds and private keys
===================================================================================================

██╗      █████╗ ██╗  ██╗ █████╗ ██╗   ██╗    ███████╗██╗  ██╗███████╗██╗  ████████╗███████╗██████╗ 
██║     ██╔══██╗██║ ██╔╝██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██║  ╚══██╔══╝██╔════╝██╔══██╗
██║     ███████║█████╔╝ ███████║ ╚████╔╝     ███████╗███████║█████╗  ██║     ██║   █████╗  ██████╔╝
██║     ██╔══██║██╔═██╗ ██╔══██║  ╚██╔╝      ╚════██║██╔══██║██╔══╝  ██║     ██║   ██╔══╝  ██╔══██╗
███████╗██║  ██║██║  ██╗██║  ██║   ██║       ███████║██║  ██║███████╗███████╗██║   ███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝

===================================================================================================

LakayShelter is a Python console application designed to securely store, manage, and validate your seed phrases and private keys – now more robust, compatible, and secure than ever in version v1.2.

---

Main Features:

1. Encrypted storage of seeds and private keys using AES-GCM 256-bit encryption.
2. Password management with bcrypt hashing and lockout mechanism after multiple failed attempts.
3. Full support for many common key formats, with strict validation rules.
4. Add, view, and delete encrypted seeds via an intuitive console menu.
5. Labels for seeds (optional, editable, preserved on password change).
6. Secure folder creation and password-protected access.
7. All validation and encryption done locally – your data never leaves your machine.

---

Supported Key Formats:

- Hexadecimal (64 characters)
- Base58 (commonly used in Solana, 40–90 characters)
- WIF (Wallet Import Format: starts with 5, K, or L)
- Compressed WIF
- Mini private keys (starts with S)
- BIP38 encrypted keys (starts with 6P)
- xprv extended private keys
- BIP39 mnemonic phrases (12 or 24 words)

When validation fails, clear and helpful messages explain the issue and suggest how to correct it.

---

Requirements:

- Python 3.6 or higher
- Install dependencies with:
pip install cryptography bcrypt

---

Installation:

1. Clone or copy the program files to your machine.
2. Install dependencies as shown above.
3. Run the main Python script

---

Getting Started:

1. On first launch, choose a folder to store encrypted data ("Shelter" subfolder will be created).
2. If no password is set, you’ll be prompted to create one. It must contain:
   - At least 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character
3. Once authenticated, the menu allows you to:
   - Add a seed phrase or private key
   - View stored entries
   - Delete a seed
   - Change your main password
   - Exit the application
4. You can optionally assign a label to each seed for better identification.
5. Labels are shown as: Seed #xxx

---

Security Features:

- AES-GCM encryption ensures strong confidentiality and data integrity.
- Passwords are hashed using bcrypt for enhanced protection.
- Lockout mechanism after 5 failed login attempts, with a 5-minute timeout.
- All operations are fully offline – no network interaction required.
- Seeds and private keys are never stored in plain text.
- Changing the password re-encrypts all saved data.
- If the password is lost, the data cannot be recovered.

---

Purpose and Use Case:

LakayShelter lets you securely store your sensitive keys on an external drive or offline device. This makes it ideal for privacy-focused users and long-term self-custody setups, where portability, safety, and clarity are essential.

---

Support:

For questions, feedback or bug reports, contact me on Telegram at @Lakay1733 or GitHub

---

Thank you for using LakayShelter to protect your crypto.

Stay sovereign. Own your keys.
