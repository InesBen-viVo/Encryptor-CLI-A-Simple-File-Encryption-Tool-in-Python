# Encryptor-CLI-A-Simple-File-Encryption-Tool-in-Python
Encryptor CLI is a simple, interactive tool that demonstrates practical encryption and decryption using a password-derived key. It’s designed to show understanding of cryptography fundamentals — key derivation, symmetric encryption, and secure encoding — all wrapped in a clean terminal interface.
🔒 About the Project

Encryptor CLI is a simple, interactive tool that demonstrates practical encryption and decryption using a password-derived key.
It’s designed to show understanding of cryptography fundamentals — key derivation, symmetric encryption, and secure encoding — all wrapped in a clean terminal interface.

⚙️ Features

Encrypt and decrypt text messages safely.

Derive encryption keys securely using PBKDF2 (Password-Based Key Derivation Function 2).

Uses AES encryption under the hood via the cryptography package.

Simple command-line interface with user prompts.

Easy to extend — can later support file encryption, GUI, or API integration.

🧠 Why It Matters

This project demonstrates:

Practical knowledge of applied cryptography.

Understanding of key management and data protection.

Ability to write clean, maintainable, and secure Python code.
It’s ideal for cybersecurity portfolios or students applying for programs in information security or software engineering.

💻 Installation

Clone the repository:

cd encryptor-cli


 Create a virtual environment:(Optional)

python3 -m venv venv
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt

🚀 Usage

Run the tool:

python3 encryptor_cli.py


Follow the prompts to:

Enter a message

Set a password

Choose encrypt or decrypt

The encrypted or decrypted message will be displayed instantly.
