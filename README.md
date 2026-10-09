🔐 PasswordToSeed 🗝️

🚀 Turn Your Password Into Words — Recover It Anytime!

🔒 PasswordToSeed is a Python project designed to transform passwords into human-readable mnemonic phrases using authenticated encryption and a custom word-encoding format.

✨ Features

* 🔐 Authenticated Encryption — ChaCha20-Poly1305
* 🛡️ Secure Key Derivation — scrypt
* 🎲 Random Salt & Nonce — Cryptographically secure random values
* 🗝️ Password Recovery — Recover the original password using your mnemonic phrase and recovery secret
* 🧩 Mnemonic Encoding — Represent encrypted data as a sequence of words
* 💻 Offline Operation — Designed to run locally
* 🧪 Testing Support — Validate recovery, corrupted phrases, and authentication failures

[!WARNING]
⚠️ PasswordToSeed uses a custom mnemonic format, not BIP-39. Review the implementation and run security tests before protecting real passwords or sensitive credentials.

⸻

⚙️ Installation

📥 Clone the repository:

git clone https://github.com/AiGptCode/PasswordToSeed.git
cd PasswordToSeed

🐍 Create and activate a virtual environment:

Linux / macOS

python3 -m venv .venv
source .venv/bin/activate

Windows

python -m venv .venv
.venv\Scripts\activate

📦 Install dependencies:

pip install pycryptodome pytest

🚀 Usage

Run the application:

python password_to_seed.py

Follow the prompts to generate a mnemonic phrase or recover the original password.

🧪 Run tests:

pytest -q

🔐 Security

* 🛡️ Use a strong, unique recovery secret.
* 🎲 Never reuse a ChaCha20-Poly1305 nonce with the same key.
* 🔒 Keep your mnemonic phrase and recovery secret private.
* 🚫 Never hard-code or publish sensitive credentials.
* ✅ Reject modified payloads that fail authentication.
* ⚠️ A mnemonic phrase is not a substitute for a standard BIP-39 wallet recovery phrase.

📂 Project Structure

PasswordToSeed/
├── README.md
├── requirements.txt
├── password_to_seed.py
└── test_password_to_seed.py

Update the filenames to match the actual repository.

🤝 Contributing

Contributions, bug reports, and security reviews are welcome! ❤️

Please include tests with code changes and never commit real passwords, recovery secrets, or private credentials.

📜 License

Add the project’s actual license and corresponding LICENSE file here.

⸻

🌟 Repository

🔗 GitHub: https://github.com/AiGptCode/PasswordToSeed

🔐 PasswordToSeed — Protect Your Password. Keep the Words. Recover When Needed. 🚀
