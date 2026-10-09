PasswordToSeed

Convert a password into a recoverable mnemonic phrase — and restore the original password when needed.

PasswordToSeed is a Python project designed to encode a password into a human-readable sequence of words using authenticated encryption and a custom mnemonic format. With the correct recovery secret, the original password can be recovered.

> **Important:** This project uses a custom mnemonic format, not standard BIP-39. Review and test the implementation before relying on it for sensitive credentials or production use.

Features

• Password recovery: Recover the original password from the generated phrase.
• Authenticated encryption: Uses ChaCha20-Poly1305 to protect the encrypted payload and detect tampering.
• Password-based key derivation: Uses scrypt to derive an encryption key from a recovery secret.
• Random salt and nonce: Designed to prevent repeated inputs from producing identical encrypted payloads.
• Mnemonic representation: Converts binary data into a sequence of readable words.
• Input validation: Rejects malformed phrases and invalid encrypted data.
• Local operation: Designed to work offline without sending passwords to an external service.

How It Works

The intended workflow is:

1. Enter the password you want to encode.
2. Provide a separate recovery secret.
3. Generate a random salt and nonce.
4. Derive an encryption key using scrypt.
5. Encrypt the password using ChaCha20-Poly1305.
6. Encode the resulting payload as a mnemonic phrase.
7. To recover the password, decode the phrase, derive the same key, authenticate and decrypt the payload.

The recovery secret is required to restore the original password. The mnemonic phrase alone should not be sufficient to decrypt the password.

Requirements

• Python 3.10 or newer
• PyCryptodome
• Pytest for running the test suite

Installation

Clone the repository:

git clone https://github.com/AiGptCode/PasswordToSeed.git
cd PasswordToSeed

Create a virtual environment:

python -m venv .venv

Activate it.

Linux / macOS

source .venv/bin/activate

Windows

.venv\Scripts\activate

Install the dependencies:

pip install pycryptodome pytest

Usage

Run the program:

python password_to_seed.py

Follow the prompts to generate a mnemonic phrase or recover a password.

Keep the mnemonic phrase and recovery secret safe. Do not share either one or commit them to source control.

Testing

Run the project’s test suite:

pytest -q

Tests should cover at least:

• Password-to-phrase-to-password round trips.
• Empty and unusually long inputs.
• Incorrect recovery secrets.
• Modified or corrupted mnemonic phrases.
• Invalid word sequences.
• Authentication failures.
• Random salt and nonce generation.

Do not consider the project production-ready until these tests pass against the actual implementation.

Security Considerations

• Use a unique, strong recovery secret.
• Never hard-code recovery secrets, passwords, encryption keys, salts, or nonces.
• Generate salts and nonces using a cryptographically secure random number generator.
• Never reuse a ChaCha20-Poly1305 nonce with the same key.
• Use authenticated encryption and reject payloads that fail authentication.
• Treat mnemonic phrases as sensitive encrypted data.
• Avoid printing passwords or recovery secrets to logs.
• Remember that encryption cannot protect a phrase if the recovery secret is compromised.

Important limitations

• A custom mnemonic format is not interchangeable with BIP-39 wallets or seed phrases.
• A checksum can detect some accidental changes, but it is not a substitute for authenticated encryption.
• Password-based encryption security depends on the recovery secret, key derivation parameters, and correct implementation.
• Python cannot reliably guarantee that sensitive strings have been erased from memory.

Project Structure

PasswordToSeed/
├── README.md
├── requirements.txt
├── password_to_seed.py
└── test_password_to_seed.py

The filenames above describe the intended structure; adjust them to match the actual repository.

Contributing

Contributions are welcome. Please open an issue before making substantial changes, and include tests for security-sensitive modifications.

License

Specify the project’s actual license here. Do not claim an open-source license unless the repository includes the corresponding license file.

────────

Project: AiGptCode/PasswordToSeed

Goal: Make password encoding and recovery understandable, testable, and secure by design.
