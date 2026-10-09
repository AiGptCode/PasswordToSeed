PasswordToSeed

An offline Python utility for converting passwords into reversible mnemonic phrases.

PasswordToSeed encrypts a password and represents the resulting encrypted data as a sequence of English words. The original password can be recovered using the complete phrase and the correct recovery secret.

Important: PasswordToSeed uses a custom mnemonic format. It is not compatible with BIP39 cryptocurrency wallet recovery phrases.

Features

* Reversible conversion: Recover the exact original password.
* Offline operation: No internet connection or external API is required at runtime.
* Authenticated encryption: Uses ChaCha20-Poly1305 to protect password data.
* Password-based key derivation: Uses Scrypt with documented parameters.
* Random cryptographic values: Generates a new salt and nonce for each conversion.
* Unicode support: Supports Persian, English, emojis, and other Unicode characters.
* Integrity checks: Detects many forms of accidental phrase corruption.
* Interactive CLI: Simple password-to-phrase and phrase-to-password workflows.
* No password echo during input: Uses Python’s getpass for password entry.

How It Works

The conversion process has two main stages.

Password to mnemonic phrase

1. The user enters a password.
2. The user creates a separate recovery secret.
3. The application generates a random salt and nonce.
4. Scrypt derives an encryption key from the recovery secret.
5. ChaCha20-Poly1305 encrypts the original password.
6. The encrypted payload and required metadata are encoded as a custom English mnemonic phrase.

Mnemonic phrase to password

1. The user enters the complete mnemonic phrase.
2. The user supplies the recovery secret.
3. The application validates the phrase and its integrity.
4. Scrypt derives the encryption key again.
5. ChaCha20-Poly1305 authenticates and decrypts the payload.
6. The application returns the original password.

The recovery secret is essential. The phrase alone is not intended to reveal the original password.

Requirements

* Python 3.10 or newer recommended
* pycryptodome

Install the dependency:

python -m pip install pycryptodome

Installation

Clone the repository:

git clone https://github.com/AiGptCode/PasswordToSeed.git
cd PasswordToSeed

Install dependencies:

python -m pip install -r requirements.txt

If the repository does not yet contain requirements.txt, create one containing:

pycryptodome>=3.20,<4

Usage

Start the application:

python password_to_seed.py

Choose one of the available options.

Convert a password to a phrase

Select P, enter the password, and create a recovery secret.

The application displays the resulting mnemonic phrase.

Store the phrase securely. Keep the recovery secret separate from it.

Recover a password

Select S, enter the complete phrase, and provide the original recovery secret.

If the phrase and secret are valid, the application returns the original password.

Security Considerations

Protect the mnemonic phrase

Anyone who obtains the phrase and the corresponding recovery secret can recover the password. Treat both as sensitive information.

Use a strong recovery secret

Choose a long, unique recovery secret that is difficult to guess. Do not reuse an important account password as the recovery secret.

Keep backups

Store the mnemonic phrase and recovery secret in secure, separate locations. Losing either may make recovery impossible.

Understand the format

The custom mnemonic is an encoding of encrypted data, not a standard cryptocurrency wallet seed phrase. Do not import it into a Bitcoin, Ethereum, or other cryptocurrency wallet.

Review before production use

The implementation should undergo automated testing and independent security review before being used to protect high-value credentials.

Limitations

* The mnemonic phrase has a variable number of words.
* The format is custom and is not BIP39-compatible.
* Recovery requires the correct recovery secret.
* Losing the phrase or recovery secret can make the original password unrecoverable.
* The application does not guarantee protection against malware, keyloggers, compromised systems, or insecure backups.
* Python cannot guarantee complete erasure of sensitive strings from memory.

Testing

Run the automated test suite if the repository includes tests:

python -m pytest -q

Recommended test cases include:

* Ordinary ASCII passwords
* Persian and other Unicode passwords
* Passwords containing spaces and punctuation
* Long passwords
* Incorrect recovery secrets
* Modified or incomplete phrases
* Invalid mnemonic words
* Repeated conversions of the same password

Do not describe the software as fully tested until these tests have actually been executed and their results reviewed.

Project Structure

PasswordToSeed/
├── password_to_seed.py
├── requirements.txt
├── test_password_to_seed.py
└── README.md

Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement the change and add tests.
4. Run the test suite.
5. Submit a pull request describing the changes.

Please do not submit real passwords, recovery secrets, or private mnemonic phrases in issues or pull requests.

License

This project is distributed under the MIT License if the repository’s existing license file specifies MIT. See the LICENSE file for the applicable terms.

Disclaimer

PasswordToSeed is provided for educational and personal use. It is not a cryptocurrency wallet, a BIP39 recovery tool, or a substitute for a professionally audited password manager.

Use it with an understanding of its limitations and verify the implementation before relying on it for important credentials.
