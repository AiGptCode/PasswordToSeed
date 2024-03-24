import base64
import getpass
import mnemonic
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import ChaCha20_Poly1305

def password_to_seed(password):
    # Derive key from the password
    salt = b'MELT'  # Use a unique salt value
    kdf_output = scrypt(password.encode('utf-8'), salt, 32, N=2**20, r=8, p=1)  
    key, nonce = kdf_output[:16], kdf_output[16:]

    # Use ChaCha20-Poly1305 to encrypt an empty message with the derived key and nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(b'')  # Encrypt an empty message

    # Concatenate the ciphertext and tag to create the seed
    seed = ciphertext + tag
    seed_hex = base64.b64encode(seed).decode('utf-8')  # Convert to base64
    # Convert the seed to a mnemonic phrase with 12 words
    mnemo = mnemonic.Mnemonic("english")
    words = mnemo.to_mnemonic(bytes.fromhex(seed_hex))
    return " ".join(words)

def seed_to_password(seed_phrase):
    # Convert the mnemonic phrase to a seed
    mnemo = mnemonic.Mnemonic("english")
    seed_hex = mnemo.to_seed(seed_phrase)
    decoded_seed = base64.b64decode(seed_hex).decode('utf-8')  # Decode from base64
    seed = bytes.fromhex(decoded_seed)

    # Use the seed as the password
    return seed

def main():
    choice = input("Do you want to convert password to seed (P) or seed to password (S)? ").upper()
    if choice == 'P':
        password = getpass.getpass(prompt='Enter your password: ')
        print("Password:", password)  # Show the entered password
        seed = password_to_seed(password)
        print("Seed Phrase:", seed)
    elif choice == 'S':
        seed_phrase = input("Enter the seed phrase (12 words): ")
        retrieved_password = seed_to_password(seed_phrase)
        print("Retrieved Password:", retrieved_password.decode('utf-8'))
    else:
        print("Invalid choice. Please enter 'P' or 'S'.")

if __name__ == "__main__":
    main()



