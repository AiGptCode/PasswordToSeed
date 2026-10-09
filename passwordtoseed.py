
#!/usr/bin/env python3
"""PasswordToSeed: reversible password-to-mnemonic encryption.

This is a custom mnemonic format, NOT a BIP39 wallet seed.
Requires: python -m pip install pycryptodome
"""

import getpass
import hashlib
import secrets
import sys

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


# 256 unique words: each byte is represented by two 4-bit word indexes.
WORDS = """
amber anchor apple april arch artist aspen atlas
autumn bamboo beacon birch bison bloom blue breeze
brick brook cabin cactus candle canvas canyon cedar
celery chalk cherry circle cliff cloud clover coast
cobalt comet coral cosmos crane creek crown crystal
daisy delta desert dolphin dream drift eagle earth
echo elm ember emerald falcon fern field finch
fire flame flint flower forest fossil fox frost
galaxy garden gem glacier glade glass globe gold
granite grape grass green harbor hawk hazel heart
heron hill honey horizon ice indigo island ivory
jade jasmine jewel journey juniper kestrel key king
kite kiwi lagoon lake lantern laurel leaf lemon
light lilac lily linden lion lizard lotus lunar
maple marble marigold marina meadow meteor mint mirror
mist monarch moon morning moss mountain mouse mulberry
nebula nectar needle nest night north novel nutmeg
oasis ocean olive onyx orange orbit orchid origin
otter owl palm panda paper pearl pebble pelican
pepper phoenix pine planet plum pocket polar pond
poppy prairie prism puma quartz quest quiet quill
rabbit raven reef river robin rocket rose ruby
saffron sail sapphire scarlet seed shadow shore silver
sky slate snow solar sparrow sphinx spice spider
spruce star stone storm stream summit sunrise swift
tangerine temple thistle thunder tiger timber topaz trail
tree tulip tundra umber valley velvet vermilion violet
volcano voyage walnut water willow wind winter wolf
wood wren xenon yarrow yellow yonder yucca zephyr
zinc zinnia zodiac zulu acorn badger basil bluejay
bonfire butter calm caravan cascade cello chime cinder
citron compass copper cypress dawn dewdrop dune evening
""".split()

MAGIC = b"PTS1"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MAX_PASSWORD_SIZE = 4096

# Scrypt parameters: approximately 32 MiB of working memory.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class PasswordToSeedError(ValueError):
    """Invalid phrase, corrupted data, or failed recovery."""


def _validate_wordlist():
    if len(WORDS) != 256 or len(set(WORDS)) != 256:
        raise RuntimeError("Mnemonic word list must contain 256 unique words.")


def _encode(payload: bytes) -> str:
    """Encode each byte as two words representing its high/low nibbles."""
    words = []
    for byte in payload:
        words.append(WORDS[byte >> 4])
        words.append(WORDS[byte & 0x0F])
    return " ".join(words)


def _decode(phrase: str) -> bytes:
    """Decode the custom mnemonic representation."""
    if not isinstance(phrase, str):
        raise PasswordToSeedError("Phrase must be text.")

    tokens = phrase.strip().lower().split()

    if not tokens or len(tokens) % 2:
        raise PasswordToSeedError("Invalid phrase length.")

    if len(tokens) > 2 * (MAX_PASSWORD_SIZE + 128):
        raise PasswordToSeedError("Phrase is too long.")

    indexes = {word: index for index, word in enumerate(WORDS)}
    result = bytearray()

    for i in range(0, len(tokens), 2):
        try:
            high = indexes[tokens[i]]
            low = indexes[tokens[i + 1]]
        except KeyError:
            raise PasswordToSeedError("Phrase contains an unknown word.") from None

        if high > 15 or low > 15:
            raise PasswordToSeedError("Invalid custom mnemonic encoding.")

        result.append((high << 4) | low)

    return bytes(result)


def password_to_seed(password: str, recovery_secret: str) -> str:
    """Encrypt a password and encode the result as a custom mnemonic."""
    _validate_wordlist()

    if not isinstance(password, str) or not isinstance(recovery_secret, str):
        raise TypeError("Password and recovery secret must be strings.")

    plaintext = password.encode("utf-8")
    secret = recovery_secret.encode("utf-8")

    if not plaintext:
        raise ValueError("Password must not be empty.")

    if len(plaintext) > MAX_PASSWORD_SIZE:
        raise ValueError(f"Password exceeds {MAX_PASSWORD_SIZE} UTF-8 bytes.")

    if len(secret) < 12:
        raise ValueError("Recovery secret must contain at least 12 characters.")

    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)

    header = (
        MAGIC
        + bytes([VERSION])
        + SCRYPT_N.to_bytes(4, "big")
        + bytes([SCRYPT_R, SCRYPT_P])
    )

    key = scrypt(
        secret,
        salt,
        KEY_SIZE,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    payload = (
        header
        + salt
        + nonce
        + len(ciphertext).to_bytes(4, "big")
        + ciphertext
        + tag
    )

    # Detect accidental phrase corruption before expensive KDF work.
    checksum = hashlib.sha256(payload).digest()[:4]

    return _encode(payload + checksum)


def seed_to_password(phrase: str, recovery_secret: str) -> str:
    """Validate, authenticate, and recover the original password."""
    _validate_wordlist()

    if not isinstance(recovery_secret, str):
        raise TypeError("Recovery secret must be a string.")

    secret = recovery_secret.encode("utf-8")

    if len(secret) < 12:
        raise ValueError("Recovery secret must contain at least 12 characters.")

    data = _decode(phrase)

    if len(data) < 4:
        raise PasswordToSeedError("Phrase is too short.")

    payload, checksum = data[:-4], data[-4:]

    expected = hashlib.sha256(payload).digest()[:4]
    if not secrets.compare_digest(checksum, expected):
        raise PasswordToSeedError("Phrase checksum failed.")

    # Header: magic (4), version (1), N (4), r (1), p (1).
    header_size = 11

    if len(payload) < header_size + SALT_SIZE + NONCE_SIZE + 4 + TAG_SIZE:
        raise PasswordToSeedError("Incomplete phrase payload.")

    header = payload[:header_size]

    if header[:4] != MAGIC or header[4] != VERSION:
        raise PasswordToSeedError("Unsupported phrase format.")

    n = int.from_bytes(header[5:9], "big")
    r, p = header[9], header[10]

    # Reject unexpected parameters to prevent malicious resource requests.
    if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise PasswordToSeedError("Unsupported KDF parameters.")

    offset = header_size
    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    length = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4

    if not 1 <= length <= MAX_PASSWORD_SIZE:
        raise PasswordToSeedError("Invalid password payload length.")

    if len(payload) != offset + length + TAG_SIZE:
        raise PasswordToSeedError("Inconsistent payload length.")

    ciphertext = payload[offset:offset + length]
    tag = payload[-TAG_SIZE:]

    key = scrypt(
        secret,
        salt,
        KEY_SIZE,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        raise PasswordToSeedError(
            "Recovery failed: incorrect recovery secret or corrupted phrase."
        ) from None


def main() -> int:
    print("PasswordToSeed — Custom Mnemonic Format")
    print("This is NOT a BIP39 cryptocurrency wallet phrase.")
    print("[P] Password to phrase")
    print("[S] Phrase to password")
    print("[Q] Quit")

    choice = input("Select an option: ").strip().upper()

    try:
        if choice == "P":
            password = getpass.getpass("Password to encode: ")
            secret = getpass.getpass("Create recovery secret (12+ characters): ")
            confirm = getpass.getpass("Confirm recovery secret: ")

            if secret != confirm:
                print("Error: recovery secrets do not match.", file=sys.stderr)
                return 1

            phrase = password_to_seed(password, secret)
            print("\nMnemonic phrase — store it securely:\n")
            print(phrase)
            print("\nKeep the recovery secret separately.")

        elif choice == "S":
            phrase = input("Enter the complete mnemonic phrase: ")
            secret = getpass.getpass("Recovery secret: ")

            password = seed_to_password(phrase, secret)
            print("\nRecovered password:")
            print(password)

        elif choice == "Q":
            return 0

        else:
            print("Invalid option.", file=sys.stderr)
            return 1

        return 0

    except (ValueError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
