from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import os, base64, json, getpass

def generate_key():
    aes_key = os.urandom(32)  # 256-bit key
    passphrase = getpass.getpass("Enter passphrase: ").encode()
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    derived_key = kdf.derive(passphrase)
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    encrypted_key = aesgcm.encrypt(nonce, aes_key, None)

    with open("encrypted_key.json", "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "key": base64.b64encode(encrypted_key).decode()
        }, f)
    print("Key generated and stored securely.")

def load_key():
    passphrase = getpass.getpass("Enter passphrase to unlock key: ").encode()
    with open("encrypted_key.json", "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    encrypted_key = base64.b64decode(data["key"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    derived_key = kdf.derive(passphrase)
    aesgcm = AESGCM(derived_key)
    return aesgcm.decrypt(nonce, encrypted_key, None)



def get_key(user_role):
    with open("roles.json") as f:
        roles = json.load(f)
    if roles.get(user_role):
        return load_key()
    else:
        raise PermissionError("Unauthorized role")


def encrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        data = f.read()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    with open(filepath + ".enc", "wb") as f:
        f.write(nonce + encrypted)
    print(f"Encrypted file saved as: {filepath}.enc")


def decrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        nonce = f.read(12)
        ciphertext = f.read()
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    output_file = filepath.replace(".enc", ".dec")
    with open(output_file, "wb") as f:
        f.write(decrypted)
    print(f"Decrypted file saved as: {output_file}")
