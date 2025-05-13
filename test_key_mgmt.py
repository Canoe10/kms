import os
from crypto_handler import generate_key, get_key, encrypt_file, decrypt_file

def test_generate_and_encrypt():
    print("Generating key...")
    generate_key()

    print("Testing authorized role (admin)...")
    try:
        key = get_key("admin")
        with open("test.txt", "wb") as f:
            f.write(b"Secret message!")

        encrypt_file("test.txt", key)
        decrypt_file("test.txt.enc", key)

        with open("test.txt.dec", "rb") as f:
            assert f.read() == b"Secret message!"
        print("Roundtrip encryption/decryption successful.")

    except Exception as e:
        print("Error during authorized test:", e)

def test_unauthorized_role():
    print("Testing unauthorized role (analyst)...")
    try:
        get_key("analyst")
        print("Unauthorized role was incorrectly granted access.")
    except PermissionError:
        print("Unauthorized role correctly denied access.")

if __name__ == "__main__":
    test_generate_and_encrypt()
    test_unauthorized_role()
