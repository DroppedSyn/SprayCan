from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a secret key from the passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# --- Encrypting a file ---

def encrypt_data(data):
    pass

passphrase = input("Enter passphrase: ")
# Salt should be random and saved along with the file
salt = os.urandom(16)

key = derive_key(passphrase, salt)
cipher = Fernet(key)

# Read the file
with open('myfile.txt', 'rb') as f:
    data = f.read()

encrypted_data = cipher.encrypt(data)

# Save salt + encrypted data
with open('myfile.txt.enc', 'wb') as f:
    f.write(salt + encrypted_data)

# --- Decrypting a file ---
passphrase = input("Enter passphrase: ")

with open('myfile.txt.enc', 'rb') as f:
    salt = f.read(16)
    encrypted_data = f.read()

key = derive_key(passphrase, salt)
cipher = Fernet(key)

decrypted_data = cipher.decrypt(encrypted_data)

with open('myfile.txt', 'wb') as f:
    f.write(decrypted_data)