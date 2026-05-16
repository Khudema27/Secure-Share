# encryption/decrypt.py
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from encryption.encrypt import derive_key
from config import Config

def decrypt_file(encrypted_data_b64: str, iv: list, salt: list, tag: list, password: bytes = None):
    """Decrypt data using AES-256-GCM"""
    if password is None:
        password = b'vaultx-secure-master-key-2026'
    
    # Decode data
    encrypted_data = base64.b64decode(encrypted_data_b64)
    iv_bytes = bytes(iv)
    salt_bytes = bytes(salt)
    tag_bytes = bytes(tag)
    
    # Derive key
    key = derive_key(password, salt_bytes)
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv_bytes, tag_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    return decrypted_data