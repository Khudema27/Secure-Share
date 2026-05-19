# encryption/encrypt.py
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from config import Config
import base64

def derive_key(password: bytes, salt: bytes, iterations: int = Config.PBKDF2_ITERATIONS):
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(data: bytes, password: bytes = None):
    """Encrypt data using AES-256-GCM"""
    if password is None:
        password = b'vaultx-secure-master-key-2026'
    
    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # Derive key
    key = derive_key(password, salt)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    return {
        'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
        'iv': list(iv),
        'salt': list(salt),
        'tag': list(encryptor.tag)
    }

def encrypt_file_from_buffer(file_buffer, password=None):
    """Encrypt file buffer"""
    return encrypt_file(file_buffer, password)