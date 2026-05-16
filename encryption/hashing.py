# encryption/hashing.py
import hashlib

def hash_data(data: bytes) -> str:
    """Generate SHA-384 hash of data"""
    return hashlib.sha384(data).hexdigest()

def verify_hash(data: bytes, expected_hash: str) -> bool:
    """Verify data against hash"""
    return hash_data(data) == expected_hash