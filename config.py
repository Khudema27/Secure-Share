# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # MongoDB
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    DB_NAME = os.getenv('DB_NAME', 'secure_share')
    
    # Security Keys (should be in .env file in production)
    SECRET_KEY = os.getenv('SECRET_KEY', 'a8f9d2k1m4x7p0q5z9w3')
    JWT_SECRET = os.getenv('JWT_SECRET', 'myverysecurejwtsecret123')
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', b'guPwEvEiIpAXnVqFGTgLSOWQaqdLfXAbJe-qTul8I78=')
    
    # File upload
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max
    
    # Session
    SESSION_TIMEOUT = 3600  # 1 hour in seconds
    
    # Encryption
    PBKDF2_ITERATIONS = 140000