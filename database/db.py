# database/db.py
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB Connection
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = os.getenv('DB_NAME', 'secure_share')

class Database:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.client = MongoClient(MONGO_URI)
            cls._instance.db = cls._instance.client[DB_NAME]
            cls._instance._init_collections()
        return cls._instance
    
    def _init_collections(self):
        """Initialize collections and indexes"""
        # Users collection
        self.users = self.db['users']
        self.users.create_index('username', unique=True)
        
        # Files collection
        self.files = self.db['files']
        self.files.create_index('fileId', unique=True)
        self.files.create_index('owner')
        self.files.create_index('shareToken')
        
        # Sessions collection
        self.sessions = self.db['sessions']
        self.sessions.create_index('token', unique=True)
        self.sessions.create_index('expires', expireAfterSeconds=0)
        
        # Audit logs collection
        self.audit_logs = self.db['audit_logs']
        self.audit_logs.create_index('timestamp')
        self.audit_logs.create_index('username')
    
    def get_collection(self, name):
        return self.db[name]

# Create global database instance
db = Database()