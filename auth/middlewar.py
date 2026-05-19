# auth/middleware.py
from functools import wraps
from flask import request, jsonify
import uuid
from datetime import datetime, timedelta
from database.db import db
from config import Config

def create_session(username):
    """Create a new session for user"""
    token = str(uuid.uuid4())
    session = {
        'token': token,
        'username': username,
        'created_at': datetime.utcnow(),
        'expires': datetime.utcnow() + timedelta(seconds=Config.SESSION_TIMEOUT)
    }
    db.sessions.insert_one(session)
    return token

def delete_user_sessions(username):
    """Delete all sessions for a user"""
    db.sessions.delete_many({'username': username})

def get_user_from_token(token):
    """Get user from token"""
    session = db.sessions.find_one({
        'token': token,
        'expires': {'$gt': datetime.utcnow()}
    })
    return session.get('username') if session else None

def token_required(f):
    """Decorator to require valid token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Token required'}), 401
        
        username = get_user_from_token(token)
        if not username:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.username = username
        request.token = token
        return f(*args, **kwargs)
    
    return decorated