# auth/register.py
from flask import request, jsonify
import bcrypt
import uuid
from datetime import datetime, timedelta
from database.db import db
from auth.middleware import create_session

def register_routes(app):
    
    @app.route('/api/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            # Validation
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
            
            if len(username) < 3:
                return jsonify({'error': 'Username must be at least 3 characters'}), 400
            
            if len(password) < 4:
                return jsonify({'error': 'Password must be at least 4 characters'}), 400
            
            # Check if user exists
            existing_user = db.users.find_one({'username': username})
            if existing_user:
                return jsonify({'error': 'Username already exists'}), 400
            
            # Hash password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Create user
            user = {
                'username': username,
                'password': hashed_password.decode('utf-8'),
                'created_at': datetime.utcnow(),
                'active': True
            }
            
            db.users.insert_one(user)
            
            # Create session
            token = create_session(username)
            
            # Log audit
            db.audit_logs.insert_one({
                'action': 'ACCOUNT_CREATED',
                'username': username,
                'status': 'success',
                'timestamp': datetime.utcnow()
            })
            
            return jsonify({
                'success': True,
                'token': token,
                'username': username
            }), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500