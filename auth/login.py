# auth/login.py
from flask import request, jsonify
import bcrypt
from datetime import datetime
from database.db import db
from auth.middleware import create_session, delete_user_sessions

def login_routes(app):
    
    @app.route('/api/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
            
            # Find user
            user = db.users.find_one({'username': username})
            if not user:
                # Log failed attempt
                db.audit_logs.insert_one({
                    'action': 'LOGIN_FAILED',
                    'username': username,
                    'status': 'failure',
                    'timestamp': datetime.utcnow()
                })
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                db.audit_logs.insert_one({
                    'action': 'LOGIN_FAILED',
                    'username': username,
                    'status': 'failure',
                    'timestamp': datetime.utcnow()
                })
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Delete existing sessions and create new one
            delete_user_sessions(username)
            token = create_session(username)
            
            # Log successful login
            db.audit_logs.insert_one({
                'action': 'USER_LOGIN',
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
    
    @app.route('/api/logout', methods=['POST'])
    def logout():
        try:
            auth_header = request.headers.get('Authorization', '')
            token = auth_header.replace('Bearer ', '')
            
            if token:
                session = db.sessions.find_one({'token': token})
                if session:
                    username = session.get('username')
                    db.sessions.delete_one({'token': token})
                    
                    db.audit_logs.insert_one({
                        'action': 'USER_LOGOUT',
                        'username': username,
                        'status': 'info',
                        'timestamp': datetime.utcnow()
                    })
            
            return jsonify({'success': True}), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/verify', methods=['GET'])
    def verify():
        try:
            auth_header = request.headers.get('Authorization', '')
            token = auth_header.replace('Bearer ', '')
            
            if not token:
                return jsonify({'valid': False}), 401
            
            session = db.sessions.find_one({
                'token': token,
                'expires': {'$gt': datetime.utcnow()}
            })
            
            if not session:
                return jsonify({'valid': False}), 401
            
            return jsonify({
                'valid': True,
                'username': session['username']
            }), 200
            
        except Exception as e:
            return jsonify({'valid': False}), 401