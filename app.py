# app.py
from flask import Flask, send_from_directory
from flask_cors import CORS
import os
from config import Config
from database.db import db
from auth.register import register_routes
from auth.login import login_routes
from auth.middleware import token_required
from encryption.encrypt import encrypt_file_from_buffer
from encryption.decrypt import decrypt_file
from encryption.hashing import hash_data
from datetime import datetime
import uuid

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object(Config)
CORS(app)

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.ENCRYPTED_FOLDER, exist_ok=True)

# Register routes
register_routes(app)
login_routes(app)

# File routes
@app.route('/api/files', methods=['GET'])
@token_required
def get_files():
    try:
        files = list(db.files.find(
            {'owner': request.username},
            {'_id': 0}
        ).sort('uploaded_at', -1))
        
        return {'files': files}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file():
    try:
        data = request.get_json()
        
        file_id = f"f_{datetime.utcnow().timestamp()}_{str(uuid.uuid4())[:8]}"
        
        # Store encrypted data in MongoDB
        file_doc = {
            'fileId': file_id,
            'name': data['name'],
            'size': data['size'],
            'unit': data['unit'],
            'owner': request.username,
            'encryptedData': data['encryptedData'],
            'iv': data['iv'],
            'salt': data['salt'],
            'hash': data['hash'],
            'shared': False,
            'shareToken': None,
            'modified': data['modified'],
            'downloadCount': 0,
            'uploaded_at': datetime.utcnow()
        }
        
        db.files.insert_one(file_doc)
        
        # Log audit
        db.audit_logs.insert_one({
            'action': 'FILE_UPLOADED',
            'username': request.username,
            'status': 'success',
            'timestamp': datetime.utcnow()
        })
        
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/file/<file_id>', methods=['GET'])
@token_required
def get_file(file_id):
    try:
        file = db.files.find_one(
            {'fileId': file_id, 'owner': request.username},
            {'_id': 0}
        )
        
        if not file:
            return {'error': 'File not found'}, 404
        
        return file, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/file/<file_id>', methods=['DELETE'])
@token_required
def delete_file(file_id):
    try:
        result = db.files.delete_one({'fileId': file_id, 'owner': request.username})
        
        if result.deleted_count == 0:
            return {'error': 'File not found'}, 404
        
        db.audit_logs.insert_one({
            'action': 'FILE_DELETED',
            'username': request.username,
            'status': 'success',
            'timestamp': datetime.utcnow()
        })
        
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/share/<file_id>', methods=['POST'])
@token_required
def create_share(file_id):
    try:
        share_token = f"share_{str(uuid.uuid4())}"
        
        result = db.files.update_one(
            {'fileId': file_id, 'owner': request.username},
            {'$set': {'shared': True, 'shareToken': share_token}}
        )
        
        if result.modified_count == 0:
            return {'error': 'File not found'}, 404
        
        db.audit_logs.insert_one({
            'action': 'SHARE_CREATED',
            'username': request.username,
            'status': 'success',
            'timestamp': datetime.utcnow()
        })
        
        return {'shareToken': share_token}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/shared/<token>', methods=['GET'])
def get_shared_file(token):
    try:
        file = db.files.find_one(
            {'shareToken': token, 'shared': True},
            {'_id': 0}
        )
        
        if not file:
            return {'error': 'Share link invalid or expired'}, 404
        
        # Increment download count
        db.files.update_one(
            {'fileId': file['fileId']},
            {'$inc': {'downloadCount': 1}}
        )
        
        return file, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/revoke/<file_id>', methods=['POST'])
@token_required
def revoke_share(file_id):
    try:
        result = db.files.update_one(
            {'fileId': file_id, 'owner': request.username},
            {'$set': {'shared': False, 'shareToken': None}}
        )
        
        if result.modified_count == 0:
            return {'error': 'File not found'}, 404
        
        db.audit_logs.insert_one({
            'action': 'SHARE_REVOKED',
            'username': request.username,
            'status': 'success',
            'timestamp': datetime.utcnow()
        })
        
        return {'success': True}, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/audit', methods=['GET'])
@token_required
def get_audit():
    try:
        logs = list(db.audit_logs.find(
            {'username': request.username},
            {'_id': 0}
        ).sort('timestamp', -1).limit(100))
        
        return {'logs': logs}, 200
    except Exception as e:
        return {'error': str(e)}, 500

# Serve frontend
@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    if os.path.exists(f'static/{path}'):
        return send_from_directory('static', path)
    return send_from_directory('templates', 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)