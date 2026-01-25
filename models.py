from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False) # Signing Key (ECDSA/Ed25519)
    encryption_public_key_pem = db.Column(db.Text, nullable=True) # Encryption Key (RSA-OAEP)
    storage_used = db.Column(db.Integer, default=0) # Bytes used
    storage_quota = db.Column(db.Integer, default=524288000) # 500MB in bytes
    is_admin = db.Column(db.Boolean, default=False)
    
    # Suspension fields
    is_suspended = db.Column(db.Boolean, default=False)
    suspended_at = db.Column(db.DateTime, nullable=True)
    
    # 2FA fields
    totp_secret = db.Column(db.String(32), nullable=True) # Base32 encoded secret
    totp_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text, nullable=True) # JSON array of backup codes
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Session tracking
    device_info = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True) # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('sessions', lazy=True))

class FileMetadata(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Cryptographic metadata (For the OWNER)
    encrypted_key = db.Column(db.Text, nullable=False) 
    iv = db.Column(db.Text, nullable=False) 
    
    # Storage reference
    storage_path = db.Column(db.String(512), nullable=True) # Valid for files, None for folders
    file_size = db.Column(db.Integer, default=0) # File size in bytes
    
    # Folder Support
    is_folder = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('file_metadata.id'), nullable=True)
    
    # Soft delete support
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    children = db.relationship('FileMetadata', backref=db.backref('parent', remote_side=[id]), lazy=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    owner = db.relationship('User', backref=db.backref('files', lazy=True))
    shares = db.relationship('FileShare', backref='file', lazy=True)

    def __repr__(self):
        return f'<File {self.filename}>'

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), db.ForeignKey('file_metadata.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The file key, encrypted with the RECIPIENT'S public key
    encrypted_key = db.Column(db.Text, nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    recipient = db.relationship('User', backref=db.backref('shared_files', lazy=True))

class PublicShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), db.ForeignKey('file_metadata.id'), nullable=False)
    token = db.Column(db.String(36), unique=True, nullable=False) # UUID
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Access Control
    access_count = db.Column(db.Integer, default=0)
    max_access = db.Column(db.Integer, nullable=True) # If set, link invalid after this many uses

    file = db.relationship('FileMetadata')
