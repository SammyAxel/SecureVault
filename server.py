from flask import Flask, request, jsonify, send_from_directory
import os, secrets, base64, json
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, utils
from models import db, User, FileMetadata, FileShare, PublicShare, Session
from sqlalchemy.orm import joinedload
from functools import wraps
import pyotp
import qrcode
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_folder="frontend")
# Use SQLite for development
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

db.init_app(app)

CHALLENGES = {}  # in-memory: username -> (nonce, expiry_timestamp)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"ok": False, "msg": "Missing or invalid token"}), 401
        
        token = auth_header.split(" ")[1]
        # Optimize: Eager load the user relationship to avoid N+1 queries
        session = Session.query.options(joinedload(Session.user)).filter_by(token=token).first()
        
        if not session or datetime.utcnow() > session.expires_at:
            return jsonify({"ok": False, "msg": "Invalid or expired token"}), 401
            
        # Attach user to request context (simple way for this app)
        request.user = session.user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.user.is_admin:
            return jsonify({"ok": False, "msg": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return send_from_directory(os.path.join(app.root_path, "frontend"), "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(os.path.join(app.root_path, "frontend"), path)

@app.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    username = data.get("username")
    pub_pem = data.get("public_key_pem")
    enc_pub_pem = data.get("encryption_public_key_pem")
    
    if not username or not pub_pem:
        return jsonify({"ok": False, "msg": "username and public_key_pem required"}), 400
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"ok": False, "msg": "username already exists"}), 400
    
    new_user = User(username=username, public_key_pem=pub_pem, encryption_public_key_pem=enc_pub_pem)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"ok": True, "msg": "User created successfully"})

@app.route("/challenge/<username>", methods=["GET"])
def get_challenge(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "msg": "unknown user"}), 404
    
    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.b64encode(challenge).decode()
    CHALLENGES[username] = challenge_b64
    return jsonify({"ok": True, "challenge": challenge_b64})

@app.route("/verify", methods=["POST"])
def verify_signature():
    data = request.get_json()
    username = data.get("username")
    signature_b64 = data.get("signature")
    challenge_b64 = data.get("challenge")
    
    if not username or not signature_b64 or not challenge_b64:
        return jsonify({"ok": False, "msg": "missing fields"}), 400
        
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "msg": "unknown user"}), 404
    
    # Check if user is suspended
    if user.is_suspended:
        return jsonify({"ok": False, "msg": "Account suspended. Please contact administrator."}), 403
        
    expected = CHALLENGES.get(username)
    if expected is None or expected != challenge_b64:
        return jsonify({"ok": False, "msg": "challenge missing or expired"}), 400
        
    # Verify Signature
    pub_pem = user.public_key_pem.encode()
    try:
        pubkey = serialization.load_pem_public_key(pub_pem)
        signature = base64.b64decode(signature_b64)
        challenge = base64.b64decode(challenge_b64)
        
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(signature, challenge)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            if len(signature) == 64:
                r = int.from_bytes(signature[:32], byteorder='big')
                s = int.from_bytes(signature[32:], byteorder='big')
                signature = utils.encode_dss_signature(r, s)
            pubkey.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        else:
            return jsonify({"ok": False, "msg": "unsupported key type"}), 400
    except Exception as e:
        return jsonify({"ok": False, "msg": "verification failed", "error": str(e)}), 400
        
    # 2FA Verification
    if user.totp_enabled:
        totp_code = data.get("totp_code")
        if not totp_code:
            return jsonify({"ok": False, "msg": "2FA required", "2fa_required": True}), 403
        
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code):
             return jsonify({"ok": False, "msg": "Invalid 2FA code"}), 403

    CHALLENGES.pop(username, None)
    
    # Session Logic
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    device_info = user_agent[:255] if user_agent else 'Unknown'

    existing_session = Session.query.filter_by(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent
    ).first()

    if existing_session:
        if existing_session.expires_at > datetime.utcnow():
            existing_session.last_active = datetime.utcnow()
            existing_session.expires_at = datetime.utcnow() + timedelta(hours=24)
            db.session.commit()
            return jsonify({
                "ok": True, 
                "token": existing_session.token, 
                "username": username, 
                "2fa_enabled": user.totp_enabled,
                "is_admin": user.is_admin
            })
        else:
            db.session.delete(existing_session)
            db.session.commit()
    
    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    new_session = Session(
        token=token, 
        user=user, 
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent,
        device_info=device_info,
        last_active=datetime.utcnow()
    )
    db.session.add(new_session)
    db.session.commit()
    
    return jsonify({
        "ok": True, 
        "token": token, 
        "username": username, 
        "2fa_enabled": user.totp_enabled,
        "is_admin": user.is_admin
    })

@app.route("/keys/<username>", methods=["GET"])
def get_key(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "msg": "unknown user"}), 404
    return jsonify({
        "ok": True, 
        "public_key_pem": user.public_key_pem,
        "encryption_public_key_pem": user.encryption_public_key_pem
    })

@app.route("/folders", methods=["POST"])
@require_auth
def create_folder():
    user = request.user
    data = request.get_json()
    name = data.get("name")
    parent_id = data.get("parent_id")
    
    if not name:
        return jsonify({"ok": False, "msg": "Folder name required"}), 400
        
    # Verify parent folder exists and is owned by user
    if parent_id:
        parent_folder = FileMetadata.query.get(parent_id)
        if not parent_folder or parent_folder.owner_id != user.id or not parent_folder.is_folder:
            return jsonify({"ok": False, "msg": "Invalid parent folder"}), 400
            
    new_folder = FileMetadata(
        filename=name,
        owner=user,
        is_folder=True,
        parent_id=parent_id,
        encrypted_key="", # Not used for folders
        iv="", # Not used for folders
        storage_path="" # Not used for folders
    )
    db.session.add(new_folder)
    db.session.commit()
    return jsonify({"ok": True, "folder_id": new_folder.id})

@app.route("/upload", methods=["POST"])
@require_auth
def upload_file():
    user = request.user

    file = request.files.get("file")
    encrypted_key = request.form.get("encrypted_key")
    iv = request.form.get("iv")
    
    if not file or not encrypted_key or not iv:
        return jsonify({"ok": False, "msg": "missing file or metadata"}), 400
        
    parent_id = request.form.get("parent_id")
    if parent_id and parent_id == 'null':
        parent_id = None
        
    # Verify parent folder exists and is owned by user
    if parent_id:
        parent_folder = FileMetadata.query.get(parent_id)
        if not parent_folder or parent_folder.owner_id != user.id or not parent_folder.is_folder:
            return jsonify({"ok": False, "msg": "Invalid parent folder"}), 400
    
    # Read file to get size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    # Check quota
    if user.storage_used + file_size > user.storage_quota:
        remaining = user.storage_quota - user.storage_used
        return jsonify({
            "ok": False, 
            "msg": f"Storage quota exceeded. You have {remaining} bytes remaining.",
            "quota_exceeded": True
        }), 400
        
    # Save file blob
    filename = secrets.token_hex(16) # Random filename on disk
    upload_dir = os.path.join(app.root_path, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, filename)
    file.save(file_path)
    
    # Save metadata
    # ID is auto-generated by default in model, but we can explicit if needed.
    # Let's rely on the default lambda in models.py
    new_file = FileMetadata(
        filename=file.filename, 
        owner=user,
        encrypted_key=encrypted_key,
        iv=iv,
        storage_path=filename,
        file_size=file_size,
        parent_id=parent_id
    )
    db.session.add(new_file)
    
    # Update user's storage usage
    user.storage_used += file_size
    db.session.commit()
    
    return jsonify({"ok": True, "file_id": new_file.id})

@app.route("/share", methods=["POST"])
@require_auth
def share_file():
    user = request.user
    data = request.get_json()
    file_id = data.get("file_id")
    recipient_username = data.get("recipient_username")
    encrypted_key = data.get("encrypted_key") # Key encrypted with Recipient's PubKey (optional for folders)
    
    if not file_id or not recipient_username:
        return jsonify({"ok": False, "msg": "missing fields"}), 400
        
    file_record = FileMetadata.query.get(file_id)
    if not file_record:
        return jsonify({"ok": False, "msg": "file not found"}), 404
        
    # Verify ownership
    if file_record.owner_id != user.id:
        return jsonify({"ok": False, "msg": "access denied"}), 403

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"ok": False, "msg": "recipient not found"}), 404
    
    # Handle folder sharing (recursive)
    if file_record.is_folder:
        return share_folder_recursive(file_record, recipient, user)
    
    # Handle file sharing (requires encrypted_key)
    if not encrypted_key:
        return jsonify({"ok": False, "msg": "encrypted_key required for file sharing"}), 400
        
    # Check if already shared
    existing = FileShare.query.filter_by(file_id=file_id, recipient_id=recipient.id).first()
    if existing:
        return jsonify({"ok": False, "msg": "already shared"}), 400
        
    share = FileShare(
        file=file_record,
        recipient=recipient,
        encrypted_key=encrypted_key
    )
    db.session.add(share)
    db.session.commit()
    
    return jsonify({"ok": True})

def share_folder_recursive(folder, recipient, owner):
    """Recursively share folder and all its contents"""
    # Share the folder itself (folders don't need encrypted_key, use empty string)
    existing_folder_share = FileShare.query.filter_by(file_id=folder.id, recipient_id=recipient.id).first()
    if not existing_folder_share:
        folder_share = FileShare(
            file=folder,
            recipient=recipient,
            encrypted_key=""  # Folders don't have encryption keys (only metadata)
        )
        db.session.add(folder_share)
    
    # Recursively share all children
    children = FileMetadata.query.filter_by(parent_id=folder.id, is_deleted=False).all()
    shared_files = 0
    shared_folders = 0
    
    for child in children:
        # Check if already shared
        existing = FileShare.query.filter_by(file_id=child.id, recipient_id=recipient.id).first()
        if existing:
            continue
            
        if child.is_folder:
            # Recursively share subfolder
            result = share_folder_recursive(child, recipient, owner)
            shared_folders += 1
        else:
            # For files, we need encrypted_key - but since we're sharing a folder,
            # we'll share the file with its current encrypted_key
            # Note: This means recipient can only decrypt if they have the key
            # In a proper implementation, we'd need to re-encrypt with recipient's key
            # For now, we'll share the folder structure and files, but files need proper key sharing
            file_share = FileShare(
                file=child,
                recipient=recipient,
                encrypted_key=child.encrypted_key  # This is encrypted for owner, not recipient
            )
            db.session.add(file_share)
            shared_files += 1
    
    db.session.commit()
    return jsonify({"ok": True, "msg": f"Folder shared. {shared_folders} folders and {shared_files} files shared."})

@app.route("/download/<file_id>", methods=["GET"])
@require_auth
def download_file(file_id):
    user = request.user

    file_record = FileMetadata.query.get(file_id)
    if not file_record:
        return jsonify({"ok": False, "msg": "file not found"}), 404
        
    # Access Control Logic
    encrypted_key_to_return = None
    
    if file_record.owner_id == user.id:
        # Owner access
        encrypted_key_to_return = file_record.encrypted_key
    else:
        # Check if shared
        share = FileShare.query.filter_by(file_id=file_id, recipient_id=user.id).first()
        if share:
            encrypted_key_to_return = share.encrypted_key
        else:
            return jsonify({"ok": False, "msg": "access denied"}), 403
    
    # If it's a folder, we can't download it directly
    if file_record.is_folder:
        return jsonify({"ok": False, "msg": "Cannot download a folder directly"}), 400
        
    upload_dir = os.path.join(app.root_path, "uploads")
    file_path = os.path.join(upload_dir, file_record.storage_path)
    
    if not os.path.exists(file_path):
        return jsonify({"ok": False, "msg": "file missing on disk"}), 500
        
    with open(file_path, "rb") as f:
        file_content = base64.b64encode(f.read()).decode()
        
    return jsonify({
        "ok": True,
        "filename": file_record.filename,
        "encrypted_key": encrypted_key_to_return,
        "iv": file_record.iv,
        "file_content_b64": file_content
    })

@app.route("/files", methods=["GET"])
@require_auth
def list_files():
    user = request.user
    
    # --- Owned Files (Hierarchy Support) ---
    parent_id = request.args.get("parent_id")
    if parent_id == 'null':
        parent_id = None
        
    # Filter by parent_id
    query = FileMetadata.query.filter_by(
        owner_id=user.id, 
        is_deleted=False,
        parent_id=parent_id
    )
    
    files = query.all()
    
    owned_response = []
    for f in files:
        owned_response.append({
            "id": f.id,
            "filename": f.filename,
            "owner": user.username,
            "file_size": f.file_size,
            "created_at": f.created_at.isoformat(),
            "is_folder": f.is_folder
        })
        
    # --- Breadcrumbs ---
    breadcrumbs = []
    if parent_id:
        curr = FileMetadata.query.get(parent_id)
        while curr:
            breadcrumbs.insert(0, {"id": curr.id, "name": curr.filename})
            if curr.parent_id:
                curr = FileMetadata.query.get(curr.parent_id)
            else:
                curr = None

    # --- Shared Files ---
    shared = []
    for s in user.shared_files:
        if not s.file.is_deleted:
            shared.append({
                "id": s.file.id,
                "filename": s.file.filename,
                "owner": s.file.owner.username,
                "file_size": s.file.file_size,
                "created_at": s.created_at.isoformat(),
                "is_folder": s.file.is_folder
            })
        
    return jsonify({"ok": True, "files": owned_response, "shared": shared, "breadcrumbs": breadcrumbs})

@app.route("/files/<file_id>", methods=["DELETE"])
@require_auth
def delete_file(file_id):
    user = request.user
    
    file_record = FileMetadata.query.get(file_id)
    if not file_record:
        return jsonify({"ok": False, "msg": "file not found"}), 404
    
    # Verify ownership
    if file_record.owner_id != user.id:
        return jsonify({"ok": False, "msg": "access denied"}), 403
    
    # Check if already deleted
    if file_record.is_deleted:
        return jsonify({"ok": False, "msg": "file already deleted"}), 400
    
    # Soft delete
    file_record.is_deleted = True
    file_record.deleted_at = datetime.utcnow()
    
    # try:
    #     if os.path.exists(file_path):
    #         os.remove(file_path)
    # except Exception as e:
    #     print(f"Error deleting physical file: {e}")
    
    # Recursive delete logic
    delete_recursive(file_record)
    
    db.session.commit()
    
    return jsonify({"ok": True, "msg": "file deleted successfully"})

def delete_recursive(file_record):
    if file_record.is_folder:
        children = FileMetadata.query.filter_by(parent_id=file_record.id).all()
        for child in children:
            delete_recursive(child)
    
    # Soft delete the item
    file_record.is_deleted = True
    file_record.deleted_at = datetime.utcnow()
    
    # If it's a file, update storage quota and delete physical
    if not file_record.is_folder:
        file_record.owner.storage_used -= file_record.file_size
        if file_record.owner.storage_used < 0:
             file_record.owner.storage_used = 0
             
        upload_dir = os.path.join(app.root_path, "uploads")
        if file_record.storage_path: # Folders have empty storage_path
            file_path = os.path.join(upload_dir, file_record.storage_path)
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Error deleting physical file: {e}")

@app.route("/files/<file_id>/rename", methods=["POST"])
@require_auth
def rename_file(file_id):
    user = request.user
    data = request.get_json()
    new_name = data.get("name")
    
    if not new_name or not new_name.strip():
        return jsonify({"ok": False, "msg": "Name is required"}), 400
    
    file_record = FileMetadata.query.get(file_id)
    if not file_record:
        return jsonify({"ok": False, "msg": "File or folder not found"}), 404
    
    # Verify ownership
    if file_record.owner_id != user.id:
        return jsonify({"ok": False, "msg": "access denied"}), 403
    
    # Check if already deleted
    if file_record.is_deleted:
        return jsonify({"ok": False, "msg": "File or folder is deleted"}), 400
    
    # Update filename
    file_record.filename = new_name.strip()
    db.session.commit()
    
    return jsonify({"ok": True, "msg": "Renamed successfully"})

@app.route("/files/<file_id>/move", methods=["POST"])
@require_auth
def move_file(file_id):
    user = request.user
    data = request.get_json()
    new_parent_id = data.get("parent_id")
    
    if new_parent_id == 'null':
        new_parent_id = None
    
    file_record = FileMetadata.query.get(file_id)
    if not file_record:
        return jsonify({"ok": False, "msg": "file not found"}), 404
    
    # Verify ownership
    if file_record.owner_id != user.id:
        return jsonify({"ok": False, "msg": "access denied"}), 403
    
    # Check if already deleted
    if file_record.is_deleted:
        return jsonify({"ok": False, "msg": "file is deleted"}), 400
    
    # Verify new parent folder exists and is owned by user
    if new_parent_id:
        parent_folder = FileMetadata.query.get(new_parent_id)
        if not parent_folder or parent_folder.owner_id != user.id or not parent_folder.is_folder:
            return jsonify({"ok": False, "msg": "Invalid parent folder"}), 400
        
        # Prevent moving folder into itself or its descendants
        if file_record.is_folder:
            current = parent_folder
            while current:
                if current.id == file_id:
                    return jsonify({"ok": False, "msg": "Cannot move folder into itself or its subfolder"}), 400
                current = current.parent
    
    # Update parent_id
    file_record.parent_id = new_parent_id
    db.session.commit()
    
    return jsonify({"ok": True, "msg": "File moved successfully"})

@app.route("/folders/list", methods=["GET"])
@require_auth
def list_folders():
    user = request.user
    
    # Get all folders owned by user (not deleted)
    folders = FileMetadata.query.filter_by(
        owner_id=user.id,
        is_folder=True,
        is_deleted=False
    ).all()
    
    # Build folder tree structure
    def build_folder_tree(folders_list, parent_id=None, exclude_id=None):
        result = []
        for folder in folders_list:
            if folder.parent_id == parent_id and folder.id != exclude_id:
                folder_data = {
                    "id": folder.id,
                    "name": folder.filename,
                    "parent_id": folder.parent_id,
                    "children": build_folder_tree(folders_list, folder.id, exclude_id)
                }
                result.append(folder_data)
        return result
    
    # Get flat list for simple selection
    flat_list = []
    for folder in folders:
        # Build path name
        path_parts = []
        current = folder
        while current:
            path_parts.insert(0, current.filename)
            if current.parent_id:
                current = FileMetadata.query.get(current.parent_id)
            else:
                current = None
        
        flat_list.append({
            "id": folder.id,
            "name": folder.filename,
            "path": " / ".join(path_parts),
            "parent_id": folder.parent_id
        })
    
    # Also return tree structure
    tree = build_folder_tree(folders)
    
    return jsonify({
        "ok": True,
        "folders": flat_list,
        "tree": tree
    })

@app.route("/quota", methods=["GET"])
@require_auth
def get_quota():
    user = request.user
    percentage = (user.storage_used / user.storage_quota * 100) if user.storage_quota > 0 else 0
    
    return jsonify({
        "ok": True,
        "used": user.storage_used,
        "quota": user.storage_quota,
        "percentage": round(percentage, 2)
    })

@app.route('/share/public', methods=['POST'])
@require_auth
def create_public_link():
    user = request.user
    data = request.get_json()
    file_id = data.get('file_id')
    duration_hours = data.get('duration_hours', 1)
    max_access = data.get('max_access') # Optional: Integer
    
    file_record = FileMetadata.query.get(file_id)
    if not file_record or file_record.owner_id != user.id:
        return jsonify({"ok": False, "msg": "file not found or access denied"}), 403
    
    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=int(duration_hours))
    
    public_share = PublicShare(
        file_id=file_id, 
        token=token, 
        expires_at=expires_at,
        max_access=int(max_access) if max_access else None
    )
    db.session.add(public_share)
    db.session.commit()
    
    return jsonify({"ok": True, "token": token})

@app.route('/public/<token>', methods=['GET'])
def get_public_file(token):
    share = PublicShare.query.filter_by(token=token).first()
    if not share:
        return jsonify({"ok": False, "msg": "Link invalid"}), 404
    
    if datetime.utcnow() > share.expires_at:
        return jsonify({"ok": False, "msg": "Link expired"}), 410
        
    if share.max_access and share.access_count >= share.max_access:
        return jsonify({"ok": False, "msg": "Link usage limit reached"}), 410
        
    # Increment access count
    share.access_count += 1
    db.session.commit()
        
    file = share.file
    return jsonify({
        "ok": True,
        "filename": file.filename,
        "file_content_b64": base64.b64encode(open(os.path.join(app.root_path, "uploads", file.storage_path), "rb").read()).decode(),
        "iv": file.iv
    })

@app.route('/shares/manage', methods=['GET'])
@require_auth
def manage_shares():
    user = request.user
        
    # 1. Public Links owned by user (via files)
    # This query is a bit complex in pure ORM without backref on PublicShare->File->User
    # Let's iterate user files
    public_links = []
    for f in user.files:
        shares = PublicShare.query.filter_by(file_id=f.id).all()
        for s in shares:
            public_links.append({
                "token": s.token,
                "file_id": f.id,
                "filename": f.filename,
                "expires_at": s.expires_at.isoformat(),
                "access_count": s.access_count,
                "max_access": s.max_access
            })
            
    # 2. User Shares (files I shared with others)
    # We need to find FileShares where file.owner == user
    # Again, iterate user files
    user_shares = []
    for f in user.files:
        shares = FileShare.query.filter_by(file_id=f.id).all()
        for s in shares:
            user_shares.append({
                "id": s.id,
                "filename": f.filename,
                "recipient": s.recipient.username,
                "created_at": s.created_at.isoformat()
            })
            
    return jsonify({"ok": True, "public_links": public_links, "user_shares": user_shares})

@app.route('/share/public/<token>', methods=['DELETE'])
@require_auth
def revoke_public_link(token):
    user = request.user
    share = PublicShare.query.filter_by(token=token).first()
    if share and share.file.owner_id == user.id:
        db.session.delete(share)
        db.session.commit()
    return jsonify({"ok": True})

@app.route('/share/user/<int:share_id>', methods=['DELETE'])
@require_auth
def revoke_user_share(share_id):
    user = request.user
    share = FileShare.query.get(share_id)
    if share and share.file.owner_id == user.id:
        db.session.delete(share)
        db.session.commit()
    return jsonify({"ok": True})


@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' blob: data:;"
    return response


# ============= 2FA ENDPOINTS =============

@app.route("/2fa/setup", methods=["GET"])
@require_auth
@limiter.limit("10 per hour")
def setup_2fa():
    user = request.user
    
    # Generate new TOTP secret
    secret = pyotp.random_base32()
    
    # Create provisioning URI for QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name="SecureVault"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Store secret temporarily (will be saved when user enables 2FA)
    user.totp_secret = secret
    db.session.commit()
    
    return jsonify({
        "ok": True,
        "secret": secret,
        "qr_code": f"data:image/png;base64,{img_str}"
    })

@app.route("/2fa/verify", methods=["POST"])
@require_auth
def verify_2fa_code():
    user = request.user
    data = request.get_json()
    code = data.get("code")
    
    if not code or not user.totp_secret:
        return jsonify({"ok": False, "msg": "Invalid request"}), 400
    
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code, valid_window=1):
        return jsonify({"ok": True})
    else:
        return jsonify({"ok": False, "msg": "Invalid code"}), 400

@app.route("/2fa/enable", methods=["POST"])
@require_auth
def enable_2fa():
    user = request.user
    data = request.get_json()
    code = data.get("code")
    
    if not code or not user.totp_secret:
        return jsonify({"ok": False, "msg": "2FA not set up"}), 400
    
    # Verify code before enabling
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "msg": "Invalid code"}), 400
    
    # Generate backup codes
    backup_codes = [secrets.token_hex(4) for _ in range(10)]
    
    user.totp_enabled = True
    user.backup_codes = json.dumps(backup_codes)
    db.session.commit()
    
    return jsonify({"ok": True, "backup_codes": backup_codes})

@app.route("/2fa/disable", methods=["POST"])
@require_auth
def disable_2fa():
    user = request.user
    data = request.get_json()
    code = data.get("code")
    
    if not user.totp_enabled:
        return jsonify({"ok": False, "msg": "2FA not enabled"}), 400
    
    # Verify code before disabling
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "msg": "Invalid code"}), 400
    
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    
    return jsonify({"ok": True})

@app.route("/2fa/status", methods=["GET"])
@require_auth
def get_2fa_status():
    user = request.user
    return jsonify({
        "ok": True,
        "enabled": user.totp_enabled
    })

# ============= SESSION MANAGEMENT ENDPOINTS =============

@app.route("/sessions", methods=["GET"])
@require_auth
def list_sessions():
    user = request.user
    current_token = request.headers.get('Authorization').split(" ")[1]
    
    sessions = []
    for session in user.sessions:
        if datetime.utcnow() < session.expires_at:
            sessions.append({
                "id": session.id,
                "device_info": session.device_info or "Unknown Device",
                "ip_address": session.ip_address or "Unknown",
                "created_at": session.created_at.isoformat(),
                "last_active": session.last_active.isoformat() if session.last_active else session.created_at.isoformat(),
                "is_current": session.token == current_token
            })
    
    return jsonify({"ok": True, "sessions": sessions})

@app.route("/sessions/<int:session_id>", methods=["DELETE"])
@require_auth
def delete_session(session_id):
    user = request.user
    current_token = request.headers.get('Authorization').split(" ")[1]
    
    session = Session.query.get(session_id)
    if not session or session.user_id != user.id:
        return jsonify({"ok": False, "msg": "Session not found"}), 404
    
    # Prevent deleting current session
    if session.token == current_token:
        return jsonify({"ok": False, "msg": "Cannot logout current session"}), 400
    
    db.session.delete(session)
    db.session.commit()
    
    return jsonify({"ok": True})

@app.route("/sessions/all", methods=["DELETE"])
@require_auth
def delete_all_sessions():
    user = request.user
    current_token = request.headers.get('Authorization').split(" ")[1]
    
    # Delete all sessions except current
    deleted_count = 0
    for session in user.sessions:
        if session.token != current_token:
            db.session.delete(session)
            deleted_count += 1
    
    db.session.commit()
    
    return jsonify({"ok": True, "deleted": deleted_count})

# Admin Endpoints
@app.route("/admin/stats", methods=["GET"])
@require_auth
@admin_required
def admin_stats():
    user_count = User.query.count()
    total_storage = db.session.query(db.func.sum(User.storage_used)).scalar() or 0
    active_sessions = Session.query.filter(Session.expires_at > datetime.utcnow()).count()
    
    return jsonify({
        "ok": True,
        "user_count": user_count,
        "total_storage": total_storage,
        "active_sessions": active_sessions
    })

@app.route("/admin/users", methods=["GET"])
@require_auth
@admin_required
def admin_users():
    users = User.query.all()
    user_list = []
    
    for u in users:
        file_count = FileMetadata.query.filter_by(owner_id=u.id).count()
        user_list.append({
            "id": u.id,
            "username": u.username,
            "storage_used": u.storage_used,
            "storage_quota": u.storage_quota,
            "file_count": file_count,
            "is_admin": u.is_admin,
            "is_suspended": u.is_suspended
        })
    
    return jsonify({"ok": True, "users": user_list})

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@require_auth
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "msg": "User not found"}), 404
    
    # Delete all user's sessions first (to avoid foreign key constraint errors)
    sessions = Session.query.filter_by(user_id=user.id).all()
    for session in sessions:
        db.session.delete(session)
    
    # Delete all user's files
    files = FileMetadata.query.filter_by(owner_id=user.id).all()
    for file in files:
        # Delete file from disk
        file_path = os.path.join(app.root_path, "uploads", file.storage_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(file)
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"ok": True, "msg": "User deleted"})

@app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
@require_auth
@admin_required
def promote_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "msg": "User not found"}), 404
    
    user.is_admin = True
    db.session.commit()
    return jsonify({"ok": True, "msg": f"User {user.username} promoted to admin"})

@app.route("/admin/users/<int:user_id>/quota", methods=["POST"])
@require_auth
@admin_required
def adjust_user_quota(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "msg": "User not found"}), 404
    
    data = request.get_json()
    new_quota = data.get("quota")
    
    if not new_quota or not isinstance(new_quota, int):
        return jsonify({"ok": False, "msg": "Invalid quota value"}), 400
    
    user.storage_quota = new_quota
    db.session.commit()
    return jsonify({"ok": True, "msg": f"Quota updated to {new_quota} bytes"})

@app.route("/admin/users/<int:user_id>/suspend", methods=["POST"])
@require_auth
@admin_required
def suspend_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "msg": "User not found"}), 404
    
    if user.is_admin:
        return jsonify({"ok": False, "msg": "Cannot suspend admin users"}), 400
    
    if user.is_suspended:
        return jsonify({"ok": False, "msg": "User already suspended"}), 400
    
    user.is_suspended = True
    user.suspended_at = datetime.utcnow()
    
    # Delete all user's active sessions
    sessions = Session.query.filter_by(user_id=user.id).all()
    for session in sessions:
        db.session.delete(session)
    
    db.session.commit()
    return jsonify({"ok": True, "msg": f"User {user.username} suspended"})

@app.route("/admin/users/<int:user_id>/unsuspend", methods=["POST"])
@require_auth
@admin_required
def unsuspend_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "msg": "User not found"}), 404
    
    if not user.is_suspended:
        return jsonify({"ok": False, "msg": "User is not suspended"}), 400
    
    user.is_suspended = False
    user.suspended_at = None
    db.session.commit()
    return jsonify({"ok": True, "msg": f"User {user.username} unsuspended"})

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP: Allow blob: for previews, unsafe-inline for current frontend structure
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; media-src 'self' blob:; object-src 'none'; frame-src 'self' blob:;"
    return response

if __name__ == "__main__":
    # In production, use gunicorn!
    # app.run(port=5000) 
    app.run(port=5000, debug=False)
