# routes/ehr.py

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import EhrFile, User
import requests, base64, hashlib
from flask import current_app
import uuid, io, os
import sys
from datetime import datetime
import json
import gc

# Add path để import abe_core từ root project
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
from System.Backend.api_gateway.abe_core import ABECore
from charm.core.engine.util import objectToBytes, bytesToObject
import uuid, io, base64, hashlib, os

ehr_bp = Blueprint('ehr', __name__, url_prefix='/api/ehr')

# Local file storage path
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize ABE Core
abe = ABECore()

# TA Client - chỉ gọi TA service cho key management
class TAClient:
    @staticmethod
    def keygen(attributes):
        """Call TA service để tạo secret key"""
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/keygen",
            json={"attributes": attributes},
            headers={"Authorization": f"Bearer {current_app.config['TA_API_TOKEN']}"},
            verify=False
        )
        res.raise_for_status()
        return base64.b64decode(res.json()['sk'])
    
    @staticmethod
    def get_public_key():
        """Get public key từ TA service"""
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_public_key",
            headers={"Authorization": f"Bearer {current_app.config['TA_API_TOKEN']}"},
            verify=False
        )
        res.raise_for_status()
        return res.json()['public_key']

    @staticmethod
    def store_ctdk(record_id, ctdk):
        """Store encrypted data key tại TA"""
        sig = hashlib.sha512(ctdk).digest()
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/store_ctdk",
            json={
                "record_id": record_id,
                "ctdk": base64.b64encode(ctdk).decode(),
                "sig": base64.b64encode(sig).decode()
            },
            headers={"Authorization": f"Bearer {current_app.config['TA_API_TOKEN']}"},
            verify=False
        )
        res.raise_for_status()

    @staticmethod
    def get_ctdk(record_id):
        """Retrieve encrypted data key từ TA"""
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_ctdk/{record_id}",
            headers={"Authorization": f"Bearer {current_app.config['TA_API_TOKEN']}"},
            verify=False
        )
        res.raise_for_status()
        data = res.json()
        return base64.b64decode(data['ctdk'])

@ehr_bp.route('/keygen', methods=['POST'])
#@jwt_required()
def keygen():
    """Generate secret key for user based on their attributes"""
    uid = 1
    
    attributes = request.json.get('attributes', [])
    if not attributes:
        return jsonify({"msg": "Attributes required"}), 400
    
    try:
        # Call TA service to generate secret key
        sk_bytes = TAClient.keygen(attributes)
        
        return jsonify({
            "secret_key": base64.b64encode(sk_bytes).decode(),
            "attributes": attributes,
            "user_id": uid,
            "timestamp": datetime.now().isoformat(),
            "message": "SECRET KEY GENERATED - SAVE THIS SECURELY!",
            "warning": "⚠️ Server will NOT store this key. If lost, your encrypted files become unrecoverable.",
            "instructions": {
                "save_as": f"user_{uid}_secret_key.json",
                "action": "Save this entire JSON response to your local device",
                "backup": "Create multiple copies in secure locations",
                "never_share": "This key grants access to your encrypted data"
            }
        }), 200
        
        # ✅ THÊM: Clear secret key từ memory
        del sk_bytes
        import gc
        gc.collect()
        
    except Exception as e:
        return jsonify({"msg": f"Key generation failed: {str(e)}"}), 500

@ehr_bp.route('/upload', methods=['POST'])
#@jwt_required()
def upload():
    uid = 1
    file = request.files.get('file')
    policy = request.form.get('policy')
    
    if not file or not policy:
        return jsonify({"msg": "file and policy required"}), 400

    data = file.read()
    record_id = str(uuid.uuid4())

    try:
        # 1. ✅ SỬA: Get public key với caching
        print("🔍 Step 1: Getting public key...")
        try:
            pk_base64 = PublicKeyManager.get_public_key()
            print(f"✅ Got public key, length: {len(pk_base64)}")
        except Exception as e:
            print(f"❌ Failed to get public key: {e}")
            return jsonify({"msg": f"Failed to get public key: {str(e)}"}), 500
        
        # 2. DEBUG: Test public key deserialization
        print("🔍 Step 2: Deserializing public key...")
        try:
            pk_bytes = base64.b64decode(pk_base64)
            print(f"✅ Base64 decoded, length: {len(pk_bytes)}")
            pk = bytesToObject(pk_bytes, abe.group)
            print("✅ Public key deserialized successfully")
        except Exception as e:
            print(f"❌ Failed to deserialize public key: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"msg": f"Public key deserialize failed: {str(e)}"}), 500
        
        # 3. DEBUG: Ensure data is bytes
        print("🔍 Step 3: Preparing data...")
        if isinstance(data, str):
            print("⚠️ Data is string, converting to bytes")
            data = data.encode('utf-8')
        print(f"✅ Final data type: {type(data)}, length: {len(data)}")
        
        # 4. DEBUG: Test encryption
        print("🔍 Step 4: Starting encryption...")
        try:
            ciphertext = abe.encrypt(pk, data, policy)
            print("✅ Encryption successful")
            print(f"🔍 Ciphertext type: {type(ciphertext)}")
            print(f"🔍 Ciphertext keys: {ciphertext.keys() if isinstance(ciphertext, dict) else 'Not a dict'}")
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"msg": f"Encryption failed: {str(e)}"}), 500
        
        # 5. DEBUG: Serialize ciphertext để lưu trữ (SỬA CÁCH NÀY)
        print("🔍 Step 5: Serializing ciphertext...")
        try:
            # Serialize từng phần riêng biệt
            abe_key_bytes = objectToBytes(ciphertext['abe_key'], abe.group)
            iv_bytes = ciphertext['iv']  # IV đã là bytes
            data_bytes = ciphertext['data']  # Encrypted data đã là bytes
            
            # Tạo structure để lưu trữ
            import struct
            encrypted_data = struct.pack(
                f'!I{len(abe_key_bytes)}sI{len(iv_bytes)}sI{len(data_bytes)}s',
                len(abe_key_bytes), abe_key_bytes,
                len(iv_bytes), iv_bytes,  
                len(data_bytes), data_bytes
            )
            
            print(f"✅ Serialization successful, length: {len(encrypted_data)}")
        except Exception as e:
            print(f"❌ Serialization failed: {e}")
            return jsonify({"msg": f"Serialization failed: {str(e)}"}), 500
        
        # 6. Store CTdk (chỉ abe_key part)
        print("🔍 Step 6: Storing CTdk...")
        try:
            ctdk_part = objectToBytes(ciphertext['abe_key'], abe.group)
            TAClient.store_ctdk(record_id, ctdk_part)
            print("✅ CTdk stored successfully")
        except Exception as e:
            print(f"❌ Store CTdk failed: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"msg": f"Store CTdk failed: {str(e)}"}), 500
        
        # 7. Save file and metadata
        print("🔍 Step 7: Saving to disk...")
        file_path = os.path.join(UPLOAD_FOLDER, f"{record_id}.enc")
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
            
        
        ef = EhrFile(
            record_id=record_id,
            filename=file.filename,
            s3_key=file_path,
            policy=policy,
            owner_id=uid
        )
        db.session.add(ef)
        db.session.commit()
        print("✅ Upload completed successfully")
        
        return jsonify({
            "record_id": record_id,
            "message": "File uploaded and encrypted successfully"
        }), 201


    except Exception as e:
        print(f"❌ Upload failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"msg": f"Encryption failed: {str(e)}"}), 500

@ehr_bp.route('/download/<record_id>', methods=['POST'])
#@jwt_required()
def download(record_id):
    uid = 1
    
    try:
        # 1. Fetch metadata
        ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
        if ef.owner_id != uid:
            return jsonify({"msg": "Access denied - not file owner"}), 403

        # ✅ SỬA: Handle multiple secret key input methods
        sk_b64 = None
        
        # Method 1: JSON payload
        if request.is_json and 'secret_key' in request.json:
            sk_b64 = request.json['secret_key']
            print("🔍 Secret key from JSON payload")
        
        # Method 2: File upload (existing)
        elif 'sk_file' in request.files:
            sk_file = request.files['sk_file']
            sk_content = sk_file.read().decode('utf-8')
            try:
                # Try parse as JSON first
                import json
                key_data = json.loads(sk_content)
                sk_b64 = key_data['secret_key']
                print("🔍 Secret key from JSON file")
            except:
                # Fallback to raw base64
                sk_b64 = sk_content.strip()
                print("🔍 Secret key from raw file")
        
        # Method 3: Form data
        elif 'secret_key' in request.form:
            sk_b64 = request.form['secret_key']
            print("🔍 Secret key from form data")
        
        if not sk_b64:
            return jsonify({
                "msg": "Secret key required for decryption",
                "methods": [
                    "JSON: {'secret_key': 'base64_encoded_key'}",
                    "File upload: sk_file parameter",
                    "Form data: secret_key parameter"
                ],
                "example": {
                    "curl_json": f"curl -X POST /download/{record_id} -H 'Content-Type: application/json' -d '{{\"secret_key\": \"your_key_here\"}}'",
                    "curl_file": f"curl -X POST /download/{record_id} -F 'sk_file=@your_key_file.json'",
                    "curl_form": f"curl -X POST /download/{record_id} -F 'secret_key=your_key_here'"
                }
            }), 400

        # 2. ✅ SỬA: Load public key với caching
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        # 3. Deserialize secret key từ client
        try:
            sk_bytes = base64.b64decode(sk_b64)
            sk = abe.deserialize_key(sk_bytes)
            print("✅ Secret key deserialized successfully")
        except Exception as e:
            return jsonify({"msg": f"Invalid secret key format: {str(e)}"}), 400
        
        # 4. Đọc encrypted data và deserialize
        with open(ef.s3_key, 'rb') as f:
            encrypted_data = f.read()
        
        # 5. Deserialize từ custom format
        import struct
        
        # Read abe_key
        abe_key_len = struct.unpack('!I', encrypted_data[:4])[0]
        abe_key_bytes = encrypted_data[4:4+abe_key_len]
        abe_key = bytesToObject(abe_key_bytes, abe.group)
        
        # Read IV
        offset = 4 + abe_key_len
        iv_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
        iv = encrypted_data[offset+4:offset+4+iv_len]
        
        # Read encrypted data
        offset = offset + 4 + iv_len
        data_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
        data = encrypted_data[offset+4:offset+4+data_len]
        
        # Reconstruct ciphertext
        ciphertext = {
            'abe_key': abe_key,
            'iv': iv,
            'data': data
        }
        
        # 7. Decrypt với ABE Core
        plaintext = abe.decrypt(pk, sk, ciphertext)
        
        # ✅ THÊM: Clear sensitive data from memory
        del sk_bytes, sk, sk_b64
        import gc
        gc.collect()
        
        if plaintext is None:
            return jsonify({
                "msg": "Decryption failed - Access denied",
                "reason": "Your attributes don't satisfy the file's access policy",
                "policy": ef.policy
            }), 403

        # 8. Return file
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=ef.filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        # ✅ THÊM: Clear sensitive data even on error
        for var in ['sk_bytes', 'sk', 'sk_b64']:
            if var in locals():
                del locals()[var]
        import gc
        gc.collect()
        
        print(f"❌ Download failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"msg": f"Decryption failed: {str(e)}"}), 500

@ehr_bp.route('/files', methods=['GET'])
#@jwt_required()
def list_files():
    """List all files owned by current user"""
    #uid = get_jwt_identity()
    uid = 1
    files = EhrFile.query.filter_by(owner_id=uid).all()
    
    return jsonify({
        "files": [{
            "record_id": f.record_id,
            "filename": f.filename,
            "policy": f.policy,
            "created_at": f.created_at.isoformat() if hasattr(f, 'created_at') else None
        } for f in files]
    }), 200

@ehr_bp.route('/delete/<record_id>', methods=['DELETE'])
#@jwt_required()
def delete_file(record_id):
    """Delete encrypted file and metadata"""
    #uid = get_jwt_identity()
    uid = 1
    ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
    if ef.owner_id != uid:
        return jsonify({"msg": "Access denied"}), 403
    
    try:
        # Delete encrypted file
        if os.path.exists(ef.s3_key):
            os.remove(ef.s3_key)
        
        # Delete metadata
        db.session.delete(ef)
        db.session.commit()
        
        return jsonify({"msg": "File deleted successfully"}), 200
        
    except Exception as e:
        return jsonify({"msg": f"Delete failed: {str(e)}"}), 500

@ehr_bp.route('/validate-key', methods=['POST'])
def validate_secret_key():
    """Validate secret key format without storing it"""
    try:
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"valid": False, "msg": "Secret key required"}), 400
        
        # Try to deserialize
        sk_bytes = base64.b64decode(sk_b64)
        sk = abe.deserialize_key(sk_bytes)
        
        # Clear from memory immediately
        del sk_bytes, sk, sk_b64
        import gc
        gc.collect()
        
        return jsonify({
            "valid": True,
            "msg": "Secret key format is valid"
        }), 200
        
    except Exception as e:
        return jsonify({
            "valid": False,
            "msg": f"Invalid secret key: {str(e)}"
        }), 400

@ehr_bp.route('/key-info', methods=['POST'])
def get_key_info():
    """Get information about secret key without storing it"""
    try:
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"msg": "Secret key required"}), 400
        
        sk_bytes = base64.b64decode(sk_b64)
        
        # Clear from memory
        del sk_bytes, sk_b64
        import gc
        gc.collect()
        
        return jsonify({
            "key_size_bytes": len(base64.b64decode(request.json.get('secret_key'))),
            "format": "Base64 encoded CP-ABE secret key",
            "usage": "Use this key to decrypt files you have access to"
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Invalid key: {str(e)}"}), 400

# Thêm constants
PUBLIC_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys', 'public_key.json')
PUBLIC_KEY_CACHE_TIME = 3600  # 1 hour cache

# Tạo thư mục keys
KEYS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
os.makedirs(KEYS_FOLDER, exist_ok=True)

@ehr_bp.route('/public-key/refresh', methods=['POST'])
def refresh_public_key():
    """Force refresh public key từ TA"""
    try:
        # Delete cached key
        if os.path.exists(PUBLIC_KEY_FILE):
            os.remove(PUBLIC_KEY_FILE)
        
        # Fetch fresh key
        pk_base64 = TAClient.get_public_key_direct()
        PublicKeyManager.save_public_key(pk_base64)
        
        return jsonify({
            "message": "Public key refreshed successfully",
            "key_preview": f"{pk_base64[:50]}...",
            "cached_at": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Failed to refresh public key: {str(e)}"}), 500

@ehr_bp.route('/public-key/status', methods=['GET'])
def public_key_status():
    """Check public key cache status"""
    try:
        if not os.path.exists(PUBLIC_KEY_FILE):
            return jsonify({
                "cached": False,
                "message": "No cached public key found"
            }), 200
        
        with open(PUBLIC_KEY_FILE, 'r') as f:
            key_data = json.load(f)
        
        is_expired = datetime.now().timestamp() > key_data.get('expires_at', 0)
        
        return jsonify({
            "cached": True,
            "cached_at": key_data.get('cached_at'),
            "expires_at": datetime.fromtimestamp(key_data.get('expires_at', 0)).isoformat(),
            "expired": is_expired,
            "key_preview": f"{key_data['public_key'][:50]}...",
            "cache_age_seconds": int(datetime.now().timestamp() - key_data.get('timestamp', 0))
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Failed to check key status: {str(e)}"}), 500

@ehr_bp.route('/public-key/get', methods=['GET'])
def get_public_key_local():
    """Get public key (from cache or TA)"""
    try:
        pk_base64 = PublicKeyManager.get_public_key()
        
        return jsonify({
            "public_key": pk_base64,
            "message": "Public key retrieved successfully"
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Failed to get public key: {str(e)}"}), 500

class PublicKeyManager:
    @staticmethod
    def save_public_key(pk_base64):
        """Lưu public key vào file với timestamp"""
        key_data = {
            "public_key": pk_base64,
            "timestamp": datetime.now().timestamp(),
            "cached_at": datetime.now().isoformat(),
            "expires_at": (datetime.now().timestamp() + PUBLIC_KEY_CACHE_TIME)
        }
        
        os.makedirs(os.path.dirname(PUBLIC_KEY_FILE), exist_ok=True)
        with open(PUBLIC_KEY_FILE, 'w') as f:
            json.dump(key_data, f, indent=2)
        
        print(f"✅ Public key cached to {PUBLIC_KEY_FILE}")
    
    @staticmethod
    def load_cached_public_key():
        """Load public key từ cache nếu còn valid"""
        try:
            if not os.path.exists(PUBLIC_KEY_FILE):
                return None
            
            with open(PUBLIC_KEY_FILE, 'r') as f:
                key_data = json.load(f)
            
            # Kiểm tra expiry
            if datetime.now().timestamp() > key_data.get('expires_at', 0):
                print("⚠️ Cached public key expired")
                return None
            
            print("✅ Using cached public key")
            return key_data['public_key']
            
        except Exception as e:
            print(f"⚠️ Failed to load cached public key: {e}")
            return None
    
    @staticmethod
    def get_public_key():
        """Get public key với caching mechanism"""
        # Try cache first
        cached_pk = PublicKeyManager.load_cached_public_key()
        if cached_pk:
            return cached_pk
        
        # Fetch từ TA nếu cache miss
        print("🔍 Fetching public key from TA...")
        try:
            pk_base64 = TAClient.get_public_key()
            
            # Cache for future use
            PublicKeyManager.save_public_key(pk_base64)
            
            return pk_base64
            
        except Exception as e:
            print(f"❌ Failed to fetch public key from TA: {e}")
            raise e


