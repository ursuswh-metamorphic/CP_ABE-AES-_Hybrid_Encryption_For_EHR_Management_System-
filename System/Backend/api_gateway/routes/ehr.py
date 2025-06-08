# routes/ehr.py

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import EhrFile, User
import requests, base64, hashlib
from flask import current_app
import uuid, io, os
import sys

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
    #uid = get_jwt_identity()
    uid = 1
    
    # Get user attributes from request or database
    attributes = request.json.get('attributes', [])
    if not attributes:
        return jsonify({"msg": "Attributes required"}), 400
    
    try:
        # Call TA service to generate secret key
        sk_bytes = TAClient.keygen(attributes)
        
        # Return secret key to client
        return jsonify({
            "secret_key": base64.b64encode(sk_bytes).decode(),
            "attributes": attributes,
            "message": "Secret key generated successfully"
        }), 200
        
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

    # DEBUG: Kiểm tra file input
    data = file.read()
    print(f"🔍 Raw file data type: {type(data)}")
    print(f"🔍 Raw file data length: {len(data)}")
    print(f"🔍 Raw file data sample: {data[:50]}")  # First 50 bytes
    
    record_id = str(uuid.uuid4())

    try:
        # 1. DEBUG: Test public key retrieval
        print("🔍 Step 1: Getting public key from TA...")
        try:
            pk_base64 = TAClient.get_public_key()
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
    
    # 1. Fetch metadata
    ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
    if ef.owner_id != uid:
        return jsonify({"msg": "Access denied - not file owner"}), 403

    # 2. Client phải gửi secret key
    if 'sk_file' not in request.files:
        return jsonify({"msg": "Missing secret key file"}), 400
    
    sk_file = request.files['sk_file']
    sk_bytes = sk_file.read()  # ← Đây cũng là bytes

    try:
        # 3. Load public key
        pk_base64 = TAClient.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        # 4. Deserialize secret key từ client
        sk = abe.deserialize_key(base64.b64decode(sk_bytes))
        
        # 5. Đọc encrypted data và deserialize
        with open(ef.s3_key, 'rb') as f:
            encrypted_data = f.read()
        
        # 6. Deserialize từ custom format
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
        
        if plaintext is None:
            return jsonify({"msg": "Decrypt failed - insufficient privileges"}), 403

        # 8. Return file (plaintext đã là bytes)
        return send_file(
            io.BytesIO(plaintext),  # ← plaintext là bytes
            as_attachment=True,
            download_name=ef.filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
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
