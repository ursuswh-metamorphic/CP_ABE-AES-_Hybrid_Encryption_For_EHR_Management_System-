# routes/ehr.py
from flask import Blueprint, request, jsonify, send_file, current_app, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import EhrFile, User
import requests, base64, hashlib
import uuid, io, os
import sys
from datetime import datetime
import json
import gc
import boto3
import traceback
from botocore.exceptions import ClientError

# AWS S3 config từ biến môi trường
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_REGION = os.environ.get("S3_REGION")
s3_client = boto3.client(
    "s3",
    region_name=S3_REGION,
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
)

# Add path để import abe_core từ root project
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
from System.Backend.api_gateway.abe_core import ABECore
from charm.core.engine.util import objectToBytes, bytesToObject

ehr_bp = Blueprint('ehr', __name__, url_prefix='/api/ehr')

# Initialize ABE Core
abe = ABECore()

# --- TAClient Class (Giữ nguyên) ---
class TAClient:
    @staticmethod
    def keygen(attributes):
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/keygen",
            json={"attributes": attributes},
            verify=False
        )
        res.raise_for_status()
        return base64.b64decode(res.json()['sk'])
    
    @staticmethod
    def get_public_key():
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_public_key",
            verify=False
        )
        res.raise_for_status()
        return res.json()['public_key']

    @staticmethod
    def store_ctdk(record_id, ctdk):
        sig = hashlib.sha512(ctdk).digest()
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/store_ctdk",
            json={
                "record_id": record_id,
                "ctdk": base64.b64encode(ctdk).decode(),
                "sig": base64.b64encode(sig).decode()
            },
            verify=False
        )
        res.raise_for_status()

    @staticmethod
    def get_ctdk(record_id):
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_ctdk/{record_id}",
            verify=False
        )
        res.raise_for_status()
        data = res.json()
        return base64.b64decode(data['ctdk'])

# --- S3 HELPER FUNCTIONS (Giữ nguyên) ---
def upload_to_s3(data: bytes, s3_key: str):
    """Upload data lên S3. Raise Exception nếu thất bại."""
    try:
        current_app.logger.info(f"Uploading to S3: bucket='{S3_BUCKET}', key='{s3_key}'")
        s3_client.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=data)
        current_app.logger.info(f"S3 Upload successful for key: {s3_key}")
    except ClientError as e:
        current_app.logger.error(f"S3 ClientError on upload for key {s3_key}: {e}")
        raise RuntimeError(f"S3 upload failed: {e.response['Error']['Message']}")
    except Exception as e:
        current_app.logger.error(f"Unknown S3 error on upload for key {s3_key}: {e}")
        traceback.print_exc()
        raise RuntimeError(f"An unexpected error occurred during S3 upload: {str(e)}")

def download_from_s3(s3_key: str) -> bytes:
    """Download data từ S3. Raise Exception nếu thất bại."""
    try:
        current_app.logger.info(f"Downloading from S3: bucket='{S3_BUCKET}', key='{s3_key}'")
        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        content = obj["Body"].read()
        current_app.logger.info(f"S3 Download successful for key: {s3_key}")
        return content
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            current_app.logger.error(f"S3 NoSuchKey error on download: Key '{s3_key}' not found.")
            raise FileNotFoundError(f"File with key '{s3_key}' not found in S3.")
        else:
            current_app.logger.error(f"S3 ClientError on download for key {s3_key}: {e}")
            raise RuntimeError(f"S3 download failed: {e.response['Error']['Message']}")
    except Exception as e:
        current_app.logger.error(f"Unknown S3 error on download for key {s3_key}: {e}")
        traceback.print_exc()
        raise RuntimeError(f"An unexpected error occurred during S3 download: {str(e)}")


# --- ROUTES ---

# @ehr_bp.route('/keygen', methods=['POST'])
#@jwt_required()
# def keygen():
#     """Generate secret key for user based on their attributes"""
#     uid = 1
#     attributes = request.json.get('attributes', [])
#     if not attributes:
#         return jsonify({"msg": "Attributes required"}), 400
    
#     try:
#         sk_bytes = TAClient.keygen(attributes)
        
#         response_data = {
#             "secret_key": base64.b64encode(sk_bytes).decode(),
#             "attributes": attributes,
#             "user_id": uid,
#             "timestamp": datetime.now().isoformat(),
#             "message": "SECRET KEY GENERATED - SAVE THIS SECURELY!",
#             "warning": "⚠️ Server will NOT store this key. If lost, your encrypted files become unrecoverable.",
#             "instructions": {
#                 "save_as": f"user_{uid}_secret_key.json",
#                 "action": "Save this entire JSON response to your local device",
#                 "backup": "Create multiple copies in secure locations",
#                 "never_share": "This key grants access to your encrypted data"
#             }
#         }
#         del sk_bytes
#         gc.collect()
#         return jsonify(response_data), 200
        
#     except Exception as e:
#         return jsonify({"msg": f"Key generation failed: {str(e)}"}), 500
# def keygen():
#     """Generate secret key for user based on their attributes"""
#     uid = 1
#     attributes = request.json.get('attributes', [])
#     if not attributes:
#         return jsonify({"msg": "Attributes required"}), 400
    
#     try:
#         # TAClient.keygen() đã trả về một chuỗi bytes đã được mã hóa base64 2 LẦN từ TA.
#         # Chúng ta sẽ không mã hóa nó thêm nữa.
#         sk_bytes_from_ta = TAClient.keygen(attributes)
        
#         # CHỈNH SỬA QUAN TRỌNG:
#         # Giải mã sk_bytes_from_ta ra thành chuỗi string để lưu vào file JSON.
#         # KHÔNG base64.b64encode() nó nữa.
#         secret_key_string_for_user = sk_bytes_from_ta.decode('utf-8')

#         response_data = {
#             # Sử dụng trực tiếp chuỗi key đã được decode 1 lần từ TA
#             "secret_key": secret_key_string_for_user,
#             "attributes": attributes,
#             "user_id": uid,
#             "timestamp": datetime.now().isoformat(),
#             "message": "SECRET KEY GENERATED - SAVE THIS SECURELY!",
#             "warning": "⚠️ Server will NOT store this key. If lost, your encrypted files become unrecoverable.",
#             "instructions": {
#                 "save_as": f"user_{uid}_secret_key.json",
#                 "action": "Save this entire JSON response to your local device",
#                 "backup": "Create multiple copies in secure locations",
#                 "never_share": "This key grants access to your encrypted data"
#             }
#         }
#         # Dọn dẹp memory
#         del sk_bytes_from_ta
#         gc.collect()
#         return jsonify(response_data), 200
        
#     except Exception as e:
        # return jsonify({"msg": f"Key generation failed: {str(e)}"}), 500

@ehr_bp.route('/keygen', methods=['POST'])
@jwt_required() # <-- Thêm JWT để yêu cầu đăng nhập
def keygen():
    """
    Tạo khóa bí mật cho người dùng dựa trên thuộc tính của họ.
    Đây là route KeyGen chính và duy nhất của hệ thống.
    """
    uid = get_jwt_identity()
    user = User.query.get_or_404(uid)

    # Chặn nếu người dùng đã tải key trước đó (logic từ keygen.py cũ)
    if user.downloaded_sk:
        return jsonify({
            "msg": "Bạn chỉ được tải Secret Key một lần. Vui lòng liên hệ quản trị viên để được cấp lại."
        }), 403

    attributes = request.json.get('attributes', [])
    if not attributes:
        return jsonify({"msg": "Trường 'attributes' là bắt buộc"}), 400
    
    current_app.logger.info(f"User {uid} is generating key with attributes: {attributes}")

    try:
        # 1. Gọi TA Service để lấy key đã mã hóa 2 lần
        sk_bytes_from_ta = TAClient.keygen(attributes)
        
        # 2. Decode một lần để có chuỗi Base64 (đã mã hóa 1 lần) để lưu vào file JSON
        secret_key_string_for_user = sk_bytes_from_ta.decode('utf-8')

        # 3. Chuẩn bị dữ liệu trả về cho người dùng
        response_data = {
            "secret_key": secret_key_string_for_user,
            "attributes": attributes,
            "user_id": uid,
            "timestamp": datetime.now().isoformat(),
            "message": "SECRET KEY GENERATED - SAVE THIS SECURELY!",
            "warning": "⚠️ Server sẽ KHÔNG lưu trữ key này. Nếu làm mất, bạn sẽ không thể phục hồi dữ liệu.",
            "instructions": {
                "save_as": f"user_{uid}_sk.json",
                "action": "Lưu toàn bộ nội dung JSON này vào thiết bị của bạn",
            }
        }
        
        # 4. Đánh dấu người dùng đã tải key và lưu vào DB
        user.downloaded_sk = True
        db.session.commit()
        
        # 5. Dọn dẹp memory và trả về
        del sk_bytes_from_ta
        gc.collect()
        return jsonify(response_data), 200
        
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"TA connection failed for user {uid}: {e}")
        return jsonify({"msg": "Không thể kết nối đến máy chủ cấp phát khóa (TA)."}), 503
    except Exception as e:
        db.session.rollback() # Rất quan trọng: rollback lại việc set downloaded_sk nếu có lỗi
        tb = traceback.format_exc()
        current_app.logger.error(f"Key generation failed for user {uid}: {tb}")
        return jsonify({"msg": f"Quá trình tạo khóa thất bại: {str(e)}"}), 500

# @ehr_bp.route('/upload', methods=['POST'])
# @jwt_required()
# def upload():
#     uid = 1
#     file = request.files.get('file')
#     policy = request.form.get('policy')
    
#     if not file or not policy:
#         return jsonify({"msg": "file and policy required"}), 400
    
#     # === THAY ĐỔI DUY NHẤT VÀ QUAN TRỌNG NHẤT ===
#     # "Dọn dẹp" chuỗi policy: loại bỏ khoảng trắng thừa xung quanh các toán tử AND/OR
#     # và đảm bảo các thuộc tính không dính khoảng trắng.
#     # Ví dụ: "role:Doctor AND  department:Cardiology" -> "role:DoctorANDdepartment:Cardiology"
#     policy = ''.join(policy_from_form.split())
#     current_app.logger.info(f"---UPLOAD DEBUG--- Original Policy: '{policy_from_form}', Cleaned Policy: '{policy}'")
#     # === KẾT THÚC THAY ĐỔI ===

#     data = file.read()
#     record_id = str(uuid.uuid4())
#     s3_key = f"{uid}/{record_id}.enc"

#     try:
#         pk_base64 = PublicKeyManager.get_public_key()
#         pk_bytes = base64.b64decode(pk_base64)
#         pk = bytesToObject(pk_bytes, abe.group)
#         ciphertext = abe.encrypt(pk, data, policy)
        
#         import struct
#         abe_key_bytes = objectToBytes(ciphertext['abe_key'], abe.group)
#         iv_bytes = ciphertext['iv']
#         data_bytes = ciphertext['data']
#         encrypted_data = struct.pack(
#             f'!I{len(abe_key_bytes)}sI{len(iv_bytes)}sI{len(data_bytes)}s',
#             len(abe_key_bytes), abe_key_bytes,
#             len(iv_bytes), iv_bytes,  
#             len(data_bytes), data_bytes
#         )
#         ctdk_part = objectToBytes(ciphertext['abe_key'], abe.group)
#         TAClient.store_ctdk(record_id, ctdk_part)

#         upload_to_s3(encrypted_data, s3_key)

#         ef = EhrFile(
#             record_id=record_id,
#             filename=file.filename,
#             s3_key=s3_key,
#             policy=policy,
#             owner_id=uid
#         )
#         db.session.add(ef)
#         db.session.commit()
        
#         return jsonify({
#             "record_id": record_id,
#             "message": "File uploaded and encrypted successfully"
#         }), 201

#     except Exception as e:
#         db.session.rollback()
#         current_app.logger.error(f"Upload process failed: {e}")
#         traceback.print_exc()
#         return jsonify({
#             "msg": "Upload process failed",
#             "error": str(e)
#         }), 500

@ehr_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    # Lấy uid từ token, không hardcode nữa
    uid = get_jwt_identity() 
    file = request.files.get('file')
    
    # 1. Nhận policy từ form vào biến `policy_from_form`
    policy_from_form = request.form.get('policy')
    
    if not file or not policy_from_form:
        return jsonify({"msg": "file và policy là bắt buộc"}), 400

    # 2. "Dọn dẹp" chuỗi policy và lưu vào biến `cleaned_policy`
    cleaned_policy = ''.join(policy_from_form.split())
    current_app.logger.info(f"---UPLOAD DEBUG--- User {uid} uploading with Original Policy: '{policy_from_form}', Cleaned Policy for ABE: '{cleaned_policy}'")

    data = file.read()
    record_id = str(uuid.uuid4())
    s3_key = f"{uid}/{record_id}.enc"

    try:
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        # 3. Sử dụng `cleaned_policy` để mã hóa
        ciphertext = abe.encrypt(pk, data, cleaned_policy)
        
        # ... (phần đóng gói dữ liệu để upload giữ nguyên)
        import struct
        abe_key_bytes = objectToBytes(ciphertext['abe_key'], abe.group)
        iv_bytes = ciphertext['iv']
        data_bytes = ciphertext['data']
        encrypted_data = struct.pack(
            f'!I{len(abe_key_bytes)}sI{len(iv_bytes)}sI{len(data_bytes)}s',
            len(abe_key_bytes), abe_key_bytes,
            len(iv_bytes), iv_bytes,  
            len(data_bytes), data_bytes
        )
        ctdk_part = objectToBytes(ciphertext['abe_key'], abe.group)
        TAClient.store_ctdk(record_id, ctdk_part)

        upload_to_s3(encrypted_data, s3_key)

        # 4. Tạo bản ghi trong DB, lưu policy GỐC để người dùng dễ đọc
        ef = EhrFile(
            record_id=record_id,
            filename=file.filename,
            s3_key=s3_key,
            policy=policy_from_form, # <-- Lưu policy gốc, chưa bị dọn dẹp
            owner_id=uid
        )
        db.session.add(ef)
        db.session.commit()
        
        return jsonify({
            "record_id": record_id,
            "message": "File uploaded and encrypted successfully"
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Upload process failed for user {uid}: {e}")
        traceback.print_exc()
        return jsonify({
            "msg": "Upload process failed",
            "error": str(e)
        }), 500

@ehr_bp.route('/download/<record_id>', methods=['POST'])
@jwt_required()
def download(record_id):
    uid = get_jwt_identity() # <-- Lấy uid từ token
    # uid = 1
    raw_sk = request.json.get('secret_key')
    current_app.logger.debug(f"Raw secret_key from client: {raw_sk!r}")
    
    try:
        ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"msg": "Secret key is required"}), 400

        encrypted_data = download_from_s3(ef.s3_key)
        
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        # sk_bytes = base64.b64decode(sk_b64)
        # sk = abe.deserialize_key(sk_bytes)
        sk = abe.deserialize_key(sk_b64)    
        
        import struct
        abe_key_len = struct.unpack('!I', encrypted_data[:4])[0]
        abe_key_bytes = encrypted_data[4:4+abe_key_len]
        abe_key = bytesToObject(abe_key_bytes, abe.group)
        offset = 4 + abe_key_len
        iv_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
        iv = encrypted_data[offset+4:offset+4+iv_len]
        offset = offset + 4 + iv_len
        data_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
        data = encrypted_data[offset+4:offset+4+data_len]
        ciphertext = {'abe_key': abe_key, 'iv': iv, 'data': data}
        plaintext = abe.decrypt(pk, sk, ciphertext)

        if plaintext is None:
            return jsonify({
                "msg": "Decryption failed - Access denied",
                "reason": "Your attributes don't satisfy the file's access policy",
                "policy": ef.policy
            }), 403

        # return send_file(
        #     io.BytesIO(plaintext),
        #     as_attachment=True,
        #     download_name=ef.filename,
        #     mimetype='application/octet-stream'
        # )
        resp = Response(
            plaintext,
            mimetype='application/octet-stream'
        )
        resp.headers["Content-Disposition"] = f'attachment; filename="{ef.filename}"'
        # Bắt buộc tắt mọi nén
        resp.headers["Content-Encoding"] = "identity"
        resp.direct_passthrough            = False
        current_app.logger.debug(f"Response headers before return: {resp.headers}")
        return resp

    except FileNotFoundError as e:
        return jsonify({"msg": "File not found on the server.", "error": str(e)}), 404
    # except Exception as e:
    #     current_app.logger.error(f"Download process failed for record {record_id}: {e}")
    #     traceback.print_exc()
    #     return jsonify({"msg": "Download process failed", "error": str(e)}), 500
    except Exception as e:
        tb = traceback.format_exc()
        current_app.logger.error(tb)
        return jsonify({
            "msg":   "Download process failed",
            "error": str(e),
            "traceback": tb
        }), 500

@ehr_bp.route('/files', methods=['GET'])
#@jwt_required()
def list_files():
    """List all files owned by current user"""
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

@ehr_bp.route('/validate-key', methods=['POST'])
def validate_secret_key():
    """Validate secret key format without storing it"""
    try:
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"valid": False, "msg": "Secret key required"}), 400
        
        sk_bytes = base64.b64decode(sk_b64)
        sk = abe.deserialize_key(sk_bytes)
        
        del sk_bytes, sk, sk_b64
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
        
        key_size = len(base64.b64decode(sk_b64))
        
        return jsonify({
            "key_size_bytes": key_size,
            "format": "Base64 encoded CP-ABE secret key",
            "usage": "Use this key to decrypt files you have access to"
        }), 200
        
    except Exception as e:
        return jsonify({"msg": f"Invalid key: {str(e)}"}), 400

# --- PublicKeyManager và các route liên quan (Giữ nguyên) ---
PUBLIC_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys', 'public_key.json')
PUBLIC_KEY_CACHE_TIME = 3600

KEYS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
os.makedirs(KEYS_FOLDER, exist_ok=True)

class PublicKeyManager:
    @staticmethod
    def save_public_key(pk_base64):
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
        try:
            if not os.path.exists(PUBLIC_KEY_FILE):
                return None
            with open(PUBLIC_KEY_FILE, 'r') as f:
                key_data = json.load(f)
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
        cached_pk = PublicKeyManager.load_cached_public_key()
        if cached_pk:
            return cached_pk
        
        print("🔍 Fetching public key from TA...")
        try:
            pk_base64 = TAClient.get_public_key()
            PublicKeyManager.save_public_key(pk_base64)
            return pk_base64
        except Exception as e:
            print(f"❌ Failed to fetch public key from TA: {e}")
            raise e

@ehr_bp.route('/public-key/refresh', methods=['POST'])
def refresh_public_key():
    try:
        if os.path.exists(PUBLIC_KEY_FILE):
            os.remove(PUBLIC_KEY_FILE)
        
        pk_base64 = TAClient.get_public_key() # Sửa: không có hàm get_public_key_direct
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
    try:
        if not os.path.exists(PUBLIC_KEY_FILE):
            return jsonify({"cached": False, "message": "No cached public key found"}), 200
        
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
    try:
        pk_base64 = PublicKeyManager.get_public_key()
        return jsonify({
            "public_key": pk_base64,
            "message": "Public key retrieved successfully"
        }), 200
    except Exception as e:
        return jsonify({"msg": f"Failed to get public key: {str(e)}"}), 500