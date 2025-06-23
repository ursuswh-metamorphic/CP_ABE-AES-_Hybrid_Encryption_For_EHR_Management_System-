from flask import Blueprint, request, jsonify, send_file, current_app, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import EhrFile, User
import requests
import base64
import hashlib
import uuid
import io
import os
import sys
from datetime import datetime
import json
import gc
import boto3
import traceback
from botocore.exceptions import ClientError
import re # Đảm bảo đã import

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_REGION = os.environ.get("S3_REGION")
s3_client = boto3.client(
    "s3",
    region_name=S3_REGION,
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
)

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
from System.Backend.api_gateway.abe_core import ABECore
from charm.core.engine.util import objectToBytes, bytesToObject

ehr_bp = Blueprint('ehr', __name__, url_prefix='/api/ehr')
abe = ABECore()

class TAClient:
    @staticmethod
    def keygen(attributes):
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/keygen",
            json={"attributes": attributes},
            verify=False
        )
        res.raise_for_status()
        # Sửa lỗi tương thích: TA Service đã được sửa để trả về base64 chuẩn.
        return res.json()['sk'].encode('utf-8')
    
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
    
    # Hàm này không cần nữa vì CTdk được lấy từ S3 blob
    # @staticmethod
    # def get_ctdk(record_id):
    #     res = requests.get(
    #         f"{current_app.config['TA_BASE_URL']}/get_ctdk/{record_id}",
    #         verify=False
    #     )
    #     res.raise_for_status()
    #     return res.json()

def upload_to_s3(data: bytes, s3_key: str):
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
    try:
        current_app.logger.info(f"Downloading from S3: bucket='{S3_BUCKET}', key='{s3_key}'")
        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        content = obj["Body"].read()
        current_app.logger.info(f"S3 Download successful for key: {s3_key}")
        return content
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            raise FileNotFoundError(f"File with key '{s3_key}' not found in S3.")
        else:
            raise RuntimeError(f"S3 download failed: {e.response['Error']['Message']}")
    except Exception as e:
        traceback.print_exc()
        raise RuntimeError(f"An unexpected error occurred during S3 download: {str(e)}")

@ehr_bp.route('/keygen', methods=['POST'])
@jwt_required()
def keygen():
    uid = get_jwt_identity()
    user = User.query.get_or_404(uid)

    if user.downloaded_sk:
        return jsonify({"msg": "Bạn chỉ được tải Secret Key một lần. Vui lòng liên hệ quản trị viên để được cấp lại."}), 403

    attributes = request.json.get('attributes', [])
    if not attributes:
        return jsonify({"msg": "Trường 'attributes' là bắt buộc"}), 400
    
    current_app.logger.info(f"User {uid} is generating key with attributes: {attributes}")

    try:
        sk_bytes_from_ta = TAClient.keygen(attributes)
        secret_key_string_for_user = sk_bytes_from_ta.decode('utf-8')

        response_data = {
            "secret_key": secret_key_string_for_user,
            "attributes": attributes,
            "user_id": uid,
            "timestamp": datetime.now().isoformat(),
            "message": "SECRET KEY GENERATED - SAVE THIS SECURELY!",
            "warning": "⚠️ Server sẽ KHÔNG lưu trữ key này. Nếu làm mất, bạn sẽ không thể phục hồi dữ liệu.",
            "instructions": {"save_as": f"user_{uid}_sk.json"}
        }
        
        user.downloaded_sk = True
        db.session.commit()
        
        del sk_bytes_from_ta
        gc.collect()
        return jsonify(response_data), 200
        
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"TA connection failed for user {uid}: {e}")
        return jsonify({"msg": "Không thể kết nối đến máy chủ cấp phát khóa (TA)."}), 503
    except Exception as e:
        db.session.rollback()
        tb = traceback.format_exc()
        current_app.logger.error(f"Key generation failed for user {uid}: {tb}")
        return jsonify({"msg": f"Quá trình tạo khóa thất bại: {str(e)}"}), 500

@ehr_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    uid = get_jwt_identity() 
    file = request.files.get('file')
    policy_from_form = request.form.get('policy')
    
    if not file or not policy_from_form:
        return jsonify({"msg": "file và policy là bắt buộc"}), 400

    cleaned_policy = re.sub(r'\s+', ' ', policy_from_form).strip()
    current_app.logger.info(f"User {uid} uploading with Original Policy: '{policy_from_form}', Cleaned Policy for ABE: '{cleaned_policy}'")

    data = file.read()
    record_id = str(uuid.uuid4())
    s3_key = f"{uid}/{record_id}.enc"

    try:
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        # === LOGIC MÃ HÓA ĐÚNG THEO SƠ ĐỒ ===
        # 1. Mã hóa file bằng AES, tạo ra khóa dk, iv, và file đã mã hóa
        ciphertext_aes = abe.symmetric_encrypt_for_upload(data)
        dk = ciphertext_aes['dk'] # Khóa session key (đối tượng GT)
        iv = ciphertext_aes['iv']
        encrypted_file_data = ciphertext_aes['data']
        
        # 2. Mã hóa dk bằng ABE, tạo ra CTdk
        ctdk_obj = abe.abe.encrypt(pk, dk, cleaned_policy)
        if ctdk_obj is None:
            raise ValueError("ABE encryption failed. Check policy syntax.")
        
        # 3. Serialize CTdk để gửi cho TA và đóng gói vào file
        ctdk_bytes = objectToBytes(ctdk_obj, abe.group)

        # 4. Gửi CTdk và signature cho TA để lưu trữ (Bước 4 trong sơ đồ)
        TAClient.store_ctdk(record_id, ctdk_bytes)
        
        # 5. Đóng gói CTdk, IV, và dữ liệu file đã mã hóa AES để lưu lên S3
        import struct
        encrypted_s3_blob = struct.pack(
            f'!I{len(ctdk_bytes)}sI{len(iv)}sI{len(encrypted_file_data)}s',
            len(ctdk_bytes), ctdk_bytes,
            len(iv), iv,
            len(encrypted_file_data), encrypted_file_data
        )
        
        # 6. Upload blob lên S3
        upload_to_s3(encrypted_s3_blob, s3_key)

        ef = EhrFile(
            record_id=record_id,
            filename=file.filename,
            s3_key=s3_key,
            policy=policy_from_form,
            owner_id=uid
        )
        db.session.add(ef)
        db.session.commit()
        
        return jsonify({"record_id": record_id, "message": "File uploaded and encrypted successfully"}), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Upload process failed for user {uid}: {e}")
        traceback.print_exc()
        return jsonify({"msg": "Upload process failed", "error": str(e)}), 500


@ehr_bp.route('/download/<record_id>', methods=['POST'])
@jwt_required()
def download(record_id):
    uid = get_jwt_identity()
    current_app.logger.info(f"User {uid} attempting local decryption for record {record_id}")
    
    try:
        # Bước 2: Get file_id (trong trường hợp này là s3_key từ DB)
        ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
        
        # Lấy khóa bí mật từ request của người dùng
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"msg": "Secret key is required"}), 400

        # Bước 3 & 4: Tải file mã hóa từ S3
        encrypted_s3_blob = download_from_s3(ef.s3_key)
        
        # Giải nén blob từ S3
        import struct
        offset = 0
        ctdk_len = struct.unpack('!I', encrypted_s3_blob[offset:offset+4])[0]
        offset += 4
        ctdk_bytes = encrypted_s3_blob[offset:offset+ctdk_len]
        offset += ctdk_len
        
        iv_len = struct.unpack('!I', encrypted_s3_blob[offset:offset+4])[0]
        offset += 4
        iv = encrypted_s3_blob[offset:offset+iv_len]
        offset += iv_len
        
        encrypted_file_data = encrypted_s3_blob[offset:]
        
        # Lấy public key (Bước 9)
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        # Khôi phục khóa bí mật của người dùng (SKU)
        sk_bytes = base64.b64decode(sk_b64)
        sk = bytesToObject(sk_bytes, abe.group)

        # Khôi phục CTdk object
        ctdk_obj = bytesToObject(ctdk_bytes, abe.group)

        current_app.logger.info("================== ABE DECRYPTION DEBUG (LOCAL) ==================")
        sk_attrs = str(getattr(sk, 'attr_list', 'N/A'))
        current_app.logger.info(f"[*] Attributes in Secret Key (SK): {sk_attrs}")
        current_app.logger.info(f"[*] Policy from DB for reference: {ef.policy}")
        current_app.logger.info("================================================================")
        
        # Bước 10: Giải mã ABE để lấy lại khóa session dk
        dk = abe.abe.decrypt(pk, sk, ctdk_obj)

        if dk is None:
            current_app.logger.warning(f"ABE decryption failed for user {uid} on record {record_id}. Attributes did not match policy.")
            return jsonify({"msg": "Decryption failed - Access denied", "reason": "Your attributes don't satisfy the file's access policy", "policy": ef.policy}), 403
        
        # Bước 11: Giải mã AES để lấy lại file gốc
        plaintext = abe.symmetric_decrypt(dk, iv, encrypted_file_data)
        
        # Bước 12: Trả file về cho người dùng
        resp = Response(plaintext, mimetype='application/octet-stream')
        resp.headers["Content-Disposition"] = f'attachment; filename="{ef.filename}"'
        resp.headers["Content-Encoding"] = "identity"
        resp.direct_passthrough = False
        current_app.logger.info(f"Successfully decrypted and sending file '{ef.filename}' to user {uid}.")
        return resp

    except FileNotFoundError as e:
        return jsonify({"msg": "File not found on the server.", "error": str(e)}), 404
    except (base64.binascii.Error, TypeError) as e:
        current_app.logger.error(f"Invalid Secret Key format for user {uid} for record {record_id}. Error: {e}")
        return jsonify({"msg": "Invalid Secret Key format. Please ensure you are using the correct, unmodified key file."}), 400
    except Exception as e:
        tb = traceback.format_exc()
        current_app.logger.error(f"Download process failed for record {record_id} for user {uid}. Traceback: {tb}")
        return jsonify({"msg": "Download process failed", "error": str(e)}), 500


@ehr_bp.route('/files', methods=['GET'])
@jwt_required()
def list_files():
    uid = get_jwt_identity()
    files = EhrFile.query.filter_by(owner_id=uid).all()
    
    return jsonify({
        "files": [{
            "record_id": f.record_id,
            "filename": f.filename,
            "policy": f.policy,
            "created_at": f.created_at.isoformat() if f.created_at else None
        } for f in files]
    }), 200

PUBLIC_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys', 'public_key.json')
PUBLIC_KEY_CACHE_TIME = 3600

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