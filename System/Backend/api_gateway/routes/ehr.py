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

    cleaned_policy = ''.join(policy_from_form.split())
    current_app.logger.info(f"User {uid} uploading with Original Policy: '{policy_from_form}', Cleaned Policy for ABE: '{cleaned_policy}'")

    data = file.read()
    record_id = str(uuid.uuid4())
    s3_key = f"{uid}/{record_id}.enc"

    try:
        pk_base64 = PublicKeyManager.get_public_key()
        pk_bytes = base64.b64decode(pk_base64)
        pk = bytesToObject(pk_bytes, abe.group)
        
        ciphertext = abe.encrypt(pk, data, cleaned_policy)
        
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

# @ehr_bp.route('/download/<record_id>', methods=['POST'])
# @jwt_required()
# def download(record_id):
#     uid = get_jwt_identity()
#     current_app.logger.info(f"User {uid} attempting to download record {record_id}")
    
#     try:
#         ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
#         sk_b64 = request.json.get('secret_key')
#         if not sk_b64:
#             return jsonify({"msg": "Secret key is required"}), 400

#         encrypted_data = download_from_s3(ef.s3_key)
        
#         pk_base64 = PublicKeyManager.get_public_key()
#         pk_bytes = base64.b64decode(pk_base64)
#         pk = bytesToObject(pk_bytes, abe.group)
        
#         sk_bytes = base64.b64decode(sk_b64)
#         sk = bytesToObject(sk_bytes, abe.group)
        
#         policy_from_db = ef.policy
#         cleaned_policy_for_decrypt = ''.join(policy_from_db.split())
        
#         current_app.logger.info("================== ABE DECRYPTION DEBUG ==================")
#         try:
#             sk_attrs = ' '.join(sk.get('attr_list', [])) if isinstance(sk, dict) else str(getattr(sk, 'attr_list', 'N/A'))
#             current_app.logger.info(f"[*] Attributes in Secret Key (SK): {sk_attrs}")
#         except Exception:
#             current_app.logger.info("[*] Could not extract attributes from Secret Key object.")
#         current_app.logger.info(f"[*] Original Policy from DB      : {policy_from_db}")
#         current_app.logger.info(f"[*] Cleaned Policy for Decryption: {cleaned_policy_for_decrypt}")
#         current_app.logger.info("==========================================================")
        
#         import struct
#         abe_key_len = struct.unpack('!I', encrypted_data[:4])[0]
#         abe_key_bytes = encrypted_data[4:4+abe_key_len]
#         abe_key = bytesToObject(abe_key_bytes, abe.group)
#         offset = 4 + abe_key_len
#         iv_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
#         iv = encrypted_data[offset+4:offset+4+iv_len]
#         offset = offset + 4 + iv_len
#         data_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
#         data = encrypted_data[offset+4:offset+4+data_len]
        
#         ciphertext = {'abe_key': abe_key, 'iv': iv, 'data': data}
        
#         plaintext = abe.decrypt(pk, sk, ciphertext, cleaned_policy_for_decrypt)

#         if plaintext is None:
#             current_app.logger.warning(f"Decryption failed for user {uid} on record {record_id}. Attributes did not match policy.")
#             return jsonify({"msg": "Decryption failed - Access denied", "reason": "Your attributes don't satisfy the file's access policy", "policy": ef.policy}), 403

#         resp = Response(plaintext, mimetype='application/octet-stream')
#         resp.headers["Content-Disposition"] = f'attachment; filename="{ef.filename}"'
#         resp.headers["Content-Encoding"] = "identity"
#         resp.direct_passthrough = False
#         current_app.logger.info(f"Successfully decrypted and sending file '{ef.filename}' to user {uid}.")
#         return resp

#     except FileNotFoundError as e:
#         return jsonify({"msg": "File not found on the server.", "error": str(e)}), 404
#     except (base64.binascii.Error, TypeError) as e:
#         return jsonify({"msg": "Invalid Secret Key format. Please ensure you are using the correct, unmodified key file."}), 400
#     except Exception as e:
#         tb = traceback.format_exc()
#         current_app.logger.error(f"Download process failed for record {record_id} for user {uid}. Traceback: {tb}")
#         return jsonify({"msg": "Download process failed", "error": str(e)}), 500

@ehr_bp.route('/download/<record_id>', methods=['POST'])
@jwt_required()
def download(record_id):
    uid = get_jwt_identity()
    current_app.logger.info(f"User {uid} attempting to download record {record_id}")
    
    try:
        ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"msg": "Secret key is required"}), 400

        # Tải dữ liệu đã mã hóa từ S3
        encrypted_data_from_s3 = download_from_s3(ef.s3_key)
        
        # Tải Public Key (dưới dạng base64)
        pk_b64 = PublicKeyManager.get_public_key()
        
        # Lấy policy đã được dọn dẹp
        policy_from_db = ef.policy
        cleaned_policy_for_decrypt = ''.join(policy_from_db.split())
        
        # --- THAY ĐỔI LỚN: GIAO VIỆC CHO TA SERVICE ---
        # Gửi tất cả các thành phần dưới dạng Base64 đến TA
        current_app.logger.info("Handing off decryption task to TA Service...")
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/decrypt",
            json={
                "pk_b64": pk_b64,
                "sk_b64": sk_b64,
                "ct_b64": base64.b64encode(encrypted_data_from_s3).decode('utf-8'),
                "policy": cleaned_policy_for_decrypt
            },
            verify=False,
            timeout=15 # Tăng timeout cho tác vụ nặng
        )
        
        # Kiểm tra xem TA có trả về lỗi không (ví dụ: giải mã thất bại 403)
        if res.status_code != 200:
            try:
                error_data = res.json()
            except:
                error_data = {"msg": "TA service returned a non-JSON error", "status": res.status_code}

            current_app.logger.warning(f"TA Service failed decryption for record {record_id}. Status: {res.status_code}. Response: {error_data}")
            return jsonify({
                "msg": error_data.get("msg", "Decryption failed - Access denied"),
                "reason": error_data.get("reason", "Your attributes don't satisfy the file's access policy"),
                "policy": ef.policy
            }), 403

        # Nếu thành công, TA sẽ trả về dữ liệu đã giải mã dưới dạng bytes
        plaintext = res.content

        # Trả file về cho người dùng
        resp = Response(plaintext, mimetype='application/octet-stream')
        resp.headers["Content-Disposition"] = f'attachment; filename="{ef.filename}"'
        resp.headers["Content-Encoding"] = "identity"
        resp.direct_passthrough = False
        current_app.logger.info(f"Successfully decrypted and sending file '{ef.filename}' to user {uid}.")
        return resp

    except FileNotFoundError as e:
        return jsonify({"msg": "File not found on the server.", "error": str(e)}), 404
    except (base64.binascii.Error, TypeError) as e:
        return jsonify({"msg": "Invalid Secret Key format. Please ensure you are using the correct, unmodified key file."}), 400
    except requests.exceptions.RequestException as e:
        tb = traceback.format_exc()
        current_app.logger.error(f"Failed to connect to TA service during download: {tb}")
        return jsonify({"msg": "Failed to connect to decryption service.", "error": str(e)}), 503
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