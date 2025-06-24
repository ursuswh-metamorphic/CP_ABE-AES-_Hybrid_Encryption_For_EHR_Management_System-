# -*- coding: utf-8 -*-
"""
File: ehr.py (Nâng cấp với kiến trúc lưu trữ lai S3 + TA)
---------------------------------------------------------
- Tái cấu trúc (refactor) lại toàn bộ luồng lưu trữ theo yêu cầu:
  1. Dữ liệu file đã mã hóa AES được lưu trên S3.
  2. Các thành phần khóa (ABE key, IV, tag, metadata, signature)
     được đóng gói và lưu trữ trên Trusted Authority (TA).
"""

import os
import sys
import base64
import json
import traceback
import uuid
from datetime import datetime
import re

import boto3
import requests
from botocore.exceptions import ClientError
from flask import Blueprint, Response, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from extensions import db
from models import EhrFile, User

# === CẤU HÌNH ===
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_REGION = os.environ.get("S3_REGION")

# Khởi tạo S3 client
s3_client = boto3.client(
    "s3",
    region_name=S3_REGION,
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
)

# === IMPORT VÀ KHỞI TẠO ABE CORE ===
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')) 
from System.Backend.api_gateway.abe_core_v2 import ABECompatWrapper as ABECore

ehr_bp = Blueprint('ehr', __name__, url_prefix='/api/ehr')
abe = ABECore()

# === LỚP HELPER: GIAO TIẾP VỚI TA & S3 ===

class TAClient:
    """Lớp giao tiếp với Dịch vụ Trusted Authority (TA)."""
    
    @staticmethod
    def get_public_key():
        """Lấy khóa công khai từ TA."""
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_public_key",
            verify=False
        )
        res.raise_for_status()
        return res.json()['public_key']

    @staticmethod
    def store_key_package(record_id: str, key_package: dict):
        """
        Gửi gói khóa (key package) đến TA để lưu trữ.
        LƯU Ý: Yêu cầu endpoint /store_key_package phải được tạo bên phía ta_app.py.
        """
        # Convert bytes to base64 for JSON serialization
        serializable_package = {}
        for key, value in key_package.items():
            if isinstance(value, bytes):
                serializable_package[key] = base64.b64encode(value).decode('utf-8')
            else:
                serializable_package[key] = value
        
        res = requests.post(
            f"{current_app.config['TA_BASE_URL']}/store_key_package",
            json={
                "record_id": record_id,
                "key_package": json.dumps(serializable_package) # Gửi dưới dạng chuỗi JSON
            },
            verify=False
        )
        res.raise_for_status()
        current_app.logger.info(f"Successfully stored key package for record_id '{record_id}' on TA.")

    @staticmethod
    def get_key_package(record_id: str) -> dict:
        """
        Lấy lại gói khóa từ TA.
        LƯU Ý: Yêu cầu endpoint /get_key_package/<record_id> phải được tạo bên phía ta_app.py.
        """
        res = requests.get(
            f"{current_app.config['TA_BASE_URL']}/get_key_package/{record_id}",
            verify=False
        )
        res.raise_for_status()
        key_package_str = res.json()['key_package']
        serializable_package = json.loads(key_package_str)
        
        # Convert base64 back to bytes for known bytes fields
        key_package = {}
        bytes_fields = ['iv', 'tag', 'encrypted_key', 'signature', 'sig', 'ct_key', 'data']
        
        for key, value in serializable_package.items():
            if key in bytes_fields and isinstance(value, str):
                try:
                    key_package[key] = base64.b64decode(value)
                except:
                    key_package[key] = value  # Keep original if decode fails
            else:
                key_package[key] = value
        
        return key_package

def upload_to_s3(data: bytes, s3_key: str):
    """Tải dữ liệu file đã mã hóa AES lên S3."""
    try:
        s3_client.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=data)
        current_app.logger.info(f"S3 Upload successful for key: {s3_key}")
    except ClientError as e:
        raise RuntimeError(f"S3 upload failed: {e.response['Error']['Message']}")

def download_from_s3(s3_key: str) -> bytes:
    """Tải dữ liệu file đã mã hóa AES từ S3."""
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return obj["Body"].read()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            raise FileNotFoundError(f"File with key '{s3_key}' not found in S3.")
        raise RuntimeError(f"S3 download failed: {e.response['Error']['Message']}")

# === ENDPOINTS ĐÃ ĐƯỢC CẬP NHẬT ===

@ehr_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    uid = get_jwt_identity() 
    file = request.files.get('file')
    policy_from_form = request.form.get('policy')
    
    if not file or not policy_from_form:
        return jsonify({"msg": "file và policy là bắt buộc"}), 400

    cleaned_policy = re.sub(r'\s+', ' ', policy_from_form).strip().lower()
    current_app.logger.info(f"User {uid} uploading with Cleaned Policy for ABE: '{cleaned_policy}'")

    data = file.read()
    record_id = str(uuid.uuid4())
    s3_key = f"{uid}/{record_id}.aes.enc" # Đuôi file chỉ chứa dữ liệu AES

    try:
        pk_base64 = TAClient.get_public_key()
        pk = abe.deserialize_key(pk_base64)
        
        # 1. Mã hóa để tạo ra gói dữ liệu hoàn chỉnh
        full_encrypted_package = abe.encrypt(pk, data, cleaned_policy, user_id=uid)

        if full_encrypted_package is None:
            raise ValueError("Quá trình mã hóa tổng thể thất bại.")

        # 2. Tách gói dữ liệu
        encrypted_ehr_data = full_encrypted_package.pop('data')
        # Phần còn lại là key_package
        key_package = full_encrypted_package 

        # 3. Gửi key_package cho TA để lưu trữ
        TAClient.store_key_package(record_id, key_package)

        # 4. Tải dữ liệu EHR đã mã hóa AES lên S3
        upload_to_s3(encrypted_ehr_data, s3_key)

        # 5. Lưu thông tin vào database (thêm lại s3_key)
        ef = EhrFile(
            record_id=record_id,
            filename=file.filename,
            s3_key=s3_key, # Lưu lại key của S3
            policy=policy_from_form,
            owner_id=uid
        )
        db.session.add(ef)
        db.session.commit()
        
        return jsonify({"record_id": record_id, "message": "File uploaded and stored successfully"}), 201

    except requests.exceptions.RequestException as e:
        db.session.rollback()
        current_app.logger.error(f"TA connection failed during upload for user {uid}: {e}")
        return jsonify({"msg": "Không thể kết nối đến máy chủ lưu trữ khóa (TA)."}), 503
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Upload process failed for user {uid}: {e}")
        traceback.print_exc()
        return jsonify({"msg": "Upload process failed", "error": str(e)}), 500


@ehr_bp.route('/download/<record_id>', methods=['POST'])
@jwt_required()
def download(record_id):
    uid = get_jwt_identity()
    current_app.logger.info(f"User {uid} attempting decryption for record {record_id}")

    try:
        ef = EhrFile.query.filter_by(record_id=record_id).first_or_404()
        sk_b64 = request.json.get('secret_key')
        if not sk_b64:
            return jsonify({"msg": "Secret key is required"}), 400

        # 1. Lấy gói khóa (key package) từ TA
        key_package = TAClient.get_key_package(record_id)
        
        # 2. Tải dữ liệu EHR đã mã hóa AES từ S3
        encrypted_ehr_data = download_from_s3(ef.s3_key)

        # 3. Tái tạo lại gói dữ liệu hoàn chỉnh để giải mã
        full_package_for_decryption = key_package
        full_package_for_decryption['data'] = encrypted_ehr_data
        
        pk_base64 = TAClient.get_public_key()
        pk = abe.deserialize_key(pk_base64)
        sk = abe.deserialize_key(sk_b64)
        
        # 4. Giải mã gói dữ liệu
        plaintext = abe.decrypt(pk, sk, full_package_for_decryption)

        if plaintext is None:
            return jsonify({
                "msg": "Decryption failed - Access Denied", 
                "reason": "Your attributes do not satisfy the file's access policy.", 
                "policy_required": ef.policy
            }), 403
        
        resp = Response(plaintext, mimetype='application/octet-stream')
        resp.headers["Content-Disposition"] = f'attachment; filename="{ef.filename}"'
        resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return resp

    except FileNotFoundError as e:
        return jsonify({"msg": "File or key material not found.", "error": str(e)}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({"msg": "Could not connect to the Key Authority service (TA)."}), 503
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