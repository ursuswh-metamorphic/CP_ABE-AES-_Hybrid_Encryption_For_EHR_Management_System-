# -*- coding: utf-8 -*-
"""
File: ta_app.py (Đã nâng cấp để tương thích với abe_core_v2 và kiến trúc mới)
-----------------------------------------------------------------------------
- Sử dụng lõi mật mã abe_core_v2.py mới.
- Loại bỏ các endpoint /store_ctdk và /get_ctdk đã lỗi thời.
- Thêm các endpoint mới (/store_key_package, /get_key_package) để xử lý
  việc lưu trữ "gói khóa" an toàn từ backend.
- Thay thế pickle bằng json để tăng cường bảo mật.
"""
import os
import traceback
import base64
import json

from flask import Flask, request, jsonify

# SỬA ĐỔI: Thay đổi import để sử dụng lớp Wrapper từ file mới
from abe_core_v2 import ABECompatWrapper as ABECore

# Giả định bạn có một module helper để tương tác với AWS Secrets Manager
# Nếu không, bạn có thể thay thế bằng logic mock hoặc đọc từ file env.
from utils.secrets_helper import store_secret, retrieve_secret

app = Flask(__name__)
# Khởi tạo lớp Wrapper, nó sẽ hoạt động giống hệt ABECore cũ
abe = ABECore()

# THAY ĐỔI: Dùng file JSON để lưu trữ an toàn thay vì pickle
KEY_PACKAGE_STORE = "secrets/key_package_store.json"

def read_store():
    """Hàm tiện ích để đọc file lưu trữ JSON một cách an toàn."""
    if not os.path.exists(KEY_PACKAGE_STORE):
        return {}
    try:
        with open(KEY_PACKAGE_STORE, 'r') as f:
            # Trả về một dict rỗng nếu file trống
            content = f.read()
            if not content:
                return {}
            return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_store(store_data):
    """Hàm tiện ích để ghi dữ liệu vào file JSON."""
    if not os.path.exists(os.path.dirname(KEY_PACKAGE_STORE)):
        os.makedirs(os.path.dirname(KEY_PACKAGE_STORE))
    with open(KEY_PACKAGE_STORE, 'w') as f:
        json.dump(store_data, f, indent=4)

@app.route('/setup', methods=['POST'])
def setup():
    """
    Thiết lập hệ thống: tạo khóa công khai (PK) và khóa chủ (MK).
    Lưu PK ra file và lưu MK vào nơi an toàn (Secrets Manager).
    """
    try:
        pk, mk = abe.setup()

        # Hàm này đã được thêm vào wrapper để đảm bảo tương thích
        abe.save_public_key(pk, filename_prefix="keys", directory=".")

        # Hàm serialize_key của wrapper đã bao gồm base64 encoding
        mk_encoded = abe.serialize_key(mk).decode('utf-8')
        secret_name = os.getenv("AWS_SECRET_NAME", "cpabe-master-key")
        store_secret(secret_name, mk_encoded)

        return jsonify({"message": "TA setup completed successfully."}), 200
    except Exception as e:
        app.logger.error(f"TA setup failed: {e}")
        traceback.print_exc()
        return jsonify({"error": "TA setup failed", "details": str(e)}), 500

@app.route('/keygen', methods=['POST'])
def keygen():
    """
    Tạo khóa bí mật (SK) cho người dùng dựa trên các thuộc tính được cung cấp.
    """
    try:
        data = request.get_json()
        if not data or 'attributes' not in data:
            return jsonify({"error": "Missing 'attributes' in request body"}), 400
        
        attrs = data.get('attributes', [])

        # Lấy MK từ Secrets Manager
        secret_name = os.getenv("AWS_SECRET_NAME", "cpabe-master-key")
        mk_encoded = retrieve_secret(secret_name)
        # deserialize_key của wrapper nhận vào chuỗi string base64
        mk = abe.deserialize_key(mk_encoded)

        # Load PK từ file
        pk = abe.load_public_key(filename='keys_public.key', directory='.')

        # Sinh khóa SK cho người dùng theo attributes
        sk = abe.keygen(pk, mk, attrs)

        # Serialize và trả về dạng base64 string
        sk_b64_bytes = abe.serialize_key(sk)
        return jsonify({
            "sk": sk_b64_bytes.decode('utf-8')
        }), 200
    except Exception as e:
        app.logger.error(f"Key generation failed: {e}")
        traceback.print_exc()
        return jsonify({"error": "Key generation failed", "details": str(e)}), 500

# === CÁC ENDPOINT MỚI CHO KIẾN TRÚC HIỆN ĐẠI ===

@app.route('/store_key_package', methods=['POST'])
def store_key_package():
    """
    Lưu trữ "gói khóa" (chứa iv, tag, metadata, sig) do backend gửi lên.
    """
    try:
        data = request.get_json()
        record_id = data.get('record_id')
        key_package_str = data.get('key_package')

        if not record_id or not key_package_str:
            return jsonify({"error": "record_id and key_package are required"}), 400

        store = read_store()
        store[record_id] = json.loads(key_package_str) # Lưu dưới dạng đối tượng JSON
        write_store(store)
        
        return jsonify({"message": f"Key package for record {record_id} stored."}), 200
    except Exception as e:
        app.logger.error(f"Failed to store key package: {e}")
        return jsonify({"error": "Failed to store key package", "details": str(e)}), 500


@app.route('/get_key_package/<record_id>', methods=['GET'])
def get_key_package(record_id):
    """
    Lấy lại "gói khóa" đã được lưu trữ cho một record_id cụ thể.
    """
    try:
        store = read_store()
        key_package = store.get(record_id)

        if key_package is None:
            return jsonify({"error": "Key package not found"}), 404
        
        return jsonify({"key_package": json.dumps(key_package)}), 200
    except Exception as e:
        app.logger.error(f"Failed to retrieve key package: {e}")
        return jsonify({"error": "Failed to retrieve key package", "details": str(e)}), 500


@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Cung cấp khóa công khai cho các dịch vụ khác."""
    try:
        # Đọc public key từ file text (được tạo bởi save_public_key)
        with open('keys_public.key', 'r') as f:
            pk_base64 = f.read().strip()
        
        return jsonify({
            "public_key": pk_base64,
            "message": "Public key retrieved successfully"
        }), 200
        
    except FileNotFoundError:
        return jsonify({"error": "Public key not found. Please run /setup first"}), 404
    except Exception as e:
        app.logger.error(f"Failed to get public key: {e}")
        return jsonify({"error": f"Failed to get public key: {str(e)}"}), 500


if __name__ == '__main__':
    # Đảm bảo thư mục certs tồn tại
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("INFO: 'certs' directory created. Please place 'ta.crt' and 'ta.key' inside for HTTPS.")
    
    ssl_cert = "certs/ta.crt"
    ssl_key = "certs/ta.key"
    
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        ssl_context = (ssl_cert, ssl_key)
        print("INFO: Starting server with HTTPS on port 5001.")
    else:
        ssl_context = None
        print("WARNING: SSL certificates not found. Starting server with HTTP. THIS IS NOT SECURE FOR PRODUCTION.")
        
    app.run(
        host="0.0.0.0",
        port=5001,
        ssl_context=ssl_context
    )
