from flask import Flask, request, jsonify, Response
from abe_core import ABECore
import os, base64, hashlib, pickle, struct, traceback
from utils.secrets_helper import store_secret, retrieve_secret
from charm.core.engine.util import objectToBytes, bytesToObject

app = Flask(__name__)
abe = ABECore()
CTDK_STORE = "secrets/ctdk_store.pkl"

@app.route('/setup', methods=['POST'])
def setup():
    pk, mk = abe.setup()

    # Lưu khóa công khai vào file base64 text
    abe.save_public_key(pk, filename_prefix="keys", directory=".")

    # Serialize master key mk và lưu vào AWS Secrets Manager (hoặc mock)

    mk_encoded = base64.b64encode(objectToBytes(mk, abe.group)).decode()
    secret_name = os.getenv("AWS_SECRET_NAME", "cpabe-master-key")
    store_secret(secret_name, mk_encoded)

    return jsonify({"message": "TA setup completed."}), 200


@app.route('/keygen', methods=['POST'])
def keygen():
    data = request.get_json()
    attrs = data.get('attributes', [])

    # Lấy MK từ Secrets Manager hoặc mock

    secret_name = os.getenv("AWS_SECRET_NAME", "cpabe-master-key")
    mk_encoded = retrieve_secret(secret_name)
    mk = abe.deserialize_key(mk_encoded)

    # Load PK từ file base64 text
    pk = abe.load_public_key(filename='keys_public.key', directory='.')

    # Sinh khóa SKU cho người dùng theo attributes
    sk = abe.keygen(pk, mk, attrs)

    # Serialize và trả về dạng base64
    sk_bytes = abe.serialize_key(sk)
    return jsonify({
        "sk": base64.b64encode(sk_bytes).decode()
    }), 200


@app.route('/store_ctdk', methods=['POST'])
def store_ctdk():
    data = request.get_json()
    record_id = data['record_id']
    ctdk = data['ctdk']
    sig = data['sig']

    if not os.path.exists(CTDK_STORE):
        store = {}
    else:
        store = pickle.load(open(CTDK_STORE, 'rb'))

    store[record_id] = {"ctdk": ctdk, "sig": sig}
    pickle.dump(store, open(CTDK_STORE, 'wb'))
    return jsonify({"message": "CTdk stored."}), 200

@app.route('/get_ctdk/<record_id>', methods=['GET'])
def get_ctdk(record_id):
    if not os.path.exists(CTDK_STORE):
        return jsonify({"error": "Not found"}), 404
    store = pickle.load(open(CTDK_STORE, 'rb'))
    if record_id not in store:
        return jsonify({"error": "Not found"}), 404
    return jsonify(store[record_id]), 200

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Return public key để backend có thể encrypt/decrypt"""
    try:
        # Đọc public key từ file
        with open('keys_public.key', 'r') as f:
            pk_base64 = f.read().strip()
        
        return jsonify({
            "public_key": pk_base64,
            "message": "Public key retrieved successfully"
        }), 200
        
    except FileNotFoundError:
        return jsonify({"error": "Public key not found. Please run /setup first"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to get public key: {str(e)}"}), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        data_b64 = data.get('data_b64')
        policy = data.get('policy')
        
        if not data_b64 or not policy:
            return jsonify({"msg": "data_b64 and policy are required"}), 400
            
        plaintext_bytes = base64.b64decode(data_b64)
        pk = abe.load_public_key(filename='keys_public.key', directory='.')
        
        ciphertext = abe.encrypt(pk, plaintext_bytes, policy)
        if ciphertext is None:
            return jsonify({"msg": "Encryption failed"}), 500
            
        return jsonify({
            "abe_key_b64": base64.b64encode(objectToBytes(ciphertext['abe_key'], abe.group)).decode('utf-8'),
            "iv_b64": base64.b64encode(ciphertext['iv']).decode('utf-8'),
            "data_b64": base64.b64encode(ciphertext['data']).decode('utf-8')
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"msg": f"Encryption error: {str(e)}"}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        pk_b64 = data.get('pk_b64')
        sk_b64 = data.get('sk_b64')
        ct_b64 = data.get('ct_b64')
        
        if not all([pk_b64, sk_b64, ct_b64]):
            return jsonify({"msg": "pk_b64, sk_b64, and ct_b64 are required"}), 400
            
        pk = bytesToObject(base64.b64decode(pk_b64), abe.group)
        sk = bytesToObject(base64.b64decode(sk_b64), abe.group)
        encrypted_data_from_s3 = base64.b64decode(ct_b64)

        abe_key_len = struct.unpack('!I', encrypted_data_from_s3[:4])[0]
        abe_key_bytes = encrypted_data_from_s3[4:4+abe_key_len]
        abe_key = bytesToObject(abe_key_bytes, abe.group)
        offset = 4 + abe_key_len
        iv_len = struct.unpack('!I', encrypted_data_from_s3[offset:offset+4])[0]
        iv = encrypted_data_from_s3[offset+4:offset+4+iv_len]
        offset = offset + 4 + iv_len
        data_len = struct.unpack('!I', encrypted_data_from_s3[offset:offset+4])[0]
        data = encrypted_data_from_s3[offset+4:offset+4+data_len]
        
        ciphertext = {'abe_key': abe_key, 'iv': iv, 'data': data}

        plaintext = abe.decrypt(pk, sk, ciphertext)

        if plaintext is None:
            return jsonify({
                "msg": "Decryption failed - Access denied",
                "reason": "Your attributes don't satisfy the file's access policy"
            }), 403

        return Response(plaintext, mimetype='application/octet-stream'), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({"msg": f"Decryption error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=5001,
        ssl_context=("certs/ta.crt", "certs/ta.key")
    )
