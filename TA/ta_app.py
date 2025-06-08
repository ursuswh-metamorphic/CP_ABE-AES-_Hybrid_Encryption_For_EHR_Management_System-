from flask import Flask, request, jsonify
from System.Backend.api_gateway.abe_core import ABECore
import os, base64, hashlib, pickle
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

if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=5001,
        ssl_context=("certs/ta.crt", "certs/ta.key")
    )
