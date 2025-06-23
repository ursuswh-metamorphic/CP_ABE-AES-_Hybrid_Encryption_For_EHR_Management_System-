from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import User
import requests
import traceback

keygen_bp = Blueprint('keygen', __name__, url_prefix='/api/keygen')

@keygen_bp.route('/', methods=['POST'])
@jwt_required()
def keygen():
    uid = get_jwt_identity()
    user = User.query.get_or_404(uid)

    if user.downloaded_sk:
        return jsonify({"msg": "Bạn chỉ được tải SK một lần. Vui lòng liên hệ quản trị viên để được cấp lại."}), 403

    try:
        res = requests.post(
            "https://127.0.0.1:5001/keygen",
            json={"attributes": request.json.get('attributes', [])},
            timeout=5,
            verify=False
        )
        res.raise_for_status()
    except Exception as e:
        traceback.print_exc()
        return jsonify({"msg": "Failed to connect to TA service", "error": str(e)}), 500

    data = res.json()
    sk = data.get('sk') or data.get('secret_key')
    if not sk:
        return jsonify({"msg": "TA service trả về không có SK"}), 500

    user.downloaded_sk = True
    db.session.commit()

    return jsonify({"sk": sk}), 200