from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import requests

keygen_bp = Blueprint('keygen', __name__, url_prefix='/api/keygen')

@keygen_bp.route('/', methods=['POST'])
@jwt_required()
def keygen():
    attrs = request.json.get('attributes')
    if not attrs: 
        return jsonify({"msg":"Missing attributes"}),400
    
    
    try:
        res = requests.post("http:localhost:5001/keygen",
            json={"attributes": attrs},
            timeout=5
        )
        if res.status_code != 200:
            return jsonify({"msg": "TA service error", "detail": res.text}), 500
        data = res.json()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"msg": "Failed to connect to TA service", "error": str(e)}), 500