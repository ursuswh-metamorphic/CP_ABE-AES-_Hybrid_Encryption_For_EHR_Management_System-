from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from extensions import db
from models import User
import bcrypt
from schemas import LoginSchema
from schemas import ChangePasswordSchema

change_pw_schema = ChangePasswordSchema()

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
login_schema = LoginSchema()


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(); errs = login_schema.validate(data)
    if errs: return jsonify(errs),400
    u = User.query.filter_by(email=data['email']).first()
    if u and bcrypt.checkpw(data['password'].encode(), u.password_hash.encode()):
        return jsonify({"access_token": create_access_token(identity=u.id)}),200
    return jsonify({"msg":"Invalid credentials"}),401

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    u = User.query.get(get_jwt_identity())
    return jsonify({"id":u.id,"username":u.username,"role":u.role,"department":u.department}),200



@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    errs = change_pw_schema.validate(data)
    if errs:
        return jsonify(errs), 400

    user = User.query.get(get_jwt_identity())

    if not bcrypt.checkpw(data['old_password'].encode(), user.password_hash.encode()):
        return jsonify({"msg": "Old password is incorrect"}), 403

    hashed_new_pw = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt())
    user.password_hash = hashed_new_pw.decode()
    db.session.commit()

    return jsonify({"msg": "Password changed successfully"}), 200
