# api_gateway/models.py

from datetime import datetime
from extensions import db
from sqlalchemy.dialects.postgresql import JSONB

class User(db.Model):
    __tablename__ = "users"
    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(50), unique=True, nullable=False)
    email          = db.Column(db.String(100), unique=True, nullable=False)
    password_hash  = db.Column(db.Text, nullable=False)
    role           = db.Column(db.String(50))
    department     = db.Column(db.String(50))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

class EhrFile(db.Model):
    __tablename__ = 'ehr_files'
    
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(255), nullable=False, unique=True)
    filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)  
    policy = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
