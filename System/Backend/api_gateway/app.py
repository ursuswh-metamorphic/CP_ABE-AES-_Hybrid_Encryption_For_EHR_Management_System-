import ssl
from flask import Flask
from config import Config
from extensions import db, jwt, migrate
from routes.auth import auth_bp
from routes.keygen import keygen_bp
from routes.ehr import ehr_bp

def create_app():
    app = Flask(__name__)
    from flask_cors import CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(keygen_bp)
    app.register_blueprint(ehr_bp)
    return app

if __name__ == "__main__":
    app = create_app()
    
    # Cấu hình TLS 1.3 cho HTTPS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # Force TLS 1.3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Load SSL certificates
    # Sử dụng ta.crt và ta.key từ thư mục gốc
    import os
    cert_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certs', 'ta.crt')
    key_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certs', 'ta.key')
    
    try:
        context.load_cert_chain(cert_path, key_path)
        print("Starting API Gateway with HTTPS (TLS 1.3)")
        app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=True)
    except FileNotFoundError as e:
        print(f"SSL Certificate not found: {e}")
        print("Falling back to HTTP (insecure)")
        app.run(host='0.0.0.0', port=5000, debug=True)