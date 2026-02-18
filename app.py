from flask import Flask
from config import Config

from extensions import init_supabase, init_email_service, init_token_service, init_encryption_service, init_pinecone_service

from blueprints.auth import auth_bp
from blueprints.llm_providers import llm_providers_bp
from blueprints.tenants import tenants_bp
from blueprints.invitations import invitations_bp, invite_accept_bp

from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow all origins with comprehensive settings
    CORS(app, 
         supports_credentials=True, 
         origins="*",
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
         expose_headers=['Content-Type', 'Authorization']
    )

    # Initialize extensions
    init_supabase(app)
    init_email_service(app)
    init_token_service(app)
    init_encryption_service(app)
    init_pinecone_service(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(llm_providers_bp, url_prefix="/api")
    app.register_blueprint(tenants_bp, url_prefix="/api")
    # Invitation CRUD under /api  (admin only)
    app.register_blueprint(invitations_bp, url_prefix="/api")
    # Invite acceptance under /auth  (public, no login required)
    app.register_blueprint(invite_accept_bp, url_prefix="/auth")


    return app