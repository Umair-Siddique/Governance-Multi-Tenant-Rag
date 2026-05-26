from flask import Flask
from config import Config

from extensions import (
    init_supabase,
    init_email_service,
    init_token_service,
    init_encryption_service,
    init_pinecone_service,
    init_openai_service,
    init_celery,
)

from blueprints.auth import auth_bp
from blueprints.llm_providers import llm_providers_bp
from blueprints.tenants import tenants_bp
from blueprints.invitations import invitations_bp, invite_accept_bp
from blueprints.document_upload import document_upload_bp
from blueprints.retriever import retriever_bp
from blueprints.chats import chats_bp
from blueprints.user_preferences import user_preferences_bp
from blueprints.audit_logs import audit_logs_bp
from blueprints.branding import branding_bp

from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # r"https://[a-z0-9][a-z0-9-]*\.elorag\.com$" matches any white-label subdomain.
    # Flask-CORS evaluates each origin with re.match(), so the trailing $ is required
    # to prevent prefix attacks like https://tenant.elorag.com.evil.com.
    CORS(app,
         supports_credentials=True,
         origins=[
             "https://governance-saas.vercel.app",
             "http://localhost:5173",
             "https://governance-multi-tenant-ui.vercel.app",
             "https://www.elorag.com",
             "https://elorag.com",
             r"https://[a-z0-9][a-z0-9-]*\.elorag\.com$",
         ],
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
    init_openai_service(app)
    
    # Initialize Celery tasks with app context
    init_celery(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(llm_providers_bp, url_prefix="/api")
    app.register_blueprint(tenants_bp, url_prefix="/api")
    # Invitation CRUD under /api  (admin only)
    app.register_blueprint(invitations_bp, url_prefix="/api")
    # Invite acceptance under /auth  (public, no login required)
    app.register_blueprint(invite_accept_bp, url_prefix="/auth")
    app.register_blueprint(document_upload_bp, url_prefix="/api")
    app.register_blueprint(retriever_bp, url_prefix="/api")
    app.register_blueprint(chats_bp, url_prefix="/api")
    app.register_blueprint(user_preferences_bp, url_prefix="/api")
    app.register_blueprint(branding_bp, url_prefix="/api")
    app.register_blueprint(audit_logs_bp, url_prefix="/api")

    return app