from supabase import create_client, Client
from config import Config
from utils.email_service import EmailService
from utils.token_service import TokenService
from utils.encryption_service import EncryptionService
from utils.pinecone_service import PineconeService
from openai import OpenAI
from celery import Celery


def init_supabase(app):
    """Initialize Supabase client"""
    if Config.SUPABASE_URL and Config.SUPABASE_SECRET_KEY:
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_SECRET_KEY)
        app.supabase_client = client
        
        print("✅ Supabase client initialized successfully")
    else:
        app.supabase_client = None
        print("⚠️  Supabase not configured - conversation storage disabled")


def init_email_service(app):
    """Initialize Email service"""
    if Config.ADMIN_EMAIL and Config.GMAIL_APP_PASSWORD:
        email_service = EmailService(Config.ADMIN_EMAIL, Config.GMAIL_APP_PASSWORD)
        app.email_service = email_service
        
        print("✅ Email service initialized successfully")
    else:
        app.email_service = None
        print("⚠️  Email service not configured - email verification disabled")


def init_token_service(app):
    """Initialize Token service"""
    token_service = TokenService(Config.SECRET_KEY)
    app.token_service = token_service
    
    print("✅ Token service initialized successfully")


def init_encryption_service(app):
    """Initialize Encryption service"""
    if Config.ENCRYPTION_KEY:
        encryption_service = EncryptionService(Config.ENCRYPTION_KEY)
        app.encryption_service = encryption_service
        
        print("✅ Encryption service initialized successfully")
    else:
        app.encryption_service = None
        print("⚠️  Encryption service not configured - API key encryption disabled")


def init_pinecone_service(app):
    """Initialize Pinecone service"""
    if Config.PINECONE_API_KEY:
        try:
            pinecone_service = PineconeService()
            app.pinecone_service = pinecone_service
            
            print("✅ Pinecone service initialized successfully")
        except Exception as e:
            app.pinecone_service = None
            print(f"⚠️  Pinecone service not configured: {str(e)}")
    else:
        app.pinecone_service = None
        print("⚠️  Pinecone not configured - vector database disabled")


def init_openai_service(app):
    """Initialize OpenAI Service"""
    app.openai_service = OpenAI(api_key=Config.OPENAI_API_KEY)


def init_celery(app):
    """Initialize Celery"""
    celery = Celery(
        app.import_name,
        broker=Config.CELERY_BROKER_URL,
        backend=Config.CELERY_RESULT_BACKEND,
    )
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
    )
    
    # Make Celery use Flask app context
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    app.celery = celery
    
    print("✅ Celery initialized successfully")
    return celery