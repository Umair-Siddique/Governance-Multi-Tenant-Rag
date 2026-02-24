import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
    
    # Secret key for token signing (can use same as Supabase or generate a new one)
    SECRET_KEY = os.getenv("SECRET_KEY", os.getenv("SUPABASE_SECRET_KEY"))
    
    # Encryption key for API keys (must be 32 bytes for Fernet)
    # Generate with: from cryptography.fernet import Fernet; Fernet.generate_key()
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", os.getenv("SECRET_KEY"))
    
    # Backend URL for verification links
    BACKEND_URL = os.getenv("BACKEND_URL")
    
    # Frontend URL (update based on your deployment)
    FRONTEND_URL = os.getenv("FRONTEND_URL")

    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")

    # Microsoft Entra ID (Azure AD) – OIDC via Supabase OAuth provider
    AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
    # e.g. https://login.microsoftonline.com/common/v2.0  (or a single-tenant URL)
    AZURE_TENANT_URL = os.getenv("AZURE_TENANT_URL", "https://login.microsoftonline.com/common")