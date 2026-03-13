import os
import sys
from dotenv import load_dotenv

load_dotenv()


def _default_tesseract_cmd():
    """Tesseract path: from env, or on Windows only default to local install."""
    cmd = os.getenv("TESSERACT_CMD")
    if cmd is not None and cmd.strip():
        return cmd.strip()
    # Production (e.g. Render): leave unset so pytesseract uses system tesseract from PATH
    if sys.platform == "win32":
        return os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Tesseract-OCR", "tesseract.exe")
    return None


class Config:
    SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
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
    AZURE_TENANT_URL = os.getenv("AZURE_TENANT_URL")

    # Tesseract OCR: set TESSERACT_CMD in .env to override. On Windows, defaults to Program Files path when unset; on Render/Linux leave unset to use system tesseract from PATH.
    TESSERACT_CMD = _default_tesseract_cmd()

    # Celery configuration
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND")