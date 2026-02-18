"""
Token generation and verification service
"""
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from typing import Optional, Tuple


class TokenService:
    def __init__(self, secret_key: str):
        """
        Initialize token service
        
        Args:
            secret_key: Secret key for token signing
        """
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.verification_salt = "email-verification"
        self.password_reset_salt = "password-reset"
        self.invite_salt = "tenant-invite"
    
    def generate_verification_token(self, email: str) -> str:
        """
        Generate a verification token for an email
        
        Args:
            email: User's email address
        
        Returns:
            str: Signed token
        """
        return self.serializer.dumps(email, salt=self.verification_salt)
    
    def verify_token(self, token: str, max_age: int = 86400) -> Tuple[Optional[str], Optional[str]]:
        """
        Verify a token and extract the email
        
        Args:
            token: Token to verify
            max_age: Maximum age in seconds (default: 24 hours = 86400)
        
        Returns:
            Tuple[Optional[str], Optional[str]]: (email, error_message)
            - If successful: (email, None)
            - If failed: (None, error_message)
        """
        try:
            email = self.serializer.loads(token, salt=self.verification_salt, max_age=max_age)
            return email, None
        except SignatureExpired:
            return None, "Verification link has expired. Please request a new one."
        except BadSignature:
            return None, "Invalid verification link."
        except Exception as e:
            return None, f"Verification failed: {str(e)}"

    def generate_password_reset_token(self, email: str) -> str:
        """
        Generate a password reset token for an email

        Args:
            email: User's email address

        Returns:
            str: Signed token
        """
        return self.serializer.dumps(email, salt=self.password_reset_salt)

    def verify_password_reset_token(self, token: str, max_age: int = 3600) -> Tuple[Optional[str], Optional[str]]:
        """
        Verify a password reset token and extract the email

        Args:
            token: Token to verify
            max_age: Maximum age in seconds (default: 1 hour = 3600)

        Returns:
            Tuple[Optional[str], Optional[str]]: (email, error_message)
        """
        try:
            email = self.serializer.loads(token, salt=self.password_reset_salt, max_age=max_age)
            return email, None
        except SignatureExpired:
            return None, "Password reset link has expired. Please request a new one."
        except BadSignature:
            return None, "Invalid password reset link."
        except Exception as e:
            return None, f"Password reset failed: {str(e)}"

    def generate_invite_token(self, payload: dict) -> str:
        """
        Generate a signed invite token containing invitation metadata.

        Args:
            payload: dict with keys: invitation_id, tenant_id, email, role

        Returns:
            str: Signed token
        """
        return self.serializer.dumps(payload, salt=self.invite_salt)

    def verify_invite_token(self, token: str, max_age: int = 259200) -> Tuple[Optional[dict], Optional[str]]:
        """
        Verify an invite token and return the embedded payload.

        Args:
            token: Token to verify
            max_age: Maximum age in seconds (default: 72 hours = 259200)

        Returns:
            Tuple[Optional[dict], Optional[str]]: (payload, error_message)
        """
        try:
            payload = self.serializer.loads(token, salt=self.invite_salt, max_age=max_age)
            return payload, None
        except SignatureExpired:
            return None, "Invitation link has expired. Please ask your admin to send a new invite."
        except BadSignature:
            return None, "Invalid invitation link."
        except Exception as e:
            return None, f"Invitation verification failed: {str(e)}"

