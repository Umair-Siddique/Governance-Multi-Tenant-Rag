"""
Encryption service for securely storing API keys at rest
Uses Fernet symmetric encryption from cryptography library
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from typing import Optional


class EncryptionService:
    """Service for encrypting and decrypting sensitive data like API keys"""
    
    def __init__(self, encryption_key: str):
        """
        Initialize encryption service
        
        Args:
            encryption_key: Base64-encoded Fernet key or a password string
                           If password string, it will be derived to a key
        """
        try:
            # Try to use as direct Fernet key (base64-encoded)
            self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        except Exception:
            # If not a valid Fernet key, derive one from the password
            # Convert string key to bytes if needed
            key_bytes = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
            
            # Use PBKDF2 to derive a key from the password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'governance_rag_salt',  # In production, use a unique salt per tenant
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
            self.fernet = Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string value
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty value")
        
        encrypted_bytes = self.fernet.encrypt(plaintext.encode())
        return encrypted_bytes.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string
        
        Args:
            ciphertext: Base64-encoded encrypted string
            
        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            raise ValueError("Cannot decrypt empty value")
        
        try:
            decrypted_bytes = self.fernet.decrypt(ciphertext.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


