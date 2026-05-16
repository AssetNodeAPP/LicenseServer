#!/usr/bin/env python3
"""
Secure Key Signing Module
Provides HMAC-based signing of license encryption keys to prevent tampering

Copyright (c) 2026 AssetNode LLC
All rights reserved. Proprietary and confidential software.
Email: support@assetnode.app
"""

import hmac
import hashlib
import base64
import struct
from cryptography.fernet import Fernet


class SecureKeySigner:
    """
    Handles signing and verification of license encryption keys using HMAC.
    Prevents key tampering by embedding a cryptographic signature.
    """
    
    # Hardcoded signing secret - NEVER change this in deployed applications!
    # This secret is baked into the application code and used to verify key authenticity
    _SIGNING_SECRET = b"DIMS_KEY_SIGN_SECRET_2024_V1_SECURE_WOULD_YOU_LIKE_TO_PLAY_A_GAME"
    
    @classmethod
    def sign_key(cls, encryption_key: bytes) -> bytes:
        """
        Sign an encryption key with HMAC and create a signed key file.
        
        Args:
            encryption_key: The Fernet encryption key to sign
            
        Returns:
            Signed key data that can be written to .key.pub file
            Format: [signature_len(4)][signature][key]
        """
        # Generate HMAC signature of the encryption key
        signature = hmac.new(
            cls._SIGNING_SECRET,
            encryption_key,
            hashlib.sha256
        ).digest()
        
        # Pack signature length (4 bytes) + signature + key
        signature_len = len(signature)
        signed_data = struct.pack('<I', signature_len) + signature + encryption_key
        
        return signed_data
    
    @classmethod
    def verify_and_extract_key(cls, signed_key_data: bytes) -> bytes:
        """
        Verify HMAC signature and extract the original encryption key.
        
        Args:
            signed_key_data: Signed key data from file
            
        Returns:
            Original encryption key if signature is valid
            
        Raises:
            ValueError: If signature verification fails or data is corrupted
        """
        if len(signed_key_data) < 4:
            raise ValueError("Invalid signed key data: too short")
        
        # Extract signature length
        signature_len = struct.unpack('<I', signed_key_data[:4])[0]
        
        if len(signed_key_data) < 4 + signature_len:
            raise ValueError("Invalid signed key data: incomplete signature")
        
        # Extract signature and key
        signature = signed_key_data[4:4 + signature_len]
        encryption_key = signed_key_data[4 + signature_len:]
        
        # Verify HMAC signature
        expected_signature = hmac.new(
            cls._SIGNING_SECRET,
            encryption_key,
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError(
                "INVALID KEY SIGNATURE!\n\n"
                "The license key file appears to have been tampered with or modified.\n"
                "Please use the original key files provided by your software vendor.\n"
                "Contact support if you believe this is an error."
            )
        
        return encryption_key
    
    @classmethod
    def is_key_signed(cls, key_data: bytes) -> bool:
        """
        Check if key data appears to be in signed format.
        
        Args:
            key_data: Key data from file
            
        Returns:
            True if data appears to be signed, False if it's raw key
        """
        if len(key_data) < 4:
            return False
        
        try:
            signature_len = struct.unpack('<I', key_data[:4])[0]
            # Reasonable signature length check (SHA256 = 32 bytes)
            return signature_len == 32 and len(key_data) >= 4 + signature_len + 44  # 44 = Fernet key length
        except:
            return False


class SecureFernet:
    """
    Wrapper around Fernet that uses signed keys automatically.
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet key"""
        return Fernet.generate_key()
    
    @staticmethod
    def create_signed_key_file(encryption_key: bytes, file_path: str):
        """
        Create a signed key file.
        
        Args:
            encryption_key: The encryption key to sign and save
            file_path: Path to save the signed key file
        """
        signed_data = SecureKeySigner.sign_key(encryption_key)
        with open(file_path, 'wb') as f:
            f.write(signed_data)
    
    @staticmethod
    def load_and_verify_key(file_path: str) -> bytes:
        """
        Load and verify a signed key file.
        
        Args:
            file_path: Path to the signed key file
            
        Returns:
            Verified encryption key
            
        Raises:
            ValueError: If signature verification fails
        """
        with open(file_path, 'rb') as f:
            signed_data = f.read()
        
        return SecureKeySigner.verify_and_extract_key(signed_data)
    
    @staticmethod
    def create_fernet_from_signed_key(file_path: str) -> Fernet:
        """
        Create a Fernet instance from a signed key file.
        
        Args:
            file_path: Path to the signed key file
            
        Returns:
            Fernet instance with verified key
            
        Raises:
            ValueError: If signature verification fails
        """
        verified_key = SecureFernet.load_and_verify_key(file_path)
        return Fernet(verified_key)