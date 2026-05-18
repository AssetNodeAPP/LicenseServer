#!/usr/bin/env python3
"""
Configuration Module for AssetNode DIMS
Handles encrypted storage of license and configuration data.

Copyright (c) 2026 AssetNode LLC
All rights reserved. Proprietary and confidential software.
"""

import base64
import json
import os
import sys
from cryptography.fernet import Fernet

def _get_data_dir():
    env_dir = os.environ.get("LICENSE_DATA_DIR", "")
    if env_dir:
        return env_dir
    if getattr(sys, 'frozen', False):
        # PyInstaller onefile: sys.executable is /tmp/_MEIxxx, use the real exe path
        if hasattr(sys, '_MEIPASS'):
            exe_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        else:
            exe_dir = os.path.dirname(os.path.realpath(sys.executable))
        return os.path.join(exe_dir, "data")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

DATA_DIR = _get_data_dir()
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, "config.py")
LICENSE_KEY_FILE = os.path.join(DATA_DIR, ".license")
CONFIG_TXT_FILE = os.path.join(DATA_DIR, "config.txt")

_SIGNING_SECRET = b"DIMS_CONFIG_SECRET_2024_V1_ENCRYPTER_WOULD_YOU_LIKE_TO_PLAY_A_GAME"


def _get_encryption_key() -> bytes:
    """Derive a consistent encryption key from the signing secret"""
    import hashlib
    key = hashlib.sha256(_SIGNING_SECRET).digest()
    return base64.urlsafe_b64encode(key)


class EncryptedLicenseStore:
    """Handles encrypted storage and retrieval of license data"""
    
    @classmethod
    def save_license(cls, encrypted_license: str, session_key: str, customer_number: str, 
                     server_url: str, mac_address: str, expiry_date: str, license_key: str = None):
        """
        Save license data encrypted in config.py
        
        Args:
            encrypted_license: AES encrypted license from server (base64 string)
            session_key: Session encryption key (base64 string)
            customer_number: Customer number from server
            server_url: License server URL
            mac_address: MAC address of this machine
            expiry_date: License expiry date
            license_key: Original license key (XXXX-XXXX-XXXX-XXXX-XXXX) for auto re-auth
        """
        license_data = {
            'encrypted_license': encrypted_license,
            'session_key': session_key,
            'customer_number': customer_number,
            'server_url': server_url,
            'mac_address': mac_address,
            'expiry_date': expiry_date,
            'license_key': license_key or ''
        }
        
        json_data = json.dumps(license_data)
        
        fernet = Fernet(_get_encryption_key())
        encrypted = fernet.encrypt(json_data.encode())
        
        with open(LICENSE_KEY_FILE, 'wb') as f:
            f.write(encrypted)
    
    @classmethod
    def load_license(cls) -> dict:
        """
        Load and decrypt license data
        
        Returns:
            dict with license data or empty dict if no license
        """
        if not os.path.exists(LICENSE_KEY_FILE):
            return {}
        
        try:
            with open(LICENSE_KEY_FILE, 'rb') as f:
                encrypted = f.read()
            
            fernet = Fernet(_get_encryption_key())
            json_data = fernet.decrypt(encrypted)
            
            return json.loads(json_data)
        except Exception as e:
            print(f"Failed to load license: {e}")
            return {}
    
    @classmethod
    def license_exists(cls) -> bool:
        """Check if stored license exists"""
        return os.path.exists(LICENSE_KEY_FILE)
    
    @classmethod
    def clear_license(cls):
        """Remove stored license"""
        if os.path.exists(LICENSE_KEY_FILE):
            os.remove(LICENSE_KEY_FILE)
    
    @classmethod
    def get_session_key(cls) -> str:
        """Get stored session key"""
        data = cls.load_license()
        return data.get('session_key', '')
    
    @classmethod
    def get_customer_number(cls) -> str:
        """Get stored customer number"""
        data = cls.load_license()
        return data.get('customer_number', '')
    
    @classmethod
    def get_server_url(cls) -> str:
        """Get stored server URL"""
        data = cls.load_license()
        return data.get('server_url', '')
    
    @classmethod
    def get_expiry_date(cls) -> str:
        """Get stored expiry date"""
        data = cls.load_license()
        return data.get('expiry_date', '')
    
    @classmethod
    def get_encrypted_license(cls) -> str:
        """Get stored encrypted license"""
        data = cls.load_license()
        return data.get('encrypted_license', '')
    
    @classmethod
    def get_license_key(cls) -> str:
        """Get stored license key for auto re-auth"""
        data = cls.load_license()
        return data.get('license_key', '')