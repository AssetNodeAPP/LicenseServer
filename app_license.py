#!/usr/bin/env python3
"""
License Generator - Flask Web Application
Modern web interface for generating and managing software licenses.

Copyright (c) 2026 AssetNode LLC
All rights reserved. Proprietary and confidential software.
"""

import base64
import hashlib
import io
import json
import os
import random
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import smtplib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, session, flash
from waitress import serve

from secure_key_signer import SecureFernet, SecureKeySigner

def _get_data_dir():
    env_dir = os.environ.get("LICENSE_DATA_DIR", "")
    if env_dir:
        return env_dir
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            exe_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        else:
            exe_dir = os.path.dirname(os.path.realpath(sys.executable))
        return os.path.join(exe_dir, "data")
    if sys.platform.startswith("linux"):
        return os.path.join(os.path.expanduser("~"), "Documents")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

DATA_DIR = _get_data_dir()
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

DB_FILE = os.path.join(DATA_DIR, "license_database.db")

# RSA Key paths
RSA_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "server_private_key.pem")
RSA_PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "server_public_key.pem")

# Server's RSA keys (generated once, stored in files)
_server_private_key = None
_server_public_key = None


def _generate_rsa_keys():
    """Generate and store RSA keys for asymmetric encryption"""
    global _server_private_key, _server_public_key
    
    if os.path.exists(RSA_PRIVATE_KEY_FILE) and os.path.exists(RSA_PUBLIC_KEY_FILE):
        # Load existing keys
        with open(RSA_PRIVATE_KEY_FILE, 'rb') as f:
            _server_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(RSA_PUBLIC_KEY_FILE, 'rb') as f:
            _server_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    else:
        # Generate new keys
        _server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        _server_public_key = _server_private_key.public_key()
        
        # Save keys
        with open(RSA_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(_server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(RSA_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(_server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return _server_public_key


def get_server_public_key_pem():
    """Get server's public key as PEM for clients"""
    if _server_public_key is None:
        _generate_rsa_keys()
    return _server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def decrypt_with_rsa(data: bytes) -> bytes:
    """Decrypt data using server's private RSA key"""
    if _server_private_key is None:
        _generate_rsa_keys()
    
    key_size_bytes = _server_private_key.key_size // 8
    decoded_data = base64.b64decode(data)
    
    if len(decoded_data) != key_size_bytes:
        raise ValueError(f"Invalid ciphertext length: expected {key_size_bytes}, got {len(decoded_data)}")
    
    return _server_private_key.decrypt(
        decoded_data,
        padding.PKCS1v15()
    )


def rsa_encrypt(data: bytes) -> bytes:
    """Encrypt data using server's public RSA key"""
    if _server_public_key is None:
        _generate_rsa_keys()
    return base64.b64encode(_server_public_key.encrypt(
        data,
        padding.PKCS1v15()
    ))


# Initialize RSA keys on startup
_generate_rsa_keys()


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def log_action(action, entity_type, entity_id=None, entity_name=None, details=None, user=None):
    """Log an action to the audit_logs table"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, action, entity_type, entity_id, entity_name, details, user)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), action, entity_type, str(entity_id) if entity_id else None, entity_name, details, user or 'system'))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to write audit log: {e}")


def init_database():
    """Initialize SQLite database"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT UNIQUE NOT NULL,
            customer_name TEXT,
            customer_email TEXT,
            mac_address TEXT NOT NULL,
            issued_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            renewal_code TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            perpetual BOOLEAN DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS renewals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL,
            renewal_id TEXT NOT NULL,
            generated_date TEXT NOT NULL,
            additional_days INTEGER NOT NULL,
            previous_expiry TEXT NOT NULL,
            new_expiry TEXT NOT NULL,
            FOREIGN KEY (license_id) REFERENCES licenses (license_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS smtp_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            smtp_server TEXT NOT NULL,
            smtp_port INTEGER NOT NULL,
            sender_email TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            use_tls BOOLEAN DEFAULT 1,
            created_date TEXT NOT NULL,
            updated_date TEXT NOT NULL
        )
    ''')

    # New customers table for online licensing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_number TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            status TEXT DEFAULT 'active',
            stripe_subscription_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')

    # Customer licenses table for online licensing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customer_licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            license_key TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            mac_address TEXT,
            ip_address TEXT,
            auto_renew BOOLEAN DEFAULT 0,
            stripe_subscription_id TEXT,
            stripe_price_id TEXT,
            renewal_interval TEXT DEFAULT 'yearly',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')

    # License sessions for managing active client sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS license_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            session_key_encrypted TEXT NOT NULL,
            mac_address TEXT,
            ip_address TEXT,
            last_check_in TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
        FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')

    # Migration: add customer_license_id to license_sessions (scopes sessions to a specific license)
    try:
        cursor.execute('ALTER TABLE license_sessions ADD COLUMN customer_license_id INTEGER REFERENCES customer_licenses(id)')
    except Exception:
        pass  # Column already exists
    
    # Stripe settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stripe_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            stripe_api_key TEXT,
            stripe_webhook_secret TEXT,
            created_date TEXT NOT NULL,
            updated_date TEXT NOT NULL
        )
    ''')

    # Stripe prices mapping table - maps Stripe Price IDs to tier types
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stripe_prices (
            stripe_price_id TEXT PRIMARY KEY,
            tier_type TEXT NOT NULL,
            display_name TEXT,
            amount_cents INTEGER,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    ''')

    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            entity_name TEXT,
            details TEXT,
            user TEXT DEFAULT 'system'
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac_address ON licenses (mac_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_license_id ON licenses (license_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_renewal_license_id ON renewals (license_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_number ON customers (customer_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_customer_id ON customer_licenses (customer_id)')

    cursor.execute("PRAGMA table_info(licenses)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'customer_email' not in columns:
        cursor.execute("ALTER TABLE licenses ADD COLUMN customer_email TEXT")

    cursor.execute("PRAGMA table_info(customer_licenses)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'auto_renew' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN auto_renew BOOLEAN DEFAULT 0")
    if 'stripe_subscription_id' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN stripe_subscription_id TEXT")
    if 'stripe_price_id' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN stripe_price_id TEXT")
    if 'renewal_interval' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN renewal_interval TEXT DEFAULT 'yearly'")
    if 'nickname' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN nickname TEXT")
    if 'ip_address' not in columns:
        cursor.execute("ALTER TABLE customer_licenses ADD COLUMN ip_address TEXT")

    cursor.execute("PRAGMA table_info(license_sessions)")
    ls_columns = [column[1] for column in cursor.fetchall()]
    if 'ip_address' not in ls_columns:
        cursor.execute("ALTER TABLE license_sessions ADD COLUMN ip_address TEXT")

    conn.commit()
    conn.close()


init_database()


USERS_FILE = os.path.join(DATA_DIR, "license_users.json")


def _load_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and 'users' in data:
                return data
            return {'users': {}}
    except Exception:
        return {'users': {}}


def _save_users(data):
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print("Failed to write users file:", e)
        return False


def _verify_password(plain, hashed):
    try:
        if not isinstance(hashed, str) or not hashed.startswith("bcrypt:"):
            return False
        hash_part = hashed.split("bcrypt:", 1)[1]
        result = bcrypt.checkpw(plain.encode("utf-8"), hash_part.encode("utf-8"))
        return result
    except Exception:
        return False


def current_user():
    u = session.get("user")
    if not u:
        return None
    users_data = _load_users()
    users = users_data.get('users', {})
    rec = users.get(u)
    if not rec:
        return None
    return {
        "username": u,
        "role": (rec.get("role") or "user"),
        "email": rec.get("email", "")
    }


@app.context_processor
def inject_current_user():
    return {"current_user": current_user()}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required', 'login_url': '/login'}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        if user.get("role") != "admin":
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return wrapper


def _create_default_admin():
    users_data = _load_users()
    if 'admin' not in users_data.get('users', {}):
        password = "admin123"
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        if 'users' not in users_data:
            users_data['users'] = {}
        users_data['users']['admin'] = {
            "password": f"bcrypt:{hashed}",
            "role": "admin",
            "email": "",
            "failed_attempts": 0,
            "locked_until": None
        }
        _save_users(users_data)


_create_default_admin()


def load_smtp_settings():
    """Load SMTP settings from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT smtp_server, smtp_port, sender_email, encrypted_password, use_tls FROM smtp_settings WHERE id = 1')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            smtp_server, smtp_port, sender_email, encrypted_password, use_tls = result
            password = base64.b64decode(encrypted_password.encode()).decode()
            return {
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'sender_email': sender_email,
                'password': password,
                'use_tls': bool(use_tls)
            }
    except Exception as e:
        print(f"Error loading SMTP settings: {e}")
    conn.close()
    return None


def save_smtp_settings(settings):
    """Save SMTP settings to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        encrypted_password = base64.b64encode(settings['password'].encode()).decode()
        now = datetime.now().isoformat()
        
        cursor.execute('SELECT id FROM smtp_settings WHERE id = 1')
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE smtp_settings 
                SET smtp_server = ?, smtp_port = ?, sender_email = ?, encrypted_password = ?, use_tls = ?, updated_date = ?
                WHERE id = 1
            ''', (
                settings['smtp_server'],
                settings['smtp_port'],
                settings['sender_email'],
                encrypted_password,
                settings['use_tls'],
                now
            ))
        else:
            cursor.execute('''
                INSERT INTO smtp_settings 
                (id, smtp_server, smtp_port, sender_email, encrypted_password, use_tls, created_date, updated_date)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                settings['smtp_server'],
                settings['smtp_port'],
                settings['sender_email'],
                encrypted_password,
                settings['use_tls'],
                now,
                now
            ))
        
        conn.commit()
        conn.close()
        log_action('UPDATE', 'settings', None, None, f"SMTP settings updated (server: {settings['smtp_server']}, email: {settings['sender_email']})")
        return True
    except Exception as e:
        conn.close()
        return False


def test_smtp_connection(settings):
    """Test SMTP connection"""
    try:
        with smtplib.SMTP(settings['smtp_server'], settings['smtp_port']) as server:
            if settings['use_tls']:
                server.starttls()
            server.login(settings['sender_email'], settings['password'])
        return True, "Connection successful!"
    except Exception as e:
        return False, str(e)


def generate_customer_number():
    """Generate a unique 10-digit random customer number"""
    while True:
        number = ''.join([str(random.randint(0, 9)) for _ in range(10)])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM customers WHERE customer_number = ?', (number,))
        if not cursor.fetchone():
            conn.close()
            return number


def generate_license_key():
    """Generate a license key in format XXXX-XXXX-XXXX-XXXX-XXXX"""
    segments = []
    for _ in range(5):
        segment = ''.join([random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4)])
        segments.append(segment)
    return '-'.join(segments)


def encrypt_with_aes(data: dict, key: bytes) -> str:
    """Encrypt data dict with AES Fernet key, return base64 string"""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    return base64.b64encode(encrypted).decode()


def decrypt_with_aes(encrypted_data: str, key: bytes) -> dict:
    """Decrypt base64 AES encrypted data, return dict"""
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(base64.b64decode(encrypted_data)).decode())


def load_stripe_settings():
    """Load Stripe settings from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT stripe_api_key, stripe_webhook_secret FROM stripe_settings WHERE id = 1')
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'stripe_api_key': result[0], 'stripe_webhook_secret': result[1]}
    except:
        pass
    conn.close()
    return None


def save_stripe_settings(api_key: str, webhook_secret: str):
    """Save Stripe settings to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.now().isoformat()
        cursor.execute('SELECT id FROM stripe_settings WHERE id = 1')
        existing = cursor.fetchone()
        if existing:
            cursor.execute('''
                UPDATE stripe_settings 
                SET stripe_api_key = ?, stripe_webhook_secret = ?, updated_date = ?
                WHERE id = 1
            ''', (api_key, webhook_secret, now))
        else:
            cursor.execute('''
                INSERT INTO stripe_settings 
                (id, stripe_api_key, stripe_webhook_secret, created_date, updated_date)
                VALUES (1, ?, ?, ?, ?)
            ''', (api_key, webhook_secret, now, now))
        conn.commit()
        conn.close()
        key_preview = api_key[:8] + '...' if api_key else 'None'
        log_action('UPDATE', 'settings', None, None, f"Stripe settings updated (API key: {key_preview})")
        return True
    except Exception as e:
        conn.close()
        return False


def send_email(recipient_email, subject, body, attachment_path=None, smtp_config=None, html_body=None):
    """Send email with optional attachment and HTML content"""
    if not smtp_config:
        return False, "SMTP not configured"
    
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_config['sender_email']
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))
            msg.attach(MIMEText(body, 'plain'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                msg.attach(part)
        
        with smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port']) as server:
            if smtp_config['use_tls']:
                server.starttls()
            server.login(smtp_config['sender_email'], smtp_config['password'])
            server.send_message(msg)
        
        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)


def generate_license_email_html(customer_name, customer_number, license_key, expiry_date, status, mac_address, auto_renew, renewal_interval, stripe_subscription_id, custom_message='', smtp_config=None, tier_type='', display_name=''):
    """Generate professional HTML email template for license details"""
    now = datetime.now().strftime('%B %d, %Y')
    status_color = '#10b981' if status == 'active' else '#ef4444' if status in ['cancelled', 'suspended'] else '#f59e0b'
    status_text = status.title()
    
    auto_renew_html = ''
    if auto_renew:
        interval_text = renewal_interval.title() if renewal_interval else 'Yearly'
        stripe_html = f'<div style="color: #6b7280; font-size: 13px; margin-top: 4px;">Managed via Stripe subscription</div>' if stripe_subscription_id else ''
        auto_renew_html = f'''
        <tr>
            <td style="padding: 16px; background-color: #f0fdf4; border-bottom: 1px solid #e5e7eb;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="background-color: #10b981; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">AUTO-RENEWAL</span>
                    <span style="color: #374151; font-weight: 500;">Enabled ({interval_text})</span>
                </div>
                {stripe_html}
            </td>
        </tr>
        '''
    
    custom_message_html = ''
    if custom_message:
        custom_message_html = f'''
        <tr>
            <td style="padding: 16px; background-color: #eff6ff; border-bottom: 1px solid #e5e7eb;">
                <div style="color: #1e40af; font-size: 13px; font-weight: 500; margin-bottom: 8px;">NOTE FROM SUPPORT:</div>
                <div style="color: #374151; font-size: 14px; line-height: 1.6;">{custom_message}</div>
            </td>
        </tr>
        '''
    
    sender_email = smtp_config['sender_email'] if smtp_config else 'support@assetnode.com'
    
    tier_type_color = '#6366f1' if tier_type == 'yearly' else '#10b981' if tier_type == 'monthly' else '#8b5cf6'
    tier_display = display_name or (tier_type.title() if tier_type else '')
    tier_html = ''
    if tier_display:
        tier_html = f'''
        <tr>
            <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">Plan:</td>
            <td style="padding: 8px 0;">
                <span style="background-color: {tier_type_color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">{tier_display}</span>
            </td>
        </tr>
        '''

    html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Details</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <table role="presentation" style="width: 100%; border-collapse: collapse; background-color: #f3f4f6;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table role="presentation" style="max-width: 600px; width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 32px; text-align: center;">
                            <div style="margin-bottom: 16px;">
                                <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" style="display: inline-block;">
                                    <rect width="64" height="64" rx="16" fill="white" fill-opacity="0.2"/>
                                    <path d="M32 16L20 24V40L32 48L44 40V24L32 16Z" fill="white" stroke="white" stroke-width="2" stroke-linejoin="round"/>
                                    <path d="M32 24V40M24 28L32 32L40 28" stroke="#667eea" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">AssetNode</h1>
                            <p style="margin: 8px 0 0 0; color: rgba(255, 255, 255, 0.9); font-size: 14px; font-weight: 500;">License Management System</p>
                        </td>
                    </tr>
                    
                    <!-- Welcome Message -->
                    <tr>
                        <td style="padding: 32px 32px 24px 32px;">
                            <h2 style="margin: 0 0 12px 0; color: #111827; font-size: 22px; font-weight: 600;">Welcome, {customer_name}!</h2>
                            <p style="margin: 0; color: #6b7280; font-size: 15px; line-height: 1.6;">Thank you for your purchase! Your license details are below. Please keep this information secure.</p>
                        </td>
                    </tr>
                    
                    <!-- License Details Card -->
                    <tr>
                        <td style="padding: 0 32px 32px 32px;">
                            <table style="width: 100%; border-collapse: collapse; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
                                <tr>
                                    <td style="background-color: #f9fafb; padding: 16px; border-bottom: 1px solid #e5e7eb;">
                                        <div style="color: #6b7280; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">CUSTOMER INFORMATION</div>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 16px; border-bottom: 1px solid #e5e7eb;">
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px; width: 140px;">Customer Number:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 600; font-family: 'Courier New', monospace;">{customer_number}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">Customer Name:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 600;">{customer_name}</td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background-color: #f9fafb; padding: 16px; border-bottom: 1px solid #e5e7eb;">
                                        <div style="color: #6b7280; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">LICENSE DETAILS</div>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 16px; border-bottom: 1px solid #e5e7eb;">
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px; width: 140px;">License Key:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 600; font-family: 'Courier New', monospace; background-color: #f3f4f6; padding: 8px 12px; border-radius: 4px; display: inline-block;">{license_key}</td>
                                            </tr>
                                            {tier_html}
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">Status:</td>
                                                <td style="padding: 8px 0;">
                                                    <span style="background-color: {status_color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">{status_text}</span>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">MAC Address:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 500;">{mac_address or 'Any (not bound)'}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">Issued Date:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 500;">{now}</td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 8px 0; color: #6b7280; font-size: 14px;">Expiry Date:</td>
                                                <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 600;">{expiry_date[:10]}</td>
                                            </tr>
                                            {auto_renew_html}
                                            {custom_message_html}
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Important Notes -->
                    <tr>
                        <td style="padding: 0 32px 32px 32px;">
                            <table style="width: 100%; border-collapse: collapse; background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px;">
                                <tr>
                                    <td style="padding: 16px;">
                                        <div style="color: #92400e; font-size: 14px; font-weight: 600; margin-bottom: 8px;">Important:</div>
                                        <ul style="margin: 0; padding-left: 20px; color: #78350f; font-size: 13px; line-height: 1.8;">
                                            <li>Keep your license key secure and do not share it with others</li>
                                            <li>This license is bound to the MAC address specified above (if applicable)</li>
                                            <li>Contact support if you need to transfer this license to a new machine</li>
                                        </ul>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Support Section -->
                    <tr>
                        <td style="padding: 0 32px 32px 32px;">
                            <table style="width: 100%; border-collapse: collapse; background-color: #f9fafb; border-radius: 8px; padding: 24px;">
                                <tr>
                                    <td style="text-align: center;">
                                        <div style="color: #6b7280; font-size: 13px; font-weight: 600; margin-bottom: 12px;">NEED HELP?</div>
                                        <div style="color: #111827; font-size: 14px; margin-bottom: 8px;">Our support team is here to assist you</div>
                                        <a href="mailto:{sender_email}" style="color: #667eea; font-size: 14px; font-weight: 600; text-decoration: none;">{sender_email}</a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f9fafb; padding: 24px 32px; text-align: center; border-top: 1px solid #e5e7eb;">
                            <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px;">Thank you for choosing AssetNode!</p>
                            <p style="margin: 0; color: #9ca3af; font-size: 12px;">Best regards,<br><strong>AssetNode Support Team</strong></p>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    '''
    
    return html.strip()


class MACLicenseGenerator:
    """License generator class"""
    
    def __init__(self):
        self.master_key = Fernet.generate_key()
        self.fernet = Fernet(self.master_key)
    
    def generate_initial_license(self, mac_address, customer_name="", expiry_days=365, is_perpetual=False):
        mac_normal = mac_address.upper().replace(':', '').replace('-', '')
        mac_formatted = ':'.join([mac_normal[i:i + 2] for i in range(0, 12, 2)])
        
        if is_perpetual:
            expiry_date = datetime.now() + timedelta(days=365000)
        else:
            expiry_date = datetime.now() + timedelta(days=expiry_days)
        
        license_data = {
            "id": str(uuid.uuid4()),
            "mac_address": mac_formatted,
            "customer_name": customer_name,
            "issued_date": datetime.now().isoformat(),
            "expiry_date": expiry_date.isoformat(),
            "features": ["full_access"],
            "renewal_code": self._generate_renewal_code(mac_formatted),
            "version": "1.0",
            "perpetual": is_perpetual
        }
        
        encrypted = self.fernet.encrypt(json.dumps(license_data).encode())
        return encrypted, self.master_key, license_data
    
    def _generate_renewal_code(self, mac_address):
        return hashlib.sha256(
            f"{mac_address}_6c9cfce1d09df87a2d2ef2da86d900c16d20ba79c2f22836d9ed769d51479ffa".encode()).hexdigest()[:16]
    
    def save_license_files(self, encrypted_license, key, output_prefix="license"):
        license_file = f"{output_prefix}.key"
        key_file = f"{output_prefix}.key.pub"
        
        with open(license_file, "wb") as f:
            f.write(encrypted_license)
        
        SecureFernet.create_signed_key_file(key, key_file)
        
        return license_file, key_file


@app.route("/admin_login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""

        users_data = _load_users()
        users = users_data.get('users', {})
        rec = users.get(u)

        if rec:
            current_time = int(datetime.now().timestamp())
            locked_until = rec.get("locked_until", 0) or 0
            if locked_until > current_time:
                remaining = locked_until - current_time
                minutes_left = (remaining + 59) // 60
                return render_template('admin_login.html', msg=f"Account locked. Try again in {minutes_left} minute(s).")

        if rec and _verify_password(p, rec.get("password", "")):
            users[u]['failed_attempts'] = 0
            users[u]['locked_until'] = None
            users_data['users'] = users
            _save_users(users_data)

            session["user"] = u
            nxt = request.args.get("next") or url_for("index")
            return redirect(nxt)

        if rec:
            users[u]['failed_attempts'] = users[u].get('failed_attempts', 0) + 1
            attempts = users[u]['failed_attempts']

            if attempts >= 5:
                users[u]['locked_until'] = int(datetime.now().timestamp()) + 900
                users[u]['failed_attempts'] = 0
                return render_template('admin_login.html', msg="Account locked for 15 minutes due to too many failed attempts.")

            users_data['users'] = users
            _save_users(users_data)

        return render_template('admin_login.html', msg="Invalid credentials")
    return render_template('admin_login.html', msg=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users_data = _load_users()
    users = users_data.get('users', {})
    
    norm = {}
    for k, v in users.items():
        role = v.get("role", "user") if isinstance(v, dict) else "user"
        pwd = v.get("password", "") if isinstance(v, dict) else ""
        email = v.get("email", "") if isinstance(v, dict) else ""
        locked_by_admin = v.get("locked_by_admin", False) if isinstance(v, dict) else False
        locked_until = v.get("locked_until", 0) if isinstance(v, dict) else 0
        lock_reason = v.get("lock_reason", "") if isinstance(v, dict) else ""
        norm[k] = {
            "role": role,
            "password": pwd,
            "email": email,
            "locked_by_admin": locked_by_admin,
            "locked_until": locked_until,
            "lock_reason": lock_reason
        }
    
    now_timestamp = int(datetime.now().timestamp())
    return render_template('license_users.html', users=norm, now_timestamp=now_timestamp)


@app.route("/admin/users/add", methods=["POST"])
@login_required
@admin_required
def admin_users_add():
    u = (request.form.get("username") or "").strip()
    p = request.form.get("password") or ""
    role = (request.form.get("role") or "user").strip() or "user"
    email = (request.form.get("email") or "").strip()

    if not u:
        flash("Username is required")
        return redirect(url_for("admin_users"))

    users_data = _load_users()
    users = users_data.get('users', {})
    is_new_user = u not in users
    rec = users.get(u, {})

    rec["role"] = role
    rec["email"] = email

    if p:
        try:
            hashed = bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            rec["password"] = f"bcrypt:{hashed}"
        except Exception as e:
            flash(f"Failed to hash password: {e}")
            return redirect(url_for("admin_users"))

    users[u] = rec
    users_data['users'] = users
    if _save_users(users_data):
        flash("User saved successfully")
    else:
        flash("Failed to save user")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete", methods=["POST"])
@login_required
@admin_required
def admin_users_delete():
    u = (request.form.get("username") or "").strip()
    if not u:
        flash("No username provided")
        return redirect(url_for("admin_users"))

    users_data = _load_users()
    users = users_data.get('users', {})
    if u in users:
        admins = [name for name, rec in users.items() if rec.get("role") == "admin"]
        if u in admins and len(admins) == 1:
            flash("Cannot delete the last admin")
            return redirect(url_for("admin_users"))
        users.pop(u, None)
        users_data['users'] = users
        if _save_users(users_data):
            flash(f"Deleted {u}")
        else:
            flash("Failed to save users")
    else:
        flash("User not found")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/lock", methods=["POST"])
@login_required
@admin_required
def admin_users_lock():
    u = (request.form.get("username") or "").strip()
    reason = (request.form.get("reason") or "").strip()

    if not u:
        return jsonify({"success": False, "error": "No username provided"}), 400

    current_user_data = current_user()
    if not current_user_data:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    if current_user_data.get("username") == u:
        return jsonify({"success": False, "error": "Cannot lock your own account"}), 400

    users_data = _load_users()
    users = users_data.get('users', {})

    if u not in users:
        return jsonify({"success": False, "error": "User not found"}), 404

    users[u]['locked_by_admin'] = True
    users[u]['locked_until'] = None
    users[u]['lock_reason'] = reason
    users[u]['locked_at'] = datetime.now().isoformat()
    users[u]['locked_by'] = current_user_data.get("username")

    users_data['users'] = users
    if _save_users(users_data):
        return jsonify({"success": True, "message": f"User {u} has been locked"})
    else:
        return jsonify({"success": False, "error": "Failed to save users.json"}), 500


@app.route("/admin/users/unlock", methods=["POST"])
@login_required
@admin_required
def admin_users_unlock():
    u = (request.form.get("username") or "").strip()

    if not u:
        return jsonify({"success": False, "error": "No username provided"}), 400

    users_data = _load_users()
    users = users_data.get('users', {})

    if u not in users:
        return jsonify({"success": False, "error": "User not found"}), 404

    users[u]['locked_by_admin'] = False
    users[u]['locked_until'] = None
    users[u]['lock_reason'] = ""
    users[u]['failed_attempts'] = 0

    users_data['users'] = users
    if _save_users(users_data):
        return jsonify({"success": True, "message": f"User {u} has been unlocked"})
    else:
        return jsonify({"success": False, "error": "Failed to save users.json"}), 500


@app.route('/')
@login_required
def index():
    """Main dashboard"""
    user = current_user()
    return render_template('license_dashboard.html', current_user=user)


@app.route('/api/licenses/by-mac/<mac_address>', methods=['GET'])
@login_required
def get_license_by_mac(mac_address):
    """Get license by MAC address"""
    mac_normal = mac_address.upper().replace(':', '').replace('-', '')
    mac_formatted = ':'.join([mac_normal[i:i + 2] for i in range(0, 12, 2)])
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, perpetual
        FROM licenses WHERE mac_address = ?
    ''', (mac_formatted,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'exists': False})
    
    license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, is_perpetual = result
    
    return jsonify({
        'exists': True,
        'license': {
            'license_id': license_id,
            'customer_name': customer_name or "",
            'customer_email': customer_email or "",
            'mac_address': mac_address,
            'issued_date': issued_date[:10],
            'expiry_date': expiry_date[:10],
            'perpetual': bool(is_perpetual)
        }
    })


@app.route('/api/licenses', methods=['GET'])
@login_required
def get_licenses():
    """Get all licenses with optional search/filter and pagination"""
    search = request.args.get('search', '')
    sort_by = request.args.get('sort', 'issued_date')
    order = request.args.get('order', 'desc')
    status_filter = request.args.get('status', 'all')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Base WHERE clause
    where_clause = '(LOWER(license_id) LIKE ? OR LOWER(customer_name) LIKE ? OR LOWER(customer_email) LIKE ? OR LOWER(mac_address) LIKE ?)'
    search_pattern = f"%{search}%"
    params = [search_pattern] * 4
    
    if status_filter == 'active':
        where_clause += ' AND perpetual = 0 AND expiry_date > ? '
        params.append(datetime.now().isoformat())
    elif status_filter == 'expired':
        where_clause += ' AND perpetual = 0 AND expiry_date <= ? '
        params.append(datetime.now().isoformat())
    elif status_filter == 'perpetual':
        where_clause += ' AND perpetual = 1 '
    
    # Get total count
    count_query = f'SELECT COUNT(*) FROM licenses WHERE {where_clause}'
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]
    
    # Add sorting
    valid_sorts = {
        'issued_date': 'issued_date',
        'expiry_date': 'expiry_date',
        'customer_name': 'customer_name',
        'mac_address': 'mac_address'
    }
    sort_col = valid_sorts.get(sort_by, 'issued_date')
    order_dir = 'DESC' if order == 'desc' else 'ASC'
    
    # Add pagination
    offset = (page - 1) * per_page
    query = f'''
        SELECT license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, perpetual
        FROM licenses
        WHERE {where_clause}
        ORDER BY {sort_col} {order_dir}
        LIMIT ? OFFSET ?
    '''
    params_pagination = params + [per_page, offset]
    
    cursor.execute(query, params_pagination)
    licenses = cursor.fetchall()
    
    results = []
    now = datetime.now()
    total = 0
    active = 0
    expired = 0
    perpetual = 0
    
    for lic in licenses:
        license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, is_perpetual = lic
        
        expiry = datetime.fromisoformat(expiry_date)
        days_left = (expiry - now).days
        
        if is_perpetual:
            status_text = "Perpetual"
            days_left_str = "∞"
            perpetual += 1
            active += 1
        elif days_left < 0:
            status_text = "Expired"
            days_left_str = str(days_left)
            expired += 1
        elif days_left <= 30:
            status_text = "Expiring"
            days_left_str = str(days_left)
            active += 1
        else:
            status_text = "Active"
            days_left_str = str(days_left)
            active += 1
        
        total += 1
        
        results.append({
            'license_id': license_id,
            'customer_name': customer_name or "N/A",
            'customer_email': customer_email or "N/A",
            'mac_address': mac_address,
            'issued_date': datetime.fromisoformat(issued_date).strftime("%Y-%m-%d"),
            'expiry_date': "Never" if is_perpetual else expiry.strftime("%Y-%m-%d"),
            'days_left': days_left_str,
            'status': status_text,
            'perpetual': is_perpetual
        })
    
    conn.close()
    
    total_pages = (total_count + per_page - 1) // per_page
    
    return jsonify({
        'licenses': results,
        'stats': {
            'total': total,
            'active': active,
            'expired': expired,
            'perpetual': perpetual
        },
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages
        }
    })


@app.route('/api/licenses/generate', methods=['POST'])
@login_required
def generate_license():
    """Generate a new license"""
    data = request.get_json()
    
    mac_address = data.get('mac_address', '').strip()
    customer_name = data.get('customer_name', '').strip()
    customer_email = data.get('customer_email', '').strip()
    is_perpetual = data.get('perpetual', False)
    days = int(data.get('days', 365))
    output_prefix = data.get('output_prefix', 'license')
    
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address is required'})
    
    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    if not mac_regex.match(mac_address):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'})
    
    try:
        generator = MACLicenseGenerator()
        encrypted_license, key, license_data = generator.generate_initial_license(
            mac_address, customer_name, days, is_perpetual
        )
        
        license_file, key_file = generator.save_license_files(
            encrypted_license, key, output_prefix
        )
        
        license_data["customer_email"] = customer_email
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO licenses 
            (license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, perpetual)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            license_data["id"],
            license_data.get("customer_name", ""),
            license_data.get("customer_email", ""),
            license_data["mac_address"],
            license_data["issued_date"],
            license_data["expiry_date"],
            license_data["renewal_code"],
            "active",
            license_data.get("perpetual", False)
        ))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'license_data': license_data,
            'license_file': license_file,
            'key_file': key_file
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/licenses/regenerate', methods=['POST'])
@login_required
def regenerate_license():
    """Regenerate license files from existing license data"""
    data = request.get_json()
    
    mac_address = data.get('mac_address', '').strip()
    output_prefix = data.get('output_prefix', 'license')
    
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address is required'})
    
    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    if not mac_regex.match(mac_address):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'})
    
    try:
        mac_normal = mac_address.upper().replace(':', '').replace('-', '')
        mac_formatted = ':'.join([mac_normal[i:i + 2] for i in range(0, 12, 2)])
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT license_id, customer_name, customer_email, issued_date, expiry_date, renewal_code, perpetual
            FROM licenses WHERE mac_address = ?
        ''', (mac_formatted,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'success': False, 'error': 'License not found for this MAC address'})
        
        license_id, customer_name, customer_email, issued_date, expiry_date, renewal_code, is_perpetual = result
        
        license_data = {
            "id": license_id,
            "mac_address": mac_formatted,
            "customer_name": customer_name,
            "issued_date": issued_date,
            "expiry_date": expiry_date,
            "features": ["full_access"],
            "renewal_code": renewal_code,
            "version": "1.0",
            "perpetual": bool(is_perpetual)
        }
        
        generator = MACLicenseGenerator()
        generator.master_key = Fernet.generate_key()
        generator.fernet = Fernet(generator.master_key)
        
        encrypted_license = generator.fernet.encrypt(json.dumps(license_data).encode())
        
        license_file, key_file = generator.save_license_files(
            encrypted_license, generator.master_key, output_prefix
        )
        
        return jsonify({
            'success': True,
            'license_data': license_data,
            'license_file': license_file,
            'key_file': key_file
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/licenses/renew', methods=['POST'])
@login_required
def process_renewal():
    """Process a license renewal"""
    data = request.get_json()
    
    mac_address = data.get('mac_address', '').strip()
    additional_days = int(data.get('days', 365))
    output_prefix = data.get('output_prefix', 'renewal')
    customer_email = data.get('customer_email', '').strip()
    
    if not mac_address:
        return jsonify({'success': False, 'error': 'MAC address is required'})
    
    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    if not mac_regex.match(mac_address):
        return jsonify({'success': False, 'error': 'Invalid MAC address format'})
    
    try:
        mac_normal = mac_address.upper().replace(':', '').replace('-', '')
        mac_formatted = ':'.join([mac_normal[i:i + 2] for i in range(0, 12, 2)])
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT license_id, expiry_date FROM licenses WHERE mac_address = ?', (mac_formatted,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'success': False, 'error': 'License not found for this MAC address'})
        
        license_id, current_expiry = result
        
        if current_expiry == "2099-12-31":
            conn.close()
            return jsonify({'success': False, 'error': 'Cannot renew a perpetual license'})
        
        expiry_date = datetime.fromisoformat(current_expiry)
        new_expiry = expiry_date + timedelta(days=additional_days)
        
        renewal_id = str(uuid.uuid4())
        
        cursor.execute('''
            UPDATE licenses SET expiry_date = ? WHERE mac_address = ?
        ''', (new_expiry.isoformat(), mac_formatted))
        
        cursor.execute('''
            INSERT INTO renewals 
            (license_id, renewal_id, generated_date, additional_days, previous_expiry, new_expiry)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            license_id,
            renewal_id,
            datetime.now().isoformat(),
            additional_days,
            current_expiry,
            new_expiry.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        renewal_data = {
            "type": "renewal",
            "mac_address": mac_formatted,
            "additional_days": additional_days,
            "generated_date": datetime.now().isoformat(),
            "renewal_id": renewal_id,
            "version": "1.0"
        }
        
        renewal_file = f"{output_prefix}.json"
        with open(renewal_file, "w") as f:
            json.dump(renewal_data, f, indent=2)
        
        return jsonify({
            'success': True,
            'renewal_data': renewal_data,
            'renewal_file': renewal_file,
            'previous_expiry': current_expiry,
            'new_expiry': new_expiry.isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/licenses/export', methods=['GET'])
@login_required
def export_licenses():
    """Export licenses to CSV"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, perpetual
        FROM licenses ORDER BY issued_date DESC
    ''')
    licenses = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    output.write("License ID,Customer,Email,MAC Address,Issued,Expires,Renewal Code,Status,Perpetual\n")
    
    now = datetime.now()
    
    for lic in licenses:
        license_id, customer_name, customer_email, mac_address, issued_date, expiry_date, renewal_code, status, is_perpetual = lic
        
        expiry = datetime.fromisoformat(expiry_date)
        days_left = (expiry - now).days
        
        if is_perpetual:
            status_text = "Perpetual"
        else:
            status_text = "Expired" if days_left < 0 else ("Expiring Soon" if days_left <= 30 else "Active")
        
        output.write(f'"{license_id}","{customer_name or "N/A"}","{customer_email or "N/A"}","{mac_address}","{issued_date[:10]}","{"Never" if is_perpetual else expiry_date[:10]}","{renewal_code}","{status_text}","{"Yes" if is_perpetual else "No"}"\n')
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=licenses_export.csv"}
    )


@app.route('/api/licenses/download/<path:filename>', methods=['GET'])
@login_required
def download_license_file(filename):
    """Download license file"""
    return send_file(filename, as_attachment=True)


@app.route('/api/email/send', methods=['POST'])
@login_required
def send_license_email():
    """Send license files via email"""
    data = request.get_json()
    
    recipient_email = data.get('email', '').strip()
    customer_name = data.get('customer_name', '').strip() or "Valued Customer"
    license_file = data.get('license_file')
    key_file = data.get('key_file')
    license_data = data.get('license_data', {})
    is_renewal = data.get('is_renewal', False)
    renewal_data = data.get('renewal_data', {})
    
    if not recipient_email:
        return jsonify({'success': False, 'error': 'Email address is required'})
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, recipient_email):
        return jsonify({'success': False, 'error': 'Invalid email address format'})
    
    smtp_config = load_smtp_settings()
    
    if not smtp_config:
        return jsonify({'success': False, 'error': 'SMTP not configured', 'preview': True})
    
    try:
        if is_renewal:
            subject = f"Your AssetNode License Renewal - {datetime.now().strftime('%Y-%m-%d')}"
            body = f"""Dear {customer_name},

Your AssetNode license renewal has been processed! Please find your renewal file attached to this email.

RENEWAL FILE INCLUDED:
• {os.path.basename(renewal_data.get('renewal_file', 'renewal.json'))} - License renewal key

RENEWAL DETAILS:
Renewal ID: {renewal_data.get('renewal_id', 'N/A')}
MAC Address: {renewal_data.get('mac_address', 'N/A')}
Additional Days: {renewal_data.get('additional_days', 'N/A')}

SUPPORT:
Email: {smtp_config['sender_email']}

Thank you for continuing to use AssetNode!

Best regards,
AssetNode Support Team
"""
        else:
            subject = f"Your AssetNode License Files - {datetime.now().strftime('%Y-%m-%d')}"
            body = f"""Dear {customer_name},

Thank you for your purchase! Please find your AssetNode license files attached to this email.

LICENSE FILES INCLUDED:
• {os.path.basename(license_file)} - Main license file
• {os.path.basename(key_file)} - Public key file

LICENSE DETAILS:
License ID: {license_data.get('id', 'N/A')}
Customer: {license_data.get('customer_name', 'N/A')}
MAC Address: {license_data.get('mac_address', 'N/A')}
Issued: {license_data.get('issued_date', 'N/A')[:10]}
Expires: {'Never' if license_data.get('perpetual', False) else license_data.get('expiry_date', 'N/A')[:10]}

SUPPORT:
Email: {smtp_config['sender_email']}

IMPORTANT:
• This license is bound to the MAC address specified above
• Do not share these files with others

Thank you for choosing AssetNode!

Best regards,
AssetNode Support Team
"""
        
        files_to_attach = []
        if not is_renewal:
            if license_file and os.path.exists(license_file):
                files_to_attach.append(license_file)
            if key_file and os.path.exists(key_file):
                files_to_attach.append(key_file)
        else:
            renewal_file = renewal_data.get('renewal_file')
            if renewal_file and os.path.exists(renewal_file):
                files_to_attach.append(renewal_file)
        
        for attach_file in files_to_attach:
            success, message = send_email(recipient_email, subject, body, attach_file, smtp_config)
            if not success:
                return jsonify({'success': False, 'error': message})
            if not success:
                return jsonify({'success': False, 'error': message})
        
        return jsonify({'success': True, 'message': f'Email sent to {recipient_email}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/settings/smtp/status', methods=['GET'])
@login_required
def smtp_status():
    """Check if SMTP is configured"""
    config = load_smtp_settings()
    return jsonify({'configured': config is not None})


def _send_license_email(customer_email, customer_name, customer_number, license_key, expiry_date, status, mac_address, auto_renew, renewal_interval, stripe_subscription_id, custom_message='', tier_type='', display_name=''):
    """Send license details email to customer with professional HTML design"""
    try:
        smtp_config = load_smtp_settings()
        if not smtp_config:
            print("SMTP not configured, skipping email")
            return False
        
        if not customer_email:
            print("No customer email, skipping email")
            return False
        
        subject = f"Your AssetNode License Details - {datetime.now().strftime('%Y-%m-%d')}"
        
        html_body = generate_license_email_html(
            customer_name=customer_name,
            customer_number=customer_number,
            license_key=license_key,
            expiry_date=expiry_date,
            status=status,
            mac_address=mac_address,
            auto_renew=auto_renew,
            renewal_interval=renewal_interval,
            stripe_subscription_id=stripe_subscription_id,
            custom_message=custom_message,
            smtp_config=smtp_config,
            tier_type=tier_type,
            display_name=display_name
        )
        
        body = f"""Dear {customer_name},

Thank you for your purchase! Below are your AssetNode license details.

CUSTOMER INFORMATION:
Customer Number: {customer_number}
Customer Name: {customer_name}

LICENSE INFORMATION:
License Key: {license_key}
Status: {status.title()}
MAC Address: {mac_address or 'Any (not bound)'}
Issued: {datetime.now().strftime('%Y-%m-%d')}
Expires: {expiry_date[:10]}

"""
        if auto_renew:
            body += f"""AUTO-RENEWAL:
Enabled ({renewal_interval.title() if renewal_interval else 'Yearly'})
"""
            if stripe_subscription_id:
                body += f"Stripe Subscription: {stripe_subscription_id}\n"
            body += "\n"
        
        if custom_message:
            body += f"""NOTE FROM SUPPORT:
{custom_message}

"""
        
        body += f"""SUPPORT:
Email: {smtp_config['sender_email']}

IMPORTANT:
• Keep your license key secure and do not share it with others
• This license is bound to the MAC address specified above (if applicable)
• Contact support if you need to transfer this license to a new machine

Thank you for choosing AssetNode!

Best regards,
AssetNode Support Team
"""
        
        success, message = send_email(customer_email, subject, body, None, smtp_config, html_body=html_body)
        if success:
            log_action('EMAIL_SENT', 'license', None, customer_name, f"License details sent to {customer_email}", 'system')
            return True
        else:
            print(f"Failed to send email: {message}")
            return False
        
    except Exception as e:
        print(f"Error sending license email: {e}")
        return False


@app.route('/api/email/send-license', methods=['POST'])
@login_required
def send_online_license_email():
    """Send online license details via email"""
    data = request.get_json()
    
    license_id = data.get('license_id')
    custom_message = data.get('message', '').strip()
    override_email = data.get('email', '').strip()
    
    if not license_id:
        return jsonify({'success': False, 'error': 'License ID is required'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cl.id, cl.license_key, cl.expiry_date, cl.status, cl.mac_address, cl.ip_address, cl.auto_renew,
               cl.renewal_interval, cl.stripe_subscription_id,
               c.name, c.email, c.customer_number
        FROM customer_licenses cl
        JOIN customers c ON cl.customer_id = c.id
        WHERE cl.id = ?
    ''', (license_id,))
    
    lic = cursor.fetchone()
    conn.close()
    
    if not lic:
        return jsonify({'success': False, 'error': 'License not found'})
    
    lic_id, license_key, expiry_date, status, mac_address, ip_address, auto_renew, renewal_interval, stripe_sub, cust_name, cust_email, cust_number = lic
    
    if override_email:
        recipient_email = override_email
    else:
        recipient_email = cust_email
    
    if not recipient_email:
        return jsonify({'success': False, 'error': 'No email address provided and no email on file for this customer'})
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, recipient_email):
        return jsonify({'success': False, 'error': 'Invalid email address format'})
    
    smtp_config = load_smtp_settings()
    if not smtp_config:
        return jsonify({'success': False, 'error': 'SMTP not configured', 'preview': True})
    
    try:
        success = _send_license_email(
            customer_email=recipient_email,
            customer_name=cust_name,
            customer_number=cust_number,
            license_key=license_key,
            expiry_date=expiry_date,
            status=status,
            mac_address=mac_address,
            auto_renew=bool(auto_renew),
            renewal_interval=renewal_interval,
            stripe_subscription_id=stripe_sub,
            custom_message=custom_message
        )
        
        if success:
            try:
                username = session.get('username', 'system')
            except:
                username = 'system'
            log_msg = f"License details emailed to {recipient_email}"
            if override_email and override_email != cust_email:
                log_msg += f" (overrode {cust_email})"
            log_action('EMAIL_SENT', 'license', license_id, cust_name, log_msg, username)
            return jsonify({'success': True, 'message': f'License details sent to {recipient_email}'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send email'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/settings/smtp', methods=['GET', 'POST'])
@login_required
def smtp_settings():
    """Get or save SMTP settings"""
    if request.method == 'GET':
        config = load_smtp_settings()
        if config:
            config['password'] = ''  # Don't expose password
        return jsonify(config or {})
    
    data = request.get_json()
    
    required_fields = ['smtp_server', 'smtp_port', 'sender_email', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'error': f'{field} is required'})
    
    success, message = test_smtp_connection(data)
    if not success:
        return jsonify({'success': False, 'error': f'Connection test failed: {message}'})
    
    if save_smtp_settings(data):
        return jsonify({'success': True, 'message': 'SMTP settings saved successfully'})
    else:
        return jsonify({'success': False, 'error': 'Failed to save settings'})


@app.route('/api/settings/smtp/test', methods=['POST'])
@login_required
def test_smtp():
    """Test SMTP connection"""
    data = request.get_json()
    
    if save_smtp_settings(data):
        return jsonify({'success': True, 'message': 'SMTP settings saved and connection successful'})
    else:
        return jsonify({'success': False, 'error': 'Connection failed'})


@app.route('/api/licenses/renewals/<license_id>', methods=['GET'])
@login_required
def get_license_renewals(license_id):
    """Get renewals for a specific license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT renewal_id, generated_date, additional_days, previous_expiry, new_expiry
        FROM renewals WHERE license_id = ? ORDER BY generated_date DESC
    ''', (license_id,))
    
    renewals = cursor.fetchall()
    conn.close()
    
    results = []
    for r in renewals:
        results.append({
            'renewal_id': r[0],
            'generated_date': r[1][:10] if r[1] else '',
            'additional_days': r[2],
            'previous_expiry': r[3][:10] if r[3] else '',
            'new_expiry': r[4][:10] if r[4] else ''
        })
    
    return jsonify({'renewals': results})


# =============================================================================
# ONLINE LICENSING API ENDPOINTS
# =============================================================================

@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    """Return server's RSA public key for client encryption"""
    return jsonify({'public_key': get_server_public_key_pem()})


@app.route('/api/activate', methods=['POST'])
def activate_license():
    """
    Public endpoint for client activation.
    Client sends: {encrypted_data: "base64_rsa_encrypted", mac_address: "AA:BB:CC:DD:EE:FF"}
    Server responds: {success: bool, encrypted_license: str, session_key: str, expiry_date: str}
    """
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        mac_address = data.get('mac_address', '').strip()
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        if not encrypted_data:
            return jsonify({'success': False, 'error': 'Missing encrypted data'})
        
        # Debug: log received data length
        print(f"Received encrypted_data length: {len(encrypted_data)}")
        
        # Decrypt the request using RSA private key
        try:
            key_size = _server_private_key.key_size // 8
            decoded = base64.b64decode(encrypted_data)
            print(f"RSA Key size: {key_size} bytes, Received ciphertext: {len(decoded)} bytes")
            
            if len(decoded) != key_size:
                return jsonify({'success': False, 'error': f'Ciphertext size mismatch: expected {key_size}, got {len(decoded)}. Did you use the correct public key?'})
            
            decrypted = decrypt_with_rsa(encrypted_data)
            request_data = json.loads(decrypted.decode())
        except ValueError as ve:
            return jsonify({'success': False, 'error': f'Encryption error: {str(ve)}'})
        except Exception as e:
            return jsonify({'success': False, 'error': f'Invalid encrypted data: {str(e)}'})
        
        license_key = request_data.get('license_key', '').strip()
        
        if not license_key or not mac_address:
            return jsonify({'success': False, 'error': 'Missing license key or MAC address'})
        
        # Validate license key format
        if not re.match(r'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$', license_key):
            return jsonify({'success': False, 'error': 'Invalid license key format'})
        
        # Find customer by license key (include mac_address from customer_licenses)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cl.id, cl.customer_id, cl.license_key, cl.expiry_date, cl.mac_address,
                   c.name, c.customer_number, c.status
            FROM customer_licenses cl
            JOIN customers c ON cl.customer_id = c.id
            WHERE cl.license_key = ? AND cl.status IN ('ready', 'active')
        ''', (license_key,))
        license_record = cursor.fetchone()
        
        if not license_record:
            conn.close()
            return jsonify({'success': False, 'error': 'License not found or inactive'})
        
        lic_id, customer_id, lic_key, expiry_date, bound_mac, company_name, customer_number, cust_status = license_record
        
        # Check if customer is active
        if cust_status != 'active':
            conn.close()
            return jsonify({'success': False, 'error': f'Customer account is {cust_status}'})
        
        # Check expiry
        expiry = datetime.fromisoformat(expiry_date)
        if datetime.now() > expiry:
            conn.close()
            return jsonify({'success': False, 'error': 'License has expired'})
        
        # --- MAC validation and single-seat enforcement ---
        incoming_mac = mac_address.upper()
        
        is_first_activation = False
        
        if bound_mac and bound_mac.strip():
            # MAC-bound license: incoming MAC must match
            if incoming_mac != bound_mac.upper():
                conn.close()
                return jsonify({'success': False, 'error': 'License is bound to a different machine'})
        else:
            # "Any machine" license: single-seat enforcement
            cursor.execute('''
                SELECT ls.mac_address 
                FROM license_sessions ls
                WHERE ls.customer_license_id = ? AND ls.expires_at > ?
                LIMIT 1
            ''', (lic_id, datetime.now().isoformat()))
            existing = cursor.fetchone()
            
            if existing:
                existing_mac = (existing[0] or '').upper()
                if existing_mac and existing_mac != incoming_mac:
                    conn.close()
                    return jsonify({'success': False, 'error': 'License already activated on another machine'})
            else:
                is_first_activation = True
        
        # Generate session key (AES)
        session_key = Fernet.generate_key()
        session_key_b64 = base64.b64encode(session_key).decode()
        
        # Encrypt the license data with session key
        license_payload = {
            'license_key': lic_key,
            'customer_number': customer_number,
            'customer_name': company_name,
            'expiry_date': expiry_date,
            'features': ['full_access']
        }
        encrypted_license = encrypt_with_aes(license_payload, session_key)
        
        # Create or update session
        now = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(days=3650)).isoformat()
        
        # Remove old session for this specific license
        cursor.execute('DELETE FROM license_sessions WHERE customer_license_id = ?', (lic_id,))
        
        # Create new session with customer_license_id
        cursor.execute('''
            INSERT INTO license_sessions (customer_id, customer_license_id, session_key_encrypted, mac_address, ip_address, last_check_in, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (customer_id, lic_id, session_key_b64, mac_address, ip_address, now, now, expires_at))
        
        # Permanently bind the MAC to the license after first activation
        cursor.execute('UPDATE customer_licenses SET mac_address = ?, status = \'active\', updated_at = ? WHERE id = ?', (mac_address, now, lic_id))
        
        if is_first_activation:
            try:
                username = 'system'
            except:
                username = 'system'
            log_action('ACTIVATE', 'license', lic_id, company_name, f'License activated on MAC: {mac_address}, IP: {ip_address}', username)
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'encrypted_license': encrypted_license,
            'session_key': session_key_b64,
            'expiry_date': expiry_date,
            'customer_number': customer_number,
            'customer_name': company_name
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/check-license', methods=['POST'])
def check_license():
    """
    Periodic check-in endpoint.
    Client sends: {encrypted_data: "base64_aes_encrypted"}
    Server responds: {status: str, days_remaining: int, encrypted_message: str}
    """
    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        
        if not encrypted_data:
            return jsonify({'success': False, 'error': 'Missing encrypted data'})
        
        # First, try to decrypt with each active session key
        # The client encrypts with the session key it received during activation
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all active sessions
        cursor.execute('''
            SELECT ls.id, ls.customer_id, ls.session_key_encrypted, ls.expires_at, 
                   c.customer_number, c.status as customer_status,
                   cl.expiry_date, cl.status as license_status,
                   ls.mac_address, ls.ip_address
            FROM license_sessions ls
            JOIN customers c ON ls.customer_id = c.id
            JOIN customer_licenses cl ON cl.customer_id = c.id
            WHERE ls.expires_at > ?
            ORDER BY ls.created_at DESC
        ''', (datetime.now().isoformat(),))
        
        sessions = cursor.fetchall()
        conn.close()
        
        decrypted_payload = None
        matched_session = None
        
        for session in sessions:
            session_id, customer_id, session_key_enc, expires_at, cust_num, cust_status, exp_date, lic_status, session_mac, session_ip = session
            try:
                session_key = base64.b64decode(session_key_enc)
                payload = json.loads(decrypt_with_aes(encrypted_data, session_key))
                
                # Verify customer number matches
                if payload.get('customer_number') == cust_num:
                    decrypted_payload = payload
                    matched_session = session
                    break
            except:
                continue
        
        if not decrypted_payload or not matched_session:
            return jsonify({'success': False, 'error': 'Invalid session or expired'})
        
        session_id, customer_id, session_key_enc, expires_at, cust_num, cust_status, exp_date, lic_status, session_mac, session_ip = matched_session
        
        # MAC re-verification: ensure client is still on the same machine that activated
        client_mac = decrypted_payload.get('mac_address', data.get('mac_address', '')).upper()
        client_ip = decrypted_payload.get('ip_address', '')
        if client_mac and session_mac and session_mac.upper() != client_mac:
            return jsonify({
                'status': 'rejected',
                'days_remaining': 0,
                'encrypted_message': encrypt_with_aes({'message': 'License is bound to a different machine'}, base64.b64decode(session_key_enc))
            })
        
        # Check customer and license status
        if cust_status != 'active':
            return jsonify({
                'status': cust_status,
                'days_remaining': 0,
                'encrypted_message': encrypt_with_aes({'message': f'Customer account is {cust_status}'}, base64.b64decode(session_key_enc))
            })
        
        if lic_status != 'active':
            return jsonify({
                'status': lic_status,
                'days_remaining': 0,
                'encrypted_message': encrypt_with_aes({'message': f'License is {lic_status}'}, base64.b64decode(session_key_enc))
            })
        
        # Check expiry
        expiry = datetime.fromisoformat(exp_date)
        days_remaining = (expiry - datetime.now()).days
        
        if days_remaining < 0:
            return jsonify({
                'status': 'expired',
                'days_remaining': days_remaining,
                'encrypted_message': encrypt_with_aes({'message': 'License has expired'}, base64.b64decode(session_key_enc))
            })
        
        # Update last check-in and extend session expiry
        new_expires_at = (datetime.now() + timedelta(days=365)).isoformat()
        stored_ip = client_ip or ip_address
        cursor.execute('UPDATE license_sessions SET last_check_in = ?, expires_at = ?, ip_address = ? WHERE id = ?', (datetime.now().isoformat(), new_expires_at, stored_ip, session_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'active',
            'days_remaining': days_remaining,
            'encrypted_message': encrypt_with_aes({'message': 'License is active'}, base64.b64decode(session_key_enc))
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# =============================================================================
# ADMIN CUSTOMER MANAGEMENT
# =============================================================================

@app.route('/api/customers', methods=['GET'])
@login_required
def get_customers():
    """Get all customers with their licenses"""
    search = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    where_clause = '(LOWER(customer_number) LIKE ? OR LOWER(name) LIKE ? OR LOWER(email) LIKE ?)'
    search_pattern = f"%{search}%"
    params = [search_pattern] * 3
    
    if status_filter != 'all':
        where_clause += ' AND status = ?'
        params.append(status_filter)
    
    cursor.execute(f'''
        SELECT id, customer_number, name, email, status, stripe_subscription_id, created_at, updated_at
        FROM customers WHERE {where_clause} ORDER BY created_at DESC
    ''', params)
    
    customers = cursor.fetchall()
    
    results = []
    for c in customers:
        cust_id, cust_num, name, email, status, stripe_sub, created, updated = c
        
        # Get licenses for this customer
        cursor.execute('''
            SELECT id, license_key, expiry_date, status, mac_address, ip_address, created_at, auto_renew, stripe_subscription_id, stripe_price_id, renewal_interval, nickname
            FROM customer_licenses WHERE customer_id = ?
        ''', (cust_id,))
        licenses = cursor.fetchall()
        
        license_list = []
        for lic in licenses:
            lic_id, key, exp, lic_status, mac, ip, created_at, auto_renew, stripe_sub, stripe_price, renewal_interval, nickname = lic
            license_list.append({
                'id': lic_id,
                'license_key_masked': key[:8] + '****' + key[-4:] if len(key) > 12 else '****',
                'expiry_date': exp,
                'status': lic_status,
                'mac_address': mac,
                'ip_address': ip,
                'created_at': created_at,
                'auto_renew': bool(auto_renew),
                'stripe_subscription_id': stripe_sub,
                'renewal_interval': renewal_interval,
                'nickname': nickname
            })
        
        results.append({
            'id': cust_id,
            'customer_number': cust_num,
            'name': name,
            'email': email,
            'status': status,
            'stripe_subscription_id': stripe_sub,
            'created_at': created[:10] if created else '',
            'updated_at': updated[:10] if updated else '',
            'licenses': license_list,
            'license_count': len(license_list)
        })
    
    conn.close()
    return jsonify({'customers': results})


@app.route('/api/customers', methods=['POST'])
@login_required
def create_customer():
    """Create a new customer with auto-generated customer number"""
    try:
        content_type = request.content_type or ''
        
        if 'application/json' not in content_type:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json(force=True, silent=False)
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400
        
        if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        customer_number = generate_customer_number()
        now = datetime.now().isoformat()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO customers (customer_number, name, email, status, created_at, updated_at)
            VALUES (?, ?, ?, 'active', ?, ?)
        ''', (customer_number, name, email, now, now))
        
        customer_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        try:
            username = session.get('username', 'system')
        except:
            username = 'system'
        log_action('CREATE', 'customer', customer_id, name, f"Customer number: {customer_number}, Email: {email or 'N/A'}", username)
        
        return jsonify({
            'success': True,
            'customer': {
                'id': customer_id,
                'customer_number': customer_number,
                'name': name,
                'email': email,
            'status': 'ready',
                'created_at': now[:10]
            }
        })
    except Exception as e:
        conn and conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/customers/<int:customer_id>', methods=['GET'])
@login_required
def get_customer(customer_id):
    """Get customer details with licenses"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, customer_number, name, email, status, stripe_subscription_id, created_at, updated_at
        FROM customers WHERE id = ?
    ''', (customer_id,))
    
    c = cursor.fetchone()
    if not c:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    cust_id, cust_num, name, email, status, stripe_sub, created, updated = c
    
    cursor.execute('''
        SELECT id, license_key, encrypted_data, expiry_date, status, mac_address, ip_address, created_at, updated_at, auto_renew, stripe_subscription_id, renewal_interval, nickname
        FROM customer_licenses WHERE customer_id = ?
    ''', (cust_id,))
    licenses = cursor.fetchall()
    
    license_list = []
    for lic in licenses:
        lic_id, key, enc_data, exp, lic_status, mac, ip, created_at, updated_at, auto_renew, stripe_sub, renewal_interval, nickname = lic
        license_list.append({
            'id': lic_id,
            'license_key': key,
            'expiry_date': exp,
            'status': lic_status,
            'mac_address': mac,
            'ip_address': ip,
            'created_at': created_at,
            'updated_at': updated_at,
            'auto_renew': bool(auto_renew),
            'stripe_subscription_id': stripe_sub,
            'renewal_interval': renewal_interval,
            'nickname': nickname
        })
    
    conn.close()
    
    return jsonify({
        'customer': {
            'id': cust_id,
            'customer_number': cust_num,
            'name': name,
            'email': email,
            'status': status,
            'stripe_subscription_id': stripe_sub,
            'created_at': created,
            'updated_at': updated,
            'licenses': license_list
        }
    })


@app.route('/api/customers/<int:customer_id>', methods=['PUT'])
@login_required
def update_customer(customer_id):
    """Update customer details"""
    data = request.get_json()
    
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, email FROM customers WHERE id = ?', (customer_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    now = datetime.now().isoformat()
    cursor.execute('''
        UPDATE customers SET name = ?, email = ?, updated_at = ? WHERE id = ?
    ''', (name, email, now, customer_id))
    
    conn.commit()
    conn.close()
    
    changes = []
    if existing[1] != name:
        changes.append(f"Name: '{existing[1]}' -> '{name}'")
    if existing[2] != email:
        changes.append(f"Email: '{existing[2]}' -> '{email or 'N/A'}'")
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('UPDATE', 'customer', customer_id, name, '; '.join(changes) if changes else 'No changes', username)
    
    return jsonify({'success': True, 'message': 'Customer updated'})


@app.route('/api/customers/<int:customer_id>/suspend', methods=['PUT'])
@login_required
def suspend_customer(customer_id):
    """Suspend a customer and all their licenses"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, status FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    if customer[2] == 'suspended':
        conn.close()
        return jsonify({'success': False, 'error': 'Customer is already suspended'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customers SET status = ?, updated_at = ? WHERE id = ?', ('suspended', now, customer_id))
    cursor.execute('UPDATE customer_licenses SET status = ?, updated_at = ? WHERE customer_id = ?', ('suspended', now, customer_id))
    cursor.execute('DELETE FROM license_sessions WHERE customer_id = ?', (customer_id,))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('SUSPEND', 'customer', customer_id, customer[1], 'Customer and all licenses suspended', username)
    
    return jsonify({'success': True, 'message': 'Customer suspended'})


@app.route('/api/customers/<int:customer_id>/cancel', methods=['PUT'])
@login_required
def cancel_customer(customer_id):
    """Cancel a customer and all their licenses"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customers SET status = ?, updated_at = ? WHERE id = ?', ('cancelled', now, customer_id))
    cursor.execute('UPDATE customer_licenses SET status = ?, updated_at = ? WHERE customer_id = ?', ('cancelled', now, customer_id))
    cursor.execute('DELETE FROM license_sessions WHERE customer_id = ?', (customer_id,))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('CANCEL', 'customer', customer_id, customer[1], 'Customer and all licenses cancelled', username)
    
    return jsonify({'success': True, 'message': 'Customer cancelled'})


@app.route('/api/customers/<int:customer_id>/reactivate', methods=['PUT'])
@login_required
def reactivate_customer(customer_id):
    """Reactivate a suspended or cancelled customer"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, status FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    if customer[2] == 'active':
        conn.close()
        return jsonify({'success': False, 'error': 'Customer is already active'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customers SET status = ?, updated_at = ? WHERE id = ?', ('active', now, customer_id))
    
    cursor.execute('''
        UPDATE customer_licenses SET status = 'active', updated_at = ? 
        WHERE customer_id = ? AND status IN ('suspended', 'cancelled', 'expired')
    ''', (now, customer_id))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('REACTIVATE', 'customer', customer_id, customer[1], f'Reactivated from {customer[2]} status', username)
    
    return jsonify({'success': True, 'message': 'Customer reactivated'})


@app.route('/api/customers/<int:customer_id>/delete', methods=['DELETE'])
@login_required
def delete_customer(customer_id):
    """Delete a customer, all licenses, and all session data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    cust_id, cust_name = customer
    
    try:
        cursor.execute('DELETE FROM license_sessions WHERE customer_id = ?', (customer_id,))
        cursor.execute('DELETE FROM customer_licenses WHERE customer_id = ?', (customer_id,))
        cursor.execute('DELETE FROM customers WHERE id = ?', (customer_id,))
        
        conn.commit()
        conn.close()
        
        try:
            username = session.get('username', 'system')
        except:
            username = 'system'
        log_action('DELETE', 'customer', cust_id, cust_name, 'Customer and all associated data permanently deleted', username)
        
        return jsonify({
            'success': True, 
            'message': f"Customer '{cust_name}' and all associated data deleted"
        })
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})


# =============================================================================
# ADMIN LICENSE MANAGEMENT
# =============================================================================

@app.route('/api/licenses/online/generate', methods=['POST'])
@login_required
def generate_online_license():
    """Generate a new license for a customer"""
    data = request.get_json()
    
    customer_id = data.get('customer_id')
    mac_address = data.get('mac_address', '').strip()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    expiry_days = int(data.get('expiry_days', 365))
    bind_to_mac = data.get('bind_to_mac', True)
    auto_renew = data.get('auto_renew', False)
    stripe_price_id = data.get('stripe_price_id', '')
    renewal_interval = data.get('renewal_interval', 'yearly')
    nickname = data.get('nickname', '').strip()[:50]
    
    if not customer_id:
        return jsonify({'success': False, 'error': 'Customer ID is required'})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, name, email FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    if not customer:
        conn.close()
        return jsonify({'success': False, 'error': 'Customer not found'})
    
    cust_id, cust_name, cust_email = customer
    
    license_key = generate_license_key()
    expiry_date = (datetime.now() + timedelta(days=expiry_days)).isoformat()
    now = datetime.now().isoformat()
    
    license_data = {
        'customer_number': customer[0],
        'customer_name': cust_name,
        'mac_address': mac_address if bind_to_mac else None,
        'expiry_date': expiry_date,
        'features': ['full_access']
    }
    
    encrypted_data = base64.b64encode(json.dumps(license_data).encode()).decode()
    
    cursor.execute('''
        INSERT INTO customer_licenses (customer_id, license_key, encrypted_data, expiry_date, status, mac_address, ip_address, auto_renew, stripe_price_id, renewal_interval, nickname, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (customer_id, license_key, encrypted_data, expiry_date, mac_address if bind_to_mac else None, ip_address, 1 if auto_renew else 0, stripe_price_id, renewal_interval, nickname if nickname else None, now, now))
    
    license_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    details = f"Expires: {expiry_date[:10]}, MAC: {mac_address if bind_to_mac else 'Any'}"
    if auto_renew:
        details += f", Auto-renew: {renewal_interval}"
    log_action('CREATE', 'license', license_id, cust_name, details, username)
    
    return jsonify({
        'success': True,
        'license': {
            'id': license_id,
            'license_key': license_key,
            'expiry_date': expiry_date[:10],
            'mac_address': mac_address if bind_to_mac else None,
            'status': 'active',
            'auto_renew': auto_renew,
            'nickname': nickname if nickname else None
        }
    })


@app.route('/api/licenses/online/<int:license_id>/suspend', methods=['PUT'])
@login_required
def suspend_online_license(license_id):
    """Suspend a specific license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, customer_id FROM customer_licenses WHERE id = ?', (license_id,))
    lic = cursor.fetchone()
    if not lic:
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET status = ?, updated_at = ? WHERE id = ?', ('suspended', now, license_id))
    cursor.execute('DELETE FROM license_sessions WHERE customer_license_id = ?', (license_id,))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('SUSPEND', 'license', license_id, None, 'License suspended', username)
    
    return jsonify({'success': True, 'message': 'License suspended'})



@app.route('/api/licenses/online/<int:license_id>/cancel', methods=['PUT'])
@login_required
def cancel_online_license(license_id):
    """Cancel a specific license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM customer_licenses WHERE id = ?', (license_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET status = ?, updated_at = ? WHERE id = ?', ('cancelled', now, license_id))
    cursor.execute('DELETE FROM license_sessions WHERE customer_license_id = ?', (license_id,))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('CANCEL', 'license', license_id, None, 'License cancelled', username)
    
    return jsonify({'success': True, 'message': 'License cancelled'})


@app.route('/api/licenses/online/<int:license_id>/reactivate', methods=['PUT'])
@login_required
def reactivate_online_license(license_id):
    """Reactivate a suspended or cancelled license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, status, expiry_date FROM customer_licenses WHERE id = ?', (license_id,))
    lic = cursor.fetchone()
    if not lic:
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    lic_id, status, expiry_date = lic
    
    if status == 'active':
        conn.close()
        return jsonify({'success': False, 'error': 'License is already active'})
    
    if datetime.fromisoformat(expiry_date) < datetime.now():
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot reactivate an expired license'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET status = ?, updated_at = ? WHERE id = ?', ('active', now, license_id))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('REACTIVATE', 'license', license_id, None, f'Reactivated from {status} status', username)
    
    return jsonify({'success': True, 'message': 'License reactivated'})


@app.route('/api/licenses/online/<int:license_id>/extend', methods=['PUT'])
@login_required
def extend_online_license(license_id):
    """Extend license expiry date"""
    data = request.get_json()
    additional_days = int(data.get('days', 365))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, expiry_date FROM customer_licenses WHERE id = ?', (license_id,))
    lic = cursor.fetchone()
    if not lic:
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    lic_id, current_expiry = lic
    new_expiry = (datetime.fromisoformat(current_expiry) + timedelta(days=additional_days)).isoformat()
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET expiry_date = ?, updated_at = ? WHERE id = ?', (new_expiry, now, license_id))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('EXTEND', 'license', license_id, None, f'Extended by {additional_days} days. New expiry: {new_expiry[:10]}', username)
    
    return jsonify({'success': True, 'expiry_date': new_expiry[:10]})


@app.route('/api/licenses/online/<int:license_id>/nickname', methods=['PUT'])
@login_required
def update_license_nickname(license_id):
    """Update license nickname"""
    data = request.get_json()
    nickname = data.get('nickname', '').strip()[:50]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM customer_licenses WHERE id = ?', (license_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})

    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET nickname = ?, updated_at = ? WHERE id = ?', (nickname if nickname else None, now, license_id))

    conn.commit()
    conn.close()

    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('UPDATE', 'license', license_id, None, f'Nickname set to: {nickname or "(cleared)"}', username)

    return jsonify({'success': True, 'nickname': nickname if nickname else None})


@app.route('/api/licenses/online/<int:license_id>/renew', methods=['POST'])
@login_required
def renew_online_license(license_id):
    """Renew a license with optional auto-renewal via Stripe"""
    data = request.get_json()
    
    additional_days = int(data.get('days', 365))
    enable_auto_renew = data.get('auto_renew', False)
    stripe_price_id = data.get('stripe_price_id', '')
    renewal_interval = data.get('renewal_interval', 'yearly')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cl.id, cl.customer_id, cl.expiry_date, cl.status, cl.auto_renew, cl.stripe_subscription_id,
               c.email, c.name
        FROM customer_licenses cl
        JOIN customers c ON cl.customer_id = c.id
        WHERE cl.id = ?
    ''', (license_id,))
    
    lic = cursor.fetchone()
    if not lic:
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    lic_id, customer_id, current_expiry, status, current_auto_renew, current_stripe_sub, cust_email, cust_name = lic
    
    if status not in ('active', 'expired', 'suspended'):
        conn.close()
        return jsonify({'success': False, 'error': f'Cannot renew license with status: {status}'})
    
    now = datetime.now().isoformat()
    expiry = datetime.fromisoformat(current_expiry)
    
    if expiry > datetime.now():
        new_expiry = (expiry + timedelta(days=additional_days)).isoformat()
    else:
        new_expiry = (datetime.now() + timedelta(days=additional_days)).isoformat()
    
    cursor.execute('''
        UPDATE customer_licenses 
        SET expiry_date = ?, status = 'active', auto_renew = ?, stripe_price_id = ?, renewal_interval = ?, updated_at = ?
        WHERE id = ?
    ''', (new_expiry, 1 if enable_auto_renew else 0, stripe_price_id, renewal_interval, now, license_id))
    
    cursor.execute('''
        INSERT INTO renewals (license_id, renewal_id, generated_date, additional_days, previous_expiry, new_expiry)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (f"online_{license_id}", str(uuid.uuid4()), now, additional_days, current_expiry, new_expiry))
    
    conn.commit()
    
    stripe_checkout_url = None
    
    if enable_auto_renew and stripe_price_id:
        stripe_config = load_stripe_settings()
        if stripe_config and stripe_config.get('stripe_api_key'):
            try:
                import stripe as stripe_lib
                stripe_lib.api_key = stripe_config['stripe_api_key']
                
                if not current_stripe_sub:
                    customer_result = stripe_lib.Customer.list(email=cust_email, limit=1)
                    stripe_customer_id = None
                    
                    if customer_result and customer_result.data:
                        stripe_customer_id = customer_result.data[0].id
                    else:
                        stripe_customer_id = stripe_lib.Customer.create(
                            email=cust_email,
                            name=cust_name,
                            metadata={'customer_id': customer_id}
                        ).id
                    
                    interval_map = {
                        'monthly': 'month',
                        'quarterly': 'month',
                        'yearly': 'year'
                    }
                    interval_count_map = {
                        'monthly': 1,
                        'quarterly': 3,
                        'yearly': 1
                    }
                    
                    price_result = stripe_lib.Price.create(
                        unit_amount=0,
                        currency='usd',
                        recurring={
                            'interval': interval_map.get(renewal_interval, 'year'),
                            'interval_count': interval_count_map.get(renewal_interval, 1)
                        },
                        product_data={'name': f'License Renewal - {cust_name}'},
                        metadata={'license_id': license_id}
                    )
                    
                    checkout_session = stripe_lib.checkout.Session.create(
                        customer=stripe_customer_id,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': price_result.id,
                            'quantity': 1,
                        }],
                        success_url=f"{request.host_url}license-success?session_id={{CHECKOUT_SESSION_ID}}",
                        cancel_url=f"{request.host_url}license-cancel",
                        metadata={
                            'license_id': license_id,
                            'customer_id': customer_id,
                            'renewal_interval': renewal_interval
                        }
                    )
                    stripe_checkout_url = checkout_session.url
                    
                    cursor.execute('''
                        UPDATE customer_licenses SET stripe_subscription_id = ?, updated_at = ?
                        WHERE id = ?
                    ''', (checkout_session.id, now, license_id))
                    conn.commit()
            except Exception as e:
                print(f"Stripe checkout error: {e}")
    
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    details = f"Extended by {additional_days} days. New expiry: {new_expiry[:10]}"
    if enable_auto_renew:
        details += f", Auto-renew: {renewal_interval}"
    if stripe_checkout_url:
        details += ", Stripe checkout created"
    log_action('RENEW', 'license', license_id, cust_name, details, username)
    
    return jsonify({
        'success': True,
        'expiry_date': new_expiry[:10],
        'auto_renew': enable_auto_renew,
        'stripe_checkout_url': stripe_checkout_url
    })


@app.route('/api/licenses/online/<int:license_id>/toggle-auto-renew', methods=['PUT'])
@login_required
def toggle_auto_renew(license_id):
    """Toggle auto-renewal for a license"""
    data = request.get_json()
    enable = data.get('enable', False)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM customer_licenses WHERE id = ?', (license_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': 'License not found'})
    
    now = datetime.now().isoformat()
    cursor.execute('UPDATE customer_licenses SET auto_renew = ?, updated_at = ? WHERE id = ?', (1 if enable else 0, now, license_id))
    
    conn.commit()
    conn.close()
    
    try:
        username = session.get('username', 'system')
    except:
        username = 'system'
    log_action('TOGGLE_AUTO_RENEW', 'license', license_id, None, f"Auto-renew {'enabled' if enable else 'disabled'}", username)
    conn.close()
    
    return jsonify({'success': True, 'auto_renew': enable})


@app.route('/api/licenses/renewals', methods=['GET'])
@login_required
def get_all_renewals():
    """Get all renewals with customer/license info"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT r.renewal_id, r.generated_date, r.additional_days, r.previous_expiry, r.new_expiry,
               c.name, c.customer_number, cl.license_key
        FROM renewals r
        JOIN customer_licenses cl ON r.license_id = 'online_' || cl.id
        JOIN customers c ON cl.customer_id = c.id
        ORDER BY r.generated_date DESC
        LIMIT 100
    ''')
    
    renewals = cursor.fetchall()
    conn.close()
    
    results = []
    for r in renewals:
        results.append({
            'renewal_id': r[0],
            'generated_date': r[1][:10] if r[1] else '',
            'additional_days': r[2],
            'previous_expiry': r[3][:10] if r[3] else '',
            'new_expiry': r[4][:10] if r[4] else '',
            'customer_name': r[5],
            'customer_number': r[6],
            'license_key': r[7][:8] + '****' + r[7][-4:] if len(r[7]) > 12 else '****'
        })
    
    return jsonify({'renewals': results})


@app.route('/api/logs', methods=['GET'])
@login_required
def get_audit_logs():
    """Get audit logs with optional filtering"""
    action_filter = request.args.get('action', '')
    entity_filter = request.args.get('entity', '')
    search = request.args.get('search', '')
    limit = int(request.args.get('limit', 200))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT id, timestamp, action, entity_type, entity_id, entity_name, details, user FROM audit_logs WHERE 1=1'
    params = []
    
    if action_filter:
        query += ' AND action = ?'
        params.append(action_filter)
    if entity_filter:
        query += ' AND entity_type = ?'
        params.append(entity_filter)
    if search:
        query += ' AND (entity_name LIKE ? OR details LIKE ? OR user LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()
    
    results = []
    for log in logs:
        results.append({
            'id': log[0],
            'timestamp': log[1],
            'action': log[2],
            'entity_type': log[3],
            'entity_id': log[4],
            'entity_name': log[5] or '',
            'details': log[6] or '',
            'user': log[7] or 'system'
        })
    
    return jsonify({'logs': results})


@app.route('/api/stripe/checkout-success', methods=['GET'])
def stripe_checkout_success():
    """Handle successful Stripe checkout"""
    session_id = request.args.get('session_id', '')
    
    if not session_id:
        return redirect(url_for('index'))
    
    stripe_config = load_stripe_settings()
    if stripe_config and stripe_config.get('stripe_api_key'):
        try:
            import stripe as stripe_lib
            stripe_lib.api_key = stripe_config['stripe_api_key']
            
            session = stripe_lib.checkout.Session.retrieve(session_id)
            
            if session.mode == 'subscription':
                subscription_id = session.subscription
                license_id = session.metadata.get('license_id')
                
                if license_id and subscription_id:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    
                    subscription = stripe_lib.Subscription.retrieve(subscription_id)
                    current_period_end = subscription.current_period_end
                    new_expiry = datetime.fromtimestamp(current_period_end).isoformat()
                    
                    now = datetime.now().isoformat()
                    cursor.execute('''
                        UPDATE customer_licenses 
                        SET stripe_subscription_id = ?, expiry_date = ?, status = 'active', auto_renew = 1, updated_at = ?
                        WHERE id = ?
                    ''', (subscription_id, new_expiry, now, license_id))
                    
                    conn.commit()
                    conn.close()
        except Exception as e:
            print(f"Stripe checkout success error: {e}")
    
    return redirect(url_for('index'))


# =============================================================================
# STRIPE WEBHOOK
# =============================================================================

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events for automated customer and license lifecycle management"""
    try:
        stripe_config = load_stripe_settings()
        if not stripe_config or not stripe_config.get('stripe_api_key'):
            return jsonify({'success': False, 'error': 'Stripe not configured'}), 400
        
        payload = request.get_data()
        signature = request.headers.get('Stripe-Signature', '')
        webhook_secret = stripe_config.get('stripe_webhook_secret', '')
        
        try:
            import stripe as stripe_lib
            stripe_lib.api_key = stripe_config['stripe_api_key']
            
            if webhook_secret and signature:
                event = stripe_lib.Webhook.construct_event(payload, signature, webhook_secret)
                event_type = event.type
                event_data = event.data.object
            else:
                event = json.loads(payload)
                event_type = event.get('type', '')
                event_data = event.get('data', {}).get('object', {})
        except Exception as e:
            print(f"Webhook verification error: {e}")
            return jsonify({'success': False, 'error': 'Invalid webhook signature'}), 400
        
        if event_type == 'checkout.session.completed':
            _handle_checkout_completed(event_data)
        
        elif event_type == 'customer.subscription.created':
            _handle_subscription_created(event_data)
        
        elif event_type == 'customer.subscription.updated':
            _handle_subscription_updated(event_data)
        
        elif event_type == 'customer.subscription.deleted':
            _handle_subscription_deleted(event_data)
        
        elif event_type == 'invoice.payment_succeeded':
            _handle_payment_succeeded(event_data)
        
        elif event_type == 'invoice.payment_failed':
            _handle_payment_failed(event_data)
        
        elif event_type == 'customer.created':
            _handle_customer_created(event_data)
        
        elif event_type == 'customer.updated':
            _handle_customer_updated(event_data)
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def _handle_checkout_completed(session):
    """Handle successful checkout - create customer and license if they don't exist"""
    try:
        import stripe as stripe_lib
        stripe_config = load_stripe_settings()
        stripe_lib.api_key = stripe_config['stripe_api_key']

        session_id = session.get('id')
        subscription_id = session.get('subscription')
        customer_email = session.get('customer_email') or session.get('customer_details', {}).get('email')
        customer_name = session.get('customer_details', {}).get('name')
        metadata = session.get('metadata', {})
        license_id = metadata.get('license_id')
        customer_id = metadata.get('customer_id')

        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        if not customer_id and customer_email:
            cursor.execute('SELECT id FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
            result = cursor.fetchone()
            if result:
                customer_id = result[0]
            else:
                customer_number = generate_customer_number()
                cursor.execute('''
                    INSERT INTO customers (customer_number, name, email, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', ?, ?)
                ''', (customer_number, customer_name or customer_email, customer_email, now, now))
                customer_id = cursor.lastrowid

        if not customer_id:
            print("No customer_id and no email to create one")
            conn.close()
            return

        if subscription_id:
            cursor.execute('''
                SELECT id FROM customer_licenses WHERE stripe_subscription_id = ?
            ''', (subscription_id,))
            already_exists = cursor.fetchone()
            if already_exists:
                print(f"License already exists for subscription {subscription_id}, skipping")
                conn.close()
                return

        if subscription_id:
            subscription = stripe_lib.Subscription.retrieve(subscription_id)
            price_id = subscription.items.data[0].price.id if subscription.items.data else ''
            interval = subscription.items.data[0].price.recurring.interval if subscription.items.data else 'year'
            current_period_end = subscription.current_period_end
            expiry_date = datetime.fromtimestamp(current_period_end).isoformat()

            interval_map = {'month': 'monthly', 'year': 'yearly'}
            renewal_interval = interval_map.get(interval, 'yearly')

            tier_type = 'yearly'
            display_name = 'Subscription'
            if price_id:
                cursor.execute('SELECT tier_type, display_name FROM stripe_prices WHERE stripe_price_id = ? AND active = 1', (price_id,))
                tier_row = cursor.fetchone()
                if tier_row:
                    tier_type = tier_row[0]
                    display_name = tier_row[1] or tier_type.title()
                else:
                    cursor.execute('INSERT INTO stripe_prices (stripe_price_id, tier_type, display_name, amount_cents, created_at) VALUES (?, ?, ?, ?, ?)',
                                   (price_id, tier_type, display_name, subscription.items.data[0].price.unit_amount if subscription.items.data else 0, now))

            if license_id and license_id != 'pending':
                cursor.execute('''
                    UPDATE customer_licenses
                    SET stripe_subscription_id = ?, expiry_date = ?, status = 'active', auto_renew = 1, stripe_price_id = ?, renewal_interval = ?, updated_at = ?
                    WHERE id = ?
                ''', (subscription_id, expiry_date, price_id, renewal_interval, now, license_id))

                log_action('UPDATE', 'license', license_id, customer_name or customer_email,
                          f'{display_name} activated. New expiry: {expiry_date[:10]}', 'stripe_webhook')

                cursor.execute('''
                    SELECT cl.license_key, cl.expiry_date, cl.status, cl.mac_address, cl.auto_renew, cl.renewal_interval, cl.stripe_subscription_id,
                           c.name, c.email, c.customer_number
                    FROM customer_licenses cl
                    JOIN customers c ON cl.customer_id = c.id
                    WHERE cl.id = ?
                ''', (license_id,))
                lic_data = cursor.fetchone()

                if lic_data:
                    l_key, l_expiry, l_status, l_mac, l_auto_renew, l_interval, l_stripe_sub, c_name, c_email, c_number = lic_data
                    _send_license_email(
                        customer_email=c_email, customer_name=c_name, customer_number=c_number,
                        license_key=l_key, expiry_date=l_expiry, status=l_status,
                        mac_address=l_mac, auto_renew=bool(l_auto_renew), renewal_interval=l_interval,
                        stripe_subscription_id=l_stripe_sub, tier_type=tier_type, display_name=display_name
                    )
            elif customer_id:
                license_key = generate_license_key()
                license_data = {
                    'customer_number': customer_id,
                    'customer_name': customer_name or '',
                    'expiry_date': expiry_date,
                    'features': ['full_access']
                }
                encrypted_data = base64.b64encode(json.dumps(license_data).encode()).decode()

                cursor.execute('''
                    INSERT INTO customer_licenses (customer_id, license_key, encrypted_data, expiry_date, status, auto_renew, stripe_subscription_id, stripe_price_id, renewal_interval, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, ?, ?)
                ''', (customer_id, license_key, encrypted_data, expiry_date, subscription_id, price_id, renewal_interval, now, now))
                license_id = cursor.lastrowid

                log_action('CREATE', 'license', license_id, customer_name or customer_email,
                          f'Auto-created from Stripe {display_name}. Expires: {expiry_date[:10]}', 'stripe_webhook')

                cursor.execute('''
                    SELECT cl.license_key, cl.expiry_date, cl.status, cl.mac_address, cl.auto_renew, cl.renewal_interval, cl.stripe_subscription_id,
                           c.name, c.email, c.customer_number
                    FROM customer_licenses cl
                    JOIN customers c ON cl.customer_id = c.id
                    WHERE cl.id = ?
                ''', (license_id,))
                lic_data = cursor.fetchone()

                if lic_data:
                    l_key, l_expiry, l_status, l_mac, l_auto_renew, l_interval, l_stripe_sub, c_name, c_email, c_number = lic_data
                    _send_license_email(
                        customer_email=c_email, customer_name=c_name, customer_number=c_number,
                        license_key=l_key, expiry_date=l_expiry, status=l_status,
                        mac_address=l_mac, auto_renew=bool(l_auto_renew), renewal_interval=l_interval,
                        stripe_subscription_id=l_stripe_sub, tier_type=tier_type, display_name=display_name
                    )
        else:
            line_items = session.get('line_items', {})
            if isinstance(line_items, dict) and 'data' in line_items:
                items_data = line_items['data']
            elif isinstance(line_items, list):
                items_data = line_items
            else:
                items_data = []

            if not items_data:
                try:
                    line_items_obj = stripe_lib.checkout.Session.list_line_items(session_id)
                    items_data = line_items_obj.data if hasattr(line_items_obj, 'data') else []
                except Exception as e:
                    print(f"Could not fetch line items for session {session_id}: {e}")
                    conn.close()
                    return

            for item in items_data:
                price_id = item.get('price', {}).get('id') if isinstance(item, dict) else (getattr(item.price, 'id', None) if hasattr(item, 'price') else None)
                if not price_id:
                    continue

                cursor.execute('''
                    SELECT id FROM customer_licenses WHERE stripe_price_id = ? AND customer_id = ?
                ''', (price_id, customer_id))
                already_exists = cursor.fetchone()
                if already_exists:
                    print(f"License already exists for price {price_id} and customer {customer_id}, skipping")
                    continue

                cursor.execute('SELECT tier_type, display_name FROM stripe_prices WHERE stripe_price_id = ? AND active = 1', (price_id,))
                tier_row = cursor.fetchone()
                if tier_row:
                    tier_type = tier_row[0]
                    display_name = tier_row[1] or tier_row[0].title()
                else:
                    tier_type = 'perpetual'
                    display_name = 'Perpetual License'
                    amount = item.get('amount_total', 0) if isinstance(item, dict) else getattr(item, 'amount_total', 0)
                    if not amount:
                        amount = item.get('price', {}).get('unit_amount', 0) if isinstance(item, dict) else (getattr(item.price, 'unit_amount', 0) if hasattr(item, 'price') else 0)
                    cursor.execute('INSERT INTO stripe_prices (stripe_price_id, tier_type, display_name, amount_cents, created_at) VALUES (?, ?, ?, ?, ?)',
                                   (price_id, tier_type, display_name, amount, now))

                if tier_type == 'perpetual':
                    expiry_date = '2099-12-31T23:59:59'
                    renewal_interval = 'perpetual'
                    auto_renew = 0
                    stripe_sub_id = None
                else:
                    expiry_date = (datetime.now() + (timedelta(days=30) if tier_type == 'monthly' else timedelta(days=365))).isoformat()
                    renewal_interval = tier_type
                    auto_renew = 0
                    stripe_sub_id = None

                license_key = generate_license_key()
                license_data = {
                    'customer_number': customer_id,
                    'customer_name': customer_name or '',
                    'expiry_date': expiry_date,
                    'features': ['full_access']
                }
                encrypted_data = base64.b64encode(json.dumps(license_data).encode()).decode()

                cursor.execute('''
                    INSERT INTO customer_licenses (customer_id, license_key, encrypted_data, expiry_date, status, auto_renew, stripe_subscription_id, stripe_price_id, renewal_interval, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
                ''', (customer_id, license_key, encrypted_data, expiry_date, auto_renew, stripe_sub_id, price_id, renewal_interval, now, now))
                new_license_id = cursor.lastrowid

                log_action('CREATE', 'license', new_license_id, customer_name or customer_email,
                          f'Auto-created from Stripe payment: {display_name}', 'stripe_webhook')

                cursor.execute('''
                    SELECT cl.license_key, cl.expiry_date, cl.status, cl.mac_address, cl.auto_renew, cl.renewal_interval, cl.stripe_subscription_id,
                           c.name, c.email, c.customer_number
                    FROM customer_licenses cl
                    JOIN customers c ON cl.customer_id = c.id
                    WHERE cl.id = ?
                ''', (new_license_id,))
                lic_data = cursor.fetchone()

                if lic_data:
                    l_key, l_expiry, l_status, l_mac, l_auto_renew, l_interval, l_stripe_sub, c_name, c_email, c_number = lic_data
                    _send_license_email(
                        customer_email=c_email, customer_name=c_name, customer_number=c_number,
                        license_key=l_key, expiry_date=l_expiry, status=l_status,
                        mac_address=l_mac, auto_renew=bool(l_auto_renew), renewal_interval=l_interval,
                        stripe_subscription_id=l_stripe_sub, tier_type=tier_type, display_name=display_name
                    )

        if customer_id:
            cursor.execute('''
                UPDATE customers SET status = 'active', updated_at = ?
                WHERE id = ?
            ''', (now, customer_id))

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"Error handling checkout.completed: {e}")


def _handle_subscription_created(subscription):
    """Handle new subscription creation - only affects the specific license linked to this subscription"""
    try:
        subscription_id = subscription.id
        status = subscription.status
        current_period_end = subscription.current_period_end
        expiry_date = datetime.fromtimestamp(current_period_end).isoformat()
        
        metadata = subscription.metadata or {}
        license_id = metadata.get('license_id')
        customer_id = metadata.get('customer_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            SELECT id FROM customer_licenses WHERE stripe_subscription_id = ?
        ''', (subscription_id,))
        already_exists = cursor.fetchone()
        
        if already_exists:
            print(f"License already exists for subscription {subscription_id}, skipping")
            conn.close()
            return
        
        price_id = subscription.items.data[0].price.id if subscription.items.data else ''
        interval = subscription.items.data[0].price.recurring.interval if subscription.items.data else 'year'
        interval_map = {'month': 'monthly', 'year': 'yearly'}
        renewal_interval = interval_map.get(interval, 'yearly')
        
        if license_id and license_id != 'pending':
            cursor.execute('''
                UPDATE customer_licenses 
                SET stripe_subscription_id = ?, expiry_date = ?, status = 'active', auto_renew = 1, stripe_price_id = ?, renewal_interval = ?, updated_at = ?
                WHERE id = ?
            ''', (subscription_id, expiry_date, price_id, renewal_interval, now, license_id))
            
            if cursor.rowcount > 0:
                cursor.execute('SELECT customer_id FROM customer_licenses WHERE id = ?', (license_id,))
                result = cursor.fetchone()
                if result:
                    customer_id = result[0]
                
                log_action('UPDATE', 'license', license_id, None,
                          f'Subscription created. Expires: {expiry_date[:10]}', 'stripe_webhook')
        elif customer_id:
            cursor.execute('''
                SELECT id FROM customer_licenses WHERE customer_id = ? AND stripe_subscription_id IS NULL LIMIT 1
            ''', (customer_id,))
            existing_license = cursor.fetchone()
            
            if existing_license:
                license_id = existing_license[0]
                license_key = generate_license_key()
                
                license_data = {
                    'customer_number': customer_id,
                    'customer_name': '',
                    'expiry_date': expiry_date,
                    'features': ['full_access']
                }
                encrypted_data = base64.b64encode(json.dumps(license_data).encode()).decode()
                
                cursor.execute('''
                    INSERT INTO customer_licenses (customer_id, license_key, encrypted_data, expiry_date, status, auto_renew, stripe_subscription_id, stripe_price_id, renewal_interval, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, ?, ?)
                ''', (customer_id, license_key, encrypted_data, expiry_date, subscription_id, price_id, renewal_interval, now, now))
                
                log_action('CREATE', 'license', cursor.lastrowid, None,
                          f'Auto-created from subscription. Expires: {expiry_date[:10]}', 'stripe_webhook')
                
                cursor.execute('''
                    SELECT cl.license_key, cl.expiry_date, cl.status, cl.mac_address, cl.auto_renew, cl.renewal_interval, cl.stripe_subscription_id,
                           c.name, c.email, c.customer_number
                    FROM customer_licenses cl
                    JOIN customers c ON cl.customer_id = c.id
                    WHERE cl.id = ?
                ''', (cursor.lastrowid,))
                lic_data = cursor.fetchone()
                
                if lic_data:
                    l_key, l_expiry, l_status, l_mac, l_auto_renew, l_interval, l_stripe_sub, c_name, c_email, c_number = lic_data
                    _send_license_email(
                        customer_email=c_email,
                        customer_name=c_name,
                        customer_number=c_number,
                        license_key=l_key,
                        expiry_date=l_expiry,
                        status=l_status,
                        mac_address=l_mac,
                        auto_renew=bool(l_auto_renew),
                        renewal_interval=l_interval,
                        stripe_subscription_id=l_stripe_sub
                    )
        
        if customer_id:
            cursor.execute('''
                UPDATE customers SET status = 'active', updated_at = ?
                WHERE id = ?
            ''', (now, customer_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error handling subscription.created: {e}")


def _handle_subscription_updated(subscription):
    """Handle subscription updates - only affects the specific license linked to this subscription"""
    try:
        subscription_id = subscription.id
        status = subscription.status
        current_period_end = subscription.current_period_end
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        our_status = 'active'
        if status in ['past_due', 'unpaid']:
            our_status = 'suspended'
        elif status in ['canceled', 'unfunded']:
            our_status = 'cancelled'
        
        cursor.execute('''
            SELECT id, customer_id FROM customer_licenses WHERE stripe_subscription_id = ?
        ''', (subscription_id,))
        license_result = cursor.fetchone()
        
        if license_result:
            license_id, customer_id = license_result
            
            if current_period_end:
                new_expiry = datetime.fromtimestamp(current_period_end).isoformat()
                cursor.execute('''
                    UPDATE customer_licenses 
                    SET status = ?, expiry_date = ?, updated_at = ?
                    WHERE stripe_subscription_id = ?
                ''', (our_status, new_expiry, now, subscription_id))
                
                log_action('UPDATE', 'license', license_id, None,
                          f'Subscription updated: status={our_status}, expiry={new_expiry[:10]}',
                          'stripe_webhook')
            else:
                cursor.execute('''
                    UPDATE customer_licenses SET status = ?, updated_at = ?
                    WHERE stripe_subscription_id = ?
                ''', (our_status, now, subscription_id))
            
            if customer_id:
                cursor.execute('''
                    UPDATE customers SET status = ?, updated_at = ? WHERE id = ?
                ''', (our_status, now, customer_id))
        else:
            print(f"No license found for subscription {subscription_id}")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error handling subscription.updated: {e}")


def _handle_subscription_deleted(subscription):
    """Handle subscription cancellation - only cancels the specific license linked to this subscription"""
    try:
        subscription_id = subscription.id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            SELECT id, customer_id FROM customer_licenses WHERE stripe_subscription_id = ?
        ''', (subscription_id,))
        license_result = cursor.fetchone()
        
        if license_result:
            license_id, customer_id = license_result
            
            cursor.execute('''
                UPDATE customer_licenses SET status = 'cancelled', auto_renew = 0, updated_at = ?
                WHERE stripe_subscription_id = ?
            ''', (now, subscription_id))
            
            log_action('CANCEL', 'license', license_id, None,
                      f'Subscription {subscription_id} deleted, license cancelled', 'stripe_webhook')
            
            if customer_id:
                cursor.execute('''
                    SELECT COUNT(*) FROM customer_licenses WHERE customer_id = ? AND status != 'cancelled'
                ''', (customer_id,))
                active_licenses = cursor.fetchone()[0]
                
                if active_licenses == 0:
                    cursor.execute('''
                        UPDATE customers SET status = 'cancelled', updated_at = ? WHERE id = ?
                    ''', (now, customer_id))
        else:
            print(f"No license found for deleted subscription {subscription_id}")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error handling subscription.deleted: {e}")


def _handle_payment_succeeded(invoice):
    """Handle successful payment - only extends the specific license linked to this subscription"""
    try:
        subscription_id = invoice.get('subscription', '')
        
        if subscription_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            period_end = invoice.get('lines', {}).get('data', [{}])[0].get('period', {}).get('end', 0)
            if period_end:
                new_expiry = datetime.fromtimestamp(period_end).isoformat()
                now = datetime.now().isoformat()
                
                cursor.execute('''
                    SELECT id, customer_id FROM customer_licenses WHERE stripe_subscription_id = ?
                ''', (subscription_id,))
                license_result = cursor.fetchone()
                
                if license_result:
                    license_id, customer_id = license_result
                    
                    cursor.execute('SELECT renewal_interval FROM customer_licenses WHERE id = ?', (license_id,))
                    lic_row = cursor.fetchone()
                    if lic_row and lic_row[0] == 'perpetual':
                        print(f"Skipping payment.succeeded for perpetual license {license_id}")
                        conn.close()
                        return
                    
                    cursor.execute('''
                        UPDATE customer_licenses 
                        SET expiry_date = ?, status = 'active', updated_at = ?
                        WHERE stripe_subscription_id = ?
                    ''', (new_expiry, now, subscription_id))
                    
                    log_action('RENEW', 'license', license_id, None,
                              f'Payment succeeded, extended to {new_expiry[:10]}', 'stripe_webhook')
            
            conn.commit()
            conn.close()
        
    except Exception as e:
        print(f"Error handling payment.succeeded: {e}")


def _handle_payment_failed(invoice):
    """Handle failed payment - only suspends the specific license linked to this subscription"""
    try:
        subscription_id = invoice.get('subscription', '')
        
        if subscription_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            now = datetime.now().isoformat()
            
            cursor.execute('''
                SELECT id, customer_id FROM customer_licenses WHERE stripe_subscription_id = ?
            ''', (subscription_id,))
            license_result = cursor.fetchone()
            
            if license_result:
                license_id, customer_id = license_result
                
                cursor.execute('''
                    UPDATE customer_licenses SET status = 'suspended', updated_at = ?
                    WHERE stripe_subscription_id = ?
                ''', (now, subscription_id))
                
                log_action('SUSPEND', 'license', license_id, None,
                          'Payment failed, license suspended', 'stripe_webhook')
            
            conn.commit()
            conn.close()
        
    except Exception as e:
        print(f"Error handling payment.failed: {e}")


def _handle_customer_created(customer):
    """Handle new customer creation in Stripe"""
    try:
        customer_id_stripe = customer.id
        customer_email = customer.email
        customer_name = customer.name or customer_email
        
        if not customer_email:
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('SELECT id FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
        result = cursor.fetchone()
        
        if not result:
            customer_number = generate_customer_number()
            cursor.execute('''
                INSERT INTO customers (customer_number, name, email, status, created_at, updated_at)
                VALUES (?, ?, ?, 'active', ?, ?)
            ''', (customer_number, customer_name, customer_email, now, now))
            
            log_action('CREATE', 'customer', cursor.lastrowid, customer_name,
                      f'Auto-created from Stripe. Email: {customer_email}', 'stripe_webhook')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error handling customer.created: {e}")


def _handle_customer_updated(customer):
    """Handle customer updates in Stripe"""
    try:
        customer_email = customer.email
        customer_name = customer.name or customer_email
        
        if not customer_email:
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            UPDATE customers SET name = ?, updated_at = ? WHERE LOWER(email) = LOWER(?)
        ''', (customer_name, now, customer_email))
        
        if cursor.rowcount > 0:
            log_action('UPDATE', 'customer', None, customer_name,
                      f'Updated from Stripe', 'stripe_webhook')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error handling customer.updated: {e}")


@app.route('/api/settings/stripe', methods=['GET', 'POST'])
@login_required
def stripe_settings():
    """Get or save Stripe settings"""
    if request.method == 'GET':
        config = load_stripe_settings()
        if config:
            config['stripe_api_key'] = config.get('stripe_api_key', '')[:20] + '...' if config.get('stripe_api_key') else ''
        return jsonify(config or {})
    
    data = request.get_json()
    api_key = data.get('stripe_api_key', '').strip()
    webhook_secret = data.get('stripe_webhook_secret', '').strip()
    
    if not api_key:
        return jsonify({'success': False, 'error': 'API key is required'})
    
    if save_stripe_settings(api_key, webhook_secret):
        return jsonify({'success': True, 'message': 'Stripe settings saved'})
    else:
        return jsonify({'success': False, 'error': 'Failed to save settings'})


@app.route('/api/stripe/prices', methods=['GET', 'POST'])
@login_required
def stripe_prices_management():
    """Get or create Stripe price mappings"""
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT stripe_price_id, tier_type, display_name, amount_cents, active, created_at FROM stripe_prices ORDER BY created_at DESC')
        rows = cursor.fetchall()
        conn.close()
        return jsonify({
            'success': True,
            'prices': [
                {
                    'stripe_price_id': r[0],
                    'tier_type': r[1],
                    'display_name': r[2],
                    'amount_cents': r[3],
                    'active': bool(r[4]),
                    'created_at': r[5]
                }
                for r in rows
            ]
        })

    data = request.get_json()
    price_id = data.get('stripe_price_id', '').strip()
    tier_type = data.get('tier_type', '').strip()
    display_name = data.get('display_name', '').strip()

    if not price_id:
        return jsonify({'success': False, 'error': 'Stripe Price ID is required'}), 400

    if not tier_type or tier_type not in ('monthly', 'yearly', 'perpetual'):
        return jsonify({'success': False, 'error': 'Tier type must be monthly, yearly, or perpetual'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    cursor.execute('SELECT 1 FROM stripe_prices WHERE stripe_price_id = ?', (price_id,))
    exists = cursor.fetchone()
    if exists:
        cursor.execute('''
            UPDATE stripe_prices SET tier_type = ?, display_name = ?, active = 1, updated_at = ?
            WHERE stripe_price_id = ?
        ''', (tier_type, display_name or tier_type.title(), now, price_id))
    else:
        amount = data.get('amount_cents', 0)
        cursor.execute('''
            INSERT INTO stripe_prices (stripe_price_id, tier_type, display_name, amount_cents, active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
        ''', (price_id, tier_type, display_name or tier_type.title(), amount, now))

    conn.commit()
    conn.close()
    log_action('CREATE' if not exists else 'UPDATE', 'stripe_price', price_id, None,
              f'Mapped to {tier_type}: {display_name}', session.get('username', 'system'))
    return jsonify({'success': True, 'message': 'Price mapping saved'})


@app.route('/api/stripe/prices/<price_id>', methods=['DELETE'])
@login_required
def delete_stripe_price(price_id):
    """Deactivate a Stripe price mapping"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE stripe_prices SET active = 0 WHERE stripe_price_id = ?', (price_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if deleted:
        log_action('DELETE', 'stripe_price', price_id, None, 'Price mapping deactivated', session.get('username', 'system'))
        return jsonify({'success': True, 'message': 'Price mapping removed'})
    return jsonify({'success': False, 'error': 'Price ID not found'}), 404


@app.route('/api/stripe/create-checkout', methods=['POST'])
@login_required
def create_stripe_checkout():
    """Create a Stripe Checkout session for a new or existing customer/license"""
    try:
        data = request.get_json()
        
        customer_name = data.get('customer_name', '').strip()
        customer_email = data.get('customer_email', '').strip()
        license_id = data.get('license_id')
        customer_id = data.get('customer_id')
        amount = data.get('amount', 0)
        currency = data.get('currency', 'usd')
        renewal_interval = data.get('renewal_interval', 'yearly')
        product_name = data.get('product_name', 'License Subscription')
        success_url = data.get('success_url', '')
        cancel_url = data.get('cancel_url', '')
        
        if not customer_email:
            return jsonify({'success': False, 'error': 'Customer email is required'}), 400
        
        if not amount or amount <= 0:
            return jsonify({'success': False, 'error': 'Valid amount is required'}), 400
        
        stripe_config = load_stripe_settings()
        if not stripe_config or not stripe_config.get('stripe_api_key'):
            return jsonify({'success': False, 'error': 'Stripe not configured'}), 400
        
        import stripe as stripe_lib
        stripe_lib.api_key = stripe_config['stripe_api_key']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        if not customer_id and customer_email:
            cursor.execute('SELECT id, name FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
            existing = cursor.fetchone()
            if existing:
                customer_id = existing[0]
                customer_name = customer_name or existing[1]
            else:
                customer_number = generate_customer_number()
                cursor.execute('''
                    INSERT INTO customers (customer_number, name, email, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', ?, ?)
                ''', (customer_number, customer_name, customer_email, now, now))
                customer_id = cursor.lastrowid
                log_action('CREATE', 'customer', customer_id, customer_name,
                          f'Created for Stripe checkout. Email: {customer_email}', session.get('username', 'system'))
        
        stripe_customer_id = None
        customer_result = stripe_lib.Customer.list(email=customer_email, limit=1)
        if customer_result and customer_result.data:
            stripe_customer_id = customer_result.data[0].id
        else:
            customer = stripe_lib.Customer.create(
                email=customer_email,
                name=customer_name,
                metadata={
                    'customer_id': customer_id,
                    'source': 'license_server'
                }
            )
            stripe_customer_id = customer.id
        
        interval_map = {
            'monthly': ('month', 1),
            'quarterly': ('month', 3),
            'yearly': ('year', 1)
        }
        interval, interval_count = interval_map.get(renewal_interval, ('year', 1))
        
        price = stripe_lib.Price.create(
            unit_amount=int(amount * 100),
            currency=currency,
            recurring={
                'interval': interval,
                'interval_count': interval_count
            },
            product_data={
                'name': product_name,
                'metadata': {
                    'customer_id': customer_id,
                    'renewal_interval': renewal_interval
                }
            },
            metadata={
                'customer_id': customer_id,
                'license_id': license_id or 'pending',
                'renewal_interval': renewal_interval
            }
        )
        
        if not success_url:
            success_url = f"{request.host_url}api/stripe/checkout-success?session_id={{CHECKOUT_SESSION_ID}}"
        if not cancel_url:
            cancel_url = f"{request.host_url}license-cancel"
        
        checkout_session = stripe_lib.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=['card'],
            mode='subscription',
            line_items=[{
                'price': price.id,
                'quantity': 1,
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                'customer_id': customer_id,
                'license_id': license_id or 'pending',
                'customer_email': customer_email,
                'customer_name': customer_name,
                'renewal_interval': renewal_interval,
                'source': 'license_server'
            }
        )
        
        if license_id:
            cursor.execute('''
                UPDATE customer_licenses SET stripe_subscription_id = ?, stripe_price_id = ?, renewal_interval = ?, updated_at = ?
                WHERE id = ?
            ''', (checkout_session.id, price.id, renewal_interval, now, license_id))
        else:
            cursor.execute('''
                UPDATE customers SET stripe_subscription_id = ?, updated_at = ?
                WHERE id = ?
            ''', (checkout_session.id, now, customer_id))
        
        conn.commit()
        conn.close()
        
        log_action('CREATE', 'stripe_checkout', checkout_session.id, customer_name,
                  f'Checkout created: {product_name} - ${amount}/{renewal_interval}', session.get('username', 'system'))
        
        return jsonify({
            'success': True,
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id,
            'customer_id': customer_id,
            'price_id': price.id
        })
        
    except Exception as e:
        print(f"Create checkout error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stripe/customer-subscriptions', methods=['GET'])
@login_required
def get_customer_stripe_subscriptions():
    """Get all Stripe subscriptions for a customer"""
    try:
        customer_id = request.args.get('customer_id')
        customer_email = request.args.get('customer_email')
        
        if not customer_id and not customer_email:
            return jsonify({'success': False, 'error': 'customer_id or customer_email required'}), 400
        
        stripe_config = load_stripe_settings()
        if not stripe_config or not stripe_config.get('stripe_api_key'):
            return jsonify({'success': False, 'error': 'Stripe not configured'}), 400
        
        import stripe as stripe_lib
        stripe_lib.api_key = stripe_config['stripe_api_key']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        stripe_customer_id = None
        if customer_id:
            cursor.execute('SELECT email, stripe_subscription_id FROM customers WHERE id = ?', (customer_id,))
        else:
            cursor.execute('SELECT email, stripe_subscription_id FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'success': False, 'error': 'Customer not found'}), 404
        
        email, local_stripe_sub = result
        
        customer_result = stripe_lib.Customer.list(email=email, limit=1)
        if customer_result and customer_result.data:
            stripe_customer_id = customer_result.data[0].id
            subscriptions = stripe_lib.Subscription.list(customer=stripe_customer_id, limit=10)
            
            return jsonify({
                'success': True,
                'subscriptions': [
                    {
                        'id': sub.id,
                        'status': sub.status,
                        'current_period_start': datetime.fromtimestamp(sub.current_period_start).isoformat(),
                        'current_period_end': datetime.fromtimestamp(sub.current_period_end).isoformat(),
                        'items': [
                            {
                                'price_id': item.price.id,
                                'amount': item.price.unit_amount / 100,
                                'currency': item.price.currency,
                                'interval': item.price.recurring.interval,
                                'product': item.price.product
                            }
                            for item in sub.items.data
                        ]
                    }
                    for sub in subscriptions.data
                ]
            })
        
        return jsonify({'success': True, 'subscriptions': []})
        
    except Exception as e:
        print(f"Get customer subscriptions error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stripe/cancel-subscription', methods=['POST'])
@login_required
def cancel_stripe_subscription():
    """Cancel a Stripe subscription"""
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id', '').strip()
        license_id = data.get('license_id')
        customer_id = data.get('customer_id')
        
        if not subscription_id:
            return jsonify({'success': False, 'error': 'Subscription ID is required'}), 400
        
        stripe_config = load_stripe_settings()
        if not stripe_config or not stripe_config.get('stripe_api_key'):
            return jsonify({'success': False, 'error': 'Stripe not configured'}), 400
        
        import stripe as stripe_lib
        stripe_lib.api_key = stripe_config['stripe_api_key']
        
        subscription = stripe_lib.Subscription.retrieve(subscription_id)
        stripe_lib.Subscription.cancel(subscription_id)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        if license_id:
            cursor.execute('''
                UPDATE customer_licenses SET status = 'cancelled', auto_renew = 0, updated_at = ?
                WHERE id = ?
            ''', (now, license_id))
        elif customer_id:
            cursor.execute('''
                UPDATE customer_licenses SET status = 'cancelled', auto_renew = 0, updated_at = ?
                WHERE customer_id = ?
            ''', (now, customer_id))
            cursor.execute('''
                UPDATE customers SET status = 'cancelled', updated_at = ?
                WHERE id = ?
            ''', (now, customer_id))
        
        conn.commit()
        conn.close()
        
        log_action('CANCEL', 'stripe_subscription', subscription_id, None,
                  f'Subscription cancelled via API', session.get('username', 'system'))
        
        return jsonify({
            'success': True,
            'message': 'Subscription cancelled successfully'
        })
        
    except Exception as e:
        print(f"Cancel subscription error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stripe/reconcile', methods=['POST'])
@login_required
def reconcile_stripe_customers():
    """Reconcile Stripe customers with local database - sync subscriptions and licenses"""
    try:
        stripe_config = load_stripe_settings()
        if not stripe_config or not stripe_config.get('stripe_api_key'):
            return jsonify({'success': False, 'error': 'Stripe not configured'}), 400
        
        import stripe as stripe_lib
        stripe_lib.api_key = stripe_config['stripe_api_key']
        
        data = request.get_json()
        reconcile_mode = data.get('mode', 'all')
        created_count = 0
        updated_count = 0
        errors = []
        
        if reconcile_mode in ['all', 'customers']:
            stripe_customers = stripe_lib.Customer.list(limit=100)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            for customer in stripe_customers.auto_paging_iter():
                try:
                    customer_email = customer.email
                    if not customer_email:
                        continue
                    
                    cursor.execute('SELECT id FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
                    result = cursor.fetchone()
                    
                    if not result:
                        customer_number = generate_customer_number()
                        customer_name = customer.name or customer_email
                        
                        cursor.execute('''
                            INSERT INTO customers (customer_number, name, email, status, created_at, updated_at)
                            VALUES (?, ?, ?, 'active', ?, ?)
                        ''', (customer_number, customer_name, customer_email, now, now))
                        
                        local_customer_id = cursor.lastrowid
                        created_count += 1
                        
                        log_action('CREATE', 'customer', local_customer_id, customer_name,
                                  f'Reconciled from Stripe. Email: {customer_email}', session.get('username', 'system'))
                    else:
                        local_customer_id = result[0]
                
                except Exception as e:
                    errors.append(f"Customer {customer.id}: {str(e)}")
            
            conn.commit()
            conn.close()
        
        if reconcile_mode in ['all', 'subscriptions']:
            stripe_subscriptions = stripe_lib.Subscription.list(limit=100, status='all')
            
            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            for subscription in stripe_subscriptions.auto_paging_iter():
                try:
                    subscription_id = subscription.id
                    customer_stripe_id = subscription.customer
                    status = subscription.status
                    current_period_end = subscription.current_period_end
                    
                    customer_email = None
                    if hasattr(subscription, 'customer') and isinstance(subscription.customer, dict):
                        customer_email = subscription.customer.get('email')
                    elif hasattr(subscription, 'customer_email'):
                        customer_email = subscription.customer_email
                    
                    if not customer_email:
                        customer_obj = stripe_lib.Customer.retrieve(customer_stripe_id)
                        customer_email = customer_obj.email
                    
                    if not customer_email:
                        continue
                    
                    cursor.execute('SELECT id FROM customers WHERE LOWER(email) = LOWER(?)', (customer_email,))
                    result = cursor.fetchone()
                    
                    if not result:
                        customer_number = generate_customer_number()
                        customer_name = customer_email
                        cursor.execute('''
                            INSERT INTO customers (customer_number, name, email, status, stripe_subscription_id, created_at, updated_at)
                            VALUES (?, ?, ?, 'active', ?, ?, ?)
                        ''', (customer_number, customer_name, customer_email, subscription_id, now, now))
                        local_customer_id = cursor.lastrowid
                        created_count += 1
                    else:
                        local_customer_id = result[0]
                        cursor.execute('''
                            UPDATE customers SET stripe_subscription_id = ?, updated_at = ?
                            WHERE id = ?
                        ''', (subscription_id, now, local_customer_id))
                    
                    our_status = 'active'
                    if status in ['past_due', 'unpaid']:
                        our_status = 'suspended'
                    elif status in ['canceled', 'unfunded']:
                        our_status = 'cancelled'
                    
                    expiry_date = datetime.fromtimestamp(current_period_end).isoformat() if current_period_end else None
                    
                    cursor.execute('SELECT id FROM customer_licenses WHERE customer_id = ?', (local_customer_id,))
                    existing_license = cursor.fetchone()
                    
                    if not existing_license:
                        license_key = generate_license_key()
                        price_id = subscription.items.data[0].price.id if subscription.items.data else ''
                        interval = subscription.items.data[0].price.recurring.interval if subscription.items.data else 'year'
                        interval_map = {'month': 'monthly', 'year': 'yearly'}
                        renewal_interval = interval_map.get(interval, 'yearly')
                        
                        license_data = {
                            'customer_number': local_customer_id,
                            'customer_name': customer_email,
                            'expiry_date': expiry_date or (datetime.now() + timedelta(days=365)).isoformat(),
                            'features': ['full_access']
                        }
                        encrypted_data = base64.b64encode(json.dumps(license_data).encode()).decode()
                        
                        cursor.execute('''
                            INSERT INTO customer_licenses (customer_id, license_key, encrypted_data, expiry_date, status, auto_renew, stripe_subscription_id, stripe_price_id, renewal_interval, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                        ''', (local_customer_id, license_key, encrypted_data, 
                              expiry_date or (datetime.now() + timedelta(days=365)).isoformat(),
                              our_status, subscription_id, price_id, renewal_interval, now, now))
                        
                        created_count += 1
                        log_action('CREATE', 'license', cursor.lastrowid, customer_email,
                                  f'Reconciled from Stripe subscription. Status: {our_status}', session.get('username', 'system'))
                    else:
                        license_id = existing_license[0]
                        if expiry_date:
                            cursor.execute('''
                                UPDATE customer_licenses 
                                SET status = ?, expiry_date = ?, stripe_subscription_id = ?, auto_renew = 1, updated_at = ?
                                WHERE id = ?
                            ''', (our_status, expiry_date, subscription_id, now, license_id))
                        else:
                            cursor.execute('''
                                UPDATE customer_licenses 
                                SET status = ?, stripe_subscription_id = ?, auto_renew = 1, updated_at = ?
                                WHERE id = ?
                            ''', (our_status, subscription_id, now, license_id))
                        
                        updated_count += 1
                
                except Exception as e:
                    errors.append(f"Subscription {subscription.id}: {str(e)}")
            
            conn.commit()
            conn.close()
        
        log_action('RECONCILE', 'stripe', None, None,
                  f'Reconciliation completed: {created_count} created, {updated_count} updated, {len(errors)} errors',
                  session.get('username', 'system'))
        
        return jsonify({
            'success': True,
            'created': created_count,
            'updated': updated_count,
            'errors': errors[:10]
        })
        
    except Exception as e:
        print(f"Reconcile error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    import socket
    
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("=" * 70)
    print("License Generator - Web Application")
    print("=" * 70)
    print(f"Local:   http://localhost:5001")
    print(f"Network: http://{local_ip}:5001")
    print("Press Ctrl+C to stop")
    print("=" * 70)
    serve(app, host='0.0.0.0', port=5001, threads=8)
