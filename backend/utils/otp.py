"""
SecureVault OTP Utilities
=========================
One-Time Password generation and handling for Multi-Factor Authentication.

Security Implementation:
- 6-digit numeric OTP
- 5-minute expiration
- Single-use (marked as used after verification)
- Cryptographically secure random generation

Note: In demo mode, OTP is displayed in server console.
In production, this would integrate with SMS/Email services.
"""

import secrets
from datetime import datetime, timedelta
from config import OTP_LENGTH, OTP_EXPIRY_MINUTES


def generate_otp():
    """
    Generate a cryptographically secure OTP.
    
    Returns:
        str: 6-digit OTP code
    """
    # Generate a secure random number
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))
    return otp


def send_otp_to_console(username, otp):
    """
    Display OTP in server console (Demo mode).
    
    In production, this would be replaced with:
    - SMS API (Twilio, AWS SNS, etc.)
    - Email API (SendGrid, AWS SES, etc.)
    
    Args:
        username (str): User requesting OTP
        otp (str): Generated OTP code
    """
    expires_at = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    print("\n" + "=" * 50)
    print("🔐 MULTI-FACTOR AUTHENTICATION")
    print("=" * 50)
    print(f"  User: {username}")
    print(f"  OTP Code: {otp}")
    print(f"  Expires: {expires_at.strftime('%H:%M:%S')} ({OTP_EXPIRY_MINUTES} minutes)")
    print("=" * 50)
    print("  📱 In production, this would be sent via SMS/Email")
    print("=" * 50 + "\n")


def format_otp_response(otp_sent=True):
    """
    Format the response for OTP generation.
    
    Args:
        otp_sent (bool): Whether OTP was successfully generated
        
    Returns:
        dict: Response object
    """
    if otp_sent:
        return {
            'success': True,
            'message': 'OTP has been sent! Check the server console.',
            'hint': 'Check the server console for your 6-digit OTP code',
            'expires_in_minutes': OTP_EXPIRY_MINUTES
        }
    else:
        return {
            'success': False,
            'message': 'Failed to generate OTP. Please try again.'
        }


def get_otp_expiry_timestamp():
    """Get the expiry timestamp for a new OTP."""
    return datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
