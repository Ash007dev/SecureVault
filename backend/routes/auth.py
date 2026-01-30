"""
SecureVault Authentication Routes
=================================
Handles user registration, login with MFA, and password reset.

Endpoints:
- POST /auth/register - Create new account
- POST /auth/login - Password verification → OTP sent
- POST /auth/verify-otp - Complete MFA → JWT issued
- POST /auth/forgot-password - Request reset OTP
- POST /auth/reset-password - Reset with OTP
- GET /auth/me - Get current user info

NIST SP 800-63-2 Compliance:
- Strong password policy enforcement
- Multi-factor authentication
- Rate limiting on login attempts
"""

from flask import Blueprint, request, jsonify, g
from models import (
    create_user, get_user_by_username, update_user_password,
    create_otp, verify_otp, create_audit_log,
    record_login_attempt, is_rate_limited, clear_login_attempts
)
from utils.crypto import hash_password, verify_password, validate_password_policy
from utils.access_control import create_jwt_token, require_auth, get_client_ip
from utils.otp import generate_otp, send_otp_to_console, format_otp_response

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# =============================================================================
# REGISTRATION
# =============================================================================

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user account.
    
    Request Body:
        - username (str): Unique username
        - password (str): Password (must meet policy)
        - role (str): 'student' or 'faculty'
        - email (str, optional): Email address
    """
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    role = data.get('role', 'student').lower()
    email = data.get('email')
    
    # Validate role (only student and faculty can self-register)
    if role not in ['student', 'faculty']:
        return jsonify({'error': 'Role must be student or faculty'}), 400
    
    # Check if username already exists
    if get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 409
    
    # Validate password policy
    is_valid, errors = validate_password_policy(password)
    if not is_valid:
        return jsonify({
            'error': 'Password does not meet requirements',
            'requirements': errors
        }), 400
    
    # Hash password and create user
    password_hash, salt = hash_password(password)
    user = create_user(username, password_hash, salt, role, email)
    
    if not user:
        return jsonify({'error': 'Failed to create user'}), 500
    
    # Audit log
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='USER_REGISTERED',
        details=f'New {role} account created',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': f'Account created successfully as {role}',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }), 201


# =============================================================================
# LOGIN (Step 1 - Password Verification)
# =============================================================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login step 1: Verify password and send OTP.
    
    Request Body:
        - username (str): Username
        - password (str): Password
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    ip_address = get_client_ip()
    
    # Check rate limiting
    if is_rate_limited(username, ip_address):
        create_audit_log(
            user_id=None,
            username=username,
            action='LOGIN_RATE_LIMITED',
            details='Too many failed attempts',
            ip_address=ip_address
        )
        return jsonify({
            'error': 'Too many failed login attempts',
            'message': 'Please try again in 15 minutes'
        }), 429
    
    # Get user
    user = get_user_by_username(username)
    
    if not user:
        record_login_attempt(username, ip_address, False)
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Verify password
    if not verify_password(password, user['password_hash'], user['salt']):
        record_login_attempt(username, ip_address, False)
        create_audit_log(
            user_id=user['id'],
            username=username,
            action='LOGIN_FAILED',
            details='Invalid password',
            ip_address=ip_address
        )
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Password correct - generate and send OTP
    otp = generate_otp()
    create_otp(username, otp)
    send_otp_to_console(username, otp)
    
    # Audit log
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='LOGIN_PASSWORD_OK',
        details='Password verified, OTP sent',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'Password verified. Please enter the OTP from the server console.',
        'requires_otp': True,
        **format_otp_response(True)
    })


# =============================================================================
# VERIFY OTP (Step 2 - Complete MFA)
# =============================================================================

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    """
    Login step 2: Verify OTP and issue JWT token.
    
    Request Body:
        - username (str): Username
        - otp (str): 6-digit OTP code
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Username and OTP are required'}), 400
    
    username = data['username'].strip()
    otp_code = data['otp'].strip()
    ip_address = get_client_ip()
    
    # Verify OTP
    if not verify_otp(username, otp_code):
        create_audit_log(
            user_id=None,
            username=username,
            action='OTP_FAILED',
            details='Invalid or expired OTP',
            ip_address=ip_address
        )
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    # Get user for token generation
    user = get_user_by_username(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Clear failed login attempts
    clear_login_attempts(username)
    
    # Generate JWT token
    token = create_jwt_token(user['id'], user['username'], user['role'])
    
    # Audit log
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='LOGIN_SUCCESS',
        details='MFA completed, token issued',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })


# =============================================================================
# FORGOT PASSWORD
# =============================================================================

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Request password reset OTP.
    
    Request Body:
        - username (str): Username
    """
    data = request.get_json()
    
    if not data or not data.get('username'):
        return jsonify({'error': 'Username is required'}), 400
    
    username = data['username'].strip()
    ip_address = get_client_ip()
    
    # Check if user exists
    user = get_user_by_username(username)
    
    if not user:
        # Don't reveal if user exists or not
        return jsonify({
            'success': True,
            'message': 'If the username exists, an OTP will be sent to the server console.'
        })
    
    # Generate and send OTP
    otp = generate_otp()
    create_otp(username, otp)
    send_otp_to_console(username, otp)
    
    # Audit log
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='PASSWORD_RESET_REQUESTED',
        details='Reset OTP sent',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'OTP sent to server console',
        **format_otp_response(True)
    })


# =============================================================================
# RESET PASSWORD
# =============================================================================

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset password with OTP verification.
    
    Request Body:
        - username (str): Username
        - otp (str): 6-digit OTP code
        - new_password (str): New password (must meet policy)
    """
    data = request.get_json()
    
    if not data or not all(k in data for k in ['username', 'otp', 'new_password']):
        return jsonify({'error': 'Username, OTP, and new password are required'}), 400
    
    username = data['username'].strip()
    otp_code = data['otp'].strip()
    new_password = data['new_password']
    ip_address = get_client_ip()
    
    # Verify OTP
    if not verify_otp(username, otp_code):
        create_audit_log(
            user_id=None,
            username=username,
            action='PASSWORD_RESET_FAILED',
            details='Invalid or expired OTP',
            ip_address=ip_address
        )
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    # Validate new password policy
    is_valid, errors = validate_password_policy(new_password)
    if not is_valid:
        return jsonify({
            'error': 'New password does not meet requirements',
            'requirements': errors
        }), 400
    
    # Hash new password and update
    password_hash, salt = hash_password(new_password)
    success = update_user_password(username, password_hash, salt)
    
    if not success:
        return jsonify({'error': 'Failed to update password'}), 500
    
    # Get user for audit log
    user = get_user_by_username(username)
    
    # Audit log
    create_audit_log(
        user_id=user['id'] if user else None,
        username=username,
        action='PASSWORD_RESET_SUCCESS',
        details='Password successfully reset',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'Password reset successfully! Please login with your new password.'
    })


# =============================================================================
# GET CURRENT USER
# =============================================================================

@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current authenticated user's info."""
    return jsonify({
        'user': {
            'id': g.user['user_id'],
            'username': g.user['username'],
            'role': g.user['role']
        }
    })
