"""
SecureVault WebAuthn Utilities
==============================
Handlers for Passkey registration and authentication using the `webauthn` library.
"""

import json
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
)
from config import RP_ID, RP_NAME, ORIGIN


def generate_reg_options(user, existing_credentials=None):
    """
    Generate options for registering a new credential (step 1).
    """
    if existing_credentials is None:
        existing_credentials = []

    # Build exclude list from existing credentials
    exclude_creds = []
    for cred in existing_credentials:
        try:
            transports_val = cred.get("transports", "[]")
            if isinstance(transports_val, str):
                transports = eval(transports_val) if transports_val else []
            else:
                transports = transports_val or []
            exclude_creds.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["credential_id"]),
                    transports=transports
                )
            )
        except Exception:
            pass

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user['id']).encode('utf-8'),
        user_name=user['username'],
        user_display_name=user['username'],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        ),
        exclude_credentials=exclude_creds if exclude_creds else None,
    )
    return options


def verify_reg_response(credential_dict, challenge_bytes):
    """
    Verify the navigator.credentials.create() response (step 2).
    
    Args:
        credential_dict: The credential object from frontend (as dict, will be serialized)
        challenge_bytes: The challenge from options (as bytes)
    
    Returns:
        VerifiedRegistration with credential_id, public_key, sign_count
    """
    # The credential must be passed as JSON string for parse_raw
    credential_json = json.dumps(credential_dict)
    
    verification = verify_registration_response(
        credential=RegistrationCredential.parse_raw(credential_json),
        expected_challenge=challenge_bytes,  # Already bytes
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    
    # Convert bytes to base64url strings for storage
    return {
        'verified': verification.verified if hasattr(verification, 'verified') else True,
        'credential_id': bytes_to_base64url(verification.credential_id),
        'credential_public_key': bytes_to_base64url(verification.credential_public_key),
        'sign_count': verification.sign_count,
    }


def generate_auth_options(existing_credentials):
    """
    Generate options for logging in (step 1).
    """
    allow_creds = []
    for cred in existing_credentials:
        try:
            transports_val = cred.get("transports", "[]")
            if isinstance(transports_val, str):
                transports = eval(transports_val) if transports_val else []
            else:
                transports = transports_val or []
            allow_creds.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["credential_id"]),
                    transports=transports
                )
            )
        except Exception:
            pass

    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=allow_creds if allow_creds else None,
    )
    return options


def verify_auth_response(credential_dict, challenge_bytes, stored_credential, current_sign_count):
    """
    Verify the navigator.credentials.get() response (step 2).
    
    Args:
        credential_dict: The credential object from frontend (as dict)
        challenge_bytes: The challenge from options (as bytes)
        stored_credential: The stored credential from DB
        current_sign_count: Current signature counter
    
    Returns:
        dict with 'verified' and 'sign_count'
    """
    credential_json = json.dumps(credential_dict)
    
    verification = verify_authentication_response(
        credential=AuthenticationCredential.parse_raw(credential_json),
        expected_challenge=challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=base64url_to_bytes(stored_credential['public_key']),
        credential_current_sign_count=current_sign_count,
    )
    
    return {
        'verified': verification.verified if hasattr(verification, 'verified') else True,
        'sign_count': verification.new_sign_count,
    }
