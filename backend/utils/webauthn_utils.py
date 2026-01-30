"""
SecureVault WebAuthn Utilities
==============================
Handlers for Passkey registration and authentication using the `webauthn` library.
"""

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    AuthenticationCredential,
)
from config import RP_ID, RP_NAME, ORIGIN

def generate_reg_options(user, existing_credentials=None):
    """
    Generate options for registering a new credential (step 1).
    """
    if existing_credentials is None:
        existing_credentials = []

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user['id']),  # Must be string
        user_name=user['username'],
        user_display_name=user['username'],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.PLATFORM, # Prefer TouchID/FaceID/Hello
        ),
        exclude_credentials=[
            {"id": base64url_to_bytes(cred["credential_id"]), "transports": eval(cred["transports"]) if cred["transports"] else []}
            for cred in existing_credentials
        ]
    )
    return options

def verify_reg_response(credential, challenge, options):
    """
    Verify the navigator.credentials.create() response (step 2).
    """
    verification = verify_registration_response(
        credential=RegistrationCredential.parse_raw(credential),
        expected_challenge=base64url_to_bytes(challenge),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    return verification

def generate_auth_options(existing_credentials):
    """
    Generate options for logging in (step 1).
    """
    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=[
            {"id": base64url_to_bytes(cred["credential_id"]), "transports": eval(cred["transports"]) if cred["transports"] else []}
            for cred in existing_credentials
        ]
    )
    return options

def verify_auth_response(credential, challenge, stored_credential, sign_count):
    """
    Verify the navigator.credentials.get() response (step 2).
    """
    verification = verify_authentication_response(
        credential=AuthenticationCredential.parse_raw(credential),
        expected_challenge=base64url_to_bytes(challenge),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=base64url_to_bytes(stored_credential['public_key']),
        credential_current_sign_count=sign_count,
    )
    return verification
