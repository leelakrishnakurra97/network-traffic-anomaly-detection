"""
Automated unit tests for NetSentinel Authentication & RBAC.
"""

import pytest
from backend.app.auth.jwt_handler import get_password_hash, verify_password, create_access_token, decode_access_token

def test_password_hashing():
    pwd = "SecureAnalystPassword123!"
    hashed = get_password_hash(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_jwt_token_generation_and_decoding():
    payload = {"sub": "42", "role": "admin"}
    token = create_access_token(payload)
    assert isinstance(token, str)
    assert len(token) > 20

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "42"
    assert decoded["role"] == "admin"
    assert "exp" in decoded

def test_invalid_jwt_token():
    decoded = decode_access_token("invalid.bearer.token")
    assert decoded is None
