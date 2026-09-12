import uuid

import jwt
import pytest

from app.core.security import (
    create_access_token,
    decode_access_token,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    generate_refresh_token,
    generate_totp_secret,
    hash_password,
    hash_refresh_token,
    parse_refresh_token_tenant_id,
    verify_password,
    verify_totp_code,
)


def test_password_hash_roundtrip():
    hashed = hash_password("Correct-Horse-Battery-Staple-1")
    assert verify_password(hashed, "Correct-Horse-Battery-Staple-1")


def test_password_hash_rejects_wrong_password():
    hashed = hash_password("Correct-Horse-Battery-Staple-1")
    assert not verify_password(hashed, "wrong-password")


def test_password_hash_is_salted_differently_each_time():
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b


def test_access_token_roundtrip():
    user_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    payload = decode_access_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["tenant_id"] == str(tenant_id)
    assert payload["typ"] == "access"


def test_access_token_rejects_none_algorithm():
    """The classic alg=none / algorithm-confusion bypass must fail closed:
    decode_access_token pins algorithms=["HS256"] explicitly, so a token
    signed (or unsigned) with "none" must never be accepted."""
    user_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    forged = jwt.encode(
        {"sub": str(user_id), "tenant_id": str(tenant_id), "typ": "access"},
        key="",
        algorithm="none",
    )
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)


def test_access_token_rejects_wrong_signing_key():
    user_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    forged = jwt.encode(
        {"sub": str(user_id), "tenant_id": str(tenant_id), "typ": "access"},
        key="attacker-controlled-key",
        algorithm="HS256",
    )
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)


def test_access_token_rejects_expired_token():
    from datetime import UTC, datetime, timedelta

    from app.core.config import get_settings

    settings = get_settings()
    payload = {
        "sub": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "typ": "access",
        "iat": datetime.now(UTC) - timedelta(hours=1),
        "exp": datetime.now(UTC) - timedelta(minutes=1),
    }
    expired = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired)


def test_refresh_token_carries_recoverable_tenant_prefix():
    tenant_id = uuid.uuid4()
    token = generate_refresh_token(tenant_id)
    assert parse_refresh_token_tenant_id(token) == tenant_id


def test_refresh_token_hash_is_deterministic_and_one_way():
    token = generate_refresh_token(uuid.uuid4())
    assert hash_refresh_token(token) == hash_refresh_token(token)
    assert hash_refresh_token(token) != token


def test_mfa_secret_encryption_roundtrip():
    secret = generate_totp_secret()
    encrypted = encrypt_mfa_secret(secret)
    assert encrypted != secret
    assert decrypt_mfa_secret(encrypted) == secret


def test_totp_verification():
    import pyotp

    secret = generate_totp_secret()
    valid_code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret=secret, code=valid_code)
    assert not verify_totp_code(secret=secret, code="000000")
