"""Password hashing, JWT issuance/verification, and MFA (TOTP) primitives.

Kept dependency-free of any HTTP/DB concerns so it's unit-testable in
isolation — see app/tests/test_security.py.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

_password_hasher = PasswordHasher()

# Fixed algorithm allowlist. PyJWT validates the token's header `alg` against
# exactly this list — "none" is never included, which is what prevents the
# classic alg-confusion/alg=none bypass (THREAT_MODEL.md §3.3).
JWT_ALGORITHM = "HS256"


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the hash was made with weaker parameters than current
    defaults — callers should re-hash and store on next successful login."""
    return _password_hasher.check_needs_rehash(password_hash)


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        # Informational only — every authorization decision re-derives
        # tenant_id from the database, never trusts this claim alone
        # (ARCHITECTURE.md §1 row 3).
        "tenant_id": str(tenant_id),
        "typ": TokenType.ACCESS.value,
        "iat": now,
        "exp": now + timedelta(seconds=settings.jwt_access_token_ttl_seconds),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError (or a subclass) on any invalid/expired/
    wrong-type token — callers must not swallow this silently."""
    settings = get_settings()
    payload: dict[str, Any] = jwt.decode(
        token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM]
    )
    if payload.get("typ") != TokenType.ACCESS.value:
        raise jwt.InvalidTokenError("not an access token")
    return payload


def generate_refresh_token(tenant_id: uuid.UUID) -> str:
    """An opaque, high-entropy bearer token prefixed with its plaintext
    tenant id (`"<tenant_id>.<random>"`) — not a JWT. The prefix carries no
    secrecy (a tenant id is not a credential) but lets the refresh endpoint
    route to the right tenant-scoped session (required because the
    `sessions` table enforces FORCE ROW LEVEL SECURITY — see
    ARCHITECTURE.md §1 row 3) without an unscoped, RLS-bypassing lookup.
    Only the hash of the *whole* string is ever stored
    (Session.refresh_token_hash), so knowing the tenant id alone is
    useless, and rotation/revocation is a plain row update rather than
    needing a JWT blocklist."""
    return f"{tenant_id}.{secrets.token_urlsafe(48)}"


def parse_refresh_token_tenant_id(token: str) -> uuid.UUID:
    tenant_id_str, _, _ = token.partition(".")
    return uuid.UUID(tenant_id_str)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(*, secret: str, account_email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_email, issuer_name="LUNATIC-IT SIEM"
    )


def verify_totp_code(*, secret: str, code: str) -> bool:
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def _fernet() -> Fernet:
    settings = get_settings()
    if not settings.mfa_encryption_key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is not configured")
    return Fernet(settings.mfa_encryption_key)


def encrypt_mfa_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_mfa_secret(encrypted_secret: str) -> str:
    try:
        return _fernet().decrypt(encrypted_secret.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("MFA secret could not be decrypted") from exc
