from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import uuid4

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from secsentinel.core.config import settings
from secsentinel.models.user import UserRole

# Argon2id: Vencedor da Password Hashing Competition (recomendado pela OWASP).
# Combina resistência a ataques de canal lateral (Argon2i) e resistência a GPU/ASIC (Argon2d).
password_hasher = PasswordHash.recommended()

# Hash Argon2id pré-calculado na inicialização para mitigar Timing Attacks:
# Quando um atacante tenta logar com um e-mail inexistente, rodamos verify_password()
# contra este hash dummy para que o tempo de resposta HTTP (~50-100ms) seja idêntico
# ao de um usuário real, impedindo enumeração de usuários por medição de latência.
DUMMY_PASSWORD_HASH: str = password_hasher.hash("dummy_mitigation_against_timing_attacks_123!")


class TokenScope(StrEnum):
    """Escopo do token JWT para prevenir ataques de Token Type Confusion."""

    ACCESS = "access"
    REFRESH = "refresh"


class TokenSecurityError(Exception):
    """Exceção levantada quando um token JWT é inválido, expirado ou adulterado."""

    pass


def hash_password(plain_password: str) -> str:
    """Gera o hash Argon2id seguro com salt aleatório criptográfico."""
    return password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica a senha em tempo constante contra o hash Argon2id."""
    return password_hasher.verify(plain_password, hashed_password)


def create_jwt_token(
    subject: str,
    role: UserRole,
    scope: TokenScope = TokenScope.ACCESS,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Cria um token JWT assinado contendo claims estritas de segurança:
    - sub: Identificador do usuário (UUID)
    - role: Papel RBAC para autorização rápida
    - type: 'access' ou 'refresh' (previne Token Type Confusion Attack)
    - jti: ID único do token (UUIDv4) para suportar revogação/denylist e rotação
    - iat / exp: Timestamps UTC de emissão e expiração curta
    """
    now = datetime.now(UTC)
    if expires_delta is None:
        if scope == TokenScope.ACCESS:
            expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        else:
            expires_delta = timedelta(days=7)

    expire = now + expires_delta

    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role.value,
        "type": scope.value,
        "jti": str(uuid4()),
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(
        payload=payload,
        key=settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_and_verify_jwt(
    token: str,
    expected_scope: TokenScope = TokenScope.ACCESS,
) -> dict[str, Any]:
    """
    Decodifica e valida rigorosamente o JWT:
    1. Força lista explícita de algoritmos permitidos (bloqueia 'alg: none').
    2. Exige a presença das claims críticas ('exp', 'iat', 'sub', 'type', 'jti', 'role').
    3. Verifica se o tipo do token corresponde ao esperado ('access' vs 'refresh').
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            jwt=token,
            key=settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={
                "require": ["exp", "iat", "sub", "type", "jti", "role"],
                "verify_signature": True,
                "verify_exp": True,
            },
        )
    except InvalidTokenError as exc:
        raise TokenSecurityError("Token inválido ou expirado.") from exc

    actual_type = payload.get("type")
    if actual_type != expected_scope.value:
        raise TokenSecurityError(
            f"Violação de tipo de token: esperado '{expected_scope.value}', "
            f"recebido '{actual_type}'."
        )

    return payload
