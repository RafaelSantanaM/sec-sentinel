import base64
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from secsentinel.core.security import (
    TokenScope,
    TokenSecurityError,
    create_jwt_token,
    decode_and_verify_jwt,
    hash_password,
    verify_password,
)
from secsentinel.db.session import get_db_session
from secsentinel.main import create_app
from secsentinel.models.user import User, UserRole
from secsentinel.schemas.auth import UserCreate


def test_argon2id_hashing_and_verification() -> None:
    """Garante que o hash gerado usa Argon2id com salt único por chamada."""
    raw = "SecSentinel#2026!Strong"
    h1 = hash_password(raw)
    h2 = hash_password(raw)

    assert h1.startswith("$argon2id$")
    assert h1 != h2  # Salts diferentes geram hashes diferentes para a mesma senha
    assert verify_password(raw, h1) is True
    assert verify_password("SenhaErrada#123", h1) is False


def test_weak_passwords_rejected_by_schema() -> None:
    """Garante que senhas curtas ou sem complexidade sejam barradas pelo DTO."""
    with pytest.raises(ValidationError):
        UserCreate(email="dev@secsentinel.io", password="curta")

    with pytest.raises(ValidationError):
        # 12+ chars mas sem caractere especial
        UserCreate(email="dev@secsentinel.io", password="Password123456")


def test_jwt_alg_none_attack_is_blocked() -> None:
    """
    Simula um ataque clássico de falsificação de JWT ('alg': 'none')
    onde o atacante remove a assinatura e tenta elevar seu privilégio para ADMIN.
    """
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": str(uuid4()),
                "role": "admin",
                "type": "access",
                "jti": str(uuid4()),
                "iat": 1700000000,
                "exp": 9999999999,
            }
        ).encode()
    ).rstrip(b"=")
    forged_token = f"{header.decode()}.{payload.decode()}."

    with pytest.raises(TokenSecurityError):
        decode_and_verify_jwt(forged_token, expected_scope=TokenScope.ACCESS)


def test_jwt_token_type_confusion_is_blocked() -> None:
    """
    Impede que um Refresh Token (validade longa de 7 dias) seja usado diretamente
    no lugar de um Access Token para acessar endpoints protegidos.
    """
    refresh_token = create_jwt_token(
        subject=str(uuid4()),
        role=UserRole.ADMIN,
        scope=TokenScope.REFRESH,
    )
    with pytest.raises(TokenSecurityError) as exc_info:
        decode_and_verify_jwt(refresh_token, expected_scope=TokenScope.ACCESS)
    assert "Violação de tipo de token" in str(exc_info.value)


def test_expired_jwt_is_rejected() -> None:
    """Garante que tokens expirados sejam imediatamente rejeitados."""
    expired_token = create_jwt_token(
        subject=str(uuid4()),
        role=UserRole.DEVELOPER,
        scope=TokenScope.ACCESS,
        expires_delta=timedelta(seconds=-10),
    )
    with pytest.raises(TokenSecurityError):
        decode_and_verify_jwt(expired_token, expected_scope=TokenScope.ACCESS)


@pytest.mark.asyncio
async def test_rbac_blocks_developer_from_admin_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Garante que um usuário autenticado com role=DEVELOPER receba 403 Forbidden
    ao tentar acessar uma rota exclusiva de ADMIN/AUDITOR (Broken Function Level Authorization).
    """
    dev_user = User(
        id=uuid4(),
        email="dev@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    auditor_user = User(
        id=uuid4(),
        email="auditor@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.AUDITOR,
        is_active=True,
    )

    users_map = {str(dev_user.id): dev_user, str(auditor_user.id): auditor_user}

    async def fake_get_by_id(self: object, user_id: object) -> User | None:
        return users_map.get(str(user_id))

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_id",
        fake_get_by_id,
    )

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db

    dev_token = create_jwt_token(subject=str(dev_user.id), role=UserRole.DEVELOPER)
    auditor_token = create_jwt_token(subject=str(auditor_user.id), role=UserRole.AUDITOR)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Developer tentando acessar endpoint de auditoria -> DEVE RECEBER 403 FORBIDDEN
        resp_dev = await client.get(
            "/api/v1/auth/admin-audit-check",
            headers={"Authorization": f"Bearer {dev_token}"},
        )
        assert resp_dev.status_code == status.HTTP_403_FORBIDDEN

        # Auditor acessando o mesmo endpoint -> DEVE RECEBER 200 OK
        resp_auditor = await client.get(
            "/api/v1/auth/admin-audit-check",
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert resp_auditor.status_code == status.HTTP_200_OK
        assert resp_auditor.json()["email"] == "auditor@secsentinel.io"


@pytest.mark.asyncio
async def test_login_rate_limiting_blocks_brute_force(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Comprova que a 6ª tentativa seguida de login em menos de 1 minuto é bloqueada
    com HTTP 429 Too Many Requests pelo SlowAPI.
    """

    async def fake_get_by_email(self: object, email: str) -> User | None:
        return None

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_email", fake_get_by_email
    )

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for attempt in range(1, 6):
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "victim@secsentinel.io", "password": f"WrongPass#{attempt}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

        # 6ª tentativa: Rate Limiter deve cortar com 429 Too Many Requests!
        blocked_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "victim@secsentinel.io", "password": "WrongPass#6"},
        )
        assert blocked_resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
