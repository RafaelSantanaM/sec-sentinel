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


@pytest.mark.asyncio
async def test_register_mass_assignment_role_is_rejected_with_422() -> None:
    """
    (a) Garante que enviar 'role': 'admin' no payload de /api/v1/auth/register
    seja rejeitado com HTTP 422 Unprocessable Entity (extra='forbid' - Anti Mass Assignment).
    """
    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "attacker@secsentinel.io",
                "password": "ValidPass#2026!",
                "role": "admin",
            },
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_register_creates_developer_and_blocks_admin_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    (b) e (c) Garante que o registro público sempre crie o usuário com role=DEVELOPER
    e que esse usuário receba 403 Forbidden em /api/v1/auth/admin-audit-check.
    """
    users_by_id: dict[str, User] = {}

    async def fake_get_by_email(self: object, email: str) -> User | None:
        return None

    async def fake_create(
        self: object, email: str, hashed_password: str, role: UserRole
    ) -> User:
        user = User(
            id=uuid4(),
            email=email,
            hashed_password=hashed_password,
            role=role,
            is_active=True,
        )
        users_by_id[str(user.id)] = user
        return user

    async def fake_get_by_id(self: object, user_id: object) -> User | None:
        return users_by_id.get(str(user_id))

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_email",
        fake_get_by_email,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.create",
        fake_create,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_id",
        fake_get_by_id,
    )

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newdev@secsentinel.io",
                "password": "ValidPass#2026!",
            },
        )
        assert reg_resp.status_code == status.HTTP_201_CREATED
        body = reg_resp.json()
        assert body["role"] == UserRole.DEVELOPER.value

        dev_token = create_jwt_token(subject=body["id"], role=UserRole.DEVELOPER)
        audit_resp = await client.get(
            "/api/v1/auth/admin-audit-check",
            headers={"Authorization": f"Bearer {dev_token}"},
        )
        assert audit_resp.status_code == status.HTTP_403_FORBIDDEN


def test_cli_create_admin_creates_admin_user(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    (d) Garante que o comando CLI `create-admin` leia a senha via getpass,
    valide a complexidade e crie o usuário com UserRole.ADMIN.
    """
    from secsentinel import cli

    class DummySessionContext:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *args: object) -> None:
            return None

    async def fake_get_by_email(self: object, email: str) -> User | None:
        return None

    async def fake_create(
        self: object, email: str, hashed_password: str, role: UserRole
    ) -> User:
        return User(
            id=uuid4(),
            email=email,
            hashed_password=hashed_password,
            role=role,
            is_active=True,
        )

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_email",
        fake_get_by_email,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.create",
        fake_create,
    )
    monkeypatch.setattr(cli, "AsyncSessionLocal", lambda: DummySessionContext())
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "StrongAdmin#2026!")

    exit_code = cli.main(["create-admin", "--email", "root@secsentinel.io"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "root@secsentinel.io" in captured.out
    assert "role=admin" in captured.out

    # Senha fraca no CLI deve falhar com código de saída 1
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "fraca")
    fail_code = cli.main(["create-admin", "--email", "root2@secsentinel.io"])
    assert fail_code == 1


@pytest.mark.asyncio
async def test_admin_can_promote_user_but_cannot_modify_own_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Testa o endpoint PATCH /api/v1/auth/users/{user_id}/role:
    - ADMIN consegue promover um DEVELOPER para AUDITOR.
    - ADMIN é impedido de alterar o próprio papel (HTTP 400).
    - Usuário inexistente retorna HTTP 404.
    """
    admin_user = User(
        id=uuid4(),
        email="admin@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    dev_user = User(
        id=uuid4(),
        email="dev@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    users_map = {str(admin_user.id): admin_user, str(dev_user.id): dev_user}

    async def fake_get_by_id(self: object, user_id: object) -> User | None:
        return users_map.get(str(user_id))

    async def fake_update_role(self: object, user: User, role: UserRole) -> User:
        user.role = role
        return user

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_id",
        fake_get_by_id,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.update_role",
        fake_update_role,
    )

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db
    admin_token = create_jwt_token(subject=str(admin_user.id), role=UserRole.ADMIN)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Admin promove dev para auditor -> 200 OK
        promote_resp = await client.patch(
            f"/api/v1/auth/users/{dev_user.id}/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "auditor"},
        )
        assert promote_resp.status_code == status.HTTP_200_OK
        assert promote_resp.json()["role"] == "auditor"

        # 2. Admin tenta alterar o próprio papel -> 400 Bad Request
        self_resp = await client.patch(
            f"/api/v1/auth/users/{admin_user.id}/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "developer"},
        )
        assert self_resp.status_code == status.HTTP_400_BAD_REQUEST

        # 3. Admin tenta promover UUID inexistente -> 404 Not Found
        not_found_resp = await client.patch(
            f"/api/v1/auth/users/{uuid4()}/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "auditor"},
        )
        assert not_found_resp.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_auth_service_register_success_and_duplicate_email() -> None:
    """Testa register_user no AuthService: sucesso (DEVELOPER) e erro em e-mail duplicado."""
    from secsentinel.repositories.user_repo import UserRepository
    from secsentinel.services.auth_service import AuthService, UserAlreadyExistsError

    users_by_email: dict[str, User] = {}

    class FakeUserRepo(UserRepository):
        def __init__(self) -> None:
            pass

        async def get_by_email(self, email: str) -> User | None:
            return users_by_email.get(email.lower().strip())

        async def create(
            self, email: str, hashed_password: str, role: UserRole
        ) -> User:
            user = User(
                id=uuid4(),
                email=email.lower().strip(),
                hashed_password=hashed_password,
                role=role,
                is_active=True,
            )
            users_by_email[user.email] = user
            return user

    service = AuthService(FakeUserRepo())
    dto = UserCreate(email="dup@secsentinel.io", password="ValidPass#2026!")

    created = await service.register_user(dto)
    assert created.email == "dup@secsentinel.io"
    assert created.role == UserRole.DEVELOPER
    assert verify_password("ValidPass#2026!", created.hashed_password) is True

    with pytest.raises(UserAlreadyExistsError):
        await service.register_user(dto)


@pytest.mark.asyncio
async def test_auth_service_authenticate_success_wrong_password_missing_and_inactive() -> None:
    """
    Testa authenticate no AuthService:
    1. Sucesso (emite access_token e refresh_token válidos).
    2. Senha incorreta -> AuthenticationError.
    3. Usuário inexistente -> AuthenticationError (com mitigação de timing attack).
    4. Usuário inativo -> AuthenticationError.
    """
    from secsentinel.repositories.user_repo import UserRepository
    from secsentinel.services.auth_service import AuthenticationError, AuthService

    active_user = User(
        id=uuid4(),
        email="active@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    inactive_user = User(
        id=uuid4(),
        email="inactive@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=False,
    )
    users_by_email = {
        active_user.email: active_user,
        inactive_user.email: inactive_user,
    }

    class FakeUserRepo(UserRepository):
        def __init__(self) -> None:
            pass

        async def get_by_email(self, email: str) -> User | None:
            return users_by_email.get(email.lower().strip())

    service = AuthService(FakeUserRepo())

    # 1. Login com sucesso
    tokens = await service.authenticate("active@secsentinel.io", "ValidPass#2026!")
    access_payload = decode_and_verify_jwt(tokens.access_token, expected_scope=TokenScope.ACCESS)
    refresh_payload = decode_and_verify_jwt(
        tokens.refresh_token, expected_scope=TokenScope.REFRESH
    )
    assert access_payload["sub"] == str(active_user.id)
    assert refresh_payload["sub"] == str(active_user.id)

    # 2. Senha errada
    with pytest.raises(AuthenticationError):
        await service.authenticate("active@secsentinel.io", "WrongPass#2026!")

    # 3. Usuário inexistente
    with pytest.raises(AuthenticationError):
        await service.authenticate("ghost@secsentinel.io", "ValidPass#2026!")

    # 4. Usuário inativo
    with pytest.raises(AuthenticationError):
        await service.authenticate("inactive@secsentinel.io", "ValidPass#2026!")


@pytest.mark.asyncio
async def test_auth_service_rotate_tokens_valid_access_confusion_and_inactive() -> None:
    """
    Testa rotate_tokens no AuthService:
    1. Refresh token válido -> emite novo par de tokens.
    2. Access token usado como refresh -> AuthenticationError.
    3. Usuário inativo -> AuthenticationError.
    """
    from secsentinel.repositories.user_repo import UserRepository
    from secsentinel.services.auth_service import AuthenticationError, AuthService

    active_user = User(
        id=uuid4(),
        email="rotate@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.AUDITOR,
        is_active=True,
    )
    inactive_user = User(
        id=uuid4(),
        email="disabled@secsentinel.io",
        hashed_password=hash_password("ValidPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=False,
    )
    users_by_id = {active_user.id: active_user, inactive_user.id: inactive_user}

    class FakeUserRepo(UserRepository):
        def __init__(self) -> None:
            pass

        async def get_by_id(self, user_id: object) -> User | None:
            return users_by_id.get(user_id)  # type: ignore[arg-type]

    service = AuthService(FakeUserRepo())

    # 1. Refresh token válido
    valid_refresh = create_jwt_token(
        subject=str(active_user.id),
        role=active_user.role,
        scope=TokenScope.REFRESH,
    )
    rotated = await service.rotate_tokens(valid_refresh)
    new_access = decode_and_verify_jwt(rotated.access_token, expected_scope=TokenScope.ACCESS)
    new_refresh = decode_and_verify_jwt(rotated.refresh_token, expected_scope=TokenScope.REFRESH)
    assert new_access["sub"] == str(active_user.id)
    assert new_refresh["sub"] == str(active_user.id)

    # 2. Access token usado no lugar de refresh token (Token Type Confusion)
    access_tok = create_jwt_token(
        subject=str(active_user.id),
        role=active_user.role,
        scope=TokenScope.ACCESS,
    )
    with pytest.raises(AuthenticationError):
        await service.rotate_tokens(access_tok)

    # 3. Refresh token de usuário inativo
    inactive_refresh = create_jwt_token(
        subject=str(inactive_user.id),
        role=inactive_user.role,
        scope=TokenScope.REFRESH,
    )
    with pytest.raises(AuthenticationError):
        await service.rotate_tokens(inactive_refresh)

