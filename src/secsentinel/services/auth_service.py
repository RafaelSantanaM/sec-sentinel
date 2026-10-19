from uuid import UUID

from secsentinel.core.security import (
    DUMMY_PASSWORD_HASH,
    TokenScope,
    TokenSecurityError,
    create_jwt_token,
    decode_and_verify_jwt,
    hash_password,
    verify_password,
)
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.user_repo import UserRepository
from secsentinel.schemas.auth import TokenResponse, UserCreate


class AuthenticationError(Exception):
    """Erro genérico de autenticação (mensagem uniforme para não revelar se o e-mail existe)."""

    pass


class UserAlreadyExistsError(Exception):
    """Levantada ao tentar registrar um e-mail já cadastrado."""

    pass


class UserNotFoundError(Exception):
    """Levantada quando o usuário alvo não é encontrado."""

    pass


class SelfRoleModificationError(Exception):
    """Levantada quando um administrador tenta alterar o próprio papel RBAC."""

    pass


class AuthService:
    """Casos de uso de registro, autenticação segura e rotação de JWT."""

    def __init__(self, user_repo: UserRepository) -> None:
        self._user_repo = user_repo

    async def register_user(self, data: UserCreate) -> User:
        existing = await self._user_repo.get_by_email(data.email)
        if existing is not None:
            raise UserAlreadyExistsError("Não foi possível concluir o cadastro com este e-mail.")

        hashed = hash_password(data.password)
        return await self._user_repo.create(
            email=data.email,
            hashed_password=hashed,
            role=UserRole.DEVELOPER,
        )

    async def update_user_role(
        self,
        target_user_id: UUID,
        new_role: UserRole,
        acting_admin: User,
    ) -> User:
        """Promove ou altera o papel de um usuário, bloqueando auto-alteração de privilégio."""
        if target_user_id == acting_admin.id:
            raise SelfRoleModificationError(
                "Operação bloqueada: um administrador não pode alterar o próprio papel."
            )

        target_user = await self._user_repo.get_by_id(target_user_id)
        if target_user is None:
            raise UserNotFoundError("Usuário não encontrado.")

        return await self._user_repo.update_role(target_user, new_role)

    async def authenticate(self, email: str, password: str) -> TokenResponse:
        """
        Autentica um usuário prevenindo User Enumeration (por mensagem e por Timing Attack).
        """
        user = await self._user_repo.get_by_email(email)

        if user is None:
            # Executa o Argon2id contra o DUMMY_PASSWORD_HASH para gastar o mesmo tempo de CPU
            verify_password(password, DUMMY_PASSWORD_HASH)
            raise AuthenticationError("Credenciais inválidas.")

        if not verify_password(password, user.hashed_password) or not user.is_active:
            raise AuthenticationError("Credenciais inválidas.")

        access_token = create_jwt_token(
            subject=str(user.id),
            role=user.role,
            scope=TokenScope.ACCESS,
        )
        refresh_token = create_jwt_token(
            subject=str(user.id),
            role=user.role,
            scope=TokenScope.REFRESH,
        )
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    async def rotate_tokens(self, refresh_token: str) -> TokenResponse:
        """Valida um refresh_token e emite um novo par de tokens (Token Rotation)."""
        try:
            payload = decode_and_verify_jwt(refresh_token, expected_scope=TokenScope.REFRESH)
            user_id = UUID(str(payload["sub"]))
        except (TokenSecurityError, ValueError) as exc:
            raise AuthenticationError("Refresh token inválido ou expirado.") from exc

        user = await self._user_repo.get_by_id(user_id)
        if user is None or not user.is_active:
            raise AuthenticationError("Usuário inativo ou inexistente.")

        return TokenResponse(
            access_token=create_jwt_token(
                subject=str(user.id), role=user.role, scope=TokenScope.ACCESS
            ),
            refresh_token=create_jwt_token(
                subject=str(user.id), role=user.role, scope=TokenScope.REFRESH
            ),
        )
