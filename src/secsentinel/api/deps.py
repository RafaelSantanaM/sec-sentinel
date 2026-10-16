from collections.abc import Callable, Coroutine
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from secsentinel.core.security import TokenScope, TokenSecurityError, decode_and_verify_jwt
from secsentinel.db.session import get_db_session
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.user_repo import UserRepository

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> User:
    """
    Extrai o Bearer token do header Authorization, valida sua assinatura/expiração/tipo ('access')
    e busca o usuário ativo no banco.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação ausente.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_and_verify_jwt(
            credentials.credentials,
            expected_scope=TokenScope.ACCESS,
        )
        user_id = UUID(str(payload["sub"]))
    except (TokenSecurityError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    repo = UserRepository(session)
    user = await repo.get_by_id(user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário inativo ou não encontrado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(
    *allowed_roles: UserRole,
) -> Callable[[User], Coroutine[Any, Any, User]]:
    """
    Dependency Factory de RBAC (Role-Based Access Control):
    Verifica se o papel do usuário autenticado está na lista de papéis permitidos para a rota.
    """

    async def role_checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado: privilégios insuficientes para esta operação.",
            )
        return current_user

    return role_checker
