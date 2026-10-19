from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from secsentinel.api.deps import get_current_user, require_roles
from secsentinel.core.rate_limit import limiter
from secsentinel.db.session import get_db_session
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.user_repo import UserRepository
from secsentinel.schemas.auth import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserRead,
    UserRoleUpdate,
)
from secsentinel.services.auth_service import (
    AuthenticationError,
    AuthService,
    SelfRoleModificationError,
    UserAlreadyExistsError,
    UserNotFoundError,
)

router = APIRouter(prefix="/auth", tags=["Auth & RBAC"])


def get_auth_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AuthService:
    return AuthService(UserRepository(session))


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    payload: UserCreate,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> User:
    try:
        return await auth_service.register_user(payload)
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    payload: LoginRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    """
    Endpoint protegido por Rate Limiting estrito (5 tentativas/minuto por IP)
    para mitigar ataques de força bruta e Credential Stuffing.
    """
    try:
        return await auth_service.authenticate(payload.email, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
async def refresh_tokens(
    request: Request,
    payload: RefreshTokenRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    try:
        return await auth_service.rotate_tokens(payload.refresh_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me", response_model=UserRead)
async def read_current_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    return current_user


@router.get("/admin-audit-check", response_model=UserRead)
async def admin_or_auditor_only(
    current_user: Annotated[
        User, Depends(require_roles(UserRole.ADMIN, UserRole.AUDITOR))
    ],
) -> User:
    """Rota protegida por RBAC: apenas ADMIN e AUDITOR possuem permissão."""
    return current_user


@router.patch("/users/{user_id}/role", response_model=UserRead)
async def update_user_role(
    user_id: UUID,
    payload: UserRoleUpdate,
    current_admin: Annotated[User, Depends(require_roles(UserRole.ADMIN))],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> User:
    """Promove ou altera o papel de um usuário (exclusivo para ADMIN; proíbe auto-alteração)."""
    try:
        return await auth_service.update_user_role(
            target_user_id=user_id,
            new_role=payload.role,
            acting_admin=current_admin,
        )
    except SelfRoleModificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
