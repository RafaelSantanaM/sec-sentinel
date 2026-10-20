import re
from uuid import UUID

import email_validator
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from secsentinel.models.user import UserRole

# Permite domínios internos/laboratório '.local' (ex: admin@secsentinel.local)
# para facilitar homologação local e Active Directory, mantendo validação RFC 5322.
if "local" in email_validator.SPECIAL_USE_DOMAIN_NAMES:
    email_validator.SPECIAL_USE_DOMAIN_NAMES.remove("local")


class UserCreate(BaseModel):
    """Schema de entrada para criação de usuário com validação estrita de senha (OWASP ASVS)."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        """
        Exige complexidade mínima: 12+ chars, maiúscula, minúscula, dígito e especial.
        Limita a 128 chars para evitar DoS por exaustão de CPU no hashing (Long Password DoS).
        """
        if not re.search(r"[A-Z]", v):
            raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r"[a-z]", v):
            raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
        if not re.search(r"\d", v):
            raise ValueError("A senha deve conter pelo menos um número.")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("A senha deve conter pelo menos um caractere especial.")
        return v


class UserRoleUpdate(BaseModel):
    """Schema estrito para alteração administrativa de papel RBAC."""

    model_config = ConfigDict(extra="forbid")

    role: UserRole


class UserRead(BaseModel):
    """Schema de saída de usuário (NUNCA expõe hashed_password!)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    role: UserRole
    is_active: bool


class LoginRequest(BaseModel):
    """Credenciais de login."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """Par de tokens JWT emitido após autenticação ou rotação."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105


class RefreshTokenRequest(BaseModel):
    """Requisição para rotacionar tokens usando um refresh_token válido."""

    refresh_token: str
