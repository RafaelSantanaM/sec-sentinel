from enum import StrEnum

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from secsentinel.db.base import Base, UUIDAuditMixin


class UserRole(StrEnum):
    """
    Papéis de controle de acesso baseado em função (RBAC - Principle of Least Privilege):
    - ADMIN: Gerencia usuários, configurações globais e visualiza todos os scans.
    - AUDITOR: Inicia auditorias de segurança e visualiza relatórios consolidados.
    - DEVELOPER: Submete scans dos próprios PRs e visualiza apenas os próprios resultados.
    """

    ADMIN = "admin"
    AUDITOR = "auditor"
    DEVELOPER = "developer"


class User(UUIDAuditMixin, Base):
    """Modelo relacional de Usuário com credenciais protegidas por Argon2id."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role_enum", native_enum=False),
        default=UserRole.DEVELOPER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
