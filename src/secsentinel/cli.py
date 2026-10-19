import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from secsentinel.core.security import hash_password
from secsentinel.db.session import AsyncSessionLocal
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.user_repo import UserRepository
from secsentinel.schemas.auth import UserCreate
from secsentinel.services.auth_service import UserAlreadyExistsError


async def create_admin_user(
    email: str,
    password: str,
    session_factory: async_sessionmaker[AsyncSession] = AsyncSessionLocal,
) -> User:
    """
    Valida email e senha contra a política OWASP ASVS (UserCreate) e cria um usuário
    com papel UserRole.ADMIN diretamente via banco de dados (fora da superfície HTTP).
    """
    validated = UserCreate(email=email, password=password)

    async with session_factory() as session:
        repo = UserRepository(session)
        existing = await repo.get_by_email(validated.email)
        if existing is not None:
            raise UserAlreadyExistsError("Não foi possível concluir o cadastro com este e-mail.")

        hashed = hash_password(validated.password)
        return await repo.create(
            email=validated.email,
            hashed_password=hashed,
            role=UserRole.ADMIN,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secsentinel.cli",
        description="Ferramenta administrativa de linha de comando do SecSentinel.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_admin_parser = subparsers.add_parser(
        "create-admin",
        help="Cria um usuário administrador (ADMIN) com validação estrita de senha.",
    )
    create_admin_parser.add_argument(
        "--email",
        required=True,
        help="Endereço de e-mail do administrador.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "create-admin":
        password = getpass.getpass("Senha do novo ADMIN: ")
        try:
            user = asyncio.run(create_admin_user(email=args.email, password=password))
        except (ValidationError, UserAlreadyExistsError) as exc:
            sys.stderr.write(f"Erro ao criar administrador: {exc}\n")
            return 1

        sys.stdout.write(f"Administrador criado com sucesso: {user.email} (role={user.role})\n")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
