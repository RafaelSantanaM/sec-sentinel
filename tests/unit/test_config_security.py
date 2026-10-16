import pytest
from pydantic import SecretStr, ValidationError

from secsentinel.core.config import Settings


def test_weak_jwt_secret_is_rejected() -> None:
    """Garante que chaves JWT curtas (< 32 chars) disparem ValidationError (Fail-Fast)."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="development",
            JWT_SECRET_KEY=SecretStr("chave_curta_123"),  # 15 chars -> DEVE FALHAR!
            POSTGRES_USER="user",
            POSTGRES_PASSWORD=SecretStr("password"),
            POSTGRES_DB="db",
        )
    assert "no mínimo 32 caracteres" in str(exc_info.value)


def test_debug_true_in_production_is_blocked() -> None:
    """Garante que DEBUG=True em ambiente de produção seja bloqueado."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,  # Violação de segurança em produção -> DEVE FALHAR!
            JWT_SECRET_KEY=SecretStr("a" * 32),
            POSTGRES_USER="user",
            POSTGRES_PASSWORD=SecretStr("password"),
            POSTGRES_DB="db",
        )
    assert "SECURITY VIOLATION" in str(exc_info.value)


def test_secret_str_does_not_leak_in_repr() -> None:
    """Garante que dar print/log no objeto Settings não exponha a chave real."""
    real_secret = "super_secret_jwt_key_with_more_than_32_chars!"
    cfg = Settings(
        ENVIRONMENT="development",
        JWT_SECRET_KEY=SecretStr(real_secret),
        POSTGRES_USER="user",
        POSTGRES_PASSWORD=SecretStr("my_db_secret_password"),
        POSTGRES_DB="db",
    )
    # Ao converter para string ou repr, o valor real jamais deve aparecer
    assert real_secret not in repr(cfg)
    assert "my_db_secret_password" not in repr(cfg)
