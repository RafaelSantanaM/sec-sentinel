import secrets

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
    assert "openssl rand -hex 32" in str(exc_info.value)


def test_known_placeholder_jwt_secret_is_rejected() -> None:
    """Garante que o placeholder antigo do .env.example e CHANGE_ME sejam rejeitados (CWE-1392)."""
    for placeholder in (
        "gere_uma_chave_hexadecimal_forte_com_pelo_menos_32_caracteres_aqui",
        "CHANGE_ME",
    ):
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENVIRONMENT="development",
                JWT_SECRET_KEY=SecretStr(placeholder),
                POSTGRES_USER="user",
                POSTGRES_PASSWORD=SecretStr("password"),
                POSTGRES_DB="db",
            )
        assert "placeholder" in str(exc_info.value).lower()
        assert "openssl rand -hex 32" in str(exc_info.value)


def test_low_entropy_jwt_secret_is_rejected() -> None:
    """Garante que chaves longas mas com baixa diversidade ('a' * 32) sejam rejeitadas."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="development",
            JWT_SECRET_KEY=SecretStr("a" * 32),
            POSTGRES_USER="user",
            POSTGRES_PASSWORD=SecretStr("password"),
            POSTGRES_DB="db",
        )
    assert "baixa diversidade" in str(exc_info.value)
    assert "openssl rand -hex 32" in str(exc_info.value)


def test_random_hex_jwt_secret_is_accepted() -> None:
    """Garante que uma chave hexadecimal aleatória (openssl rand -hex 32) seja aceita."""
    strong_hex_key = secrets.token_hex(32)
    cfg = Settings(
        ENVIRONMENT="development",
        JWT_SECRET_KEY=SecretStr(strong_hex_key),
        POSTGRES_USER="user",
        POSTGRES_PASSWORD=SecretStr("password"),
        POSTGRES_DB="db",
    )
    assert cfg.JWT_SECRET_KEY.get_secret_value() == strong_hex_key


def test_debug_true_in_production_is_blocked() -> None:
    """Garante que DEBUG=True em ambiente de produção seja bloqueado."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,  # Violação de segurança em produção -> DEVE FALHAR!
            JWT_SECRET_KEY=SecretStr(secrets.token_hex(32)),
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
