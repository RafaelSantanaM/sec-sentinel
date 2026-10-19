from typing import Literal

from pydantic import PostgresDsn, SecretStr, ValidationInfo, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configurações globais validadas na inicialização (Fail-Fast).
    Se uma variável crítica estiver ausente ou insegura, a aplicação não sobe.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    PROJECT_NAME: str = "SecSentinel"
    DEBUG: bool = False

    # SEGURANÇA: SecretStr mascara o valor em logs e stack traces (ex: SecretStr('**********'))
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: Literal["HS256", "RS256"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15

    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_DB: str
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432

    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret_strength(cls, v: SecretStr) -> SecretStr:
        """
        Impede chaves fracas, placeholders públicos (CWE-1392/CWE-798) ou chaves de baixa
        diversidade (CWE-321) que seriam facilmente forjadas ou quebradas offline.
        Exige no mínimo 32 caracteres (256 bits para HS256 conforme RFC 7518) e >= 10
        caracteres distintos.
        """
        secret_value = v.get_secret_value()
        known_placeholders = {
            "gere_uma_chave_hexadecimal_forte_com_pelo_menos_32_caracteres_aqui",
            "change_me",
            "changeme",
        }
        if secret_value.strip().lower() in known_placeholders:
            raise ValueError(
                "A variável JWT_SECRET_KEY utiliza um valor placeholder público conhecido! "
                "Gere uma chave exclusiva com: `openssl rand -hex 32`."
            )
        if len(secret_value) < 32:
            raise ValueError(
                "A variável JWT_SECRET_KEY é insegura! "
                "Deve conter no mínimo 32 caracteres (256 bits). "
                "Gere uma chave forte com: `openssl rand -hex 32`."
            )
        if len(set(secret_value)) < 10:
            raise ValueError(
                "A variável JWT_SECRET_KEY possui baixa diversidade/entropia "
                "(mínimo de 10 caracteres distintos). "
                "Gere uma chave forte com: `openssl rand -hex 32`."
            )
        return v

    @field_validator("DEBUG")
    @classmethod
    def prevent_debug_in_production(cls, v: bool, info: ValidationInfo) -> bool:
        """Garante que DEBUG=True jamais seja ativado em produção."""
        env = info.data.get("ENVIRONMENT")
        if env == "production" and v is True:
            raise ValueError(
                "SECURITY VIOLATION: DEBUG não pode ser True em ambiente de produção!"
            )
        return v

    @computed_field(repr=False)  # type: ignore[prop-decorator]
    @property
    def sqlalchemy_database_uri(self) -> str:
        """Constrói a URI assíncrona do PostgreSQL de forma segura."""
        dsn = PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD.get_secret_value(),
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )
        return str(dsn)


# Instância singleton carregada na importação
settings = Settings()  # type: ignore[call-arg]
