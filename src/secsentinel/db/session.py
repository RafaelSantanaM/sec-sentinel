from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from secsentinel.core.config import settings

# Configuração de Pool resiliente contra esgotamento de conexões (DoS)
engine = create_async_engine(
    settings.sqlalchemy_database_uri,
    echo=False,  # Nunca logar queries SQL em produção (podem conter dados sensíveis)
    pool_pre_ping=True,  # Testa se a conexão está viva antes de usar
    pool_size=10,  # Conexões mantidas abertas no pool
    max_overflow=20,  # Pico máximo sob carga intensa
    pool_timeout=30,  # Timeout caso todas as conexões estejam ocupadas
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency Injection do FastAPI para fornecer uma sessão de banco por request.
    Garante rollback em caso de erro e fechamento seguro da conexão.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
