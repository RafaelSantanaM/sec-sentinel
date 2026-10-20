import logging
import time
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from secsentinel.api.v1.router import api_v1_router
from secsentinel.core.config import settings
from secsentinel.core.rate_limit import limiter
from secsentinel.db.session import get_db_session

logger = logging.getLogger(__name__)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    DEFESA CONTRA VAZAMENTO DE STACK TRACE (CWE-209 / OWASP A05:2021):
    Registra a exceção detalhada apenas nos logs internos do servidor e retorna
    uma mensagem genérica e segura ao cliente HTTP, jamais expondo caminhos de
    arquivos, versões de bibliotecas, queries SQL ou variáveis locais.
    """
    logger.exception(
        "Erro interno não tratado na rota %s %s",
        request.method,
        request.url.path,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": (
                "Ocorreu um erro interno inesperado ao processar a requisição. "
                "O incidente foi registrado para análise da equipe de engenharia."
            )
        },
    )


async def check_database_health(session: AsyncSession) -> dict[str, Any]:
    """Executa uma sonda ativa ('SELECT 1') no PostgreSQL e mede a latência em ms."""
    start = time.perf_counter()
    try:
        await session.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "up", "latency_ms": latency_ms}
    except Exception as exc:
        logger.warning("Falha na sonda de conectividade do PostgreSQL", exc_info=exc)
        return {"status": "down"}


async def check_redis_health() -> dict[str, Any]:
    """Executa uma sonda ativa ('PING') no broker Redis e mede a latência em ms."""
    start = time.perf_counter()
    client = aioredis.from_url(
        settings.REDIS_URL,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
    )
    try:
        await client.ping()
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {"status": "up", "latency_ms": latency_ms}
    except Exception as exc:
        logger.warning("Falha na sonda de conectividade do Redis", exc_info=exc)
        return {"status": "down"}
    finally:
        await client.aclose()


def create_app() -> FastAPI:
    """Application Factory para facilitar testes isolados e múltiplas configurações."""
    # Em produção, desabilitamos Swagger/OpenAPI público para reduzir superfície de reconhecimento
    docs_url = "/docs" if settings.ENVIRONMENT != "production" else None
    redoc_url = "/redoc" if settings.ENVIRONMENT != "production" else None
    openapi_url = "/openapi.json" if settings.ENVIRONMENT != "production" else None

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    # Registra o Rate Limiter (SlowAPI) e os handlers de segurança
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)

    app.include_router(api_v1_router)

    @app.get("/health", tags=["System"])
    async def liveness_probe() -> dict[str, str]:
        """
        Liveness Probe leve: confirma que o processo Python/ASGI está vivo e respondendo.
        Usado pelo Kubernetes (livenessProbe) para detectar travamento de event loop.
        """
        return {"status": "ok", "environment": settings.ENVIRONMENT}

    @app.get("/healthz", tags=["System"])
    @app.get("/ready", tags=["System"])
    async def readiness_probe(
        session: Annotated[AsyncSession, Depends(get_db_session)],
    ) -> JSONResponse:
        """
        Readiness & Deep Health Check realista: verifica ativamente a conectividade
        com o banco de dados PostgreSQL ('SELECT 1') e com o broker Redis ('PING').
        Retorna HTTP 200 (healthy) se ambos responderem ou HTTP 503 (degraded) se
        alguma dependência crítica estiver indisponível.
        """
        db_check = await check_database_health(session)
        redis_check = await check_redis_health()

        is_healthy = db_check["status"] == "up" and redis_check["status"] == "up"
        http_status = (
            status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        )

        return JSONResponse(
            status_code=http_status,
            content={
                "status": "healthy" if is_healthy else "degraded",
                "environment": settings.ENVIRONMENT,
                "checks": {
                    "database": db_check,
                    "redis": redis_check,
                },
            },
        )

    return app


app = create_app()
