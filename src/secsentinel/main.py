import logging

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from secsentinel.api.v1.router import api_v1_router
from secsentinel.core.config import settings
from secsentinel.core.rate_limit import limiter

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
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "environment": settings.ENVIRONMENT}

    return app


app = create_app()
