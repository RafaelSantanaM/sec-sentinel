from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from secsentinel.api.v1.router import api_v1_router
from secsentinel.core.config import settings
from secsentinel.core.rate_limit import limiter


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

    # Registra o Rate Limiter (SlowAPI) e o handler HTTP 429 Too Many Requests
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    app.include_router(api_v1_router)

    @app.get("/health", tags=["System"])
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "environment": settings.ENVIRONMENT}

    return app


app = create_app()
