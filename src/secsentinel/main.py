from fastapi import FastAPI

from secsentinel.core.config import settings


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

    @app.get("/health", tags=["System"])
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "environment": settings.ENVIRONMENT}

    return app


app = create_app()
