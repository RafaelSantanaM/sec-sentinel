import pytest
from httpx import ASGITransport, AsyncClient

from secsentinel.main import create_app
from secsentinel.models.scan import ScanType
from secsentinel.worker.tasks import execute_security_scan_task


@pytest.mark.asyncio
async def test_cwe209_unhandled_exception_never_leaks_stack_trace_or_secrets() -> None:
    """
    Comprova a resposta do Desafio da Fase 7 (Prevenção de CWE-209):
    Se ocorrer um erro interno contendo credenciais de banco ou endereços IP internos
    na exceção do Python, o cliente HTTP recebe apenas uma mensagem genérica 500
    e jamais vê o Stack Trace, a URI do banco ou a senha!
    """
    app = create_app()

    @app.get("/boom-internal-error")
    async def trigger_leaky_db_exception() -> dict[str, str]:
        raise RuntimeError(
            "Connection failed to postgresql+asyncpg://admin:UltraSecretProdPass99@10.24.0.19:5432/prod"
        )

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/boom-internal-error")

    assert resp.status_code == 500
    assert "Ocorreu um erro interno inesperado" in resp.json()["detail"]
    # Garante que NENHUM dado sensível da exceção ou do Traceback vazou na resposta HTTP
    assert "UltraSecretProdPass99" not in resp.text
    assert "10.24.0.19" not in resp.text
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_health_check_endpoint() -> None:
    """Valida o endpoint de healthcheck usado pelo Docker Compose e Load Balancers."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_celery_worker_task_executes_pr_audit_and_returns_assessment() -> None:
    """
    Testa a execução direta da task do Celery Worker em modo PR_AUDIT,
    garantindo que ela acione SecretScanner + SASTEngine e retorne o veredito BLOCK.
    """
    vulnerable_diff = 'import os\nos.system(f"rm -rf {user_dir}")\n'
    result = execute_security_scan_task(
        scan_id="00000000-0000-0000-0000-000000000123",
        target_url="https://github.com/org/repo/pull/99",
        scan_type=ScanType.PR_AUDIT.value,
        code_snippet=vulnerable_diff,
    )

    assert result["status"] == "completed"
    assert result["verdict"] == "BLOCK"
    assert result["risk_score"] >= 8.5
    assert result["total_findings"] >= 1
