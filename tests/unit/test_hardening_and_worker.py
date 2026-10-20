from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from secsentinel.main import create_app
from secsentinel.models.finding import Finding
from secsentinel.models.scan import Scan, ScanStatus, ScanType
from secsentinel.scanners.base import RawFinding
from secsentinel.worker import tasks
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
    """Valida o endpoint de liveness check (/health) usado pelo Kubernetes."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_readiness_healthz_and_ready_endpoints_healthy_and_degraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Valida que /healthz e /ready testam ativamente PostgreSQL ('SELECT 1') e Redis ('PING'),
    retornando HTTP 200 (healthy) quando ambos respondem e HTTP 503 (degraded) quando falham.
    """
    from secsentinel import main as main_module
    from secsentinel.db.session import get_db_session

    class FakeHealthySession:
        async def execute(self, _stmt: object) -> int:
            return 1

    class FakeBrokenSession:
        async def execute(self, _stmt: object) -> int:
            raise ConnectionError("PostgreSQL connection refused")

    class FakeHealthyRedis:
        async def ping(self) -> bool:
            return True

        async def aclose(self) -> None:
            return None

    class FakeBrokenRedis:
        async def ping(self) -> bool:
            raise ConnectionError("Redis connection refused")

        async def aclose(self) -> None:
            return None

    app = create_app()

    # 1. Cenário Healthy: DB up + Redis up -> HTTP 200 OK
    async def override_healthy_db() -> object:
        yield FakeHealthySession()

    app.dependency_overrides[get_db_session] = override_healthy_db
    monkeypatch.setattr(main_module.aioredis, "from_url", lambda *a, **kw: FakeHealthyRedis())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp_healthz = await client.get("/healthz")
        resp_ready = await client.get("/ready")

    assert resp_healthz.status_code == 200
    assert resp_ready.status_code == 200
    body = resp_healthz.json()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["status"] == "up"
    assert body["checks"]["redis"]["status"] == "up"

    # 2. Cenário Degraded: DB down + Redis down -> HTTP 503 Service Unavailable
    async def override_broken_db() -> object:
        yield FakeBrokenSession()

    app.dependency_overrides[get_db_session] = override_broken_db
    monkeypatch.setattr(main_module.aioredis, "from_url", lambda *a, **kw: FakeBrokenRedis())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp_degraded = await client.get("/healthz")

    assert resp_degraded.status_code == 503
    deg_body = resp_degraded.json()
    assert deg_body["status"] == "degraded"
    assert deg_body["checks"]["database"]["status"] == "down"
    assert deg_body["checks"]["redis"]["status"] == "down"


def test_seed_demo_data_and_onboarding_banner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Valida que o script de Seed (`secsentinel.seed`) cria os usuários de teste,
    popula o Scan demonstrativo de forma idempotente e imprime o banner com Swagger e JWT.
    """
    from secsentinel import seed
    from secsentinel.models.user import User, UserRole

    added_objects: list[object] = []

    class FakeSession:
        def add(self, obj: object) -> None:
            added_objects.append(obj)

        def add_all(self, objs: Sequence[object]) -> None:
            added_objects.extend(objs)

        async def flush(self) -> None:
            return None

        async def commit(self) -> None:
            return None

    class FakeSessionContext:
        async def __aenter__(self) -> FakeSession:
            return FakeSession()

        async def __aexit__(self, *args: object) -> None:
            return None

    class DummyEngine:
        async def dispose(self) -> None:
            return None

    created_users: dict[str, User] = {}

    async def fake_get_by_email(self: object, email: str) -> User | None:
        return created_users.get(email)

    async def fake_create_user(
        self: object, email: str, hashed_password: str, role: UserRole
    ) -> User:
        user = User(
            id=uuid4(),
            email=email,
            hashed_password=hashed_password,
            role=role,
            is_active=True,
        )
        created_users[email] = user
        return user

    async def fake_get_scan_by_id(self: object, scan_id: UUID) -> Scan | None:
        return None

    monkeypatch.setattr(seed, "AsyncSessionLocal", lambda: FakeSessionContext())
    monkeypatch.setattr(seed, "engine", DummyEngine())
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_email",
        fake_get_by_email,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.create",
        fake_create_user,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.get_by_id",
        fake_get_scan_by_id,
    )

    exit_code = seed.main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "http://localhost:8000/docs" in captured.out
    assert "admin@secsentinel.local" in captured.out
    assert "00000000-0000-0000-0000-000000000001" in captured.out
    assert len(added_objects) == 4  # 1 Scan + 3 Findings


def test_celery_worker_task_executes_pr_audit_and_returns_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Testa a execução direta da task do Celery Worker em modo PR_AUDIT:
    - Abre sessão assíncrona e delega ao ScanService.execute_scan_pipeline.
    - Transita o status do Scan por RUNNING e COMPLETED.
    - Persiste os Findings no banco e retorna o veredito BLOCK.
    """
    scan_uuid = UUID("00000000-0000-0000-0000-000000000123")
    now = datetime.now(UTC)
    stored_scan = Scan(
        id=scan_uuid,
        target="https://github.com/org/repo/pull/99",
        scan_type=ScanType.PR_AUDIT,
        status=ScanStatus.PENDING,
        triggered_by_id=uuid4(),
        risk_score=0.0,
        created_at=now,
        updated_at=now,
        findings=[],
    )
    observed_statuses: list[ScanStatus] = []

    class DummySessionContext:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *args: object) -> None:
            return None

    async def fake_get_by_id(self: object, scan_id: UUID) -> Scan | None:
        return stored_scan if scan_id == scan_uuid else None

    async def fake_mark_running(self: object, scan: Scan) -> Scan:
        scan.status = ScanStatus.RUNNING
        observed_statuses.append(scan.status)
        return scan

    async def fake_complete_scan_with_findings(
        self: object,
        scan: Scan,
        raw_findings: Sequence[RawFinding],
        risk_score: float,
    ) -> Scan:
        scan.status = ScanStatus.COMPLETED
        observed_statuses.append(scan.status)
        scan.risk_score = risk_score
        scan.findings = [
            Finding(
                id=uuid4(),
                scan_id=scan.id,
                category=raw.category,
                severity=raw.severity,
                cvss_score=raw.cvss_score,
                title=raw.title,
                description=raw.description,
                file_path=raw.file_path,
                line_number=raw.line_number,
                remediation=raw.remediation,
                created_at=now,
                updated_at=now,
            )
            for raw in raw_findings
        ]
        return scan

    dispose_called = False

    class DummyEngine:
        async def dispose(self) -> None:
            nonlocal dispose_called
            dispose_called = True

    monkeypatch.setattr(tasks, "AsyncSessionLocal", lambda: DummySessionContext())
    monkeypatch.setattr(tasks, "engine", DummyEngine())
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.get_by_id",
        fake_get_by_id,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.mark_running",
        fake_mark_running,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.complete_scan_with_findings",
        fake_complete_scan_with_findings,
    )

    vulnerable_diff = 'import os\nos.system(f"rm -rf {user_dir}")\n'
    result = execute_security_scan_task(
        scan_id=str(scan_uuid),
        target_url=stored_scan.target,
        scan_type=ScanType.PR_AUDIT.value,
        code_snippet=vulnerable_diff,
    )

    assert observed_statuses == [ScanStatus.RUNNING, ScanStatus.COMPLETED]
    assert stored_scan.status == ScanStatus.COMPLETED
    assert len(stored_scan.findings) >= 1
    assert result["status"] == "completed"
    assert result["verdict"] == "BLOCK"
    assert result["risk_score"] >= 8.5
    assert result["total_findings"] == len(stored_scan.findings)
    assert dispose_called is True


def test_celery_worker_task_marks_failed_with_sanitized_error_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Garante que falhas durante a execução marquem o Scan como FAILED e gravem
    uma error_message sanitizada (sem stack trace ou segredos internos - CWE-209).
    """
    scan_uuid = UUID("00000000-0000-0000-0000-000000000999")
    now = datetime.now(UTC)
    stored_scan = Scan(
        id=scan_uuid,
        target="https://api.example.com/v1/health",
        scan_type=ScanType.API_AUDIT,
        status=ScanStatus.PENDING,
        triggered_by_id=uuid4(),
        risk_score=0.0,
        created_at=now,
        updated_at=now,
        findings=[],
    )
    observed_statuses: list[ScanStatus] = []

    class DummySessionContext:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *args: object) -> None:
            return None

    async def fake_get_by_id(self: object, scan_id: UUID) -> Scan | None:
        return stored_scan if scan_id == scan_uuid else None

    async def fake_mark_running(self: object, scan: Scan) -> Scan:
        scan.status = ScanStatus.RUNNING
        observed_statuses.append(scan.status)
        return scan

    async def fake_mark_failed(self: object, scan: Scan, error_message: str) -> Scan:
        scan.status = ScanStatus.FAILED
        scan.error_message = error_message
        observed_statuses.append(scan.status)
        return scan

    async def fake_leaky_probe(self: object, target_url: str) -> list[RawFinding]:
        raise RuntimeError(
            "Traceback: DB failure postgresql+asyncpg://root:TopSecretPass@10.0.0.9:5432/sec"
        )

    dispose_called = False

    class DummyEngine:
        async def dispose(self) -> None:
            nonlocal dispose_called
            dispose_called = True

    monkeypatch.setattr(tasks, "AsyncSessionLocal", lambda: DummySessionContext())
    monkeypatch.setattr(tasks, "engine", DummyEngine())
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.get_by_id",
        fake_get_by_id,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.mark_running",
        fake_mark_running,
    )
    monkeypatch.setattr(
        "secsentinel.repositories.scan_repo.ScanRepository.mark_failed",
        fake_mark_failed,
    )
    monkeypatch.setattr(
        "secsentinel.scanners.dast.engine.APIProber.probe_endpoint",
        fake_leaky_probe,
    )

    with pytest.raises(RuntimeError):
        execute_security_scan_task(
            scan_id=str(scan_uuid),
            target_url=stored_scan.target,
            scan_type=ScanType.API_AUDIT.value,
            code_snippet=None,
        )

    assert observed_statuses == [ScanStatus.RUNNING, ScanStatus.FAILED]
    assert stored_scan.status == ScanStatus.FAILED
    assert stored_scan.error_message is not None
    assert "TopSecretPass" not in stored_scan.error_message
    assert "10.0.0.9" not in stored_scan.error_message
    assert "Traceback" not in stored_scan.error_message
    assert dispose_called is True
