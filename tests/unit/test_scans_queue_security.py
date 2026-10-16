from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import status
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from secsentinel.api.v1.endpoints.scans import get_scan_service
from secsentinel.core.security import create_jwt_token, hash_password
from secsentinel.db.session import get_db_session
from secsentinel.main import create_app
from secsentinel.models.scan import Scan, ScanStatus, ScanType
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.schemas.scan import ScanCreate
from secsentinel.services.scan_service import ScanService
from secsentinel.worker.celery_app import celery_app


def test_celery_hardening_disallows_pickle_rce() -> None:
    """
    Garante que o Celery esteja configurado exclusivamente com serializador JSON,
    prevenindo Remote Code Execution (RCE) via deserialização insegura de Pickle.
    """
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]
    assert "pickle" not in celery_app.conf.accept_content


@pytest.mark.parametrize(
    "malicious_url",
    [
        "http://127.0.0.1:6379/0",  # Loopback Redis interno
        "http://localhost:5432/db",  # Hostname local
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS Cloud Metadata SSRF!
        "http://10.0.0.15/internal-admin",  # Rede privada RFC1918 Classe A
        "http://192.168.1.1/router",  # Rede privada RFC1918 Classe C
        "http://[::1]:8000/health",  # Loopback IPv6
        "file:///etc/passwd",  # Local File Disclosure via file:// scheme
        "gopher://127.0.0.1:6379/_FLUSHALL",  # Protocolo Gopher para atacar Redis
    ],
)
def test_ssrf_payloads_are_blocked_by_scan_create_schema(malicious_url: str) -> None:
    """
    Comprova que todos os vetores clássicos de SSRF (Cloud Metadata, Loopback, RFC1918,
    file:// e gopher://) são rejeitados antes mesmo de chegarem ao Service ou Worker.
    """
    with pytest.raises(ValidationError):
        ScanCreate(target_url=malicious_url, scan_type=ScanType.API_AUDIT)


def test_valid_public_https_url_is_accepted() -> None:
    """Garante que URLs públicas legítimas passem na validação."""
    dto = ScanCreate(
        target_url="https://api.github.com/repos/org/repo/pulls/42",
        scan_type=ScanType.PR_AUDIT,
    )
    assert dto.target_url == "https://api.github.com/repos/org/repo/pulls/42"


@pytest.mark.asyncio
async def test_enqueue_scan_and_bola_idor_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Testa o fluxo completo da Fase 3:
    1. Dev A dispara POST /api/v1/scans -> 202 Accepted e aciona o mock da fila Celery.
    2. Dev A consulta GET /api/v1/scans/{id} -> 200 OK.
    3. Dev B tenta consultar o Scan do Dev A (Ataque BOLA/IDOR) -> 403 Forbidden!
    4. Auditor consulta o Scan do Dev A -> 200 OK.
    """
    dev_a = User(
        id=uuid4(),
        email="dev_a@secsentinel.io",
        hashed_password=hash_password("StrongPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    dev_b = User(
        id=uuid4(),
        email="dev_b@secsentinel.io",
        hashed_password=hash_password("StrongPass#2026!"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    auditor = User(
        id=uuid4(),
        email="auditor@secsentinel.io",
        hashed_password=hash_password("StrongPass#2026!"),
        role=UserRole.AUDITOR,
        is_active=True,
    )

    users_map = {str(dev_a.id): dev_a, str(dev_b.id): dev_b, str(auditor.id): auditor}
    scans_store: dict[UUID, Scan] = {}
    dispatched_jobs: list[tuple[str, str, str]] = []

    async def fake_get_user_by_id(self: object, user_id: UUID) -> User | None:
        return users_map.get(str(user_id))

    monkeypatch.setattr(
        "secsentinel.repositories.user_repo.UserRepository.get_by_id",
        fake_get_user_by_id,
    )

    class InMemoryScanRepo(ScanRepository):
        def __init__(self) -> None:
            pass

        async def create(
            self, target: str, scan_type: ScanType, triggered_by_id: UUID
        ) -> Scan:
            now = datetime.now(UTC)
            scan = Scan(
                id=uuid4(),
                target=target,
                scan_type=scan_type,
                status=ScanStatus.PENDING,
                triggered_by_id=triggered_by_id,
                risk_score=0.0,
                created_at=now,
                updated_at=now,
                findings=[],
            )
            scans_store[scan.id] = scan
            return scan

        async def update_task_id(self, scan: Scan, celery_task_id: str) -> Scan:
            scan.celery_task_id = celery_task_id
            return scan

        async def get_by_id(self, scan_id: UUID) -> Scan | None:
            return scans_store.get(scan_id)

    def mock_dispatcher(
        scan_id: str,
        target_url: str,
        scan_type: str,
        code_snippet: str | None,
    ) -> str:
        dispatched_jobs.append((scan_id, target_url, scan_type))
        return "mock-celery-task-uuid-999"

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_scan_service] = lambda: ScanService(
        scan_repo=InMemoryScanRepo(),
        task_dispatcher=mock_dispatcher,
    )

    token_dev_a = create_jwt_token(subject=str(dev_a.id), role=UserRole.DEVELOPER)
    token_dev_b = create_jwt_token(subject=str(dev_b.id), role=UserRole.DEVELOPER)
    token_auditor = create_jwt_token(subject=str(auditor.id), role=UserRole.AUDITOR)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Dev A enfileira um Scan
        enqueue_resp = await client.post(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token_dev_a}"},
            json={
                "target_url": "https://github.com/org/repo/pull/10",
                "scan_type": "pr_audit",
            },
        )
        assert enqueue_resp.status_code == status.HTTP_202_ACCEPTED
        body = enqueue_resp.json()
        scan_id = body["scan_id"]
        assert body["celery_task_id"] == "mock-celery-task-uuid-999"
        assert len(dispatched_jobs) == 1

        # 2. Dev A consulta seu próprio Scan -> 200 OK
        own_resp = await client.get(
            f"/api/v1/scans/{scan_id}",
            headers={"Authorization": f"Bearer {token_dev_a}"},
        )
        assert own_resp.status_code == status.HTTP_200_OK

        # 3. Dev B tenta acessar o Scan do Dev A (Ataque BOLA / IDOR) -> 403 FORBIDDEN!
        bola_resp = await client.get(
            f"/api/v1/scans/{scan_id}",
            headers={"Authorization": f"Bearer {token_dev_b}"},
        )
        assert bola_resp.status_code == status.HTTP_403_FORBIDDEN

        # 4. Auditor acessa o Scan do Dev A -> 200 OK
        auditor_resp = await client.get(
            f"/api/v1/scans/{scan_id}",
            headers={"Authorization": f"Bearer {token_auditor}"},
        )
        assert auditor_resp.status_code == status.HTTP_200_OK
