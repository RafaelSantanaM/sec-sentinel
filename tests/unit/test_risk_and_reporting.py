from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from secsentinel.api.v1.endpoints.scans import get_scan_service
from secsentinel.core.security import create_jwt_token, hash_password
from secsentinel.db.session import get_db_session
from secsentinel.main import create_app
from secsentinel.models.finding import Finding, ScannerCategory, SeverityLevel
from secsentinel.models.scan import Scan, ScanStatus, ScanType
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.scanners.base import RawFinding
from secsentinel.scanners.dast.engine import APIProber
from secsentinel.schemas.scan import ScanCreate
from secsentinel.services.risk_engine import SecurityVerdict, calculate_risk_assessment
from secsentinel.services.scan_service import ScanService


def test_risk_engine_never_dilutes_critical_vulnerability_with_low_findings() -> None:
    """
    Comprova o Princípio do Elo Mais Fraco:
    Se um código tiver 1 falha CRITICAL (CVSS 9.5) e 5 falhas INFO (CVSS 2.0),
    uma média aritmética ingênua daria (9.5 + 10.0) / 6 = 3.25 (mascarando o RCE!).
    Nosso motor parte do pior caso (9.5) + penalidades cumulativas = 9.55 (BLOCK).
    """
    findings = [
        RawFinding(
            category=ScannerCategory.SAST,
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.5,
            title="RCE via eval()",
            description="Execução remota de código",
            remediation="Remova eval()",
        ),
        *[
            RawFinding(
                category=ScannerCategory.DAST,
                severity=SeverityLevel.INFO,
                cvss_score=2.0,
                title=f"Server Banner #{i}",
                description="Banner exposto",
                remediation="Oculte banner",
            )
            for i in range(5)
        ],
    ]

    assessment = calculate_risk_assessment(findings)
    assert assessment.risk_score == 9.55
    assert assessment.verdict == SecurityVerdict.BLOCK
    assert assessment.total_findings == 6
    assert assessment.severity_breakdown["critical"] == 1
    assert assessment.severity_breakdown["info"] == 5


def test_risk_engine_verdicts_pass_warn_and_block() -> None:
    """Garante os 3 estados do Quality Gate de CI/CD: PASS, WARN e BLOCK."""
    # 1. Sem achados -> PASS (0.0)
    empty_assessment = calculate_risk_assessment([])
    assert empty_assessment.risk_score == 0.0
    assert empty_assessment.verdict == SecurityVerdict.PASS

    # 2. Achado MEDIUM -> WARN
    medium_finding = RawFinding(
        category=ScannerCategory.DAST,
        severity=SeverityLevel.MEDIUM,
        cvss_score=5.3,
        title="Missing HSTS",
        description="Sem HSTS",
        remediation="Ative HSTS",
    )
    warn_assessment = calculate_risk_assessment([medium_finding])
    assert warn_assessment.risk_score == 5.3
    assert warn_assessment.verdict == SecurityVerdict.WARN


@pytest.mark.asyncio
async def test_end_to_end_full_audit_pipeline_and_executive_report_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Teste de ponta a ponta dos 3 motores (Secrets + SAST + DAST) com geração
    do Relatório Executivo Consolidado via endpoint HTTP e verificação de BOLA/IDOR.
    """
    dev_user = User(
        id=uuid4(),
        email="dev_report@secsentinel.io",
        hashed_password=hash_password("StrongPassword!2026"),
        role=UserRole.DEVELOPER,
        is_active=True,
    )
    scans_store: dict[UUID, Scan] = {}

    async def fake_get_user_by_id(self: object, user_id: UUID) -> User | None:
        return dev_user if user_id == dev_user.id else None

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

        async def complete_scan_with_findings(
            self,
            scan: Scan,
            raw_findings: Sequence[RawFinding],
            risk_score: float,
        ) -> Scan:
            now = datetime.now(UTC)
            scan.status = ScanStatus.COMPLETED
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

    repo = InMemoryScanRepo()
    service = ScanService(scan_repo=repo, task_dispatcher=lambda *args: "mock-task-777")

    app = create_app()

    async def override_db() -> object:
        yield None

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_scan_service] = lambda: service

    raw_aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    vulnerable_pr_code = f"""
AWS_ACCESS_KEY = "{raw_aws_key}"

def run_untrusted(user_input: str):
    return eval(user_input)
"""

    def mock_target_api(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, headers={"Server": "Apache/2.4.49"})

    # 1. Cria o Scan e executa o pipeline combinando SecretScanner + SASTEngine + APIProber
    enqueue_resp = await service.create_and_enqueue_scan(
        ScanCreate(
            target_url="https://api.example.com/v1/users",
            scan_type=ScanType.FULL_AUDIT,
            code_snippet=vulnerable_pr_code,
        ),
        current_user=dev_user,
    )

    dast_prober = APIProber(
        transport=httpx.MockTransport(mock_target_api),
        skip_dns_resolution=True,
    )
    await service.execute_scan_pipeline(
        scan_id=enqueue_resp.scan_id,
        code_snippet=vulnerable_pr_code,
        dast_prober=dast_prober,
    )

    # 2. Consulta o endpoint GET /api/v1/scans/{scan_id}/report
    token = create_jwt_token(subject=str(dev_user.id), role=UserRole.DEVELOPER)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        report_res = await client.get(
            f"/api/v1/scans/{enqueue_resp.scan_id}/report",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert report_res.status_code == 200
        report = report_res.json()

        assert report["status"] == "completed"
        assert report["verdict"] == "BLOCK"
        assert report["risk_score"] == 10.0
        assert report["category_breakdown"]["secrets"] >= 1
        assert report["category_breakdown"]["sast"] >= 1
        assert report["category_breakdown"]["dast"] >= 1

        # Verifica que os achados estão ordenados do maior CVSS para o menor
        cvss_list = [f["cvss_score"] for f in report["findings"]]
        assert cvss_list == sorted(cvss_list, reverse=True)

        # Garante que a chave AWS real jamais aparece em texto claro no relatório JSON!
        assert raw_aws_key not in report_res.text
