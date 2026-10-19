import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from secsentinel.models.scan import Scan, ScanType
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.scanners.base import RawFinding
from secsentinel.scanners.dast.engine import APIProber, SSRFResolutionError
from secsentinel.scanners.sast.engine import SASTEngine
from secsentinel.scanners.secrets.engine import SecretScanner
from secsentinel.schemas.scan import (
    FindingRead,
    ScanCreate,
    ScanEnqueueResponse,
    ScanExecutiveReport,
)
from secsentinel.services.risk_engine import calculate_risk_assessment

logger = logging.getLogger(__name__)


def sanitize_scan_error(exc: Exception) -> str:
    """
    Prevenção de CWE-209 (Generation of Error Message Containing Sensitive Information):
    Garante que nenhum stack trace, credencial de banco ou IP interno vaze para error_message.
    """
    if isinstance(exc, SSRFResolutionError):
        return str(exc)[:500]
    return (
        f"Falha interna ao executar os motores de segurança ({type(exc).__name__}). "
        "Consulte os logs internos do servidor."
    )


class ScanNotFoundError(Exception):
    """Levantada quando o Scan não existe no banco de dados."""

    pass


class ScanAccessDeniedError(Exception):
    """
    Levantada quando um usuário tenta acessar o relatório de outro usuário
    sem possuir papel de ADMIN ou AUDITOR (Proteção contra BOLA / IDOR).
    """

    pass


def default_task_dispatcher(
    scan_id: str,
    target_url: str,
    scan_type: str,
    code_snippet: str | None,
) -> str:
    """Enfileira a task no Celery/Redis e retorna o ID do job assíncrono."""
    from secsentinel.worker.tasks import execute_security_scan_task

    async_result = execute_security_scan_task.delay(
        scan_id=scan_id,
        target_url=target_url,
        scan_type=scan_type,
        code_snippet=code_snippet,
    )
    return str(async_result.id)


class ScanService:
    """Orquestra a criação de auditorias, execução dos motores, cálculo de risco e BOLA."""

    def __init__(
        self,
        scan_repo: ScanRepository,
        task_dispatcher: Callable[[str, str, str, str | None], Any] = default_task_dispatcher,
    ) -> None:
        self._scan_repo = scan_repo
        self._task_dispatcher = task_dispatcher

    async def create_and_enqueue_scan(
        self,
        payload: ScanCreate,
        current_user: User,
    ) -> ScanEnqueueResponse:
        """
        1. Persiste o Scan com status=PENDING vinculado ao usuário autenticado.
        2. Despacha o job para a fila Redis/Celery.
        3. Salva o celery_task_id no registro do Scan.
        """
        scan = await self._scan_repo.create(
            target=payload.target_url,
            scan_type=payload.scan_type,
            triggered_by_id=current_user.id,
        )

        task_id = str(
            self._task_dispatcher(
                str(scan.id),
                payload.target_url,
                payload.scan_type.value,
                payload.code_snippet,
            )
        )
        scan = await self._scan_repo.update_task_id(scan, task_id)

        return ScanEnqueueResponse(
            scan_id=scan.id,
            status=scan.status,
            celery_task_id=task_id,
        )

    async def execute_scan_pipeline(
        self,
        scan_id: UUID,
        code_snippet: str | None = None,
        dast_prober: APIProber | None = None,
    ) -> Scan:
        """
        Executa os motores de segurança (SecretScanner, SASTEngine e/ou APIProber),
        calcula o Risk Score consolidado e persiste os achados no banco.
        """
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ScanNotFoundError("Scan não encontrado para execução.")

        all_findings: list[RawFinding] = []

        try:
            scan = await self._scan_repo.mark_running(scan)

            # 1. Motores White-Box (Secrets + SAST) para PR_AUDIT e FULL_AUDIT
            if scan.scan_type in (ScanType.PR_AUDIT, ScanType.FULL_AUDIT) and code_snippet:
                secret_scanner = SecretScanner()
                sast_engine = SASTEngine()
                all_findings.extend(
                    secret_scanner.scan_text(code_snippet, file_path=scan.target)
                )
                all_findings.extend(sast_engine.scan_code(code_snippet, file_path=scan.target))

            # 2. Motor Black-Box (Mini-DAST) para API_AUDIT e FULL_AUDIT
            if scan.scan_type in (ScanType.API_AUDIT, ScanType.FULL_AUDIT):
                prober = dast_prober or APIProber()
                dast_findings = await prober.probe_endpoint(scan.target)
                all_findings.extend(dast_findings)

            assessment = calculate_risk_assessment(all_findings)
            return await self._scan_repo.complete_scan_with_findings(
                scan=scan,
                raw_findings=all_findings,
                risk_score=assessment.risk_score,
            )
        except Exception as exc:
            logger.exception("Erro ao executar pipeline do Scan ID=%s", scan_id, exc_info=exc)
            await self._scan_repo.mark_failed(scan, sanitize_scan_error(exc))
            raise

    async def get_scan_for_user(self, scan_id: UUID, current_user: User) -> Scan:
        """
        Busca um Scan aplicando defesa estrita contra BOLA / IDOR (OWASP API1:2023):
        - ADMIN e AUDITOR podem auditar qualquer Scan.
        - DEVELOPER só pode acessar Scans cujo triggered_by_id == current_user.id.
        """
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ScanNotFoundError("Scan não encontrado.")

        is_privileged = current_user.role in (UserRole.ADMIN, UserRole.AUDITOR)
        if not is_privileged and scan.triggered_by_id != current_user.id:
            raise ScanAccessDeniedError(
                "Acesso negado: você não tem permissão para visualizar o scan de outro usuário."
            )

        return scan

    async def get_executive_report_for_user(
        self, scan_id: UUID, current_user: User
    ) -> ScanExecutiveReport:
        """
        Gera o Relatório Executivo Consolidado com cálculo de veredito (PASS/WARN/BLOCK),
        distribuição por severidade/categoria e vulnerabilidades ordenadas por CVSS.
        """
        scan = await self.get_scan_for_user(scan_id, current_user)

        raw_findings = [
            RawFinding(
                category=f.category,
                severity=f.severity,
                cvss_score=f.cvss_score,
                title=f.title,
                description=f.description,
                remediation=f.remediation,
                file_path=f.file_path,
                line_number=f.line_number,
            )
            for f in scan.findings
        ]
        assessment = calculate_risk_assessment(raw_findings)

        sorted_finding_models = sorted(
            scan.findings, key=lambda f: f.cvss_score, reverse=True
        )

        return ScanExecutiveReport(
            scan_id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            risk_score=assessment.risk_score,
            verdict=assessment.verdict,
            total_findings=assessment.total_findings,
            severity_breakdown=assessment.severity_breakdown,
            category_breakdown=assessment.category_breakdown,
            created_at=scan.created_at,
            findings=[FindingRead.model_validate(f) for f in sorted_finding_models],
        )
