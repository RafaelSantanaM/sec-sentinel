import asyncio
import logging
from typing import Any
from uuid import UUID

from secsentinel.db.session import AsyncSessionLocal
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.scanners.base import RawFinding
from secsentinel.services.risk_engine import calculate_risk_assessment
from secsentinel.services.scan_service import ScanService
from secsentinel.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _run_scan_pipeline_async(
    scan_id: UUID,
    code_snippet: str | None = None,
) -> dict[str, Any]:
    """Abre uma AsyncSession dedicada do worker e delega ao ScanService.execute_scan_pipeline."""
    async with AsyncSessionLocal() as session:
        scan_repo = ScanRepository(session)
        scan_service = ScanService(scan_repo=scan_repo)
        scan = await scan_service.execute_scan_pipeline(
            scan_id=scan_id,
            code_snippet=code_snippet,
        )

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
    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "scan_type": scan.scan_type.value,
        "risk_score": scan.risk_score,
        "verdict": assessment.verdict.value,
        "total_findings": assessment.total_findings,
    }


@celery_app.task(name="secsentinel.execute_security_scan", bind=True, max_retries=2)  # type: ignore[untyped-decorator]
def execute_security_scan_task(
    self: Any,
    scan_id: str,
    target_url: str,
    scan_type: str,
    code_snippet: str | None = None,
) -> dict[str, Any]:
    """
    Task assíncrona executada pelo Celery Worker:
    Abre uma AsyncSession própria e delega para ScanService.execute_scan_pipeline,
    persistindo transições de status (RUNNING -> COMPLETED / FAILED) e Findings no banco.
    """
    logger.info(
        "Iniciando processamento assíncrono do Scan ID=%s (type=%s, target=%s)",
        scan_id,
        scan_type,
        target_url,
    )
    return asyncio.run(
        _run_scan_pipeline_async(
            scan_id=UUID(scan_id),
            code_snippet=code_snippet,
        )
    )
