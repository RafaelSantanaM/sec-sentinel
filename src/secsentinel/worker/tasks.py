import asyncio
import logging
from typing import Any

from secsentinel.models.scan import ScanType
from secsentinel.scanners.base import RawFinding
from secsentinel.scanners.dast.engine import APIProber
from secsentinel.scanners.sast.engine import SASTEngine
from secsentinel.scanners.secrets.engine import SecretScanner
from secsentinel.services.risk_engine import calculate_risk_assessment
from secsentinel.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


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
    Executa os motores puros (SecretScanner, SASTEngine, APIProber) e calcula o Risk Score.
    """
    logger.info(
        "Iniciando processamento assíncrono do Scan ID=%s (type=%s)",
        scan_id,
        scan_type,
    )
    findings: list[RawFinding] = []

    if scan_type in (ScanType.PR_AUDIT.value, ScanType.FULL_AUDIT.value) and code_snippet:
        findings.extend(SecretScanner().scan_text(code_snippet, file_path=target_url))
        findings.extend(SASTEngine().scan_code(code_snippet, file_path=target_url))

    if scan_type in (ScanType.API_AUDIT.value, ScanType.FULL_AUDIT.value):
        prober = APIProber()
        findings.extend(asyncio.run(prober.probe_endpoint(target_url)))

    assessment = calculate_risk_assessment(findings)
    return {
        "scan_id": scan_id,
        "status": "completed",
        "scan_type": scan_type,
        "risk_score": assessment.risk_score,
        "verdict": assessment.verdict.value,
        "total_findings": assessment.total_findings,
    }
