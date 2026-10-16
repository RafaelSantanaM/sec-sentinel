import logging
from typing import Any

from secsentinel.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="secsentinel.execute_security_scan", bind=True, max_retries=2)  # type: ignore[untyped-decorator]
def execute_security_scan_task(
    self: Any,
    scan_id: str,
    target_url: str,
    scan_type: str,
    code_snippet: str | None = None,
) -> dict[str, str]:
    """
    Task assíncrona executada pelo Celery Worker.
    Nas Fases 4, 5 e 6, conectaremos aqui os motores puros:
    - SecretScanner (Entropia de Shannon + Regex)
    - SASTEngine (Python AST)
    - APIProber (Mini-DAST)
    """
    logger.info(
        "Iniciando processamento assíncrono do Scan ID=%s (type=%s)",
        scan_id,
        scan_type,
    )
    return {
        "scan_id": scan_id,
        "status": "dispatched",
        "scan_type": scan_type,
    }
