from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from secsentinel.api.deps import get_current_user
from secsentinel.core.rate_limit import limiter
from secsentinel.db.session import get_db_session
from secsentinel.models.scan import Scan
from secsentinel.models.user import User
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.schemas.scan import (
    ScanCreate,
    ScanEnqueueResponse,
    ScanExecutiveReport,
    ScanRead,
)
from secsentinel.services.scan_service import (
    ScanAccessDeniedError,
    ScanNotFoundError,
    ScanService,
)

router = APIRouter(prefix="/scans", tags=["Security Scans"])


def get_scan_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ScanService:
    return ScanService(ScanRepository(session))


@router.post(
    "",
    response_model=ScanEnqueueResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("20/minute")
async def enqueue_scan(
    request: Request,
    payload: ScanCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanEnqueueResponse:
    """
    Recebe um pedido de auditoria de PR ou API, valida contra SSRF
    e despacha assincronamente para o worker Celery via Redis (HTTP 202 Accepted).
    """
    return await scan_service.create_and_enqueue_scan(payload, current_user)


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan_status_and_report(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
) -> Scan:
    """
    Consulta o status e as vulnerabilidades de um Scan.
    Protegido contra BOLA/IDOR: Developers só acessam seus próprios Scans.
    """
    try:
        return await scan_service.get_scan_for_user(scan_id, current_user)
    except ScanNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ScanAccessDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc


@router.get("/{scan_id}/report", response_model=ScanExecutiveReport)
async def get_scan_executive_report(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanExecutiveReport:
    """
    Retorna o Relatório Executivo consolidado com Risk Score (0-10),
    veredito de CI/CD Quality Gate (PASS/WARN/BLOCK) e métricas por severidade e motor.
    Protegido contra BOLA/IDOR.
    """
    try:
        return await scan_service.get_executive_report_for_user(scan_id, current_user)
    except ScanNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ScanAccessDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
