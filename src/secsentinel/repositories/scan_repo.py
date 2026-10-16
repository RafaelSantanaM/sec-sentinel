from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from secsentinel.models.scan import Scan, ScanStatus, ScanType


class ScanRepository:
    """Repositório assíncrono para persistência e consulta de Scans."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        target: str,
        scan_type: ScanType,
        triggered_by_id: UUID,
    ) -> Scan:
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            triggered_by_id=triggered_by_id,
            risk_score=0.0,
        )
        self._session.add(scan)
        await self._session.commit()
        await self._session.refresh(scan)
        return scan

    async def update_task_id(self, scan: Scan, celery_task_id: str) -> Scan:
        scan.celery_task_id = celery_task_id
        await self._session.commit()
        await self._session.refresh(scan)
        return scan

    async def get_by_id(self, scan_id: UUID) -> Scan | None:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(Scan.id == scan_id)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
