from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from secsentinel.models.finding import Finding
from secsentinel.models.scan import Scan, ScanStatus, ScanType
from secsentinel.scanners.base import RawFinding


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

    async def complete_scan_with_findings(
        self,
        scan: Scan,
        raw_findings: Sequence[RawFinding],
        risk_score: float,
    ) -> Scan:
        """Persiste todos os achados dos scanners, atualiza o risk_score e marca COMPLETED."""
        scan.status = ScanStatus.COMPLETED
        scan.risk_score = risk_score
        for raw in raw_findings:
            finding_model = Finding(
                scan_id=scan.id,
                category=raw.category,
                severity=raw.severity,
                cvss_score=raw.cvss_score,
                title=raw.title,
                description=raw.description,
                file_path=raw.file_path,
                line_number=raw.line_number,
                remediation=raw.remediation,
            )
            self._session.add(finding_model)
        await self._session.commit()
        loaded = await self.get_by_id(scan.id)
        return loaded if loaded is not None else scan

    async def mark_failed(self, scan: Scan, error_message: str) -> Scan:
        """Marca o Scan como FAILED caso ocorra erro ou bloqueio SSRF na execução."""
        scan.status = ScanStatus.FAILED
        scan.error_message = error_message[:1000]
        await self._session.commit()
        await self._session.refresh(scan)
        return scan
