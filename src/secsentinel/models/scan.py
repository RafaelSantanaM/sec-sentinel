from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secsentinel.db.base import Base, UUIDAuditMixin

if TYPE_CHECKING:
    from secsentinel.models.finding import Finding


class ScanType(StrEnum):
    """Tipos de auditoria suportados pelo SecSentinel."""

    PR_AUDIT = "pr_audit"  # Executa Secret Scanner + SAST no código/PR
    API_AUDIT = "api_audit"  # Executa API Prober (Mini-DAST) no endpoint
    FULL_AUDIT = "full_audit"  # Executa todos os motores aplicáveis


class ScanStatus(StrEnum):
    """Ciclo de vida do job assíncrono na fila."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(UUIDAuditMixin, Base):
    """Registro de uma execução de auditoria de segurança (Job assíncrono)."""

    __tablename__ = "scans"

    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type_enum", native_enum=False),
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status_enum", native_enum=False),
        default=ScanStatus.PENDING,
        index=True,
        nullable=False,
    )
    triggered_by_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    celery_task_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
