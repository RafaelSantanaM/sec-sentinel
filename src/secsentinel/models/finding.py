from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secsentinel.db.base import Base, UUIDAuditMixin

if TYPE_CHECKING:
    from secsentinel.models.scan import Scan


class ScannerCategory(StrEnum):
    """Qual motor de segurança detectou a vulnerabilidade."""

    SECRETS = "secrets"
    SAST = "sast"
    DAST = "dast"


class SeverityLevel(StrEnum):
    """Classificação padronizada de severidade (alinhada ao CVSS v3.1)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(UUIDAuditMixin, Base):
    """Vulnerabilidade ou achado de segurança vinculado a um Scan."""

    __tablename__ = "findings"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    category: Mapped[ScannerCategory] = mapped_column(
        Enum(ScannerCategory, name="scanner_category_enum", native_enum=False),
        nullable=False,
    )
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, name="severity_level_enum", native_enum=False),
        index=True,
        nullable=False,
    )
    cvss_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
