from dataclasses import dataclass

from secsentinel.models.finding import ScannerCategory, SeverityLevel


@dataclass(frozen=True, slots=True)
class RawFinding:
    """
    Objeto de Valor (Value Object) imutável retornado pelos motores de scan.
    Totalmente desacoplado de banco de dados (SQLAlchemy) e de HTTP (FastAPI).
    """

    category: ScannerCategory
    severity: SeverityLevel
    cvss_score: float
    title: str
    description: str
    remediation: str
    file_path: str | None = None
    line_number: int | None = None
