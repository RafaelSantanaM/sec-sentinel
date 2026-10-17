from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.models.scan import ScanStatus, ScanType
from secsentinel.services.risk_engine import SecurityVerdict

BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}


class FindingRead(BaseModel):
    """DTO de saída para uma vulnerabilidade detectada."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    category: ScannerCategory
    severity: SeverityLevel
    cvss_score: float
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    remediation: str


class ScanCreate(BaseModel):
    """
    Contrato de entrada para disparo de auditoria assíncrona.
    Inclui proteção rigorosa contra Server-Side Request Forgery (SSRF) e DoS por payload gigante.
    """

    target_url: str = Field(
        min_length=8,
        max_length=2048,
        description="URL HTTPS pública do repositório/PR ou da API alvo.",
    )
    scan_type: ScanType = ScanType.FULL_AUDIT
    code_snippet: str | None = Field(
        default=None,
        max_length=200_000,  # Limita a ~200KB para prevenir DoS de memória no Redis/Worker
        description="Diff ou código-fonte opcional do PR para análise estática e de segredos.",
    )

    @field_validator("target_url")
    @classmethod
    def prevent_ssrf_on_target_url(cls, v: str) -> str:
        """
        DEFESA CONTRA SSRF (OWASP API7:2023):
        1. Aceita apenas esquemas http:// ou https:// (bloqueia file://, gopher://, dict://).
        2. Bloqueia localhost e hostnames internos de cloud metadata.
        3. Se o host for um IP literal, bloqueia loopback (127.0.0.1, ::1), redes privadas
           (10.x, 172.16-31.x, 192.168.x) e Link-Local/AWS IMDS (169.254.169.254).
        """
        parsed = urlparse(v.strip())
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Esquema de URL inválido. Apenas http:// e https:// são permitidos.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("A URL alvo deve conter um hostname válido.")

        if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".internal"):
            raise ValueError("SSRF BLOCKED: Hostnames locais ou internos não são permitidos.")

        # Verifica se o hostname é um endereço IP literal (IPv4 ou IPv6)
        try:
            ip = ip_address(hostname)
        except ValueError:
            # Não é um IP literal (é um domínio como github.com), segue normalmente
            return v.strip()

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                f"SSRF BLOCKED: O endereço IP '{ip}' pertence a uma faixa privada, "
                "loopback ou reservada (ex: Cloud Metadata 169.254.169.254)."
            )

        return v.strip()


class ScanEnqueueResponse(BaseModel):
    """Resposta imediata (HTTP 202 Accepted) ao enfileirar um job de scan."""

    scan_id: UUID
    status: ScanStatus
    celery_task_id: str
    message: str = "Scan enfileirado com sucesso para processamento em segundo plano."


class ScanRead(BaseModel):
    """Representação completa de um Scan e suas vulnerabilidades."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target: str
    scan_type: ScanType
    status: ScanStatus
    triggered_by_id: UUID
    celery_task_id: str | None = None
    risk_score: float
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    findings: list[FindingRead] = []


class ScanExecutiveReport(BaseModel):
    """
    Relatório Executivo e de CI/CD Gate consolidado de um Scan:
    Inclui o veredito (PASS/WARN/BLOCK), pontuação de risco (0-10),
    contagem por severidade/categoria e vulnerabilidades ordenadas por criticidade.
    """

    scan_id: UUID
    target: str
    scan_type: ScanType
    status: ScanStatus
    risk_score: float
    verdict: SecurityVerdict
    total_findings: int
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    created_at: datetime
    findings: list[FindingRead] = []
