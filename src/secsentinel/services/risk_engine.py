from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.base import RawFinding


class SecurityVerdict(StrEnum):
    """
    Veredito de Quality Gate para esteiras de CI/CD (GitHub Actions / GitLab CI):
    - PASS: Sem achados de médio/alto risco (PR liberado para merge).
    - WARN: Achados de risco moderado (requer revisão manual do time).
    - BLOCK: Achados HIGH ou CRITICAL (bloqueia o merge do Pull Request!).
    """

    PASS = "PASS"  # noqa: S105
    WARN = "WARN"
    BLOCK = "BLOCK"


SEVERITY_PENALTY_WEIGHTS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 0.50,
    SeverityLevel.HIGH: 0.30,
    SeverityLevel.MEDIUM: 0.15,
    SeverityLevel.LOW: 0.05,
    SeverityLevel.INFO: 0.01,
}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Resultado consolidado do cálculo de risco e métricas de um Scan."""

    risk_score: float
    verdict: SecurityVerdict
    total_findings: int
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]


def calculate_risk_assessment(findings: Sequence[RawFinding]) -> RiskAssessment:
    """
    Calcula o Risk Score consolidado (0.0 a 10.0) usando o Princípio do Elo Mais Fraco
    (Worst-Case Base + Penalidade Cumulativa Ponderada), evitando o erro clássico de
    usar média aritmética simples (que diluiria uma falha CRITICAL no meio de falhas LOW).
    """
    severity_counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
    category_counts: dict[str, int] = {cat.value: 0 for cat in ScannerCategory}

    if not findings:
        return RiskAssessment(
            risk_score=0.0,
            verdict=SecurityVerdict.PASS,
            total_findings=0,
            severity_breakdown=severity_counts,
            category_breakdown=category_counts,
        )

    for finding in findings:
        severity_counts[finding.severity.value] += 1
        category_counts[finding.category.value] += 1

    # Ordena do maior CVSS para o menor para identificar o elo mais fraco
    sorted_findings = sorted(findings, key=lambda f: f.cvss_score, reverse=True)
    worst_cvss = sorted_findings[0].cvss_score

    # Soma penalidades adicionais das demais vulnerabilidades encontradas
    additional_penalty = sum(
        SEVERITY_PENALTY_WEIGHTS.get(f.severity, 0.0) for f in sorted_findings[1:]
    )

    final_score = round(min(10.0, worst_cvss + additional_penalty), 2)

    # Determina o veredito de CI/CD Gate
    if (
        severity_counts[SeverityLevel.CRITICAL.value] > 0
        or severity_counts[SeverityLevel.HIGH.value] > 0
        or final_score >= 7.0
    ):
        verdict = SecurityVerdict.BLOCK
    elif severity_counts[SeverityLevel.MEDIUM.value] > 0 or final_score >= 4.0:
        verdict = SecurityVerdict.WARN
    else:
        verdict = SecurityVerdict.PASS

    return RiskAssessment(
        risk_score=final_score,
        verdict=verdict,
        total_findings=len(findings),
        severity_breakdown=severity_counts,
        category_breakdown=category_counts,
    )
