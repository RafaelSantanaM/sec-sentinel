import math
import re
from collections import Counter
from dataclasses import dataclass

from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.base import RawFinding


@dataclass(frozen=True, slots=True)
class SecretPatternRule:
    """Regra determinística baseada em Regex para provedores conhecidos."""

    id: str
    title: str
    pattern: re.Pattern[str]
    severity: SeverityLevel
    cvss_score: float
    remediation: str


# Regras compiladas (bounded quantifiers para prevenir ataques de ReDoS!)
KNOWN_SECRET_RULES: tuple[SecretPatternRule, ...] = (
    SecretPatternRule(
        id="SEC-AWS-001",
        title="AWS Access Key ID Exposta",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.8,
        remediation=(
            "Revogue imediatamente a credencial no console do AWS IAM, "
            "audite o AWS CloudTrail e utilize IAM Roles ou AWS Secrets Manager."
        ),
    ),
    SecretPatternRule(
        id="SEC-GH-001",
        title="GitHub Personal/App Access Token Exposto",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.5,
        remediation=(
            "Revogue o token em GitHub Settings > Developer Settings e utilize "
            "GITHUB_TOKEN efêmero com permissões mínimas no workflow."
        ),
    ),
    SecretPatternRule(
        id="SEC-PEM-001",
        title="Chave Privada Criptográfica (PEM/OpenSSH) no Código",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.8,
        remediation=(
            "Remova a chave privada do histórico Git (git-filter-repo), gere um novo "
            "par de chaves e injete a chave privada via cofre de segredos em runtime."
        ),
    ),
    SecretPatternRule(
        id="SEC-STRIPE-001",
        title="Stripe Live Secret Key Exposta",
        pattern=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,99})\b"),
        severity=SeverityLevel.CRITICAL,
        cvss_score=9.6,
        remediation=(
            "Realize o roll-out da chave de API no painel do Stripe imediatamente "
            "e armazene-a em variáveis de ambiente seguras."
        ),
    ),
    SecretPatternRule(
        id="SEC-SLACK-001",
        title="Slack Bot/User Token Exposto",
        pattern=re.compile(r"\b(xox[baprs]-[0-9a-zA-Z\-]{10,120})\b"),
        severity=SeverityLevel.HIGH,
        cvss_score=8.5,
        remediation=(
            "Revogue o token do app Slack e mova a credencial para um gerenciador de segredos."
        ),
    ),
)

# Captura atribuições a variáveis com nomes sensíveis: ex: api_key = "valor..."
# Usa quantificadores limitados {16,256} para evitar Catastrophic Backtracking (ReDoS).
GENERIC_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key)
    \s*[:=]\s*
    ['"]([^'"\s]{16,256})['"]
    """
)

# Palavras/placeholders comuns que não devem gerar alerta mesmo se longas
SAFE_PLACEHOLDER_PREFIXES = (
    "your_",
    "example_",
    "changeme",
    "placeholder",
    "gere_uma_chave",
    "dummy_",
    "postgres://",
    "postgresql://",
    "postgresql+asyncpg://",
    "http://",
    "https://",
)


def calculate_shannon_entropy(data: str) -> float:
    """
    Calcula a Entropia de Informação de Shannon H(X) em bits por caractere:
        H(X) = - sum( P(x_i) * log2(P(x_i)) )
    Valores próximos de 0 indicam repetição ('aaaaaa');
    Valores >= 3.6 (hex) ou >= 4.2 (base64/alphanum) indicam alta aleatoriedade criptográfica.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def redact_secret(raw_secret: str) -> str:
    """
    Mascaramento seguro (Redaction) para que o próprio relatório de segurança
    NUNCA armazene ou vaze a credencial real encontrada no código.
    Ex: 'AKIAIOSFODNN7EXAMPLE' -> 'AKIA************MPLE'
    """
    clean = raw_secret.strip()
    if len(clean) <= 8:
        return "*" * len(clean)
    return f"{clean[:4]}{'*' * min(12, len(clean) - 8)}{clean[-4:]}"


def _is_hex_string(candidate: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in candidate)


class SecretScanner:
    """
    Motor híbrido de detecção de credenciais:
    1. Regex determinístico para provedores conhecidos (AWS, GitHub, Stripe, Slack, PEM).
    2. Análise de Entropia de Shannon para segredos genéricos/customizados de alta aleatoriedade.
    """

    def __init__(
        self,
        base64_entropy_threshold: float = 4.2,
        hex_entropy_threshold: float = 3.5,
    ) -> None:
        self.base64_entropy_threshold = base64_entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold

    def scan_text(self, content: str, file_path: str = "inline_snippet") -> list[RawFinding]:
        findings: list[RawFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Permite supressão auditável em linhas específicas se necessário
            if "# nosec" in line or "# secsentinel:ignore" in line:
                continue

            matched_on_line = False

            # Camada 1: Regras de Regex de alta precisão
            for rule in KNOWN_SECRET_RULES:
                match = rule.pattern.search(line)
                if match:
                    secret_val = match.group(1)
                    redacted = redact_secret(secret_val)
                    findings.append(
                        RawFinding(
                            category=ScannerCategory.SECRETS,
                            severity=rule.severity,
                            cvss_score=rule.cvss_score,
                            title=f"[{rule.id}] {rule.title}",
                            description=(
                                f"Credencial detectada na linha {line_idx} "
                                f"(amostra mascarada: `{redacted}`)."
                            ),
                            remediation=rule.remediation,
                            file_path=file_path,
                            line_number=line_idx,
                        )
                    )
                    matched_on_line = True

            if matched_on_line:
                continue

            # Camada 2: Detecção heurística por Entropia de Shannon em atribuições suspeitas
            for generic_match in GENERIC_SECRET_ASSIGNMENT_RE.finditer(line):
                candidate = generic_match.group(1)
                lower_cand = candidate.lower()

                if any(lower_cand.startswith(p) for p in SAFE_PLACEHOLDER_PREFIXES):
                    continue

                entropy = calculate_shannon_entropy(candidate)
                threshold = (
                    self.hex_entropy_threshold
                    if _is_hex_string(candidate)
                    else self.base64_entropy_threshold
                )

                if entropy >= threshold:
                    redacted = redact_secret(candidate)
                    findings.append(
                        RawFinding(
                            category=ScannerCategory.SECRETS,
                            severity=SeverityLevel.HIGH,
                            cvss_score=8.2,
                            title="[SEC-ENTROPY-001] Segredo de Alta Entropia Hardcoded",
                            description=(
                                f"String com alta entropia de Shannon ({entropy:.2f} bits/char) "
                                f"atribuída a variável sensível na linha {line_idx} "
                                f"(amostra mascarada: `{redacted}`)."
                            ),
                            remediation=(
                                "Remova o segredo hardcoded do código-fonte e carregue-o "
                                "via variáveis de ambiente ou cofre de segredos."
                            ),
                            file_path=file_path,
                            line_number=line_idx,
                        )
                    )

        return findings
