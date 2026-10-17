from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.secrets.engine import (
    SecretScanner,
    calculate_shannon_entropy,
    redact_secret,
)


def test_shannon_entropy_math_accuracy() -> None:
    """
    Valida a matemática da Entropia de Shannon:
    - String com 1 único caractere repetido ('aaaaaaaa') tem entropia 0.0.
    - String com 2 chars igualmente distribuídos ('abababab') tem entropia exata de 1.0 bit/char.
    - Chave criptográfica aleatória tem entropia > 4.2 bits/char.
    """
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0
    assert calculate_shannon_entropy("abababab") == 1.0

    high_entropy_key = "k9#mP2$vL8@qR5!xZ1&wN4^tY7*uJ0(eB3"
    assert calculate_shannon_entropy(high_entropy_key) > 4.5


def test_secret_redaction_never_exposes_plaintext() -> None:
    """Garante que o mascaramento oculte o meio da credencial."""
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(raw_aws)
    assert redacted == "AKIA************MPLE"
    assert "IOSFODNN7EXA" not in redacted
    assert redact_secret("curto") == "*****"


def test_detects_aws_github_and_private_keys() -> None:
    """Comprova a detecção determinística de chaves AWS, GitHub e RSA Private Key."""
    vulnerable_pr_code = '''
    # Config de deploy
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GH_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----"""
    '''
    scanner = SecretScanner()
    findings = scanner.scan_text(vulnerable_pr_code, file_path="deploy.py")

    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert any("SEC-AWS-001" in t for t in titles)
    assert any("SEC-GH-001" in t for t in titles)
    assert any("SEC-PEM-001" in t for t in titles)

    # Verifica que NENHUM finding vazou o segredo completo na descrição!
    for f in findings:
        assert f.category == ScannerCategory.SECRETS
        assert f.severity == SeverityLevel.CRITICAL
        assert "AKIAIOSFODNN7EXAMPLE" not in f.description
        assert "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" not in f.description


def test_detects_generic_high_entropy_secret_and_ignores_low_entropy() -> None:
    """
    Comprova o diferencial da Entropia de Shannon:
    - Ignora palavras comuns ou placeholders ('bearer', 'your_api_key_here_placeholder')
    - Detecta uma chave real de alta entropia atribuída a uma variável 'api_key'.
    """
    code_sample = """
    token_type = "bearer"
    password = "aaaaaaaaaa"
    api_key = "your_api_key_here_placeholder"
    client_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e"
    """
    scanner = SecretScanner()
    findings = scanner.scan_text(code_sample, file_path="settings.py")

    # Apenas a linha 5 (client_secret hexadecimal de alta entropia) deve ser reportada!
    assert len(findings) == 1
    finding = findings[0]
    assert "SEC-ENTROPY-001" in finding.title
    assert finding.line_number == 5
    assert "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e" not in finding.description
    assert "9f8e************1f0e" in finding.description
