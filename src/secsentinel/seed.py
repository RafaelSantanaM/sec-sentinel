import asyncio
import sys
from datetime import timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from secsentinel.core.security import TokenScope, create_jwt_token, hash_password
from secsentinel.db.session import AsyncSessionLocal, engine
from secsentinel.models.finding import Finding, ScannerCategory, SeverityLevel
from secsentinel.models.scan import Scan, ScanStatus, ScanType
from secsentinel.models.user import UserRole
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.repositories.user_repo import UserRepository

DEMO_SCAN_ID = UUID("00000000-0000-0000-0000-000000000001")
SEED_ADMIN_EMAIL = "admin@secsentinel.local"
SEED_ADMIN_PASSWORD = "senha123"  # noqa: S105
SEED_DEV_EMAIL = "dev@secsentinel.local"
SEED_DEV_PASSWORD = "SecSentinel#2026!"  # noqa: S105


async def seed_demo_data(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> dict[str, str]:
    """
    Popula o banco de dados de forma idempotente com usuários de teste (ADMIN e DEVELOPER)
    e um Scan de auditoria completo para avaliação imediata por recrutadores e tech leads.
    """
    factory = session_factory or AsyncSessionLocal
    async with factory() as session:
        user_repo = UserRepository(session)
        scan_repo = ScanRepository(session)

        # 1. Garante usuário ADMIN de teste rápido (admin@secsentinel.local / senha123)
        admin_user = await user_repo.get_by_email(SEED_ADMIN_EMAIL)
        if admin_user is None:
            admin_user = await user_repo.create(
                email=SEED_ADMIN_EMAIL,
                hashed_password=hash_password(SEED_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
            )

        # 2. Garante usuário DEVELOPER para testes de RBAC e BOLA/IDOR
        dev_user = await user_repo.get_by_email(SEED_DEV_EMAIL)
        if dev_user is None:
            dev_user = await user_repo.create(
                email=SEED_DEV_EMAIL,
                hashed_password=hash_password(SEED_DEV_PASSWORD),
                role=UserRole.DEVELOPER,
            )

        # 3. Garante um Scan demonstrativo já concluído (FULL_AUDIT) com Findings reais
        demo_scan = await scan_repo.get_by_id(DEMO_SCAN_ID)
        if demo_scan is None:
            demo_scan = Scan(
                id=DEMO_SCAN_ID,
                target="https://github.com/acme-corp/payment-gateway/pull/42",
                scan_type=ScanType.FULL_AUDIT,
                status=ScanStatus.COMPLETED,
                triggered_by_id=admin_user.id,
                celery_task_id="seed-demo-task-0001",
                risk_score=10.0,
            )
            session.add(demo_scan)
            await session.flush()

            demo_findings = [
                Finding(
                    scan_id=demo_scan.id,
                    category=ScannerCategory.SECRETS,
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.8,
                    title="[SECRET-AWS-001] AWS Access Key ID Exposta (Redacted: AKIA****MPLE)",
                    description=(
                        "Chave de acesso AWS detectada no código-fonte. "
                        "O valor original foi mascarado em memória (Zero-Trust Redaction)."
                    ),
                    file_path="src/payments/aws_client.py",
                    line_number=14,
                    remediation=(
                        "Revogue a credencial imediatamente no AWS IAM e utilize IAM Roles "
                        "ou AWS Secrets Manager."
                    ),
                ),
                Finding(
                    scan_id=demo_scan.id,
                    category=ScannerCategory.SAST,
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.8,
                    title="[SAST-CMD-001] Command Injection via subprocess com shell=True (CWE-78)",
                    description=(
                        "Chamada perigosa a subprocess.run(..., shell=True) detectada via AST."
                    ),
                    file_path="src/payments/invoice_exporter.py",
                    line_number=48,
                    remediation=(
                        "Remova shell=True e passe os argumentos como lista: "
                        "subprocess.run(['cmd', arg], shell=False, check=True)."
                    ),
                ),
                Finding(
                    scan_id=demo_scan.id,
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    title="[DAST-HDR-001] Ausência de Strict-Transport-Security (HSTS)",
                    description=(
                        "O endpoint auditado não envia o cabeçalho HSTS, permitindo ataques "
                        "de SSL Stripping (MITM)."
                    ),
                    file_path=None,
                    line_number=None,
                    remediation=(
                        "Adicione o cabeçalho 'Strict-Transport-Security: "
                        "max-age=63072000; includeSubDomains; preload'."
                    ),
                ),
            ]
            session.add_all(demo_findings)
            await session.commit()

        access_token = create_jwt_token(
            subject=str(admin_user.id),
            role=admin_user.role,
            scope=TokenScope.ACCESS,
            expires_delta=timedelta(hours=24),
        )
        refresh_token = create_jwt_token(
            subject=str(admin_user.id),
            role=admin_user.role,
            scope=TokenScope.REFRESH,
        )

    await engine.dispose()

    return {
        "admin_email": SEED_ADMIN_EMAIL,
        "admin_password": SEED_ADMIN_PASSWORD,
        "dev_email": SEED_DEV_EMAIL,
        "dev_password": SEED_DEV_PASSWORD,
        "scan_id": str(DEMO_SCAN_ID),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def format_onboarding_banner(data: dict[str, str]) -> str:
    """Formata o painel visual exibido ao final do `make up` / `make seed`."""
    lines = [
        "",
        "=" * 86,
        "🛡️  SECSENTINEL — AMBIENTE PRONTO PARA AVALIAÇÃO (ZERO-FRICTION ONBOARDING)",
        "=" * 86,
        "🌐 Endpoints Principais:",
        "   • Swagger UI (Interativo) : http://localhost:8000/docs",
        "   • ReDoc (Documentação)    : http://localhost:8000/redoc",
        "   • Health Check Realista   : http://localhost:8000/healthz",
        "",
        "👤 Credenciais Pré-Cadastradas (Seed Idempotente):",
        f"   • [ADMIN]     E-mail: {data['admin_email']}  | Senha: {data['admin_password']}",
        f"   • [DEVELOPER] E-mail: {data['dev_email']}    | Senha: {data['dev_password']}",
        "",
        "📊 Scan Demonstrativo Pré-Populado (Veredito: BLOCK | Risk Score: 10.0):",
        f"   • Scan ID     : {data['scan_id']}",
        f"   • Relatório   : http://localhost:8000/api/v1/scans/{data['scan_id']}/report",
        "",
        "🔑 Token JWT Válido Pré-Gerado (ADMIN — válido por 24h):",
        f"   {data['access_token']}",
        "",
        "🚀 Teste Rápido em 1 Comando (copie e cole no terminal):",
        f'   curl -s http://localhost:8000/api/v1/scans/{data["scan_id"]}/report \\',
        f'     -H "Authorization: Bearer {data["access_token"]}" | python3 -m json.tool',
        "=" * 86,
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    data = asyncio.run(seed_demo_data())
    sys.stdout.write(format_onboarding_banner(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
