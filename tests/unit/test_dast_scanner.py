import socket

import httpx
import pytest

from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.dast.engine import (
    EVIL_ORIGIN,
    APIProber,
    SSRFResolutionError,
    validate_target_dns_against_ssrf,
)


def test_dns_rebinding_to_cloud_metadata_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Comprova a resposta do Desafio da Fase 3:
    Mesmo que a URL pareça um domínio público ('https://evil-rebinding.com'),
    se o DNS resolver para 169.254.169.254 (AWS IMDS) ou 127.0.0.1,
    validate_target_dns_against_ssrf aborta antes de abrir conexão HTTP!
    """

    def fake_getaddrinfo(host: str, port: int, proto: int = 0) -> list[tuple[object, ...]]:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(SSRFResolutionError) as exc_info:
        validate_target_dns_against_ssrf("https://evil-rebinding.com/api/v1/status")

    assert "SSRF DNS REBINDING BLOCKED" in str(exc_info.value)
    assert "169.254.169.254" in str(exc_info.value)


@pytest.mark.asyncio
async def test_dast_detects_missing_headers_cors_reflection_and_jwt_alg_none() -> None:
    """
    Simula uma API alvo vulnerável que:
    1. Não envia HSTS, CSP nem X-Content-Type-Options: nosniff.
    2. Expõe versão no header 'Server: nginx/1.18.0'.
    3. Reflete qualquer Origin no CORS com Access-Control-Allow-Credentials: true.
    4. Retorna 401 sem token, mas aceita 200 OK quando recebe um token JWT com 'alg: none'!
    """

    def vulnerable_api_handler(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers.get("Authorization", "")
        headers = {
            "Server": "nginx/1.18.0",
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true",
        }
        # Simula servidor vulnerável que aceita qualquer JWT com alg:none
        if auth_header.startswith("Bearer ") and auth_header.endswith("."):
            return httpx.Response(200, json={"admin_secret": "exposed"}, headers=headers)
        return httpx.Response(401, json={"detail": "Unauthorized"}, headers=headers)

    prober = APIProber(
        transport=httpx.MockTransport(vulnerable_api_handler),
        skip_dns_resolution=True,
    )
    findings = await prober.probe_endpoint("https://vulnerable-api.example.com/v1/admin")

    titles = [f.title for f in findings]
    assert all(f.category == ScannerCategory.DAST for f in findings)
    assert any("DAST-HDR-001" in t for t in titles)  # Sem HSTS
    assert any("DAST-HDR-002" in t for t in titles)  # Sem X-Content-Type-Options
    assert any("DAST-HDR-003" in t for t in titles)  # Sem CSP
    assert any("DAST-HDR-004" in t for t in titles)  # Server version leak
    assert any("DAST-CORS-001" in t for t in titles)  # CORS reflection + credentials (CRITICAL)
    assert any("DAST-JWT-001" in t for t in titles)  # JWT alg:none bypass (CRITICAL)

    critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    assert critical_count == 2


@pytest.mark.asyncio
async def test_dast_hardened_api_returns_zero_findings() -> None:
    """
    Comprova que uma API devidamente configurada (HSTS, CSP, nosniff, CORS restrito
    e rejeição de JWT alg:none) retorna 0 vulnerabilidades.
    """

    def hardened_api_handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" not in request.headers:
            assert request.headers.get("Origin") == EVIL_ORIGIN
        headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Server": "SecSentinel-Gateway",
            "Access-Control-Allow-Origin": "https://app.secsentinel.io",
        }
        return httpx.Response(401, json={"detail": "Invalid token"}, headers=headers)

    prober = APIProber(
        transport=httpx.MockTransport(hardened_api_handler),
        skip_dns_resolution=True,
    )
    findings = await prober.probe_endpoint("https://secure-api.secsentinel.io/v1/data")

    assert findings == []
