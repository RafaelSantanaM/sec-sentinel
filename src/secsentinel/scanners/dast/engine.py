import base64
import json
import socket
from ipaddress import ip_address
from urllib.parse import urlparse

import httpx

from secsentinel.models.finding import ScannerCategory, SeverityLevel
from secsentinel.scanners.base import RawFinding

EVIL_ORIGIN = "https://evil-attacker.secsentinel.invalid"


class SSRFResolutionError(Exception):
    """Levantada quando o DNS de uma URL resolve para um IP interno/privado/loopback."""

    pass


def validate_target_dns_against_ssrf(target_url: str) -> None:
    """
    DEFESA EM PROFUNDIDADE CONTRA DNS REBINDING / SSRF (Fase 6):
    Resolve o hostname da URL via DNS antes de abrir conexão HTTP e verifica
    se algum endereço IP retornado (IPv4 ou IPv6) aponta para loopback,
    rede privada (RFC 1918) ou Link-Local (AWS/Cloud Metadata 169.254.169.254).
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFResolutionError("Hostname ausente na URL alvo.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addr_info_list = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFResolutionError(f"Não foi possível resolver o DNS para '{hostname}'.") from exc

    for addr_info in addr_info_list:
        sockaddr = addr_info[4]
        resolved_ip_str = str(sockaddr[0])
        ip_obj = ip_address(resolved_ip_str)

        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            raise SSRFResolutionError(
                f"SSRF DNS REBINDING BLOCKED: O domínio '{hostname}' resolveu para o IP "
                f"interno/reservado '{resolved_ip_str}'."
            )


def _build_alg_none_jwt_probe() -> str:
    """Constrói um token JWT sem assinatura ('alg: none') para testar bypass de autenticação."""
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "role": "admin", "exp": 9999999999}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}."


class APIProber:
    """
    Motor Mini-DAST para auditoria ativa de endpoints de API:
    1. Validação Anti-SSRF por DNS e bloqueio de redirecionamentos (follow_redirects=False).
    2. Checagem de Security Headers (HSTS, CSP, X-Content-Type-Options, Server Banner Leak).
    3. Auditoria de CORS Misconfiguration (reflexão de origem arbitrária + credentials).
    4. Sonda de vulnerabilidade JWT 'alg: none'.
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        skip_dns_resolution: bool = False,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self.skip_dns_resolution = skip_dns_resolution

    async def probe_endpoint(self, target_url: str) -> list[RawFinding]:
        if not self.skip_dns_resolution:
            validate_target_dns_against_ssrf(target_url)

        findings: list[RawFinding] = []

        # SEGURANÇA: follow_redirects=False impede que o alvo redirecione (301/302)
        # o nosso scanner para http://169.254.169.254/ ou http://127.0.0.1/!
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            baseline_resp = await client.get(
                target_url,
                headers={"Origin": EVIL_ORIGIN, "User-Agent": "SecSentinel-APIProber/0.1"},
            )

            findings.extend(self._inspect_security_headers(target_url, baseline_resp.headers))
            findings.extend(self._inspect_cors_policy(target_url, baseline_resp.headers))

            # Se o endpoint respondeu 401/403 sem credenciais, testamos JWT 'alg: none'
            if baseline_resp.status_code in (401, 403):
                jwt_finding = await self._probe_jwt_alg_none_bypass(client, target_url)
                if jwt_finding is not None:
                    findings.append(jwt_finding)

        return findings

    def _inspect_security_headers(
        self, target_url: str, headers: httpx.Headers
    ) -> list[RawFinding]:
        results: list[RawFinding] = []

        # 1. HSTS (Strict-Transport-Security)
        if "strict-transport-security" not in headers:
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    title="[DAST-HDR-001] Ausência de Header HSTS (Strict-Transport-Security)",
                    description=(
                        f"O endpoint '{target_url}' não retornou o cabeçalho "
                        "'Strict-Transport-Security', expondo clientes a ataques de SSL Stripping."
                    ),
                    remediation=(
                        "Adicione o header 'Strict-Transport-Security: max-age=63072000; "
                        "includeSubDomains; preload'."
                    ),
                    file_path=target_url,
                )
            )

        # 2. X-Content-Type-Options: nosniff
        xcto = headers.get("x-content-type-options", "").lower()
        if xcto != "nosniff":
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.LOW,
                    cvss_score=3.7,
                    title="[DAST-HDR-002] Ausência de 'X-Content-Type-Options: nosniff'",
                    description=(
                        f"O endpoint '{target_url}' não protege contra MIME-type sniffing."
                    ),
                    remediation="Configure o header 'X-Content-Type-Options: nosniff'.",
                    file_path=target_url,
                )
            )

        # 3. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.LOW,
                    cvss_score=4.3,
                    title="[DAST-HDR-003] Ausência de Content-Security-Policy (CSP)",
                    description=(
                        f"O endpoint '{target_url}' não define uma política CSP para "
                        "mitigar Cross-Site Scripting (XSS) e Clickjacking."
                    ),
                    remediation=(
                        "Defina um cabeçalho 'Content-Security-Policy' restritivo "
                        "(ex: \"default-src 'none'; frame-ancestors 'none'\")."
                    ),
                    file_path=target_url,
                )
            )

        # 4. Exposição de Versão no Banner 'Server' / 'X-Powered-By'
        server_banner = headers.get("server", "")
        if any(char.isdigit() for char in server_banner):
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.INFO,
                    cvss_score=2.0,
                    title="[DAST-HDR-004] Vazamento de Versão no Header 'Server'",
                    description=(
                        f"O cabeçalho 'Server: {server_banner}' expõe a versão exata da "
                        "tecnologia, facilitando busca por CVEs conhecidas."
                    ),
                    remediation="Oculte os tokens de versão no servidor web ou API Gateway.",
                    file_path=target_url,
                )
            )

        return results

    def _inspect_cors_policy(
        self, target_url: str, headers: httpx.Headers
    ) -> list[RawFinding]:
        results: list[RawFinding] = []
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == EVIL_ORIGIN and acac:
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.1,
                    title="[DAST-CORS-001] CORS Reflete Origem Arbitrária com Credenciais",
                    description=(
                        f"O endpoint '{target_url}' refletiu a origem atacante '{EVIL_ORIGIN}' "
                        "com 'Access-Control-Allow-Credentials: true', permitindo roubo "
                        "cross-origin de dados autenticados."
                    ),
                    remediation=(
                        "Valide o header 'Origin' contra uma allowlist estrita de domínios "
                        "confiáveis e jamais reflita origens arbitrárias com credenciais ativas."
                    ),
                    file_path=target_url,
                )
            )
        elif acao in ("*", EVIL_ORIGIN):
            results.append(
                RawFinding(
                    category=ScannerCategory.DAST,
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    title="[DAST-CORS-002] Política CORS Excessivamente Permissiva",
                    description=(
                        f"O endpoint '{target_url}' permite 'Access-Control-Allow-Origin: {acao}'."
                    ),
                    remediation=(
                        "Restrinja 'Access-Control-Allow-Origin' apenas aos domínios "
                        "de frontend autorizados."
                    ),
                    file_path=target_url,
                )
            )

        return results

    async def _probe_jwt_alg_none_bypass(
        self, client: httpx.AsyncClient, target_url: str
    ) -> RawFinding | None:
        forged_token = _build_alg_none_jwt_probe()
        probe_resp = await client.get(
            target_url,
            headers={
                "Authorization": f"Bearer {forged_token}",
                "User-Agent": "SecSentinel-APIProber/0.1",
            },
        )
        if 200 <= probe_resp.status_code < 300:
            return RawFinding(
                category=ScannerCategory.DAST,
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.8,
                title="[DAST-JWT-001] Bypass de Autenticação via JWT 'alg: none'",
                description=(
                    f"O endpoint protegido '{target_url}' rejeitou chamadas anônimas, mas "
                    f"respondeu HTTP {probe_resp.status_code} ao receber um token JWT forjado "
                    "com algoritmo 'none' e sem assinatura criptográfica!"
                ),
                remediation=(
                    "Configure o validador JWT para exigir uma lista explícita de algoritmos "
                    "criptográficos (ex: algorithms=['HS256'] ou ['RS256']) e rejeitar 'none'."
                ),
                file_path=target_url,
            )
        return None
