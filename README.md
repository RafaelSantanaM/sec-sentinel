# 🛡️ SecSentinel — Plataforma DevSecOps de Auditoria de Pull Requests e APIs

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLAlchemy 2.0](https://img.shields.io/badge/SQLAlchemy-2.0%20Async-D71F00)](https://www.sqlalchemy.org/)
[![Celery + Redis](https://img.shields.io/badge/Queue-Celery%20%2B%20Redis-DC382D?logo=redis&logoColor=white)](https://docs.celeryq.dev/)
[![Security: Bandit & Ruff](https://img.shields.io/badge/Security-Ruff%20%2B%20Bandit%20%2B%20MyPy-success)](https://docs.astral.sh/ruff/)

**SecSentinel** é uma plataforma assíncrona de automação de segurança (**AppSec / DevSecOps**) projetada para auditar Pull Requests e APIs REST em tempo real. Combina três motores independentes de análise (**Secret Scanning por Entropia de Shannon**, **SAST via Python AST** e **Mini-DAST API Prober**) com um motor de cálculo de risco baseado no **Princípio do Elo Mais Fraco (CVSS v3.1)** para atuar como **Quality Gate automatizado (`PASS` / `WARN` / `BLOCK`)** em esteiras de CI/CD.

---

## 🏗️ Arquitetura do Sistema (Clean Architecture + Processamento Assíncrono)

O projeto segue rigorosamente a **Regra da Dependência** da Clean Architecture combinada com o padrão **Service-Repository**: os motores de segurança (`src/secsentinel/scanners/`) são pacotes de domínio puros e determinísticos, 100% desacoplados de frameworks web (FastAPI) e de ORM (SQLAlchemy).

```mermaid
flowchart LR
    Client["Dev / GitHub Webhook"] -->|"POST /api/v1/scans (JWT + Rate Limit)"| API["FastAPI Gateway"]
    API -->|"1. Valida SSRF & Persiste PENDING"| DB[("PostgreSQL 16 (Async)")]
    API -->|"2. Enfileira Job (JSON-only)"| Redis[("Redis 7 Broker")]
    Redis -->|"3. Consome Task"| Worker["Celery Worker (Non-Root)"]

    subgraph Motores de Seguranca Puros
        Worker --> Secrets["Scanner 1: Secret & Shannon Entropy"]
        Worker --> SAST["Scanner 2: Python AST SAST"]
        Worker --> DAST["Scanner 3: Mini-DAST API Prober"]
    end

    Secrets --> Risk["Risk Scoring Engine (CVSS + Gate Verdict)"]
    SAST --> Risk
    DAST --> Risk
    Risk -->|"4. Salva Findings & Score"| DB
    Client -->|"GET /api/v1/scans/{id}/report (BOLA Check)"| API
```

---

## 🔬 Os 3 Motores de Segurança e o Motor de Risco

### 1. Motor de Detecção de Credenciais (`scanners/secrets/engine.py`)
- **Assinaturas Determinísticas (Regex):** Detecta AWS Access Keys (`AKIA...`), GitHub Personal/Fine-Grained Tokens (`ghp_...`, `github_pat_...`), Slack Tokens, Stripe Live Keys e blocos de chaves privadas (`RSA`/`OPENSSH`/`EC`).
- **Análise Matemática de Entropia de Shannon ($H(X)$):** Calcula a incerteza informacional em bits por caractere para identificar segredos genéricos de alta aleatoriedade que não possuem prefixo fixo:
  $$H(X) = -\sum P(x_i) \log_2 P(x_i)$$
- **Zero-Trust Redaction (`redact_secret`):** O segredo capturado é mascarado imediatamente em memória (`AKIA****MPLE`) antes de instanciar o objeto `RawFinding`, garantindo que o banco de dados e os logs jamais se tornem um repositório de credenciais vazadas.

### 2. Motor SAST via Abstract Syntax Tree (`scanners/sast/engine.py`)
- Analisa código Python convertendo-o em uma **Árvore Sintática Abstrata (`ast.parse`)** sem jamais executar o código não confiável:
  - **`SAST-RCE-001` (CWE-95):** Uso de `eval()` ou `exec()`.
  - **`SAST-CMD-001` (CWE-78):** Execução de comandos via `os.system()`, `os.popen()` ou `subprocess.*(..., shell=True)`.
  - **`SAST-SQLI-001` (CWE-89):** Construção dinâmica de queries SQL via `f-strings` (`ast.JoinedStr`), concatenação (`+`) ou `.format()` dentro de `.execute()`.
  - **`SAST-DESER-001` (CWE-502):** Deserialização arbitrária via `pickle.loads()` ou `yaml.load()` sem `SafeLoader`.
  - **`SAST-CRYPTO-001` (CWE-328):** Uso de algoritmos de hash criptograficamente quebrados (`hashlib.md5`, `hashlib.sha1`).

### 3. Motor Mini-DAST / API Prober (`scanners/dast/engine.py`)
- Audita endpoints HTTP/HTTPS em execução usando `httpx.AsyncClient` com `follow_redirects=False`:
  - **Prevenção de DNS Rebinding Anti-SSRF (`validate_target_dns_against_ssrf`):** Resolve o DNS via `socket.getaddrinfo()` antes da conexão HTTP e bloqueia qualquer domínio que resolva para IPs privados (RFC 1918), loopback (`127.0.0.1`, `::1`) ou Cloud Metadata (`169.254.169.254`).
  - **Auditoria de Security Headers:** Verifica `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options: nosniff` e vazamento de versões no banner `Server`.
  - **Auditoria Ativa de CORS:** Envia cabeçalho `Origin` controlado para detectar reflexão arbitrária combinada com `Access-Control-Allow-Credentials: true` (**CVSS 9.1 - CRITICAL**).
  - **Sonda de Bypass JWT `alg: none`:** Testa se endpoints protegidos (`401/403`) aceitam tokens JWT forjados sem assinatura criptográfica (**CVSS 9.8 - CRITICAL**).

### 4. Motor de Cálculo de Risco e CI/CD Gate (`services/risk_engine.py`)
- Aplica o **Princípio do Elo Mais Fraco (*Worst-Case Base + Cumulative Penalty*)**: parte do maior CVSS detectado e soma penalidades cumulativas ponderadas por severidade (teto `10.0`), evitando que falhas informativas diluam falhas críticas.
- Emite o veredito de esteira (`SecurityVerdict`): **`PASS`**, **`WARN`** ou **`BLOCK`**.

---

## 🔒 Defesa em Profundidade da Própria Plataforma (Self-Hardening)

| Camada | Ameaça Mitigada (OWASP / CWE) | Implementação no SecSentinel |
| :--- | :--- | :--- |
| **Configuração** | Fail-Open / Vazamento de Secrets em Logs | `pydantic-settings` com `SecretStr` e validação *Fail-Fast* (recusa chaves JWT < 32 bytes ou `DEBUG=True` em produção). |
| **Autenticação** | Brute-Force, GPU Cracking & JWT Forgery | Hashing **Argon2id** (`pwdlib`), JWT com claims `jti`/`type`/`role` estritos, bloqueio de `alg: none` e proteção contra *Token Type Confusion*. |
| **Autorização** | BOLA / IDOR (OWASP API1:2023) | Chaves primárias `UUIDv4` + validação de propriedade no `ScanService` (`DEVELOPER` só acessa seus próprios scans; `AUDITOR`/`ADMIN` possuem visão global). |
| **Fila & Workers** | Pickle Deserialization RCE & Container Breakout | Celery travado exclusivamente em `accept_content=["json"]` e Dockerfile multi-stage rodando sob usuário Linux sem privilégios (`UID 10001`). |
| **Rede & Entrada** | Server-Side Request Forgery (SSRF - API7:2023) | Dupla camada Anti-SSRF: validação de URL/IP no schema Pydantic + validação de resolução DNS anti-rebinding no DAST. |
| **Tratamento de Erros** | Stack Trace Disclosure (CWE-209) | `unhandled_exception_handler` global que registra o traceback apenas nos logs internos e retorna resposta HTTP 500 sanitizada. |

---

## 🚀 Como Executar e Testar

### 1. Subindo a Infraestrutura Completa com Docker Compose
```bash
cp .env.example .env
# Gere uma chave JWT criptograficamente forte e atualize JWT_SECRET_KEY no .env:
# openssl rand -hex 32
docker compose up --build -d
```

### 2. Configuração e Execução em Ambiente Local (Virtualenv)
```bash
# 1. Criar e ativar o ambiente virtual Python 3.12+
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

# 2. Configurar variáveis de ambiente (.env) com chave JWT de alta entropia
cp .env.example .env
sed -i "s/^JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env

# 3. Aplicar migrações do banco de dados (Alembic)
alembic upgrade head

# 4. Criar o primeiro usuário ADMIN via CLI seguro (fora da superfície HTTP, lê senha via getpass)
python -m secsentinel.cli create-admin --email admin@secsentinel.io

# 5. Iniciar a API FastAPI (Uvicorn) e o Worker Assíncrono (Celery)
uvicorn secsentinel.main:app --host 127.0.0.1 --port 8000 --reload
celery -A secsentinel.worker.celery_app:celery_app worker --loglevel=info
```

### 3. Executando a Suíte de Testes, Linter (Bandit) e Type Checking Localmente
> **Dica (Kali Linux / Debian):** Utilize sempre `python -m pytest` (dentro da `.venv` ativada ou via `.venv/bin/python -m pytest`) em vez de chamar `pytest` globalmente, garantindo que o interpretador e os plugins da `.venv` sejam carregados no `sys.path`.

```bash
# 1. Lint & Regras de Segurança (Ruff + Flake8-Bandit)
ruff check .

# 2. Verificação Estrita de Tipos (MyPy Strict Mode)
mypy src

# 3. Testes Automatizados de Segurança + Cobertura (>= 85%)
python -m pytest -v --cov=secsentinel --cov-report=term-missing --cov-fail-under=85
```

---

## 📡 Principais Endpoints da API (`/api/v1`)

| Método | Rota | Descrição | Controle de Acesso |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Registro de usuário (`DEVELOPER`) com política estrita de senha, `extra="forbid"` e hash Argon2id | Público (Rate Limited `10/minute`) |
| `POST` | `/api/v1/auth/login` | Autenticação e emissão de par `access_token` + `refresh_token` | Público (Rate Limited `5/minute`) |
| `POST` | `/api/v1/auth/refresh` | Rotação de par JWT usando um `refresh_token` válido | Público (Rate Limited `10/minute`) |
| `GET` | `/api/v1/auth/admin-audit-check` | Rota administrativa de verificação de privilégios | RBAC: `ADMIN` / `AUDITOR` |
| `PATCH` | `/api/v1/auth/users/{user_id}/role` | Promoção/alteração de papel RBAC (bloqueia auto-alteração) | RBAC: `ADMIN` |
| `POST` | `/api/v1/scans` | Enfileira uma auditoria assíncrona (`pr_audit`, `api_audit`, `full_audit`) | Autenticado (`202 Accepted`, Rate Limited `20/minute`) |
| `GET` | `/api/v1/scans/{scan_id}` | Consulta o status e achados brutos do Scan | Autenticado + Anti-BOLA |
| `GET` | `/api/v1/scans/{scan_id}/report` | Gera o **Relatório Executivo** com `risk_score` e veredito (`PASS`/`WARN`/`BLOCK`) | Autenticado + Anti-BOLA |
