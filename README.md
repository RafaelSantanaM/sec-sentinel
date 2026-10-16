# 🛡️ SecSentinel

**SecSentinel** é uma plataforma DevSecOps de automação de segurança que audita Pull Requests e APIs de forma assíncrona.

## Arquitetura & Stack
- **Backend:** Python 3.12+, FastAPI, Pydantic v2 (`pydantic-settings`)
- **Persistência:** PostgreSQL 16 + SQLAlchemy 2.0 (Async) + Alembic
- **Fila & Workers:** Redis 7 + Celery
- **Segurança:** Argon2id, JWT (HS256/RS256), RBAC, Rate Limiting (`slowapi`)
- **Motores de Scan:**
  1. **Secret Scanner:** Regex + Entropia de Shannon
  2. **SAST Engine:** Análise de AST (`ast` nativo do Python)
  3. **API Prober (Mini-DAST):** Auditoria de Security Headers, CORS e JWT `alg: none`
