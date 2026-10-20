.PHONY: help setup up down seed test lint ci logs

PYTHON := $(shell if [ -x .venv/bin/python ]; then echo ".venv/bin/python"; else echo "python3"; fi)
COMPOSE := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)

help: ## Exibe os comandos disponíveis no Makefile
	@echo "======================================================================"
	@echo "🛡️  SecSentinel — Comandos de Automação (Zero-Friction DevSecOps)"
	@echo "======================================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo "======================================================================"

setup: ## Cria o arquivo .env a partir do .env.example e gera JWT_SECRET_KEY forte
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Arquivo .env criado a partir do .env.example."; \
	else \
		echo "ℹ️  Arquivo .env já existe (preservando configurações atuais)."; \
	fi
	@if grep -q "^JWT_SECRET_KEY=CHANGE_ME" .env 2>/dev/null; then \
		SECRET=$$(python3 -c "import secrets; print(secrets.token_hex(32))"); \
		sed -i "s/^JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$$SECRET/" .env; \
		echo "🔐 Chave criptográfica JWT_SECRET_KEY (256-bit hex) gerada automaticamente no .env."; \
	fi

up: setup ## Sobe todos os containers, aguarda healthcheck, roda migrações e popula dados (Seed)
	@echo "🐳 Construindo imagem hardened do SecSentinel (Multi-Stage Non-Root)..."
	@docker build -t secsentinel-app:latest .
	@echo "🚀 Subindo infraestrutura base (PostgreSQL 16 + Redis 7)..."
	@$(COMPOSE) up -d --no-recreate db redis
	@echo "⏳ Aguardando banco de dados PostgreSQL e broker Redis ficarem saudáveis..."
	@until docker exec secsentinel-db pg_isready -U secsentinel_user -d secsentinel_db >/dev/null 2>&1; do sleep 1; done
	@until docker exec secsentinel-redis redis-cli ping >/dev/null 2>&1; do sleep 1; done
	@echo "📦 Executando migrações automáticas de schema (Alembic upgrade head)..."
	@$(COMPOSE) run --rm --no-deps migrations alembic upgrade head
	@echo "🌐 Iniciando API Gateway (FastAPI) e Celery Worker Assíncrono..."
	@$(COMPOSE) up -d --no-recreate api worker
	@echo "🩺 Verificando Readiness Probe ativa em http://localhost:8000/healthz..."
	@for i in $$(seq 1 30); do \
		if curl -fsS http://localhost:8000/healthz >/dev/null 2>&1; then break; fi; \
		sleep 1; \
	done
	@echo "🌱 Executando Seed idempotente e gerando credenciais + JWT para avaliação..."
	@docker exec secsentinel-api python -m secsentinel.seed

down: ## Para e remove todos os containers e redes da aplicação
	@echo "🛑 Parando e limpando containers do SecSentinel..."
	@$(COMPOSE) down --remove-orphans
	@echo "✅ Ambiente encerrado com sucesso."

seed: ## Executa apenas o script de população inicial e exibe o token JWT
	@docker exec secsentinel-api python -m secsentinel.seed

test: ## Executa a suíte de testes automatizados com relatório de cobertura no terminal
	@$(PYTHON) -m pytest -v --cov=secsentinel --cov-report=term-missing --cov-fail-under=85

lint: ## Executa análise estática (Ruff + Bandit Security Rules + MyPy Strict)
	@$(PYTHON) -m ruff check .
	@$(PYTHON) -m mypy src

ci: lint test ## Executa localmente toda a esteira de Quality & Security Gate do GitHub Actions

logs: ## Exibe os logs em tempo real da API e do Worker
	@$(COMPOSE) logs -f api worker
