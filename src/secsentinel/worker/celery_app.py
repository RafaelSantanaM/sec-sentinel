from celery import Celery

from secsentinel.core.config import settings

celery_app = Celery(
    "secsentinel_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["secsentinel.worker.tasks"],
)

# HARDENING DO CELERY:
# 1. Proíbe 'pickle' (que permite Remote Code Execution - RCE) aceitando apenas JSON puro.
# 2. Define limites estritos de tempo (Soft=60s, Hard=90s) para impedir que um scan
#    travado por ReDoS ou timeout de rede prenda o worker indefinidamente.
# 3. task_acks_late=True garante que a tarefa só seja removida da fila após concluir.
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=60,
    task_time_limit=90,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)
