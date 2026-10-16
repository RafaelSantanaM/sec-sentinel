from collections.abc import Callable
from typing import Any
from uuid import UUID

from secsentinel.models.scan import Scan
from secsentinel.models.user import User, UserRole
from secsentinel.repositories.scan_repo import ScanRepository
from secsentinel.schemas.scan import ScanCreate, ScanEnqueueResponse
from secsentinel.worker.tasks import execute_security_scan_task


class ScanNotFoundError(Exception):
    """Levantada quando o Scan não existe no banco de dados."""

    pass


class ScanAccessDeniedError(Exception):
    """
    Levantada quando um usuário tenta acessar o relatório de outro usuário
    sem possuir papel de ADMIN ou AUDITOR (Proteção contra BOLA / IDOR).
    """

    pass


def default_task_dispatcher(
    scan_id: str,
    target_url: str,
    scan_type: str,
    code_snippet: str | None,
) -> str:
    """Enfileira a task no Celery/Redis e retorna o ID do job assíncrono."""
    async_result = execute_security_scan_task.delay(
        scan_id=scan_id,
        target_url=target_url,
        scan_type=scan_type,
        code_snippet=code_snippet,
    )
    return str(async_result.id)


class ScanService:
    """Orquestra a criação de auditorias, enfileiramento no Celery e controle de acesso BOLA."""

    def __init__(
        self,
        scan_repo: ScanRepository,
        task_dispatcher: Callable[[str, str, str, str | None], Any] = default_task_dispatcher,
    ) -> None:
        self._scan_repo = scan_repo
        self._task_dispatcher = task_dispatcher

    async def create_and_enqueue_scan(
        self,
        payload: ScanCreate,
        current_user: User,
    ) -> ScanEnqueueResponse:
        """
        1. Persiste o Scan com status=PENDING vinculado ao usuário autenticado.
        2. Despacha o job para a fila Redis/Celery.
        3. Salva o celery_task_id no registro do Scan.
        """
        scan = await self._scan_repo.create(
            target=payload.target_url,
            scan_type=payload.scan_type,
            triggered_by_id=current_user.id,
        )

        task_id = str(
            self._task_dispatcher(
                str(scan.id),
                payload.target_url,
                payload.scan_type.value,
                payload.code_snippet,
            )
        )
        scan = await self._scan_repo.update_task_id(scan, task_id)

        return ScanEnqueueResponse(
            scan_id=scan.id,
            status=scan.status,
            celery_task_id=task_id,
        )

    async def get_scan_for_user(self, scan_id: UUID, current_user: User) -> Scan:
        """
        Busca um Scan aplicando defesa estrita contra BOLA / IDOR (OWASP API1:2023):
        - ADMIN e AUDITOR podem auditar qualquer Scan.
        - DEVELOPER só pode acessar Scans cujo triggered_by_id == current_user.id.
        """
        scan = await self._scan_repo.get_by_id(scan_id)
        if scan is None:
            raise ScanNotFoundError("Scan não encontrado.")

        is_privileged = current_user.role in (UserRole.ADMIN, UserRole.AUDITOR)
        if not is_privileged and scan.triggered_by_id != current_user.id:
            raise ScanAccessDeniedError(
                "Acesso negado: você não tem permissão para visualizar o scan de outro usuário."
            )

        return scan
