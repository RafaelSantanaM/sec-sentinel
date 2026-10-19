import inspect

import slowapi.extension
from slowapi import Limiter
from slowapi.util import get_remote_address

# Compatibilidade Python 3.14+ (Kali Linux): evita DeprecationWarning do asyncio.iscoroutinefunction
# disparado pelo SlowAPI ao decorar as 4 rotas protegidas por @limiter.limit.
slowapi.extension.asyncio.iscoroutinefunction = inspect.iscoroutinefunction  # type: ignore[attr-defined]

# Rate Limiter global baseado no IP de origem para mitigar Brute-Force e Credential Stuffing
limiter = Limiter(key_func=get_remote_address)
