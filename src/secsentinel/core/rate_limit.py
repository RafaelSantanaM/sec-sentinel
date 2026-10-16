from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate Limiter global baseado no IP de origem para mitigar Brute-Force e Credential Stuffing
limiter = Limiter(key_func=get_remote_address)
