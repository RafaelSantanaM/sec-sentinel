from fastapi import APIRouter

from secsentinel.api.v1.endpoints import auth

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth.router)
