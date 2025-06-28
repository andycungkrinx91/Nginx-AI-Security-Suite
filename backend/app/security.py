from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from app.core.config import settings

API_KEY_NAME = "X-API-KEY"
api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header_auth)):
    """
    A dependency function that validates the provided API key against the one
    loaded from the .env file.
    """
    if api_key == settings.BACKEND_API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
    )