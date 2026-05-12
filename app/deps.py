import hashlib
import hmac

from fastapi import Header, HTTPException, Request, status

from app.config import get_settings


ADMIN_SESSION_COOKIE = "admin_session"


def _admin_session_value() -> str:
    settings = get_settings()
    secret = settings.key_hash_secret.encode("utf-8")
    password = settings.admin_panel_password.encode("utf-8")
    return hmac.new(secret, password, hashlib.sha256).hexdigest()


def is_admin_session_authenticated(request: Request) -> bool:
    return request.cookies.get(ADMIN_SESSION_COOKIE) == _admin_session_value()


def get_admin_guard(request: Request, x_admin_token: str | None = Header(default=None)) -> str:
    settings = get_settings()
    if x_admin_token == settings.admin_token:
        return "token"
    if is_admin_session_authenticated(request):
        return "session"
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized", "message": "Bạn chưa đăng nhập admin hoặc token không hợp lệ."},
    )


def require_admin_session(request: Request) -> None:
    if not is_admin_session_authenticated(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "Bạn cần đăng nhập admin trước."},
        )
