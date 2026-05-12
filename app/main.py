from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.admin import router as admin_router
from app.api.public import router as public_router
from app.config import get_settings
from app.database import Base, engine
from app.deps import ADMIN_SESSION_COOKIE, _admin_session_value, is_admin_session_authenticated
from app.services.poller import CachePoller


settings = get_settings()
poller = CachePoller()
ADMIN_BASE_PATH = "/admin"
ADMIN_ALIAS_PATH = "/phancongtriadmin"


@asynccontextmanager
async def lifespan(_: FastAPI):
    await poller.start()
    try:
        yield
    finally:
        await poller.stop()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

Base.metadata.create_all(bind=engine)

app.include_router(public_router)
app.include_router(admin_router)

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


async def _extract_login_password(request: Request) -> tuple[str, bool]:
    content_type = (request.headers.get("content-type") or "").lower()
    is_json = "application/json" in content_type
    if is_json:
        try:
            data = await request.json()
        except Exception:
            return "", True
        return str((data or {}).get("password", "")).strip(), True

    raw = (await request.body()).decode("utf-8", errors="ignore")
    params = parse_qs(raw, keep_blank_values=True)
    return str((params.get("password") or [""])[0]).strip(), False


def _build_admin_login_success_response(is_json: bool):
    response = JSONResponse({"ok": True}) if is_json else RedirectResponse(url=ADMIN_BASE_PATH, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=_admin_session_value(),
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 12,
        path="/",
    )
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_: Request, exc: StarletteHTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "http_error", "message": str(exc.detail)},
    )


@app.get("/")
async def root():
    return FileResponse(static_dir / "index.html")


@app.get(ADMIN_BASE_PATH)
async def admin_panel(request: Request):
    if not is_admin_session_authenticated(request):
        return RedirectResponse(url=f"{ADMIN_BASE_PATH}/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return FileResponse(static_dir / "admin.html")


@app.get(ADMIN_ALIAS_PATH)
async def admin_panel_alias():
    return RedirectResponse(url=ADMIN_BASE_PATH, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.get(f"{ADMIN_BASE_PATH}/login")
async def admin_login_page(request: Request):
    if is_admin_session_authenticated(request):
        return RedirectResponse(url=ADMIN_BASE_PATH, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return FileResponse(static_dir / "admin_login.html")


@app.get(f"{ADMIN_ALIAS_PATH}/login")
async def admin_login_page_alias():
    return RedirectResponse(url=f"{ADMIN_BASE_PATH}/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.post(f"{ADMIN_BASE_PATH}/login")
async def admin_login(request: Request):
    password, is_json = await _extract_login_password(request)
    if password != settings.admin_panel_password:
        if is_json:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_password", "message": "Mật khẩu admin không đúng."},
            )
        return RedirectResponse(url=f"{ADMIN_BASE_PATH}/login?error=1", status_code=status.HTTP_303_SEE_OTHER)
    return _build_admin_login_success_response(is_json=is_json)


@app.post(f"{ADMIN_ALIAS_PATH}/login")
async def admin_login_alias(request: Request):
    return await admin_login(request)


@app.post(f"{ADMIN_BASE_PATH}/logout")
async def admin_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(key=ADMIN_SESSION_COOKIE, path="/")
    return response


@app.post(f"{ADMIN_ALIAS_PATH}/logout")
async def admin_logout_alias():
    return await admin_logout()


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
