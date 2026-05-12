import json
import re
import html
from datetime import UTC, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import AccessKey, NetflixSession
from app.schemas import (
    FamilyLinkResponse,
    LoginCodeItem,
    LoginCodeListResponse,
    ResolveCodeRequest,
    ResolveCodeResponse,
)
from app.security import decrypt_secret, hash_key
from app.services.family_code_service import FamilyCodeError, get_latest_family_link
from app.services.login_code_service import LoginCodeError, get_recent_login_codes_for_key
from app.services.resolve_service import ResolveError, resolve_code


router = APIRouter(prefix="/api/code", tags=["public"])
HANOI_TZ = timezone(timedelta(hours=7))


def _to_hanoi_time(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(HANOI_TZ)


def _load_netflix_session_value(session_row: NetflixSession) -> str:
    raw = decrypt_secret(session_row.session_encrypted)
    try:
        data = json.loads(raw)
    except Exception:
        raw_text = str(raw).strip()
        if raw_text:
            return raw_text
        raise ValueError("Invalid Netflix session payload.")

    if isinstance(data, dict):
        session_text = str(data.get("session", "")).strip()
        if session_text:
            return session_text
    raise ValueError("Invalid Netflix session payload.")


def _extract_netflix_cookie_header(raw_session: str) -> str:
    parts: list[str] = []
    for token in raw_session.split(";"):
        item = token.strip()
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in {"NetflixId", "SecureNetflixId"} and value:
            parts.append(f"{key}={value}")
    if parts:
        return "; ".join(parts)
    return raw_session.strip()


def _find_active_key(db: Session, key_plain: str) -> AccessKey | None:
    hashed = hash_key(key_plain)
    return (
        db.execute(
            select(AccessKey)
            .where(AccessKey.key_hash == hashed)
            .options(joinedload(AccessKey.mailbox), joinedload(AccessKey.parser_rule))
        )
        .scalars()
        .first()
    )


def _get_session_cookie_for_key(db: Session, key_row: AccessKey) -> str:
    session_row = db.execute(select(NetflixSession).where(NetflixSession.key_id == key_row.id)).scalars().first()
    if not session_row or not session_row.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "netflix_login_required",
                "message": "Missing Netflix session. Please sync session from admin panel.",
            },
        )
    try:
        session_value = _load_netflix_session_value(session_row)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "netflix_credentials_invalid",
                "message": "Saved Netflix session is invalid. Please update from admin panel.",
            },
        )
    if not session_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "session_cookie_required",
                "message": "Family code flow requires Netflix session cookie. Please run manual Netflix session sync in admin panel.",
            },
        )
    return session_value


def _extract_family_code_from_html(page_html: str) -> tuple[str | None, str | None]:
    text = re.sub(r"<[^>]+>", " ", page_html or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None, None

    normalized = text.lower()
    marker_windows = (
        "use this code",
        "enter this code",
        "use this code to watch on your device",
        "enter this code on the requesting device",
        "temporary access",
        "this code expires after",
        "expires after",
        "4-digit code",
        "nhap ma",
        "nhan ma",
        "ma truy cap tam thoi",
        "ma se het han",
    )

    # Only extract code near explicit "code" markers.
    # Do not fallback to generic 4-digit numbers to avoid false positives
    # from expired pages (e.g., footer years).
    for marker in marker_windows:
        idx = normalized.find(marker)
        if idx < 0:
            continue
        start = max(0, idx - 180)
        end = min(len(text), idx + 320)
        window = text[start:end]
        match = re.search(r"(?<!\d)(\d(?:\s*\d){3})(?!\d)", window)
        if match:
            code = re.sub(r"\s+", "", match.group(1))
            if len(code) == 4 and code.isdigit():
                snippet = window[max(0, match.start() - 36) : min(len(window), match.end() + 36)]
                source = f"marker={marker}; snippet={snippet}"
                return code, source
    return None, None


def _is_expired_family_link_page(page_html: str) -> bool:
    text = re.sub(r"<[^>]+>", " ", page_html or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    if not text:
        return False
    markers = (
        "link no longer valid",
        "this link is no longer valid",
        "please request again on the original device",
        "lien ket nay khong con hieu luc",
        "vui long yeu cau lai tren thiet bi ban dau",
        "vui lòng yêu cầu lại trên thiết bị ban đầu",
    )
    return any(marker in text for marker in markers)


def _resolve_family_code_via_session_link(url: str, session_value: str) -> tuple[str | None, str, str | None]:
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    headers = {
        "User-Agent": user_agent,
        "Cookie": _extract_netflix_cookie_header(session_value),
    }
    try:
        with httpx.Client(follow_redirects=True, timeout=15.0, headers=headers) as client:
            resp = client.get(url)
            if resp.status_code >= 400:
                return None, f"Netflix verify link returned HTTP {resp.status_code}.", None
            if _is_expired_family_link_page(resp.text):
                return None, "Netflix verify link has expired. Please request a new family code.", None
            code, source = _extract_family_code_from_html(resp.text)
            if not code:
                return None, "Cannot extract 4-digit code from Netflix verify page.", source
            return code, "ok", source
    except Exception as exc:
        return None, f"Failed to open Netflix verify link: {exc}", None


@router.post("/login-codes", response_model=LoginCodeListResponse)
async def get_login_codes(payload: ResolveCodeRequest, db: Session = Depends(get_db)):
    try:
        items = get_recent_login_codes_for_key(db=db, key_plain=payload.key, limit=1)
    except LoginCodeError as err:
        http_status = status.HTTP_400_BAD_REQUEST
        if err.code == "invalid_key":
            http_status = status.HTTP_401_UNAUTHORIZED
        raise HTTPException(status_code=http_status, detail={"error": err.code, "message": err.message}) from err
    return LoginCodeListResponse(
        ok=True,
        feature="login_code",
        total=len(items),
        items=[LoginCodeItem(code=i.code, received_at=_to_hanoi_time(i.received_at), subject=i.subject) for i in items],
    )


@router.post("/family-link", response_model=FamilyLinkResponse)
async def get_family_link(payload: ResolveCodeRequest, db: Session = Depends(get_db)):
    key_row = _find_active_key(db, payload.key)
    if not key_row or not key_row.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_key", "message": "Invalid key or inactive key."},
        )

    session_value = _get_session_cookie_for_key(db, key_row)

    try:
        # Fast scan for low latency first.
        result = get_latest_family_link(
            db=db,
            key_plain=payload.key,
            key_row=key_row,
            max_messages=25,
            since_minutes=180,
        )
    except FamilyCodeError as err:
        # Fallback deep scan to reduce false 404 when email arrives with delay
        # or user requested code earlier than 3 hours ago.
        if err.code == "no_family_link_found":
            try:
                result = get_latest_family_link(
                    db=db,
                    key_plain=payload.key,
                    key_row=key_row,
                    max_messages=200,
                    since_minutes=60 * 24 * 14,
                )
            except FamilyCodeError as deep_err:
                err = deep_err

        http_status = status.HTTP_400_BAD_REQUEST
        if err.code == "invalid_key":
            http_status = status.HTTP_401_UNAUTHORIZED
        elif err.code == "no_family_link_found":
            http_status = status.HTTP_404_NOT_FOUND
        raise HTTPException(status_code=http_status, detail={"error": err.code, "message": err.message}) from err

    code, code_message, _ = _resolve_family_code_via_session_link(result.url, session_value)
    if not code:
        lower_message = (code_message or "").lower()
        is_expired = "expired" in lower_message or "khong con hieu luc" in lower_message or "không còn hiệu lực" in lower_message
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if is_expired else status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "family_link_expired" if is_expired else "family_code_extract_failed",
                "message": "Link đã hết hiệu lực. Vui lòng Gửi lại mã." if is_expired else code_message,
            },
        )

    return FamilyLinkResponse(
        ok=True,
        feature="family_code",
        url=result.url,
        code=code,
        received_at=_to_hanoi_time(result.received_at),
        subject=result.subject,
    )


@router.post("/resolve", response_model=ResolveCodeResponse)
async def resolve_code_by_key(payload: ResolveCodeRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    try:
        resolved = await resolve_code(db, key_plain=payload.key, ip=ip)
        return ResolveCodeResponse(
            code=resolved.code,
            received_at=_to_hanoi_time(resolved.received_at),
            source_label=resolved.source_label,
            ttl_hint=resolved.ttl_hint,
        )
    except ResolveError as err:
        http_status = status.HTTP_400_BAD_REQUEST
        if err.code == "invalid_key":
            http_status = status.HTTP_401_UNAUTHORIZED
        elif err.code == "rate_limited":
            http_status = status.HTTP_429_TOO_MANY_REQUESTS
        elif err.code == "no_recent_code":
            http_status = status.HTTP_404_NOT_FOUND
        elif err.code == "imap_unavailable":
            http_status = status.HTTP_503_SERVICE_UNAVAILABLE
        raise HTTPException(
            status_code=http_status,
            detail={
                "error": err.code,
                "message": err.message,
                "ttl_hint": err.ttl_hint,
            },
        ) from err

