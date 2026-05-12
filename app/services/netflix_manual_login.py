import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from app.database import SessionLocal
from app.models import NetflixSession
from app.security import encrypt_secret


@dataclass
class ManualLoginJob:
    id: str
    key_id: int
    key_label: str
    status: str
    message: str
    created_at: datetime
    updated_at: datetime


_JOBS: dict[str, ManualLoginJob] = {}
_LOCK = threading.Lock()


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _job_to_dict(job: ManualLoginJob) -> dict:
    return {
        "job_id": job.id,
        "key_id": job.key_id,
        "key": job.key_label,
        "status": job.status,
        "message": job.message,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }


def _update_job(job_id: str, *, status: str | None = None, message: str | None = None) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        if status:
            job.status = status
        if message is not None:
            job.message = message
        job.updated_at = _now_utc()


def get_manual_login_job(job_id: str) -> dict | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return None
        return _job_to_dict(job)


def _save_session_payload(key_id: int, session_text: str) -> None:
    db = SessionLocal()
    try:
        payload = json.dumps({"type": "session", "session": session_text}, ensure_ascii=False)
        row = db.execute(select(NetflixSession).where(NetflixSession.key_id == key_id)).scalars().first()
        if not row:
            row = NetflixSession(
                key_id=key_id,
                session_encrypted=encrypt_secret(payload),
                active=True,
            )
            db.add(row)
        else:
            row.session_encrypted = encrypt_secret(payload)
            row.active = True
            db.add(row)
        db.commit()
    finally:
        db.close()


def _extract_session_cookie_blob(cookies: list[dict]) -> str:
    cookie_map = {c.get("name"): c.get("value") for c in cookies if c.get("name") and c.get("value")}
    parts = []
    if cookie_map.get("NetflixId"):
        parts.append(f"NetflixId={cookie_map['NetflixId']}")
    if cookie_map.get("SecureNetflixId"):
        parts.append(f"SecureNetflixId={cookie_map['SecureNetflixId']}")
    return "; ".join(parts)


def _manual_session_capture_worker(job_id: str, key_id: int) -> None:
    _update_job(job_id, status="running", message="Dang mo trinh duyet Netflix...")
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        _update_job(
            job_id,
            status="error",
            message=f"Chua co Playwright ({exc}). Cai dat: pip install playwright && python -m playwright install chromium",
        )
        return

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, slow_mo=120)
            context = browser.new_context()
            page = context.new_page()
            page.goto("https://www.netflix.com/vn/login", wait_until="domcontentloaded", timeout=45000)
            _update_job(
                job_id,
                status="running",
                message="Hay dang nhap Netflix thu cong tren cua so vua mo. Dang doi session hop le...",
            )

            deadline = time.time() + 300
            while time.time() < deadline:
                current_url = page.url.lower()
                cookies = context.cookies(["https://www.netflix.com"])
                session_blob = _extract_session_cookie_blob(cookies)
                has_session = bool(session_blob)
                landed = any(token in current_url for token in ("/browse", "/account", "/profiles"))
                if has_session and landed:
                    _save_session_payload(key_id=key_id, session_text=session_blob)
                    _update_job(job_id, status="success", message="Dang nhap thanh cong. Da tu dong luu session vao KEY.")
                    browser.close()
                    return
                time.sleep(2)

            _update_job(job_id, status="timeout", message="Het 300s cho dang nhap. Thu lai.")
            browser.close()
    except Exception as exc:
        _update_job(job_id, status="error", message=f"Manual capture gap loi: {exc}")


def start_manual_session_capture_job(key_id: int, key_label: str) -> dict:
    with _LOCK:
        for job in _JOBS.values():
            if job.key_id == key_id and job.status == "running":
                return _job_to_dict(job)
        now = _now_utc()
        job = ManualLoginJob(
            id=uuid.uuid4().hex,
            key_id=key_id,
            key_label=key_label,
            status="queued",
            message="Dang khoi tao...",
            created_at=now,
            updated_at=now,
        )
        _JOBS[job.id] = job

    thread = threading.Thread(
        target=_manual_session_capture_worker,
        args=(job.id, key_id),
        daemon=True,
    )
    thread.start()
    return _job_to_dict(job)
