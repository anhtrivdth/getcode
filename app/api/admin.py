import imaplib
import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
import httpx

from app.database import get_db
from app.deps import get_admin_guard
from app.models import AccessKey, AuditLog, Mailbox, NetflixSession, ParserRule
from app.schemas import (
    AccessKeyCreate,
    AccessKeyOut,
    AccessKeyUpdate,
    MailboxCreate,
    MailboxOut,
    MailboxUpdate,
    ParserRuleCreate,
    ParserRuleOut,
    ParserRuleUpdate,
)
from app.security import decrypt_secret, encrypt_secret, hash_key, mask_email
from app.services.netflix_manual_login import get_manual_login_job, start_manual_session_capture_job
from app.services.netflix_login import attempt_netflix_login


router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(get_admin_guard)])


def _verify_imap_login(email_full: str, app_password: str, imap_server: str = "imap.gmail.com", imap_port: int = 993):
    conn = imaplib.IMAP4_SSL(imap_server, imap_port)
    try:
        conn.login(email_full, app_password)
        return True, "IMAP login success"
    except imaplib.IMAP4.error as exc:
        return False, f"IMAP login failed: {exc}"
    except Exception as exc:
        return False, f"IMAP connection error: {exc}"
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _default_rule(db: Session) -> ParserRule:
    rule = db.execute(select(ParserRule).where(ParserRule.name == "__default_simple_otp__")).scalars().first()
    if rule:
        return rule
    rule = ParserRule(
        name="__default_simple_otp__",
        code_type="login_code",
        regex_patterns="\n".join(
            [
                r"OTP[:\s]+(\d{6})",
                r"code[:\s]+([A-Z0-9]{6,8})",
                r"\b(\d{6})\b",
            ]
        ),
        sender_filter=None,
        subject_filter=None,
        time_window_minutes=60,
        active=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def _find_key_by_plain(db: Session, key_plain: str) -> AccessKey | None:
    return db.execute(select(AccessKey).where(AccessKey.key_hash == hash_key(key_plain))).scalars().first()


def _save_netflix_credentials(db: Session, key_id: int, netflix_email: str, netflix_password: str) -> None:
    credential_payload = json.dumps(
        {"email": netflix_email, "password": netflix_password},
        ensure_ascii=False,
    )
    _save_netflix_payload(db=db, key_id=key_id, payload_text=credential_payload)


def _save_netflix_payload(db: Session, key_id: int, payload_text: str) -> None:

    session_row = db.execute(select(NetflixSession).where(NetflixSession.key_id == key_id)).scalars().first()
    if not session_row:
        session_row = NetflixSession(
            key_id=key_id,
            session_encrypted=encrypt_secret(payload_text),
            active=True,
        )
        db.add(session_row)
    else:
        session_row.session_encrypted = encrypt_secret(payload_text)
        session_row.active = True
        db.add(session_row)
    db.commit()


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


def _check_netflix_cookie_alive(session_value: str) -> tuple[bool, str]:
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    headers = {
        "User-Agent": user_agent,
        "Cookie": _extract_netflix_cookie_header(session_value),
    }
    try:
        with httpx.Client(follow_redirects=True, timeout=20.0, headers=headers) as client:
            resp = client.get("https://www.netflix.com/browse")
            final_url = str(resp.url).lower()
            if any(token in final_url for token in ("/browse", "/profiles", "/account")):
                return True, "Netflix session con song."
            if any(token in final_url for token in ("/login", "/signin")):
                return False, "Netflix session da het han."
            return False, "Khong xac dinh duoc trang thai session Netflix."
    except Exception as exc:
        return False, f"Loi check session Netflix: {exc}"


@router.post("/simple/setup")
def simple_setup(payload: dict, db: Session = Depends(get_db)):
    key_plain = str(payload.get("key", "")).strip()
    email_full = str(payload.get("email", "")).strip()
    app_password = str(payload.get("app_password", "")).strip()
    imap_server = str(payload.get("imap_server", "imap.gmail.com")).strip() or "imap.gmail.com"
    imap_port = int(payload.get("imap_port", 993))

    if len(key_plain) < 8:
        raise HTTPException(status_code=400, detail={"error": "invalid_key", "message": "KEY must be at least 8 characters."})
    if "@" not in email_full:
        raise HTTPException(status_code=400, detail={"error": "invalid_email", "message": "Email is invalid."})
    if not app_password:
        raise HTTPException(status_code=400, detail={"error": "invalid_password", "message": "App password is required."})

    ok, login_message = _verify_imap_login(
        email_full=email_full,
        app_password=app_password,
        imap_server=imap_server,
        imap_port=imap_port,
    )
    if not ok:
        raise HTTPException(status_code=400, detail={"error": "imap_login_failed", "message": login_message})

    mailbox = db.execute(select(Mailbox).where(Mailbox.email_full == email_full)).scalars().first()
    label = f"mailbox-{email_full.split('@')[0]}"
    if not mailbox:
        mailbox = Mailbox(
            label=label,
            email_full=email_full,
            email_masked=mask_email(email_full),
            app_password_encrypted=encrypt_secret(app_password),
            imap_server=imap_server,
            imap_port=imap_port,
            active=True,
        )
        db.add(mailbox)
        db.commit()
        db.refresh(mailbox)
    else:
        mailbox.email_masked = mask_email(email_full)
        mailbox.app_password_encrypted = encrypt_secret(app_password)
        mailbox.imap_server = imap_server
        mailbox.imap_port = imap_port
        mailbox.active = True
        db.add(mailbox)
        db.commit()
        db.refresh(mailbox)

    rule = _default_rule(db)

    key_hash_value = hash_key(key_plain)
    key_row = db.execute(select(AccessKey).where(AccessKey.key_hash == key_hash_value)).scalars().first()
    if not key_row:
        key_row = AccessKey(
            key_hash=key_hash_value,
            key_label=key_plain,
            mailbox_id=mailbox.id,
            parser_rule_id=rule.id,
            active=True,
        )
        db.add(key_row)
        db.commit()
        db.refresh(key_row)
    else:
        key_row.key_label = key_plain
        key_row.mailbox_id = mailbox.id
        key_row.parser_rule_id = rule.id
        key_row.active = True
        db.add(key_row)
        db.commit()
        db.refresh(key_row)

    return {
        "ok": True,
        "message": "IMAP login success, config saved.",
        "imap_login": "success",
        "key": key_row.key_label,
        "email_masked": mailbox.email_masked,
        "mailbox_id": mailbox.id,
    }


@router.post("/simple/netflix-login")
def simple_test_netflix_login(payload: dict, db: Session = Depends(get_db)):
    key_plain = str(payload.get("key", "")).strip()
    netflix_email = str(payload.get("netflix_email", "")).strip()
    netflix_password = str(payload.get("netflix_password", "")).strip()

    if len(key_plain) < 8:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_key", "message": "KEY must be at least 8 characters."},
        )
    if "@" not in netflix_email:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_email", "message": "Netflix email is invalid."},
        )
    if not netflix_password:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_password", "message": "Netflix password is required."},
        )

    key_row = _find_key_by_plain(db, key_plain)
    if not key_row or not key_row.active:
        raise HTTPException(
            status_code=404,
            detail={"error": "key_not_found", "message": "Key not found or inactive."},
        )

    login_result = attempt_netflix_login(netflix_email, netflix_password)
    if not login_result.ok:
        raise HTTPException(
            status_code=400,
            detail={"error": "netflix_login_failed", "message": login_result.message},
        )

    _save_netflix_credentials(
        db=db,
        key_id=key_row.id,
        netflix_email=netflix_email,
        netflix_password=netflix_password,
    )

    return {
        "ok": True,
        "message": "Test Netflix login successful. Credentials saved for TV verify flow.",
        "key": key_row.key_label,
        "netflix_email": netflix_email,
    }


@router.post("/simple/netflix-session-sync")
def simple_sync_netflix_session(payload: dict, db: Session = Depends(get_db)):
    key_plain = str(payload.get("key", "")).strip()
    netflix_session = str(payload.get("netflix_session", "")).strip()

    if len(key_plain) < 8:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_key", "message": "KEY must be at least 8 characters."},
        )
    if len(netflix_session) < 20:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_session", "message": "Netflix session is too short."},
        )

    key_row = _find_key_by_plain(db, key_plain)
    if not key_row or not key_row.active:
        raise HTTPException(
            status_code=404,
            detail={"error": "key_not_found", "message": "Key not found or inactive."},
        )

    payload_text = json.dumps({"type": "session", "session": netflix_session}, ensure_ascii=False)
    _save_netflix_payload(db=db, key_id=key_row.id, payload_text=payload_text)
    return {
        "ok": True,
        "key": key_row.key_label,
        "message": "Netflix session synced successfully.",
    }


@router.post("/simple/netflix-login-manual/start")
def simple_start_netflix_login_manual(payload: dict, db: Session = Depends(get_db)):
    key_plain = str(payload.get("key", "")).strip()

    if len(key_plain) < 8:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_key", "message": "KEY must be at least 8 characters."},
        )

    key_row = _find_key_by_plain(db, key_plain)
    if not key_row or not key_row.active:
        raise HTTPException(
            status_code=404,
            detail={"error": "key_not_found", "message": "Key not found or inactive."},
        )

    job = start_manual_session_capture_job(
        key_id=key_row.id,
        key_label=key_row.key_label,
    )
    return {
        "ok": True,
        "job_id": job["job_id"],
        "status": job["status"],
        "message": "Da mo cua so Netflix. Hay dang nhap thu cong, he thong se tu luu session vao KEY.",
    }


@router.get("/simple/netflix-login-manual/{job_id}")
def simple_get_netflix_login_manual(job_id: str):
    job = get_manual_login_job(job_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail={"error": "job_not_found", "message": "Manual login job not found."},
        )
    return job


@router.post("/simple/netflix-session-check")
def simple_check_netflix_session(payload: dict, db: Session = Depends(get_db)):
    key_id = payload.get("key_id")
    key_plain = str(payload.get("key", "")).strip()

    key_row = None
    if key_id is not None:
        try:
            key_row = db.get(AccessKey, int(key_id))
        except Exception:
            key_row = None
    elif key_plain:
        key_row = _find_key_by_plain(db, key_plain)
    else:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "message": "Require key_id or key."},
        )

    if not key_row or not key_row.active:
        raise HTTPException(
            status_code=404,
            detail={"error": "key_not_found", "message": "Key not found or inactive."},
        )

    session_row = db.execute(select(NetflixSession).where(NetflixSession.key_id == key_row.id)).scalars().first()
    if not session_row or not session_row.active:
        return {
            "ok": True,
            "alive": False,
            "key": key_row.key_label,
            "message": "Key nay chua co Netflix session.",
        }

    try:
        raw = decrypt_secret(session_row.session_encrypted)
    except Exception:
        return {
            "ok": True,
            "alive": False,
            "key": key_row.key_label,
            "message": "Khong giai ma duoc Netflix session.",
        }

    auth_mode = "unknown"
    alive = False
    message = "Khong xac dinh duoc trang thai."
    try:
        data = json.loads(raw)
    except Exception:
        data = None

    if isinstance(data, dict) and str(data.get("type", "")).strip().lower() == "session":
        auth_mode = "session"
        session_value = str(data.get("session", "")).strip()
        alive, message = _check_netflix_cookie_alive(session_value)
    elif isinstance(data, dict):
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", "")).strip()
        if "@" in email and password:
            auth_mode = "credentials"
            login_result = attempt_netflix_login(email, password)
            alive = login_result.ok
            message = login_result.message

    return {
        "ok": True,
        "alive": alive,
        "key": key_row.key_label,
        "auth_mode": auth_mode,
        "message": message,
    }


@router.get("/simple/list")
def simple_list(db: Session = Depends(get_db)):
    rows = db.execute(select(AccessKey).order_by(AccessKey.id.desc())).scalars().all()
    output = []
    for row in rows:
        mailbox = db.get(Mailbox, row.mailbox_id)
        nfx = db.execute(select(NetflixSession).where(NetflixSession.key_id == row.id)).scalars().first()
        output.append(
            {
                "id": row.id,
                "key": row.key_label,
                "email_masked": mailbox.email_masked if mailbox else None,
                "imap_server": mailbox.imap_server if mailbox else None,
                "active": row.active,
                "has_netflix_credentials": bool(nfx and nfx.active),
                "session_updated_at": nfx.updated_at if nfx else None,
            }
        )
    return output


@router.get("/mailboxes", response_model=list[MailboxOut])
def list_mailboxes(db: Session = Depends(get_db)):
    rows = db.execute(select(Mailbox).order_by(Mailbox.id.desc())).scalars().all()
    return rows


@router.post("/mailboxes", response_model=MailboxOut, status_code=status.HTTP_201_CREATED)
def create_mailbox(payload: MailboxCreate, db: Session = Depends(get_db)):
    row = Mailbox(
        label=payload.label,
        email_full=payload.email_full,
        email_masked=mask_email(payload.email_full),
        app_password_encrypted=encrypt_secret(payload.app_password),
        imap_server=payload.imap_server,
        imap_port=payload.imap_port,
        active=payload.active,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.patch("/mailboxes/{mailbox_id}", response_model=MailboxOut)
def update_mailbox(mailbox_id: int, payload: MailboxUpdate, db: Session = Depends(get_db)):
    row = db.get(Mailbox, mailbox_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Mailbox not found."})
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field == "email_full":
            row.email_full = value
            row.email_masked = mask_email(value)
        elif field == "app_password":
            row.app_password_encrypted = encrypt_secret(value)
        else:
            setattr(row, field, value)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/mailboxes/{mailbox_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mailbox(mailbox_id: int, db: Session = Depends(get_db)):
    row = db.get(Mailbox, mailbox_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Mailbox not found."})
    db.delete(row)
    db.commit()
    return None


@router.get("/rules", response_model=list[ParserRuleOut])
def list_rules(db: Session = Depends(get_db)):
    rows = db.execute(select(ParserRule).order_by(ParserRule.id.desc())).scalars().all()
    output: list[ParserRuleOut] = []
    for row in rows:
        output.append(
            ParserRuleOut(
                id=row.id,
                name=row.name,
                code_type=row.code_type,
                regex_patterns=[p for p in row.regex_patterns.splitlines() if p],
                sender_filter=row.sender_filter,
                subject_filter=row.subject_filter,
                time_window_minutes=row.time_window_minutes,
                active=row.active,
            )
        )
    return output


@router.post("/rules", response_model=ParserRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(payload: ParserRuleCreate, db: Session = Depends(get_db)):
    row = ParserRule(
        name=payload.name,
        code_type=payload.code_type,
        regex_patterns="\n".join(payload.regex_patterns),
        sender_filter=payload.sender_filter,
        subject_filter=payload.subject_filter,
        time_window_minutes=payload.time_window_minutes,
        active=payload.active,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return ParserRuleOut(
        id=row.id,
        name=row.name,
        code_type=row.code_type,
        regex_patterns=[p for p in row.regex_patterns.splitlines() if p],
        sender_filter=row.sender_filter,
        subject_filter=row.subject_filter,
        time_window_minutes=row.time_window_minutes,
        active=row.active,
    )


@router.patch("/rules/{rule_id}", response_model=ParserRuleOut)
def update_rule(rule_id: int, payload: ParserRuleUpdate, db: Session = Depends(get_db)):
    row = db.get(ParserRule, rule_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Rule not found."})
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field == "regex_patterns":
            row.regex_patterns = "\n".join(value)
        else:
            setattr(row, field, value)
    db.add(row)
    db.commit()
    db.refresh(row)
    return ParserRuleOut(
        id=row.id,
        name=row.name,
        code_type=row.code_type,
        regex_patterns=[p for p in row.regex_patterns.splitlines() if p],
        sender_filter=row.sender_filter,
        subject_filter=row.subject_filter,
        time_window_minutes=row.time_window_minutes,
        active=row.active,
    )


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    row = db.get(ParserRule, rule_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Rule not found."})
    db.delete(row)
    db.commit()
    return None


@router.get("/keys", response_model=list[AccessKeyOut])
def list_keys(db: Session = Depends(get_db)):
    rows = db.execute(select(AccessKey).order_by(AccessKey.id.desc())).scalars().all()
    return rows


@router.post("/keys", response_model=AccessKeyOut, status_code=status.HTTP_201_CREATED)
def create_key(payload: AccessKeyCreate, db: Session = Depends(get_db)):
    mailbox = db.get(Mailbox, payload.mailbox_id)
    rule = db.get(ParserRule, payload.parser_rule_id)
    if not mailbox or not rule:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_dependency", "message": "mailbox_id or parser_rule_id is invalid."},
        )
    row = AccessKey(
        key_hash=hash_key(payload.key_plain),
        key_label=payload.key_label,
        mailbox_id=payload.mailbox_id,
        parser_rule_id=payload.parser_rule_id,
        active=payload.active,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.patch("/keys/{key_id}", response_model=AccessKeyOut)
def update_key(key_id: int, payload: AccessKeyUpdate, db: Session = Depends(get_db)):
    row = db.get(AccessKey, key_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Key not found."})

    changes = payload.model_dump(exclude_unset=True)
    if "mailbox_id" in changes and not db.get(Mailbox, changes["mailbox_id"]):
        raise HTTPException(status_code=400, detail={"error": "invalid_mailbox", "message": "mailbox_id is invalid."})
    if "parser_rule_id" in changes and not db.get(ParserRule, changes["parser_rule_id"]):
        raise HTTPException(status_code=400, detail={"error": "invalid_rule", "message": "parser_rule_id is invalid."})
    for field, value in changes.items():
        setattr(row, field, value)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_key(key_id: int, db: Session = Depends(get_db)):
    row = db.get(AccessKey, key_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Key not found."})
    db.delete(row)
    db.commit()
    return None


@router.get("/audit")
def list_audit(limit: int = 100, db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
    return [
        {
            "id": r.id,
            "key_id": r.key_id,
            "ip_address": r.ip_address,
            "outcome": r.outcome,
            "code_preview": r.code_preview,
            "detail": r.detail,
            "created_at": r.created_at,
        }
        for r in rows
    ]
