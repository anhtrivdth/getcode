from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.models import AccessKey, AuditLog
from app.security import decrypt_secret, hash_key
from app.services.cache import KeyLockRegistry, ResolveCache
from app.services.imap_client import ImapClient
from app.services.parser import extract_code, parse_patterns


settings = get_settings()


class ResolveError(Exception):
    def __init__(self, code: str, message: str, ttl_hint: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.ttl_hint = ttl_hint


@dataclass
class ResolveResult:
    code: str
    received_at: datetime
    source_label: str
    ttl_hint: int


cache = ResolveCache()
lock_registry = KeyLockRegistry()


def _log(
    db: Session,
    key_id: int | None,
    ip: str | None,
    outcome: str,
    detail: str | None = None,
    code: str | None = None,
) -> None:
    preview = None
    if code:
        preview = f"{code[:2]}***{code[-1:]}" if len(code) > 3 else "***"
    db.add(AuditLog(key_id=key_id, ip_address=ip, outcome=outcome, detail=detail, code_preview=preview))
    db.commit()


def _get_key_entity(db: Session, key_plain: str) -> AccessKey | None:
    hashed = hash_key(key_plain)
    stmt = (
        select(AccessKey)
        .where(AccessKey.key_hash == hashed)
        .options(joinedload(AccessKey.mailbox), joinedload(AccessKey.parser_rule))
    )
    return db.execute(stmt).scalars().first()


def _ttl_hint_seconds(next_allowed_at: datetime) -> int:
    delta = int((next_allowed_at - datetime.utcnow()).total_seconds())
    return max(delta, 0)


def fetch_latest_code_for_entity(key: AccessKey) -> tuple[str, datetime, str] | None:
    mailbox = key.mailbox
    rule = key.parser_rule
    app_password = decrypt_secret(mailbox.app_password_encrypted)
    imap = ImapClient(
        host=mailbox.imap_server,
        port=mailbox.imap_port,
        username=mailbox.email_full,
        password=app_password,
    )
    patterns = parse_patterns(rule.regex_patterns)
    mails = imap.fetch_recent_mails(
        max_messages=settings.imap_max_messages_scan,
        since_minutes=rule.time_window_minutes,
    )
    for mail in mails:
        code = extract_code(
            body=mail.body,
            patterns=patterns,
            sender=mail.sender,
            subject=mail.subject,
            sender_filter=rule.sender_filter,
            subject_filter=rule.subject_filter,
        )
        if code:
            return code, mail.received_at, f"{mailbox.label}/{rule.name}"
    return None


async def resolve_code(db: Session, key_plain: str, ip: str | None = None) -> ResolveResult:
    key = _get_key_entity(db, key_plain)
    if not key or not key.active or not key.mailbox.active or not key.parser_rule.active:
        _log(db, key.id if key else None, ip, "invalid_key")
        raise ResolveError("invalid_key", "Key không hợp lệ hoặc đang bị vô hiệu hóa.")

    key_lock = await lock_registry.lock_for(key.id)
    async with key_lock:
        db.expire_all()
        key = db.execute(
            select(AccessKey)
            .where(AccessKey.id == key.id)
            .options(joinedload(AccessKey.mailbox), joinedload(AccessKey.parser_rule))
        ).scalars().first()
        if not key or not key.active or not key.mailbox.active or not key.parser_rule.active:
            _log(db, key.id if key else None, ip, "invalid_key")
            raise ResolveError("invalid_key", "Key không hợp lệ hoặc đang bị vô hiệu hóa.")

        if key.last_resolved_at:
            rate_limit_until = key.last_resolved_at + timedelta(minutes=settings.rate_limit_minutes)
            if rate_limit_until > datetime.utcnow():
                ttl = _ttl_hint_seconds(rate_limit_until)
                _log(db, key.id, ip, "rate_limited", detail=f"ttl={ttl}")
                raise ResolveError("rate_limited", "Key đã vượt hạn mức gọi API.", ttl_hint=ttl)

        key.last_resolved_at = datetime.utcnow()
        db.add(key)
        db.commit()

        cached = cache.get(key.id)
        if cached:
            _log(db, key.id, ip, "ok_cached", code=cached.code)
            return ResolveResult(
                code=cached.code,
                received_at=cached.received_at,
                source_label=cached.source_label,
                ttl_hint=settings.rate_limit_minutes * 60,
            )
        try:
            latest = fetch_latest_code_for_entity(key)
        except Exception as exc:
            _log(db, key.id, ip, "imap_error", detail=str(exc)[:220])
            raise ResolveError("imap_unavailable", "Không thể truy cập mailbox lúc này.", ttl_hint=120) from exc

        if latest:
            code, received_at, source_label = latest
            cache.set(
                key.id,
                code=code,
                received_at=received_at,
                source_label=source_label,
                ttl_seconds=settings.cache_ttl_seconds,
            )
            _log(db, key.id, ip, "ok_live", code=code)
            return ResolveResult(
                code=code,
                received_at=received_at,
                source_label=source_label,
                ttl_hint=settings.rate_limit_minutes * 60,
            )

        _log(db, key.id, ip, "not_found")
        raise ResolveError(
            "no_recent_code",
            "Không tìm thấy mã hợp lệ trong cửa sổ thời gian hiện tại.",
            ttl_hint=60,
        )
