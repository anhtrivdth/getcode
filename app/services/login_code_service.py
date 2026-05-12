from dataclasses import dataclass
from datetime import datetime
import re
import unicodedata

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models import AccessKey
from app.security import decrypt_secret, hash_key
from app.services.imap_client import ImapClient, ImapMail


@dataclass
class LoginCodeRecord:
    code: str
    received_at: datetime
    subject: str | None


class LoginCodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_text(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    raw = raw.replace("đ", "d")
    decomposed = unicodedata.normalize("NFD", raw)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


def _looks_like_netflix_login_mail(mail: ImapMail) -> bool:
    subject_norm = _normalize_text(mail.subject)
    body_norm = _normalize_text(mail.body)
    sender_norm = _normalize_text(mail.sender)

    if "netflix" not in subject_norm and "netflix" not in sender_norm and "netflix" not in body_norm:
        return False
    if "ma dang nhap" in subject_norm:
        return True
    if "nhap ma nay de dang nhap" in body_norm:
        return True
    if "ma se het han sau 15 phut" in body_norm and "dang nhap netflix" in body_norm:
        return True
    return False


def _extract_4_digit_code(body: str) -> str | None:
    body_norm = _normalize_text(body)

    anchor_phrases = [
        "nhap ma nay de dang nhap",
        "ma dang nhap cua ban",
    ]
    for anchor in anchor_phrases:
        idx = body_norm.find(anchor)
        if idx >= 0:
            window = body[idx : idx + 240]
            m = re.search(r"(?<!\d)(\d(?:\s*\d){3})(?!\d)", window)
            if m:
                code = re.sub(r"\s+", "", m.group(1))
                if len(code) == 4 and code.isdigit():
                    return code

    for candidate in re.findall(r"(?<!\d)(\d(?:\s*\d){3})(?!\d)", body):
        code = re.sub(r"\s+", "", candidate)
        if len(code) == 4 and code.isdigit():
            return code
    return None


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


def get_recent_login_codes_for_key(db: Session, key_plain: str, limit: int = 10) -> list[LoginCodeRecord]:
    key_row = _find_active_key(db, key_plain)
    if not key_row or not key_row.active or not key_row.mailbox.active:
        raise LoginCodeError("invalid_key", "Key sai hoặc chưa được cấp quyền.")

    mailbox = key_row.mailbox
    app_password = decrypt_secret(mailbox.app_password_encrypted)
    imap = ImapClient(
        host=mailbox.imap_server,
        port=mailbox.imap_port,
        username=mailbox.email_full,
        password=app_password,
    )
    mails = imap.fetch_recent_mails(max_messages=200, since_minutes=60 * 24 * 14)
    items: list[LoginCodeRecord] = []
    for mail in mails:
        if not _looks_like_netflix_login_mail(mail):
            continue
        code = _extract_4_digit_code(mail.body or "")
        if not code:
            continue
        items.append(LoginCodeRecord(code=code, received_at=mail.received_at, subject=mail.subject))
        if len(items) >= limit:
            break
    return items
