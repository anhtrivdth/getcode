from dataclasses import dataclass
from datetime import datetime
import html
import re
import unicodedata

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models import AccessKey
from app.security import decrypt_secret, hash_key
from app.services.imap_client import ImapClient, ImapMail


@dataclass
class FamilyLinkResult:
    url: str
    received_at: datetime
    subject: str | None


class FamilyCodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_text(value: str | None) -> str:
    raw = (value or "").strip().lower().replace("đ", "d")
    if not raw:
        return ""
    decomposed = unicodedata.normalize("NFD", raw)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


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


def _looks_like_family_mail(mail: ImapMail) -> bool:
    subject_norm = _normalize_text(mail.subject)
    body_norm = _normalize_text(mail.body)
    sender_norm = _normalize_text(mail.sender)
    if "netflix" not in subject_norm and "netflix" not in sender_norm and "netflix" not in body_norm:
        return False
    if "ma truy cap netflix tam thoi cua ban" in subject_norm:
        return True
    if "ma truy cap tam thoi cua ban" in body_norm and "nhan ma" in body_norm:
        return True
    return False


def _extract_links_from_html(html_body: str) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    for m in re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body, flags=re.IGNORECASE | re.DOTALL):
        href = html.unescape(m.group(1)).strip()
        anchor_text = html.unescape(re.sub(r"<[^>]+>", " ", m.group(2))).strip()
        if href:
            links.append((href, anchor_text))
    return links


def _is_good_family_link(url: str) -> bool:
    u = url.strip().lower()
    if not u.startswith(("http://", "https://")):
        return False
    if "netflix.com" not in u:
        return False
    bad_tokens = [
        "unsubscribe",
        "notificationsettings",
        "privacy",
        "help.netflix.com",
    ]
    return not any(token in u for token in bad_tokens)


def _extract_family_link(mail: ImapMail) -> str | None:
    html_body = mail.html_body or ""
    if html_body:
        links = _extract_links_from_html(html_body)
        for href, text in links:
            if "nhan ma" in _normalize_text(text) and _is_good_family_link(href):
                return href
        for href, _ in links:
            if _is_good_family_link(href):
                return href

    plain_links = re.findall(r"https?://[^\s<>\"]+", mail.body or "")
    for link in plain_links:
        clean = link.rstrip(").,")
        if _is_good_family_link(clean):
            return clean
    return None


def get_latest_family_link(
    db: Session,
    key_plain: str,
    *,
    key_row: AccessKey | None = None,
    max_messages: int = 200,
    since_minutes: int = 60 * 24 * 14,
) -> FamilyLinkResult:
    key_row = key_row or _find_active_key(db, key_plain)
    if not key_row or not key_row.active or not key_row.mailbox.active:
        raise FamilyCodeError("invalid_key", "Key sai hoặc chưa được cấp quyền.")

    mailbox = key_row.mailbox
    app_password = decrypt_secret(mailbox.app_password_encrypted)
    imap = ImapClient(
        host=mailbox.imap_server,
        port=mailbox.imap_port,
        username=mailbox.email_full,
        password=app_password,
    )
    mails = imap.fetch_recent_mails(max_messages=max_messages, since_minutes=since_minutes)
    for mail in mails:
        if not _looks_like_family_mail(mail):
            continue
        url = _extract_family_link(mail)
        if url:
            return FamilyLinkResult(url=url, received_at=mail.received_at, subject=mail.subject)
    raise FamilyCodeError("no_family_link_found", "Không tìm thấy link 'Nhận mã' phù hợp trong mail hộ gia đình.")
