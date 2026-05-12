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

    # Vietnamese markers
    vi_markers = (
        "ma truy cap netflix tam thoi cua ban",
        "ma truy cap tam thoi cua ban",
        "nhan ma",
        "xac minh",
        "ho gia dinh",
    )
    # English markers (some Netflix templates are in English)
    en_markers = (
        "temporary access code",
        "use this code",
        "enter this code",
        "verify",
        "household",
    )
    for marker in (*vi_markers, *en_markers):
        if marker in subject_norm or marker in body_norm:
            return True

    # Fallback: for Netflix mails, if body has 4-digit pattern and a link, treat as candidate.
    has_4_digit = bool(re.search(r"(?<!\d)\d{4}(?!\d)", body_norm))
    has_link = "http://" in body_norm or "https://" in body_norm
    return has_4_digit and has_link


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
        "lkid=url_logo",
        "lnktrk=evo",
    ]
    return not any(token in u for token in bad_tokens)


def _score_family_link(url: str, anchor_text: str | None = None) -> int:
    u = url.strip().lower()
    t = _normalize_text(anchor_text)
    if not _is_good_family_link(u):
        return -999

    score = 0
    positive_url_tokens = (
        "travel/verify",
        "household",
        "temporary",
        "verify",
        "code",
        "/account/",
    )
    positive_text_tokens = (
        "nhan ma",
        "lay ma",
        "ma tam thoi",
        "ma truy cap",
        "get code",
        "use this code",
        "enter this code",
        "verification code",
        "temporary access",
    )
    negative_url_tokens = (
        "/browse",
        "/login",
        "/signup",
        "/kids",
        "lkid=url_logo",
        "lnktrk=evo",
    )

    for token in positive_url_tokens:
        if token in u:
            score += 3
    for token in positive_text_tokens:
        if token in t:
            score += 5
    for token in negative_url_tokens:
        if token in u:
            score -= 8

    return score


def _extract_family_link(mail: ImapMail) -> str | None:
    html_body = mail.html_body or ""
    if html_body:
        links = _extract_links_from_html(html_body)
        best_href = None
        best_score = -999
        for href, text in links:
            score = _score_family_link(href, text)
            if score > best_score:
                best_score = score
                best_href = href
        if best_href and best_score >= 1:
            return best_href

    plain_links = re.findall(r"https?://[^\s<>\"]+", mail.body or "")
    best_plain = None
    best_plain_score = -999
    for link in plain_links:
        clean = link.rstrip(").,")
        score = _score_family_link(clean, mail.subject or "")
        if score > best_plain_score:
            best_plain_score = score
            best_plain = clean
    if best_plain and best_plain_score >= 1:
        return best_plain
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
