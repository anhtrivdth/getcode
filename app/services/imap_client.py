from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import email
from email.header import decode_header
from email.message import Message
from email.utils import parsedate_to_datetime
import imaplib


@dataclass
class ImapMail:
    body: str
    sender: str | None
    subject: str | None
    received_at: datetime
    html_body: str | None = None


def _decode_mime_header(value: str | None) -> str | None:
    if not value:
        return value
    chunks = []
    for raw, charset in decode_header(value):
        if isinstance(raw, bytes):
            chunks.append(raw.decode(charset or "utf-8", errors="ignore"))
        else:
            chunks.append(raw)
    return "".join(chunks)


def _bodies_from_message(msg: Message) -> tuple[str, str | None]:
    plain_text = ""
    html_text = None
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp.lower():
                continue
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    plain_text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
        if plain_text:
            return plain_text, html_text
        if html_text:
            return html_text, html_text
        return "", None
    content_type = msg.get_content_type()
    payload = msg.get_payload(decode=True)
    if not payload:
        return "", None
    decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
    if content_type == "text/html":
        return decoded, decoded
    return decoded, None


def _normalize_dt(dt: datetime | None) -> datetime:
    if not dt:
        return datetime.utcnow()
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class ImapClient:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def _fetch_once(self, max_messages: int, since_minutes: int) -> list[ImapMail]:
        since_dt = datetime.utcnow() - timedelta(minutes=since_minutes)
        since_label = since_dt.strftime("%d-%b-%Y")
        conn = imaplib.IMAP4_SSL(self.host, self.port, timeout=15)
        try:
            conn.login(self.username, self.password)
            conn.select("INBOX", readonly=True)
            status, search_data = conn.search(None, f'(SINCE "{since_label}")')
            if status != "OK":
                return []
            all_ids = search_data[0].split()
            if not all_ids:
                return []
            ids = all_ids[-max_messages:]
            id_set = ",".join(i.decode() if isinstance(i, (bytes, bytearray)) else str(i) for i in ids)
            fetch_status, parts = conn.fetch(id_set, "(RFC822)")
            if fetch_status != "OK" or not parts:
                return []
            result: list[ImapMail] = []
            for part in parts:
                if not isinstance(part, tuple):
                    continue
                payload = part[1]
                if not payload:
                    continue
                message = email.message_from_bytes(payload)
                body, html_body = _bodies_from_message(message)
                sender = _decode_mime_header(message.get("From"))
                subject = _decode_mime_header(message.get("Subject"))
                date_header = message.get("Date")
                parsed_dt = None
                if date_header:
                    try:
                        parsed_dt = parsedate_to_datetime(date_header)
                    except Exception:
                        parsed_dt = None
                received_at = _normalize_dt(parsed_dt)
                if received_at < since_dt:
                    continue
                result.append(
                    ImapMail(
                        body=body,
                        html_body=html_body,
                        sender=sender,
                        subject=subject,
                        received_at=received_at,
                    )
                )
            return sorted(result, key=lambda x: x.received_at, reverse=True)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def fetch_recent_mails(self, max_messages: int = 30, since_minutes: int = 60) -> list[ImapMail]:
        try:
            return self._fetch_once(max_messages=max_messages, since_minutes=since_minutes)
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error):
            # lightweight reconnect strategy for unstable PaaS network
            return self._fetch_once(max_messages=max_messages, since_minutes=since_minutes)
