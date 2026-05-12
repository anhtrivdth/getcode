from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import email
from email.header import decode_header
from email.message import Message
from email.utils import parsedate_to_datetime
import imaplib
import re
import unicodedata


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
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        preferred_mailboxes: list[str] | None = None,
        strict_preferred_mailboxes: bool = False,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.preferred_mailboxes = [m.strip() for m in (preferred_mailboxes or []) if m and m.strip()]
        self.strict_preferred_mailboxes = strict_preferred_mailboxes

    @staticmethod
    def _normalize_mailbox_name(value: str) -> str:
        raw = (value or "").strip().lower()
        decomposed = unicodedata.normalize("NFD", raw)
        normalized = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
        normalized = normalized.replace("\\", "/")
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _pick_preferred_mailboxes(self, discovered: list[str]) -> list[str]:
        if not self.preferred_mailboxes:
            return []
        discovered_pairs = [(name, self._normalize_mailbox_name(name)) for name in discovered]
        picked: list[str] = []
        for preferred in self.preferred_mailboxes:
            target = self._normalize_mailbox_name(preferred)
            # Skip system prefix if user provided it.
            target = target.removeprefix("[gmail]/").removeprefix("[googlemail]/")
            # Exact normalized match first.
            exact = [name for name, norm in discovered_pairs if norm == target]
            if exact:
                for name in exact:
                    if name not in picked:
                        picked.append(name)
                continue
            # Then match folder tail (e.g. "[Gmail]/Label" ends with "label").
            tail = [name for name, norm in discovered_pairs if norm.endswith("/" + target) or ("/" + norm).endswith("/" + target)]
            if tail:
                for name in tail:
                    if name not in picked:
                        picked.append(name)
        return picked

    def _discover_mailboxes(self, conn: imaplib.IMAP4_SSL) -> list[str]:
        candidates = ["INBOX"]
        discovered: list[str] = []
        try:
            status, mailbox_data = conn.list()
        except Exception:
            return candidates
        if status != "OK" or not mailbox_data:
            return candidates

        for row in mailbox_data:
            line = row.decode(errors="ignore") if isinstance(row, (bytes, bytearray)) else str(row)
            match = re.search(r'"([^"]+)"\s*$', line)
            name = match.group(1).strip() if match else ""
            if not name:
                continue
            discovered.append(name)
            lower_name = name.lower()
            if (
                "\\all" in line.lower()
                or "all mail" in lower_name
                or "allmail" in lower_name
                or "archive" in lower_name
                or "\\junk" in line.lower()
                or "\\spam" in line.lower()
            ):
                candidates.append(name)

        preferred = self._pick_preferred_mailboxes(discovered)
        if preferred:
            return preferred
        if self.strict_preferred_mailboxes and self.preferred_mailboxes:
            return []

        # Keep order and dedupe.
        unique = []
        seen = set()
        for mbox in candidates:
            key = mbox.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(mbox)
        return unique

    def _fetch_once(self, max_messages: int, since_minutes: int) -> list[ImapMail]:
        since_dt = datetime.utcnow() - timedelta(minutes=since_minutes)
        since_label = since_dt.strftime("%d-%b-%Y")
        conn = imaplib.IMAP4_SSL(self.host, self.port, timeout=15)
        try:
            conn.login(self.username, self.password)
            result: list[ImapMail] = []
            seen_messages: set[tuple[str, str, str]] = set()
            mailboxes = self._discover_mailboxes(conn)

            for mailbox_name in mailboxes:
                status, _ = conn.select(mailbox_name, readonly=True)
                if status != "OK":
                    continue
                search_status, search_data = conn.search(None, f'(SINCE "{since_label}")')
                if search_status != "OK":
                    continue
                all_ids = search_data[0].split()
                if not all_ids:
                    continue
                ids = all_ids[-max_messages:]
                id_set = ",".join(i.decode() if isinstance(i, (bytes, bytearray)) else str(i) for i in ids)
                fetch_status, parts = conn.fetch(id_set, "(RFC822)")
                if fetch_status != "OK" or not parts:
                    continue

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

                    message_id = (message.get("Message-ID") or "").strip()
                    signature = (
                        message_id or "",
                        (subject or "").strip().lower(),
                        received_at.isoformat(),
                    )
                    if signature in seen_messages:
                        continue
                    seen_messages.add(signature)

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
