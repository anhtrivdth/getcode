import json

from app.models import AccessKey, Mailbox, NetflixSession, ParserRule
from app.security import encrypt_secret, hash_key, mask_email


def create_seed(db):
    mailbox = Mailbox(
        label="team-mailbox",
        email_full="team@example.com",
        email_masked=mask_email("team@example.com"),
        app_password_encrypted=encrypt_secret("app-password"),
        imap_server="imap.gmail.com",
        imap_port=993,
        active=True,
    )
    rule = ParserRule(
        name="login_code",
        code_type="login_code",
        regex_patterns=r"OTP[:\s]+(\d{6})",
        sender_filter="no-reply@example.com",
        subject_filter="Your OTP",
        time_window_minutes=120,
        active=True,
    )
    db.add(mailbox)
    db.add(rule)
    db.commit()
    db.refresh(mailbox)
    db.refresh(rule)

    key = AccessKey(
        key_hash=hash_key("team-secret-key"),
        key_label="team-k1",
        mailbox_id=mailbox.id,
        parser_rule_id=rule.id,
        active=True,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return mailbox, rule, key


def attach_session_cookie_to_key(db, key, session_text: str | None = None):
    payload = {
        "type": "session",
        "session": session_text or "NetflixId=fake-session; SecureNetflixId=fake-session-2; Path=/;",
    }
    row = NetflixSession(
        key_id=key.id,
        session_encrypted=encrypt_secret(json.dumps(payload)),
        active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
