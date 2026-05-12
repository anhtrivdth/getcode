import imaplib
from datetime import datetime

from app.services.imap_client import ImapClient, ImapMail


def test_reconnect_when_first_fetch_fails(monkeypatch):
    client = ImapClient("imap.gmail.com", 993, "x", "y")
    calls = {"count": 0}

    def fake_fetch_once(self, max_messages, since_minutes):
        calls["count"] += 1
        if calls["count"] == 1:
            raise imaplib.IMAP4.abort("dropped")
        return [
            ImapMail(body="OTP: 111111", sender="a", subject="b", received_at=datetime.utcnow())
        ]

    monkeypatch.setattr(ImapClient, "_fetch_once", fake_fetch_once)
    result = client.fetch_recent_mails()
    assert calls["count"] == 2
    assert len(result) == 1
