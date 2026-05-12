from datetime import datetime

from app.services.imap_client import ImapMail
from app.services.resolve_service import cache
from tests.helpers import create_seed


def test_valid_key_returns_code_and_received_at(client, db_session, monkeypatch):
    create_seed(db_session)
    cache._store.clear()

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        return [
            ImapMail(
                body="OTP: 123456",
                sender="no-reply@example.com",
                subject="Your OTP",
                received_at=datetime.utcnow(),
            )
        ]

    monkeypatch.setattr("app.services.imap_client.ImapClient.fetch_recent_mails", fake_fetch_recent_mails)
    response = client.post("/api/code/resolve", json={"key": "team-secret-key"})
    assert response.status_code == 200
    data = response.json()
    assert data["code"] == "123456"
    assert data["source_label"] == "team-mailbox/login_code"
    assert "received_at" in data


def test_invalid_key_returns_error(client, db_session):
    create_seed(db_session)
    cache._store.clear()
    response = client.post("/api/code/resolve", json={"key": "wrong-key-value"})
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_key"


def test_rate_limit_returns_429(client, db_session, monkeypatch):
    create_seed(db_session)
    cache._store.clear()

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        return [
            ImapMail(
                body="OTP: 123456",
                sender="no-reply@example.com",
                subject="Your OTP",
                received_at=datetime.utcnow(),
            )
        ]

    monkeypatch.setattr("app.services.imap_client.ImapClient.fetch_recent_mails", fake_fetch_recent_mails)
    first = client.post("/api/code/resolve", json={"key": "team-secret-key"})
    assert first.status_code == 200
    second = client.post("/api/code/resolve", json={"key": "team-secret-key"})
    assert second.status_code == 429
    assert second.json()["error"] == "rate_limited"


def test_no_recent_code_returns_404(client, db_session, monkeypatch):
    create_seed(db_session)
    cache._store.clear()

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        return [
            ImapMail(
                body="Welcome newsletter",
                sender="newsletter@example.com",
                subject="Daily",
                received_at=datetime.utcnow(),
            )
        ]

    monkeypatch.setattr("app.services.imap_client.ImapClient.fetch_recent_mails", fake_fetch_recent_mails)
    response = client.post("/api/code/resolve", json={"key": "team-secret-key"})
    assert response.status_code == 404
    assert response.json()["error"] == "no_recent_code"
