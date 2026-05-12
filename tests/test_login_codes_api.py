from datetime import datetime

from app.services.imap_client import ImapMail
from tests.helpers import create_seed


def test_login_codes_returns_latest_code_only(client, db_session, monkeypatch):
    create_seed(db_session)

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        rows = []
        for i in range(12):
            rows.append(
                ImapMail(
                    body=f"Nhập mã này để đăng nhập\n{(i % 10)} {(i % 10)} {(i % 10)} {(i % 10)}\nMã sẽ hết hạn sau 15 phút.",
                    sender="Netflix <info@account.netflix.com>",
                    subject="Netflix: Mã đăng nhập của bạn",
                    received_at=datetime(2026, 5, 10, 20, 49, 0),
                )
            )
        return rows

    monkeypatch.setattr("app.services.imap_client.ImapClient.fetch_recent_mails", fake_fetch_recent_mails)
    response = client.post("/api/code/login-codes", json={"key": "team-secret-key"})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["feature"] == "login_code"
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["code"] == "0000"


def test_login_codes_invalid_key(client, db_session):
    create_seed(db_session)
    response = client.post("/api/code/login-codes", json={"key": "wrong-key-value"})
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_key"
