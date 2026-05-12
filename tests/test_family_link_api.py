from datetime import datetime

from app.services.imap_client import ImapMail
from tests.helpers import attach_session_cookie_to_key, create_seed


def test_family_link_returns_receive_button_url(client, db_session, monkeypatch):
    _, _, key = create_seed(db_session)
    attach_session_cookie_to_key(db_session, key)

    html_body = """
    <html><body>
      <h1>Mã truy cập tạm thời của bạn</h1>
      <a href="https://www.netflix.com/account/travel/verify?token=abc123">Nhận mã</a>
      <a href="https://www.netflix.com/notificationsettings/email">Notification Settings</a>
    </body></html>
    """

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        return [
            ImapMail(
                body="Mã truy cập tạm thời của bạn. Nhận mã tại link bên dưới.",
                sender="Netflix <info@account.netflix.com>",
                subject="Mã truy cập Netflix tạm thời của bạn",
                received_at=datetime(2026, 5, 10, 7, 19, 0),
                html_body=html_body,
            )
        ]

    monkeypatch.setattr("app.services.imap_client.ImapClient.fetch_recent_mails", fake_fetch_recent_mails)
    monkeypatch.setattr("app.api.public._check_netflix_cookie_alive", lambda session_value: (True, "ok"))
    monkeypatch.setattr("app.api.public._resolve_family_code_via_session_link", lambda url, session_value: ("8398", "ok"))
    response = client.post("/api/code/family-link", json={"key": "team-secret-key"})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["feature"] == "family_code"
    assert data["url"] == "https://www.netflix.com/account/travel/verify?token=abc123"
    assert data["code"] == "8398"


def test_family_link_invalid_key(client, db_session):
    create_seed(db_session)
    response = client.post("/api/code/family-link", json={"key": "wrong-key-value"})
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "invalid_key"
