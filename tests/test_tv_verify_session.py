from datetime import datetime

from app.services.family_code_service import FamilyLinkResult
from app.services.netflix_login import NetflixLoginResult
from tests.helpers import create_seed


def test_tv_verify_requires_netflix_login_setup(client, db_session):
    create_seed(db_session)
    response = client.post("/api/code/access-check", json={"key": "team-secret-key", "feature": "tv_verify"})
    assert response.status_code == 403
    data = response.json()
    assert data["error"] == "netflix_login_required"


def test_admin_netflix_login_returns_error_when_fail(client, db_session, monkeypatch):
    create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    monkeypatch.setattr(
        "app.api.admin.attempt_netflix_login",
        lambda email, password: NetflixLoginResult(ok=False, message="Wrong credentials"),
    )

    response = client.post(
        "/api/admin/simple/netflix-login",
        json={
            "key": "team-secret-key",
            "netflix_email": "user@example.com",
            "netflix_password": "bad-password",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "netflix_login_failed"


def test_tv_verify_passes_after_admin_test_login(client, db_session, monkeypatch):
    create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    monkeypatch.setattr(
        "app.api.admin.attempt_netflix_login",
        lambda email, password: NetflixLoginResult(ok=True, message="OK"),
    )
    set_login = client.post(
        "/api/admin/simple/netflix-login",
        json={
            "key": "team-secret-key",
            "netflix_email": "user@example.com",
            "netflix_password": "good-password",
        },
    )
    assert set_login.status_code == 200

    monkeypatch.setattr(
        "app.api.public.attempt_netflix_login",
        lambda email, password: NetflixLoginResult(ok=True, message="OK"),
    )
    monkeypatch.setattr(
        "app.api.public.get_latest_family_link",
        lambda db, key_plain: FamilyLinkResult(
            url="https://www.netflix.com/account/travel/verify?token=abc123",
            received_at=datetime(2026, 5, 10, 7, 19, 0),
            subject="Netflix temporary access code",
        ),
    )

    check = client.post("/api/code/access-check", json={"key": "team-secret-key", "feature": "tv_verify"})
    assert check.status_code == 200
    assert check.json()["ok"] is True
    assert "Netflix login is ready." in check.json()["message"]


def test_tv_verify_passes_after_manual_session_sync(client, db_session, monkeypatch):
    create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    sync_session = client.post(
        "/api/admin/simple/netflix-session-sync",
        json={
            "key": "team-secret-key",
            "netflix_session": "NetflixId=fake-session; SecureNetflixId=fake-session-2; Path=/;",
        },
    )
    assert sync_session.status_code == 200

    monkeypatch.setattr(
        "app.api.public.get_latest_family_link",
        lambda db, key_plain: FamilyLinkResult(
            url="https://www.netflix.com/account/travel/verify?token=abc123",
            received_at=datetime(2026, 5, 10, 7, 19, 0),
            subject="Netflix temporary access code",
        ),
    )
    monkeypatch.setattr("app.api.public._check_netflix_cookie_alive", lambda session_value: (True, "ok"))

    check = client.post("/api/code/access-check", json={"key": "team-secret-key", "feature": "tv_verify"})
    assert check.status_code == 200
    assert check.json()["ok"] is True
    assert "Netflix session is ready." in check.json()["message"]
