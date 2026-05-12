from tests.helpers import create_seed


def test_session_check_returns_not_found_when_no_session(client, db_session):
    _, _, key = create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    response = client.post("/api/admin/simple/netflix-session-check", json={"key_id": key.id})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["alive"] is False


def test_session_check_returns_alive_for_synced_session(client, db_session, monkeypatch):
    _, _, key = create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    sync = client.post(
        "/api/admin/simple/netflix-session-sync",
        json={
            "key": "team-secret-key",
            "netflix_session": "NetflixId=fake-session; SecureNetflixId=fake-session-2; Path=/;",
        },
    )
    assert sync.status_code == 200

    monkeypatch.setattr("app.api.admin._check_netflix_cookie_alive", lambda s: (True, "alive"))
    response = client.post("/api/admin/simple/netflix-session-check", json={"key_id": key.id})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["alive"] is True
