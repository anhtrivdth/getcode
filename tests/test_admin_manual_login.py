from tests.helpers import create_seed


def test_start_manual_login_job(client, db_session, monkeypatch):
    create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    monkeypatch.setattr(
        "app.api.admin.start_manual_session_capture_job",
        lambda key_id, key_label: {
            "job_id": "job-1",
            "status": "queued",
            "message": "Dang khoi tao...",
            "key_id": key_id,
            "key": key_label,
        },
    )

    response = client.post(
        "/api/admin/simple/netflix-login-manual/start",
        json={"key": "team-secret-key"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["job_id"] == "job-1"


def test_get_manual_login_job_not_found(client, db_session):
    create_seed(db_session)
    login = client.post("/admin/login", json={"password": "123456"})
    assert login.status_code == 200

    response = client.get("/api/admin/simple/netflix-login-manual/not-exist")
    assert response.status_code == 404
    assert response.json()["error"] == "job_not_found"
