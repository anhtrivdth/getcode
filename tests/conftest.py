import os
from pathlib import Path
import tempfile

import pytest
from fastapi.testclient import TestClient


test_db = Path(tempfile.gettempdir()) / "imap_code_resolver_test.db"
if test_db.exists():
    test_db.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{test_db}"
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["KEY_HASH_SECRET"] = "test-secret"
os.environ["POLL_INTERVAL_SECONDS"] = "0"

from app.config import get_settings
get_settings.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def setup_env():
    yield
    if test_db.exists():
        try:
            test_db.unlink()
        except PermissionError:
            pass


@pytest.fixture()
def client(setup_env):
    from app.main import app
    return TestClient(app)


@pytest.fixture()
def db_session(setup_env):
    from app.database import Base, SessionLocal, engine
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
