import pytest
from pathlib import Path
import app as tv
tv.limiter.enabled = False

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(tv, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(tv, "UPLOAD_DIR", tmp_path / "uploads")
    tv.UPLOAD_DIR.mkdir()
    tv.app.config.update(TESTING=True, SECRET_KEY="test-secret", WTF_CSRF_ENABLED=False)
    tv.init_db()
    with tv.app.test_client() as client:
        yield client
