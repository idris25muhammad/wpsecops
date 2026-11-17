import os
import sys
import pytest

os.environ["WPSECOPS_SKIP_CREATE_APP"] = "1"

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import Config
from app import create_app, init_db
from extensions import db


@pytest.fixture()
def app(tmp_path):
    db_file = tmp_path / "test_wpsecops.db"

    class TestConfig(Config):
        TESTING = True
        AUTO_INIT_DB = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_file}"
        CELERY_TASK_ALWAYS_EAGER = True
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False
        ADMIN_USERNAME = "admin"
        ADMIN_PASSWORD = "testpassword123"
        SECRET_KEY = "test-secret-key"

    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "testpassword123"

    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        init_db()
        yield flask_app
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(client):
    resp = client.post("/", data={"username": "admin", "password": "testpassword123"}, follow_redirects=False)
    assert resp.status_code in (302, 200)
    return client
