import os
import sys
import uuid
import pytest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app
from models import Database


@pytest.fixture
def app():
    app = create_app("testing")
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # Create isolated in-memory DB per test
    db_uri = f"file:test_mem_{uuid.uuid4().hex}?mode=memory&cache=shared"
    app.db = Database(db_uri)
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def csrf_client():
    app = create_app("testing")
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    db_uri = f"file:test_csrf_{uuid.uuid4().hex}?mode=memory&cache=shared"
    app.db = Database(db_uri)
    return app.test_client()
