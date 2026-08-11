import sys
from pathlib import Path

# To add path to the app module for testing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from app.app import app as flask_app


@pytest.fixture
def app():
    flask_app.config.update({"TESTING": True})
    yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()