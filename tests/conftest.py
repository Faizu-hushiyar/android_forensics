import sys
import os
import pytest

# Ensure the project root (one level up from the tests directory) is on sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


@pytest.fixture(autouse=True, scope="session")
def initialize_db():
    """Ensure database tables exist before any test runs."""
    from services import db
    db.init_db()
