"""
Database session management for NetSentinel.

Supports PostgreSQL (production) with a seamless SQLite development fallback.
Configured via the DATABASE_URL environment variable.

IMPORTANT: create_all() in init_db() creates missing tables but does NOT
perform schema migrations on existing tables.  Do not assume that calling
init_db() automatically applies column/constraint changes to an existing
database.

Security: DATABASE_URL is read from environment only.  Do not commit
credentials to source code.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Only an absent DATABASE_URL falls back to SQLite.
# An explicitly set but invalid DATABASE_URL will cause SQLAlchemy to raise
# a clear configuration error — it will NOT be silently replaced with SQLite.
_raw_url = os.getenv("DATABASE_URL")
DATABASE_URL: str = _raw_url if _raw_url else "sqlite:///./netsentinel.db"

connect_args: dict = {}
if DATABASE_URL.startswith("sqlite"):
    # check_same_thread=False is required for SQLite with FastAPI/threading.
    connect_args = {"check_same_thread": False}
# No SQLite-specific arguments are applied to PostgreSQL connections.

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True  # Detect stale connections before use.
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    FastAPI database dependency.
    Yields one session per request and always closes it, even on exception.
    Each request receives its own independent session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables defined in SQLAlchemy models (create_all strategy).

    NOTE: create_all() creates missing tables but does NOT migrate existing
    tables to a new schema.  For schema migrations, a dedicated migration tool
    (such as Alembic) would be required — which is outside the scope of the
    current academic project.
    """
    # Import models here to ensure they are registered with Base before create_all().
    import backend.app.database.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
