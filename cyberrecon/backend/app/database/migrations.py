"""Minimal versioned migrations.

Version 1 creates the full schema. Later versions append (version, description, callable) entries
below; they run once, in order, and are recorded in ``schema_version``. For a larger deployment,
swap this for Alembic (documented in docs/ARCHITECTURE.md).
"""
from __future__ import annotations

from typing import Callable

from sqlalchemy import inspect, select, text
from sqlalchemy.engine import Engine

from app.database.session import Base, Database
from app.models import entities  # noqa: F401  (register tables)
from app.models.entities import SchemaVersion


def _v1_create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)


MIGRATIONS: list[tuple[int, str, Callable[[Engine], None]]] = [
    (1, "initial schema", _v1_create_schema),
]


def current_version(db: Database) -> int:
    if not inspect(db.engine).has_table("schema_version"):
        return 0
    with db.session() as s:
        versions = s.scalars(select(SchemaVersion.version)).all()
        return max(versions) if versions else 0


def migrate(db: Database) -> int:
    """Apply any pending migrations and return the resulting schema version."""
    # schema_version must exist before we can read it
    SchemaVersion.__table__.create(db.engine, checkfirst=True)
    have = current_version(db)
    for version, description, fn in MIGRATIONS:
        if version > have:
            fn(db.engine)
            with db.session() as s:
                s.add(SchemaVersion(version=version, description=description))
            have = version
    return have


def database_ok(db: Database) -> bool:
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
