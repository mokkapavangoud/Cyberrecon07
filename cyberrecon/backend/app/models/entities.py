"""Database entities.

Data model
----------
Assessment 1──* ModuleResult   (module-specific result JSON + status + errors)
           1──* Finding        (individual observations, each tagged observed / third_party / estimate)
           1──* DataSource     (every source consulted, including unavailable/failed ones with reasons)
           1──* Report         (generated exports, with file hash)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class UTCDateTime(TypeDecorator):
    """DateTime that always round-trips as timezone-aware UTC (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    module: Mapped[str] = mapped_column(String(24), index=True)  # link | image | infrastructure | screenshot
    target: Mapped[str] = mapped_column(String(2048))
    target_label: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued|running|completed|partial|failed
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    results: Mapped[list["ModuleResult"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    sources: Mapped[list["DataSource"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_assessments_target", "target_label"),)


class ModuleResult(Base):
    __tablename__ = "module_results"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="results")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    module: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(48))
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), default="info")  # info | low | medium | high
    evidence_type: Mapped[str] = mapped_column(String(16), default="observed")  # observed | third_party | estimate
    source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")


class DataSource(Base):
    __tablename__ = "data_sources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24))  # http | dns | rdap | asn | geoip | ct | file | browser
    reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(16))  # ok | unavailable | failed | skipped
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="sources")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    format: Mapped[str] = mapped_column(String(8))  # pdf | json | csv
    variant: Mapped[str | None] = mapped_column(String(32), nullable=True)  # csv table name
    filename: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    assessment: Mapped[Assessment] = relationship(back_populates="reports")


class SchemaVersion(Base):
    __tablename__ = "schema_version"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    description: Mapped[str] = mapped_column(String(200), default="")
