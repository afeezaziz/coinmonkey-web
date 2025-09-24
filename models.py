from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, String, Text, create_engine, func, ForeignKey, Float, Boolean, text, Integer, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    strategy: Mapped[str] = mapped_column(String(64), default="custom")
    status: Mapped[str] = mapped_column(String(32), default="stopped")
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin")  # admin | operator | readonly
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertCooldown(Base):
    __tablename__ = "alert_cooldowns"
    __table_args__ = (
        UniqueConstraint('alert_id', 'label_key', name='uq_alert_label'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), nullable=False)
    label_key: Mapped[str] = mapped_column(Text, nullable=False)
    next_allowed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), nullable=False)
    metric: Mapped[str] = mapped_column(String(128))
    labels_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, server_default=text("0"), default=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="")
    metric: Mapped[str] = mapped_column(String(128))  # e.g., agent_pair_last_price
    labels_json: Mapped[str] = mapped_column(Text)  # JSON dict filter for labels e.g., {"pair":"ETH/USDT","exchange":"binance"}
    operator: Mapped[str] = mapped_column(String(8))  # gt | lt
    threshold: Mapped[float] = mapped_column(Float)
    webhook_url: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("1"), default=True)
    last_fired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)
    ctype: Mapped[str] = mapped_column(String(32))  # evm_rpc | cex
    name: Mapped[str] = mapped_column(String(255), default="default")
    data_encrypted: Mapped[str] = mapped_column(Text)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())

# Database URL (default to SQLite). For production, set DATABASE_URL (e.g., postgresql+psycopg2://...)
_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///agents.db")
_engine = create_engine(_DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(_engine)


def apply_migrations() -> None:
    """Lightweight migrations for SQLite: add missing columns if needed."""
    try:
        # Only run for SQLite
        if not _DATABASE_URL.startswith("sqlite"):
            return
        with _engine.connect() as conn:
            # Check alerts table columns
            rows = conn.execute(text("PRAGMA table_info(alerts)")).fetchall()
            cols = {r[1] for r in rows} if rows else set()
            if 'enabled' not in cols:
                try:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN enabled INTEGER DEFAULT 1"))
                except Exception:
                    pass
            if 'last_fired_at' not in cols:
                try:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN last_fired_at DATETIME"))
                except Exception:
                    pass
    except Exception:
        # ignore migration failures
        pass


def new_agent_id() -> str:
    return str(uuid.uuid4())
