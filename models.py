from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, String, Text, create_engine, func, ForeignKey, Float
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
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)
    ctype: Mapped[str] = mapped_column(String(32))  # evm_rpc | cex
    name: Mapped[str] = mapped_column(String(255), default="default")
    data_encrypted: Mapped[str] = mapped_column(Text)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())

# SQLite database in project root for simplicity
_engine = create_engine("sqlite:///agents.db", echo=False, future=True)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(_engine)


def new_agent_id() -> str:
    return str(uuid.uuid4())
