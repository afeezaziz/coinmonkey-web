"""
Initial schema for CoinMonkey app

Revision ID: 0001
Revises: 
Create Date: 2025-09-24 15:58:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # agents
    op.create_table(
        'agents',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('strategy', sa.String(length=64), nullable=False, server_default=sa.text("'custom'")),
        sa.Column('status', sa.String(length=32), nullable=False, server_default=sa.text("'stopped'")),
        sa.Column('config', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default=sa.text("'admin'")),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('email', name='uq_users_email'),
    )

    # alerts
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('agent_id', sa.String(length=36), sa.ForeignKey('agents.id'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=sa.text("''")),
        sa.Column('metric', sa.String(length=128), nullable=False),
        sa.Column('labels_json', sa.Text(), nullable=False),
        sa.Column('operator', sa.String(length=8), nullable=False),
        sa.Column('threshold', sa.Float(), nullable=False),
        sa.Column('webhook_url', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_fired_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # credentials
    op.create_table(
        'credentials',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('agent_id', sa.String(length=36), sa.ForeignKey('agents.id'), nullable=False),
        sa.Column('ctype', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=sa.text("'default'")),
        sa.Column('data_encrypted', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # alert_events
    op.create_table(
        'alert_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('agent_id', sa.String(length=36), sa.ForeignKey('agents.id'), nullable=False),
        sa.Column('alert_id', sa.String(length=36), sa.ForeignKey('alerts.id'), nullable=False),
        sa.Column('metric', sa.String(length=128), nullable=False),
        sa.Column('labels_json', sa.Text(), nullable=True),
        sa.Column('value', sa.Float(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('fired_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # alert_cooldowns
    op.create_table(
        'alert_cooldowns',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('alert_id', sa.String(length=36), sa.ForeignKey('alerts.id'), nullable=False),
        sa.Column('label_key', sa.Text(), nullable=False),
        sa.Column('next_allowed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('alert_id', 'label_key', name='uq_alert_label'),
    )


def downgrade() -> None:
    op.drop_table('alert_cooldowns')
    op.drop_table('alert_events')
    op.drop_table('credentials')
    op.drop_table('alerts')
    op.drop_table('users')
    op.drop_table('agents')
