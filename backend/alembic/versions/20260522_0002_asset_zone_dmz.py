"""Add DMZ to asset_zone enum.

Revision ID: 20260522_0002
Revises: 20260522_0001
Create Date: 2026-05-22 00:02:00.000000
"""
from alembic import op


revision = "20260522_0002"
down_revision = "20260522_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE asset_zone ADD VALUE IF NOT EXISTS 'dmz'")


def downgrade() -> None:
    # PostgreSQL enums cannot safely drop values without rebuild.
    pass
