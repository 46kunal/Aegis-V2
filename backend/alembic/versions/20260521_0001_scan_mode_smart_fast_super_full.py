"""Add smart_fast and super_full to scan_mode enum.

Revision ID: 20260521_0001
Revises: 20260520_0003_attack_engine_fields
Create Date: 2026-05-21 00:01:00.000000
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "20260521_0001"
down_revision = "20260520_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE scan_mode ADD VALUE IF NOT EXISTS 'smart_fast'")
    op.execute("ALTER TYPE scan_mode ADD VALUE IF NOT EXISTS 'super_full'")


def downgrade() -> None:
    # PostgreSQL enums cannot drop values safely without a rebuild.
    pass
