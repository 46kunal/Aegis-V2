"""Add CVSS score to findings

Revision ID: 20260420_0004
Revises: 20260420_0003
Create Date: 2026-04-20 01:20:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260420_0004"
down_revision = "20260420_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("cvss_score", sa.Numeric(precision=4, scale=1), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "cvss_score")
