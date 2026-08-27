"""Add CPE normalization fields to findings.

Revision ID: 20260521_0002
Revises: 20260521_0001
Create Date: 2026-05-21 00:02:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "20260521_0002"
down_revision = "20260521_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("raw_service", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("normalized_service", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("extracted_version", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("generated_cpe", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "generated_cpe")
    op.drop_column("findings", "extracted_version")
    op.drop_column("findings", "normalized_service")
    op.drop_column("findings", "raw_service")
