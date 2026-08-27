"""Add cwe_id to findings; index cve_cache.updated_at for cache expiry queries

Revision ID: 20260519_0001
Revises: 77bda52ebdd8
Create Date: 2026-05-19 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260519_0001"
down_revision = "77bda52ebdd8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CWE weakness classification for each finding
    op.add_column("findings", sa.Column("cwe_id", sa.String(length=32), nullable=True))
    op.create_index("ix_findings_cwe_id", "findings", ["cwe_id"], unique=False)

    # Speed up the 7-day cache-expiry query: WHERE updated_at < now() - interval '7 days'
    op.create_index("ix_cve_cache_updated_at", "cve_cache", ["updated_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cve_cache_updated_at", table_name="cve_cache")
    op.drop_index("ix_findings_cwe_id", table_name="findings")
    op.drop_column("findings", "cwe_id")
