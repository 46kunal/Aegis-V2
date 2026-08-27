"""Attack engine fields: exploitability_score, technique_id, technique_name on asset_edges

Revision ID: 20260520_0003
Revises: 20260520_0002
Create Date: 2026-05-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260520_0003"
down_revision = "20260520_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_edges", sa.Column("exploitability_score", sa.Float(), nullable=True))
    op.add_column("asset_edges", sa.Column("technique_id",         sa.String(length=20),  nullable=True))
    op.add_column("asset_edges", sa.Column("technique_name",       sa.String(length=128), nullable=True))
    op.create_index("ix_asset_edges_technique_id", "asset_edges", ["technique_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_asset_edges_technique_id", table_name="asset_edges")
    op.drop_column("asset_edges", "technique_name")
    op.drop_column("asset_edges", "technique_id")
    op.drop_column("asset_edges", "exploitability_score")
