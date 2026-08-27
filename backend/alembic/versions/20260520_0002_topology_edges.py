"""Digital twin topology: asset_edges relationship graph table

Revision ID: 20260520_0002
Revises: 20260520_0001
Create Date: 2026-05-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260520_0002"
down_revision = "20260520_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relationship", sa.String(length=48), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("inferred_from", sa.String(length=64), nullable=True),
        sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_id", "target_id", "relationship", name="uq_asset_edges_src_tgt_rel"),
    )
    op.create_index("ix_asset_edges_owner_id",    "asset_edges", ["owner_id"],    unique=False)
    op.create_index("ix_asset_edges_source_id",   "asset_edges", ["source_id"],   unique=False)
    op.create_index("ix_asset_edges_target_id",   "asset_edges", ["target_id"],   unique=False)
    op.create_index("ix_asset_edges_relationship","asset_edges", ["relationship"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_asset_edges_relationship", table_name="asset_edges")
    op.drop_index("ix_asset_edges_target_id",    table_name="asset_edges")
    op.drop_index("ix_asset_edges_source_id",    table_name="asset_edges")
    op.drop_index("ix_asset_edges_owner_id",     table_name="asset_edges")
    op.drop_table("asset_edges")
