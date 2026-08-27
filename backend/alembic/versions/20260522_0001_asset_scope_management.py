"""Add asset scope management fields.

Revision ID: 20260522_0001
Revises: 20260521_0002
Create Date: 2026-05-22 00:01:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "20260522_0001"
down_revision = "20260521_0002"
branch_labels = None
depends_on = None


_ASSET_ZONE_ENUM = "asset_zone"


def upgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_zone') THEN "
        "CREATE TYPE asset_zone AS ENUM ('lab','internal','external','infrastructure','unknown'); "
        "END IF; END$$;"
    )

    op.add_column("assets", sa.Column("managed", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column(
        "assets",
        sa.Column(
            "asset_zone",
            sa.Enum(
                "lab",
                "internal",
                "external",
                "infrastructure",
                "unknown",
                name=_ASSET_ZONE_ENUM,
            ),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column("assets", sa.Column("topology_visible", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("assets", sa.Column("attack_surface_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))

    op.create_index("ix_assets_managed", "assets", ["managed"])
    op.create_index("ix_assets_asset_zone", "assets", ["asset_zone"])
    op.create_index("ix_assets_topology_visible", "assets", ["topology_visible"])


def downgrade() -> None:
    op.drop_index("ix_assets_topology_visible", table_name="assets")
    op.drop_index("ix_assets_asset_zone", table_name="assets")
    op.drop_index("ix_assets_managed", table_name="assets")

    op.drop_column("assets", "attack_surface_enabled")
    op.drop_column("assets", "topology_visible")
    op.drop_column("assets", "asset_zone")
    op.drop_column("assets", "managed")

    op.execute("DROP TYPE IF EXISTS asset_zone")
