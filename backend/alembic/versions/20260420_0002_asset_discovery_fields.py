"""Add asset discovery fields

Revision ID: 20260420_0002
Revises: 20260420_0001
Create Date: 2026-04-20 00:30:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260420_0002"
down_revision = "20260420_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("ip_address", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("hostname", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("mac_address", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("discovery_status", sa.String(length=16), nullable=True))

    op.create_index("ix_assets_ip_address", "assets", ["ip_address"], unique=False)
    op.create_index("ix_assets_mac_address", "assets", ["mac_address"], unique=False)
    op.create_unique_constraint("uq_assets_owner_ip_address", "assets", ["owner_id", "ip_address"])


def downgrade() -> None:
    op.drop_constraint("uq_assets_owner_ip_address", "assets", type_="unique")
    op.drop_index("ix_assets_mac_address", table_name="assets")
    op.drop_index("ix_assets_ip_address", table_name="assets")

    op.drop_column("assets", "discovery_status")
    op.drop_column("assets", "mac_address")
    op.drop_column("assets", "hostname")
    op.drop_column("assets", "ip_address")
