"""Add service intelligence fields to findings and os_fingerprint to assets

Revision ID: 20260420_0005
Revises: 20260420_0004
Create Date: 2026-04-20 02:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260420_0005"
down_revision = "20260420_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Finding: structured service intelligence columns
    op.add_column("findings", sa.Column("port", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("protocol", sa.String(length=10), nullable=True))
    op.add_column("findings", sa.Column("detected_product", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("detected_version", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("cpe", sa.String(length=512), nullable=True))
    op.add_column("findings", sa.Column("script_output", sa.Text(), nullable=True))

    # Asset: OS fingerprint from nmap -O
    op.add_column("assets", sa.Column("os_fingerprint", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "os_fingerprint")
    op.drop_column("findings", "script_output")
    op.drop_column("findings", "cpe")
    op.drop_column("findings", "detected_version")
    op.drop_column("findings", "detected_product")
    op.drop_column("findings", "protocol")
    op.drop_column("findings", "port")
