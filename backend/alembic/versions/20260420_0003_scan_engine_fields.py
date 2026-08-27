"""Add scan engine fields

Revision ID: 20260420_0003
Revises: 20260420_0002
Create Date: 2026-04-20 01:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260420_0003"
down_revision = "20260420_0002"
branch_labels = None
depends_on = None


scan_mode = sa.Enum("fast", "medium", "full", name="scan_mode")


def upgrade() -> None:
    bind = op.get_bind()
    scan_mode.create(bind, checkfirst=True)

    op.add_column("scans", sa.Column("mode", scan_mode, nullable=False, server_default="fast"))
    op.add_column("scans", sa.Column("progress", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("celery_task_id", sa.String(length=255), nullable=True))
    op.add_column("scans", sa.Column("raw_xml", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("error_message", sa.Text(), nullable=True))

    op.create_index("ix_scans_mode", "scans", ["mode"], unique=False)

    op.alter_column("scans", "mode", server_default=None)
    op.alter_column("scans", "progress", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_scans_mode", table_name="scans")

    op.drop_column("scans", "error_message")
    op.drop_column("scans", "raw_xml")
    op.drop_column("scans", "celery_task_id")
    op.drop_column("scans", "progress")
    op.drop_column("scans", "mode")

    bind = op.get_bind()
    scan_mode.drop(bind, checkfirst=True)
