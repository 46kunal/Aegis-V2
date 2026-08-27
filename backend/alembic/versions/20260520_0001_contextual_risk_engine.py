"""Contextual risk engine: asset exposure, risk_score, finding is_kev, kev_catalog table

Revision ID: 20260520_0001
Revises: 20260519_0001
Create Date: 2026-05-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260520_0001"
down_revision = "20260519_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Asset exposure classification
    op.execute("CREATE TYPE asset_exposure AS ENUM ('internal', 'external', 'segmented', 'isolated')")
    op.add_column(
        "assets",
        sa.Column(
            "exposure",
            sa.Enum("internal", "external", "segmented", "isolated", name="asset_exposure"),
            nullable=False,
            server_default="internal",
        ),
    )
    op.create_index("ix_assets_exposure", "assets", ["exposure"], unique=False)

    # Stored contextual risk score (0-100) — updated after each scan
    op.add_column("assets", sa.Column("risk_score", sa.Float(), nullable=True))
    op.create_index("ix_assets_risk_score", "assets", ["risk_score"], unique=False)

    # KEV flag on findings
    op.add_column(
        "findings",
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_findings_is_kev", "findings", ["is_kev"], unique=False)

    # CISA KEV catalog cache table
    op.create_table(
        "kev_catalog",
        sa.Column("cve_id", sa.String(length=40), nullable=False),
        sa.Column("vulnerability_name", sa.String(length=512), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_index("ix_kev_catalog_date_added", "kev_catalog", ["date_added"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_kev_catalog_date_added", table_name="kev_catalog")
    op.drop_table("kev_catalog")
    op.drop_index("ix_findings_is_kev", table_name="findings")
    op.drop_column("findings", "is_kev")
    op.drop_index("ix_assets_risk_score", table_name="assets")
    op.drop_column("assets", "risk_score")
    op.drop_index("ix_assets_exposure", table_name="assets")
    op.drop_column("assets", "exposure")
    op.execute("DROP TYPE asset_exposure")
