"""Initial Aegis V2 schema

Revision ID: 20260420_0001
Revises:
Create Date: 2026-04-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260420_0001"
down_revision = None
branch_labels = None
depends_on = None


user_role = postgresql.ENUM("admin", "user", name="user_role", create_type=False)
asset_type = postgresql.ENUM("host", "domain", "ip", "webapp", "cloud", "api", name="asset_type", create_type=False)
asset_status = postgresql.ENUM("active", "inactive", "retired", name="asset_status", create_type=False)
asset_criticality = postgresql.ENUM("low", "medium", "high", "critical", name="asset_criticality", create_type=False)
scan_type = postgresql.ENUM("baseline", "network", "web", "config", "compliance", name="scan_type", create_type=False)
scan_status = postgresql.ENUM("queued", "running", "completed", "failed", "cancelled", name="scan_status", create_type=False)
finding_severity = postgresql.ENUM("info", "low", "medium", "high", "critical", name="finding_severity", create_type=False)
finding_status = postgresql.ENUM("open", "in_progress", "resolved", "false_positive", name="finding_status", create_type=False)
report_type = postgresql.ENUM("executive", "technical", "compliance", "incident", name="report_type", create_type=False)
report_status = postgresql.ENUM("pending", "ready", "failed", name="report_status", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    user_role.create(bind, checkfirst=True)
    asset_type.create(bind, checkfirst=True)
    asset_status.create(bind, checkfirst=True)
    asset_criticality.create(bind, checkfirst=True)
    scan_type.create(bind, checkfirst=True)
    scan_status.create(bind, checkfirst=True)
    finding_severity.create(bind, checkfirst=True)
    finding_status.create(bind, checkfirst=True)
    report_type.create(bind, checkfirst=True)
    report_status.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_index("ix_users_role", "users", ["role"], unique=False)
    op.create_index("ix_users_is_active", "users", ["is_active"], unique=False)

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("status", asset_status, nullable=False),
        sa.Column("criticality", asset_criticality, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_assets_owner_id", "assets", ["owner_id"], unique=False)
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"], unique=False)
    op.create_index("ix_assets_status", "assets", ["status"], unique=False)
    op.create_index("ix_assets_criticality", "assets", ["criticality"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scan_type", scan_type, nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_scans_asset_id", "scans", ["asset_id"], unique=False)
    op.create_index("ix_scans_requested_by_id", "scans", ["requested_by_id"], unique=False)
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)
    op.create_index("ix_scans_created_at", "scans", ["created_at"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("cve_id", sa.String(length=40), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("ix_findings_status", "findings", ["status"], unique=False)

    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("generated_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("report_type", report_type, nullable=False),
        sa.Column("status", report_status, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(length=128), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["generated_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_reports_generated_by_id", "reports", ["generated_by_id"], unique=False)
    op.create_index("ix_reports_asset_id", "reports", ["asset_id"], unique=False)
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"], unique=False)
    op.create_index("ix_reports_status", "reports", ["status"], unique=False)
    op.create_index("ix_reports_created_at", "reports", ["created_at"], unique=False)

    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False)
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_reports_created_at", table_name="reports")
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index("ix_reports_scan_id", table_name="reports")
    op.drop_index("ix_reports_asset_id", table_name="reports")
    op.drop_index("ix_reports_generated_by_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_requested_by_id", table_name="scans")
    op.drop_index("ix_scans_asset_id", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_index("ix_assets_status", table_name="assets")
    op.drop_index("ix_assets_asset_type", table_name="assets")
    op.drop_index("ix_assets_owner_id", table_name="assets")
    op.drop_table("assets")

    op.drop_index("ix_users_is_active", table_name="users")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    bind = op.get_bind()
    report_status.drop(bind, checkfirst=True)
    report_type.drop(bind, checkfirst=True)
    finding_status.drop(bind, checkfirst=True)
    finding_severity.drop(bind, checkfirst=True)
    scan_status.drop(bind, checkfirst=True)
    scan_type.drop(bind, checkfirst=True)
    asset_criticality.drop(bind, checkfirst=True)
    asset_status.drop(bind, checkfirst=True)
    asset_type.drop(bind, checkfirst=True)
    user_role.drop(bind, checkfirst=True)
