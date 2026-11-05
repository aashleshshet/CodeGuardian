"""Initial immutable application schema."""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("user", sa.Column("id", sa.String(), primary_key=True), sa.Column("github_id", sa.Integer(), nullable=False, unique=True), sa.Column("login", sa.String(), nullable=False), sa.Column("encrypted_token", sa.String(), nullable=False))
    op.create_table("loginsession", sa.Column("id", sa.String(), primary_key=True), sa.Column("user_id", sa.String(), sa.ForeignKey("user.id"), nullable=False), sa.Column("csrf_token", sa.String(), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False))
    op.create_table("oauthstate", sa.Column("id", sa.String(), primary_key=True), sa.Column("verifier", sa.String(), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False))
    op.create_table("repository", sa.Column("id", sa.String(), primary_key=True), sa.Column("owner_id", sa.String(), sa.ForeignKey("user.id"), nullable=False), sa.Column("full_name", sa.String(), nullable=False), sa.Column("github_id", sa.Integer()), sa.Column("installation_id", sa.Integer()), sa.Column("branch", sa.String(), nullable=False), sa.Column("is_fixture", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False), sa.UniqueConstraint("owner_id", "full_name"))
    op.create_table("scan", sa.Column("id", sa.String(), primary_key=True), sa.Column("repository_id", sa.String(), sa.ForeignKey("repository.id"), nullable=False), sa.Column("commit_sha", sa.String(), nullable=False), sa.Column("status", sa.String(), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False), sa.Column("completed_at", sa.DateTime()), sa.Column("findings", sa.JSON()), sa.Column("files", sa.JSON()), sa.Column("coverage", sa.JSON()), sa.Column("error", sa.String()), sa.Column("baseline_id", sa.String()))
    op.create_table("review", sa.Column("id", sa.String(), primary_key=True), sa.Column("scan_id", sa.String(), sa.ForeignKey("scan.id"), nullable=False), sa.Column("fingerprint", sa.String(), nullable=False), sa.Column("owner_id", sa.String(), sa.ForeignKey("user.id"), nullable=False), sa.Column("status", sa.String(), nullable=False), sa.Column("note", sa.String(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False), sa.UniqueConstraint("scan_id", "fingerprint", "owner_id"))
    op.create_table("webhookdelivery", sa.Column("id", sa.String(), primary_key=True), sa.Column("received_at", sa.DateTime(), nullable=False))
    op.create_table("auditevent", sa.Column("id", sa.String(), primary_key=True), sa.Column("user_id", sa.String(), nullable=False), sa.Column("action", sa.String(), nullable=False), sa.Column("resource_id", sa.String(), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False))
    for table, column in [("user", "github_id"), ("loginsession", "user_id"), ("repository", "owner_id"), ("scan", "repository_id"), ("review", "scan_id"), ("auditevent", "user_id")]:
        op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    for table in ["auditevent", "webhookdelivery", "review", "scan", "repository", "oauthstate", "loginsession", "user"]: op.drop_table(table)
