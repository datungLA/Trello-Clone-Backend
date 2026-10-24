ALTER TABLE users ADD COLUMN is_admin boolean NOT NULL DEFAULT false,
 ADD COLUMN suspended_at timestamptz;
ALTER TABLE workspaces ADD COLUMN archived boolean NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ADD COLUMN user_agent text NOT NULL DEFAULT 'Unknown device';
CREATE INDEX refresh_tokens_session ON refresh_tokens(user_id,family_id,created_at);
CREATE TABLE admin_audit (
 id uuid PRIMARY KEY, actor_id uuid REFERENCES users(id), action text NOT NULL,
 target_type text NOT NULL, target_id uuid NOT NULL, details jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX admin_audit_created ON admin_audit(created_at DESC,id);
CREATE INDEX admin_audit_actor ON admin_audit(actor_id,created_at DESC);
