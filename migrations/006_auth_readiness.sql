ALTER TABLE users ADD COLUMN email_verified_at timestamptz,
 ADD COLUMN app_role text NOT NULL DEFAULT 'user' CHECK (app_role IN ('user','admin','super_admin'));
-- Existing learning accounts are explicitly grandfathered; new registrations require proof.
UPDATE users SET email_verified_at=now(),app_role=CASE WHEN is_admin THEN 'admin' ELSE 'user' END;
CREATE TABLE email_verifications (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE INDEX email_verifications_user ON email_verifications(user_id);
CREATE TABLE auth_audit (
 id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action text NOT NULL, outcome text NOT NULL, identifier_hash text, ip_hash text,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_audit_created ON auth_audit(created_at DESC);
CREATE TABLE bootstrap_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 completed_at timestamptz
);
INSERT INTO bootstrap_state(singleton,completed_at)
VALUES(true,CASE WHEN EXISTS(SELECT 1 FROM users WHERE is_admin) THEN now() ELSE NULL END);
CREATE FUNCTION protect_bootstrap_latch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at) THEN
  RAISE EXCEPTION 'Bootstrap latch is immutable once closed';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER bootstrap_latch BEFORE UPDATE OR DELETE ON bootstrap_state
FOR EACH ROW EXECUTE FUNCTION protect_bootstrap_latch();
