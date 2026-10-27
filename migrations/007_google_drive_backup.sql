CREATE TABLE backup_settings (
  id boolean PRIMARY KEY DEFAULT true CHECK(id),
  namespace uuid NOT NULL DEFAULT gen_random_uuid(),
  enabled boolean NOT NULL DEFAULT false,
  schedule jsonb NOT NULL DEFAULT '{"frequency":"daily","hour":2,"minute":0,"dayOfWeek":0,"timezone":"America/Los_Angeles"}',
  retention_count integer NOT NULL DEFAULT 7 CHECK(retention_count BETWEEN 1 AND 30),
  scope_db boolean NOT NULL DEFAULT true,
  scope_configs boolean NOT NULL DEFAULT true,
  remote_folder text NOT NULL DEFAULT 'Trello Clone Backups',
  folder_id text,
  token_ciphertext text,
  account_email text NOT NULL DEFAULT '',
  last_slot text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO backup_settings(id) VALUES(true);
CREATE TABLE backup_runs (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK(kind IN('manual','scheduled')),
  status text NOT NULL CHECK(status IN('pending','running','success','failed')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  heartbeat_at timestamptz NOT NULL DEFAULT now(),
  size_bytes bigint NOT NULL DEFAULT 0,
  checksum text NOT NULL DEFAULT '',
  verified_at timestamptz,
  error text NOT NULL DEFAULT '',
  remote_path text NOT NULL DEFAULT '',
  scope_db boolean NOT NULL,
  scope_configs boolean NOT NULL,
  triggered_by uuid REFERENCES users(id) ON DELETE SET NULL,
  settings jsonb NOT NULL
);
CREATE UNIQUE INDEX backup_single_active ON backup_runs((true)) WHERE status IN('pending','running');
CREATE INDEX backup_runs_recent ON backup_runs(started_at DESC,id);
