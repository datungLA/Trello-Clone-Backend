CREATE TABLE planner_blocks (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
 notes text NOT NULL DEFAULT '' CHECK(length(notes)<=10000),
 starts_at timestamptz NOT NULL,
 ends_at timestamptz NOT NULL,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 deleted_at timestamptz,
 CHECK(ends_at>=starts_at+interval '1 minute' AND ends_at<=starts_at+interval '24 hours')
);
CREATE INDEX planner_active_owner_time ON planner_blocks(user_id,starts_at,id) WHERE deleted_at IS NULL;
