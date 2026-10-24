CREATE TABLE notifications (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
 card_id uuid NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('assigned','comment')),
 read_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user_created ON notifications(user_id,created_at DESC,id);
