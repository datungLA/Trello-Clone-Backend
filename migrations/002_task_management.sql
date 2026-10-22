ALTER TABLE lists ADD COLUMN wip_limit integer CHECK(wip_limit>0 AND wip_limit<=10000);
ALTER TABLE cards ADD COLUMN label_ids uuid[] NOT NULL DEFAULT '{}',
 ADD COLUMN assignee_ids uuid[] NOT NULL DEFAULT '{}', ADD COLUMN cover_color text,
 ADD COLUMN start_date timestamptz, ADD COLUMN due_date timestamptz,
 ADD COLUMN completed boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT card_date_order CHECK(start_date IS NULL OR due_date IS NULL OR start_date<=due_date);
CREATE TABLE labels(id uuid PRIMARY KEY, board_id uuid NOT NULL REFERENCES boards(id) ON DELETE CASCADE, name text NOT NULL, color text NOT NULL);
CREATE INDEX labels_board ON labels(board_id);
CREATE TABLE checklists(id uuid PRIMARY KEY, card_id uuid NOT NULL REFERENCES cards(id) ON DELETE CASCADE, title text NOT NULL, position integer NOT NULL);
CREATE INDEX checklists_card ON checklists(card_id);
CREATE TABLE checklist_items(id uuid PRIMARY KEY, checklist_id uuid NOT NULL REFERENCES checklists(id) ON DELETE CASCADE, title text NOT NULL, completed boolean NOT NULL DEFAULT false, position integer NOT NULL);
CREATE INDEX checklist_items_parent ON checklist_items(checklist_id,position);
CREATE TABLE comments(id uuid PRIMARY KEY, card_id uuid NOT NULL REFERENCES cards(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id), body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX comments_card ON comments(card_id,created_at);
CREATE TABLE activity(id uuid PRIMARY KEY, board_id uuid NOT NULL REFERENCES boards(id) ON DELETE CASCADE, card_id uuid REFERENCES cards(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id), action text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX activity_card ON activity(card_id,created_at);
CREATE TABLE saved_views(id uuid PRIMARY KEY, board_id uuid NOT NULL REFERENCES boards(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, name text NOT NULL, filters jsonb NOT NULL);
CREATE INDEX saved_views_scope ON saved_views(board_id,user_id);
CREATE TABLE workspace_activity(id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id), action text NOT NULL, target_id uuid, created_at timestamptz NOT NULL DEFAULT now());
