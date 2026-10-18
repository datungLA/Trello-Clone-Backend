CREATE TABLE users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL, display_name text NOT NULL,
 password_hash text NOT NULL, token_version integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE refresh_tokens (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 family_id uuid NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz,
 revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user ON refresh_tokens(user_id);
CREATE TABLE password_resets (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE workspaces (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE memberships (
 workspace_id uuid REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id uuid REFERENCES users(id) ON DELETE CASCADE,
 role text NOT NULL CHECK (role IN ('owner','member')), PRIMARY KEY(workspace_id,user_id)
);
CREATE TABLE invitations (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 email text NOT NULL, token_hash text UNIQUE NOT NULL,
 expires_at timestamptz NOT NULL, accepted_at timestamptz, revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE boards (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 title text NOT NULL, color text NOT NULL DEFAULT '#0079bf', closed boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE board_preferences (
 board_id uuid REFERENCES boards(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE CASCADE,
 favorite boolean NOT NULL DEFAULT false, last_opened_at timestamptz, PRIMARY KEY(board_id,user_id)
);
CREATE TABLE lists (
 id uuid PRIMARY KEY, board_id uuid NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
 title text NOT NULL, position integer NOT NULL CHECK(position>=0), archived boolean NOT NULL DEFAULT false
);
CREATE INDEX lists_board ON lists(board_id,position);
CREATE TABLE cards (
 id uuid PRIMARY KEY, list_id uuid NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
 title text NOT NULL, description text NOT NULL DEFAULT '', position integer NOT NULL CHECK(position>=0),
 archived boolean NOT NULL DEFAULT false
);
CREATE INDEX cards_list ON cards(list_id,position);
