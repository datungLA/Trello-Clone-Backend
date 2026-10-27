CREATE TABLE inbox_items (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
 description text NOT NULL DEFAULT '' CHECK(length(description)<=10000),
 position integer NOT NULL CHECK(position>=0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 converted_at timestamptz,
 converted_card_id uuid REFERENCES cards(id) ON DELETE SET NULL,
 conversion_list_id uuid REFERENCES lists(id) ON DELETE SET NULL
);
CREATE INDEX inbox_active_owner ON inbox_items(user_id,position,id) WHERE converted_at IS NULL;
