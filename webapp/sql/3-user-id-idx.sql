use isuconp;
ALTER TABLE posts ADD INDEX user_id_idx (user_id, created_at DESC);