-- VisionGuard Supabase schema bootstrap

CREATE TABLE IF NOT EXISTS users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uniq ON users ((lower(username)));

CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_user_exp_idx ON auth_sessions (user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS auth_sessions_exp_idx ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  video_name TEXT NOT NULL,
  video_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  total_frames INT NOT NULL DEFAULT 0,
  total_detections INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT sessions_status_chk CHECK (status IN ('pending','processing','completed','error'))
);
CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS sessions_user_status_idx ON sessions (user_id, status);

CREATE TABLE IF NOT EXISTS detections (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  frame_number INT,
  class_name TEXT,
  confidence NUMERIC(6,4),
  x1 NUMERIC(10,2),
  y1 NUMERIC(10,2),
  x2 NUMERIC(10,2),
  y2 NUMERIC(10,2),
  timestamp_sec NUMERIC(12,3),
  thumbnail TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS detections_session_frame_idx ON detections (session_id, frame_number);
CREATE INDEX IF NOT EXISTS detections_user_created_idx ON detections (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS detections_user_class_idx ON detections (user_id, class_name);

CREATE TABLE IF NOT EXISTS settings (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
);
