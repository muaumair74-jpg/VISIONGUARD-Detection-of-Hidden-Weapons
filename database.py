import contextvars
import hashlib
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
AUTH_TOKEN_PEPPER = os.getenv("AUTH_TOKEN_PEPPER", "").strip()
DATA_BACKEND = os.getenv("DATA_BACKEND", "").strip().lower()

if DATA_BACKEND != "postgres":
    raise RuntimeError("DATA_BACKEND must be set to 'postgres' (SQLite fallback removed).")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required in strict Postgres mode.")
if not AUTH_TOKEN_PEPPER:
    raise RuntimeError("AUTH_TOKEN_PEPPER is required in strict Postgres mode.")

_request_user_id = contextvars.ContextVar("request_user_id", default=None)


def _pg_connect():
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def _normalize_username(username):
    return (username or "").strip().lower()


def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 210000)
    return f"{salt}${digest.hex()}"


def _verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        candidate = _hash_password(password, salt).split("$", 1)[1]
        return secrets.compare_digest(candidate, expected)
    except Exception:
        return False


def set_request_user(user_id):
    _request_user_id.set(int(user_id) if user_id is not None else None)


def _current_user_id():
    uid = _request_user_id.get()
    if uid is None:
        raise RuntimeError("Request user context is not set")
    return int(uid)


def _resolve_user_id(db_path=None):
    if db_path is not None and str(db_path).strip() not in {"", "None"}:
        try:
            return int(db_path)
        except (TypeError, ValueError):
            pass
    return _current_user_id()


def _token_hash(token):
    return hashlib.sha256(f"{token}{AUTH_TOKEN_PEPPER}".encode("utf-8")).hexdigest()


def init_db():
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
            """)
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uniq ON users ((lower(username)));")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS auth_sessions_user_exp_idx ON auth_sessions (user_id, expires_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS auth_sessions_exp_idx ON auth_sessions (expires_at);")
            cur.execute("""
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
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS sessions_user_created_idx ON sessions (user_id, created_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS sessions_user_status_idx ON sessions (user_id, status);")
            cur.execute("""
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
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS detections_session_frame_idx ON detections (session_id, frame_number);")
            cur.execute("CREATE INDEX IF NOT EXISTS detections_user_created_idx ON detections (user_id, created_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS detections_user_class_idx ON detections (user_id, class_name);")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (user_id, key)
                );
            """)
        conn.commit()


def get_user_db_path(user_id):
    return int(user_id)


def create_user(username, password):
    uname = _normalize_username(username)
    if len(uname) < 3 or len(password or "") < 6:
        return None
    try:
        with _pg_connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                    (uname, _hash_password(password)),
                )
                uid = cur.fetchone()["id"]
                cur.execute(
                    """INSERT INTO settings (user_id, key, value)
                       VALUES (%s, 'confidence', '0.25'),
                              (%s, 'frame_skip', '5'),
                              (%s, 'alert_sound', 'true')
                       ON CONFLICT DO NOTHING""",
                    (uid, uid, uid),
                )
            conn.commit()
        return {"id": uid, "username": uname}
    except Exception:
        return None


def authenticate_user(username, password):
    uname = _normalize_username(username)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, password_hash FROM users WHERE lower(username) = %s", (uname,))
            row = cur.fetchone()
    if not row:
        return None
    if not _verify_password(password or "", row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"]}


def create_auth_session(user_id, days=30):
    token = secrets.token_urlsafe(40)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO auth_sessions (token_hash, user_id, expires_at)
                   VALUES (%s, %s, now() + (%s || ' days')::interval)""",
                (_token_hash(token), user_id, str(days)),
            )
        conn.commit()
    return token


def get_user_from_token(token):
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT u.id, u.username
                   FROM auth_sessions s
                   JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = %s
                     AND s.revoked_at IS NULL
                     AND s.expires_at > now()""",
                (_token_hash(token),),
            )
            row = cur.fetchone()
    return dict(row) if row else None


def revoke_auth_session(token):
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE auth_sessions SET revoked_at = now() WHERE token_hash = %s", (_token_hash(token),))
        conn.commit()


def create_session(video_name, video_path, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sessions (user_id, video_name, video_path, status)
                   VALUES (%s, %s, %s, 'pending') RETURNING id""",
                (uid, video_name, video_path),
            )
            sid = cur.fetchone()["id"]
        conn.commit()
    return sid


def update_session(session_id, db_path, **kwargs):
    allowed = {"status", "total_frames", "total_detections"}
    parts, vals = [], []
    for k, v in kwargs.items():
        if k in allowed:
            parts.append(k)
            vals.append(v)
    if not parts:
        return
    uid = _resolve_user_id(db_path)
    assignments = ", ".join([f"{k} = %s" for k in parts])
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE sessions SET {assignments} WHERE id = %s AND user_id = %s", (*vals, session_id, uid))
        conn.commit()


def get_session(session_id, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM sessions WHERE id = %s AND user_id = %s", (session_id, uid))
            row = cur.fetchone()
    return dict(row) if row else None


def add_detection(session_id, frame_number, class_name, confidence,
                  x1, y1, x2, y2, timestamp_sec, db_path, thumbnail=None):
    uid = _resolve_user_id(db_path)
    conf = round(confidence, 4)
    rx1, ry1, rx2, ry2 = round(x1, 1), round(y1, 1), round(x2, 1), round(y2, 1)
    ts = round(timestamp_sec, 2)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO detections
                   (user_id, session_id, frame_number, class_name, confidence, x1, y1, x2, y2, timestamp_sec, thumbnail)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (uid, session_id, frame_number, class_name, conf, rx1, ry1, rx2, ry2, ts, thumbnail),
            )
        conn.commit()


def get_session_detections(session_id, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM detections WHERE session_id = %s AND user_id = %s ORDER BY frame_number",
                (session_id, uid),
            )
            rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_all_sessions(db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM sessions WHERE user_id = %s ORDER BY created_at DESC", (uid,))
            rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_all_alerts(db_path, limit=200):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT d.*, s.video_name
                   FROM detections d
                   JOIN sessions s ON d.session_id = s.id
                   WHERE d.user_id = %s
                   ORDER BY d.created_at DESC
                   LIMIT %s""",
                (uid, limit),
            )
            rows = cur.fetchall()
    return [dict(r) for r in rows]


def delete_alert(alert_id, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM detections WHERE id = %s AND user_id = %s", (alert_id, uid))
        conn.commit()


def delete_session(session_id, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE id = %s AND user_id = %s", (session_id, uid))
        conn.commit()


def get_stats(db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM sessions WHERE user_id = %s", (uid,))
            total_sessions = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM detections WHERE user_id = %s", (uid,))
            total_detections = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM sessions WHERE user_id = %s AND status = 'completed'", (uid,))
            completed = cur.fetchone()["c"]
            cur.execute(
                """SELECT class_name, COUNT(*) as cnt
                   FROM detections
                   WHERE user_id = %s
                   GROUP BY class_name
                   ORDER BY cnt DESC
                   LIMIT 6""",
                (uid,),
            )
            top_classes = cur.fetchall()
            cur.execute(
                "SELECT * FROM detections WHERE user_id = %s ORDER BY created_at DESC LIMIT 10",
                (uid,),
            )
            recent_detections = cur.fetchall()
    return {
        "total_sessions": total_sessions,
        "total_detections": total_detections,
        "completed_sessions": completed,
        "top_classes": [dict(r) for r in top_classes],
        "recent_detections": [dict(r) for r in recent_detections],
    }


def get_setting(key, db_path, default=None):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE user_id = %s AND key = %s", (uid, key))
            row = cur.fetchone()
    return row["value"] if row else default


def set_setting(key, value, db_path):
    uid = _resolve_user_id(db_path)
    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO settings (user_id, key, value)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value""",
                (uid, key, value),
            )
        conn.commit()
