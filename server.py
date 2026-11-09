"""Chat server: username/password auth, 1:1 + group chats, read receipts, image sharing.

Run:  python3 server.py            (listens on 0.0.0.0:5000)
Env:  CHAT_DB, CHAT_UPLOADS, PORT
"""
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request, send_from_directory, abort
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("CHAT_DB", os.path.join(BASE, "chat.db"))
UPLOAD_DIR = os.environ.get("CHAT_UPLOADS", os.path.join(BASE, "uploads"))
MAX_IMAGE_BYTES = 5 * 1024 * 1024
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

app = Flask(__name__, static_folder=os.path.join(BASE, "static"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + 512 * 1024
os.makedirs(UPLOAD_DIR, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash TEXT NOT NULL,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chats(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('dm','group')),
  name TEXT,
  dm_key TEXT UNIQUE,
  created_by INTEGER REFERENCES users(id),
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS members(
  chat_id INTEGER NOT NULL REFERENCES chats(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  last_read INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL REFERENCES chats(id),
  sender_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT,
  image TEXT,
  created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id, id);
CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ---------- helpers ----------
_attempts = defaultdict(deque)


def rate_limited(key, limit=10, window=60):
    now = time.time()
    q = _attempts[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def err(msg, code=400):
    return jsonify({"error": msg}), code


def current_user():
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    token = token or request.args.get("token")
    if not token:
        return None
    return db().execute(
        "SELECT u.id, u.username FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,),
    ).fetchone()


def require_auth(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*a, **kw):
        user = current_user()
        if not user:
            return err("unauthorized", 401)
        g.user = user
        return fn(*a, **kw)

    return wrapper


def is_member(chat_id, user_id):
    return db().execute(
        "SELECT 1 FROM members WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone() is not None


def new_token(user_id):
    token = secrets.token_urlsafe(32)
    db().execute("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)", (token, user_id, time.time()))
    db().commit()
    return token


def detect_image_ext(head):
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def message_dict(row, members):
    """members: list of (user_id, last_read) excluding the sender."""
    others = [lr for uid, lr in members if uid != row["sender_id"]]
    read_by = sum(1 for lr in others if lr >= row["id"])
    return {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "sender_id": row["sender_id"],
        "sender": row["sender"],
        "body": row["body"],
        "image": f"/uploads/{row['image']}" if row["image"] else None,
        "created": row["created"],
        "read_by": read_by,
        "recipients": len(others),
    }


# ---------- auth ----------
@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if rate_limited("reg:" + (request.remote_addr or ""), 20, 3600):
        return err("too many attempts, try later", 429)
    if not USERNAME_RE.match(username):
        return err("username must be 3-20 letters, numbers or underscore")
    if len(password) < 6 or len(password) > 128:
        return err("password must be 6-128 characters")
    try:
        cur = db().execute(
            "INSERT INTO users(username,pw_hash,created) VALUES(?,?,?)",
            (username, generate_password_hash(password), time.time()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return err("username already taken", 409)
    return jsonify({"token": new_token(cur.lastrowid), "user": {"id": cur.lastrowid, "username": username}})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if rate_limited("login:" + username.lower() + (request.remote_addr or ""), 8, 300):
        return err("too many attempts, try again in a few minutes", 429)
    row = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], password):
        return err("invalid username or password", 401)
    return jsonify({"token": new_token(row["id"]), "user": {"id": row["id"], "username": row["username"]}})


@app.post("/api/logout")
@require_auth
def logout():
    token = request.headers.get("Authorization", "")[7:] or request.args.get("token")
    db().execute("DELETE FROM tokens WHERE token=?", (token,))
    db().commit()
    return jsonify({"ok": True})


@app.get("/api/me")
@require_auth
def me():
    return jsonify({"id": g.user["id"], "username": g.user["username"]})


@app.get("/api/users")
@require_auth
def search_users():
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return jsonify([])
    like = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = db().execute(
        "SELECT id, username FROM users WHERE username LIKE ? ESCAPE '\\' AND id<>? ORDER BY username LIMIT 20",
        (like, g.user["id"]),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------- chats ----------
def chat_summary(chat_id, me_id):
    d = db()
    chat = d.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
    members = d.execute(
        "SELECT u.id, u.username, m.last_read FROM members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=?",
        (chat_id,),
    ).fetchall()
    last = d.execute(
        "SELECT m.*, u.username AS sender FROM messages m JOIN users u ON u.id=m.sender_id "
        "WHERE m.chat_id=? ORDER BY m.id DESC LIMIT 1",
        (chat_id,),
    ).fetchone()
    my_last_read = next((m["last_read"] for m in members if m["id"] == me_id), 0)
    unread = d.execute(
        "SELECT COUNT(*) c FROM messages WHERE chat_id=? AND id>? AND sender_id<>?",
        (chat_id, my_last_read, me_id),
    ).fetchone()["c"]
    if chat["type"] == "dm":
        other = next((m for m in members if m["id"] != me_id), None)
        name = other["username"] if other else "Unknown"
    else:
        name = chat["name"]
    return {
        "id": chat["id"],
        "type": chat["type"],
        "name": name,
        "members": [{"id": m["id"], "username": m["username"]} for m in members],
        "unread": unread,
        "last": None if not last else {
            "id": last["id"],
            "sender": last["sender"],
            "body": last["body"] if last["body"] else "📷 Photo",
            "created": last["created"],
        },
        "sort": last["created"] if last else chat["created"],
    }


@app.get("/api/chats")
@require_auth
def list_chats():
    ids = [r["chat_id"] for r in db().execute(
        "SELECT chat_id FROM members WHERE user_id=?", (g.user["id"],)).fetchall()]
    chats = [chat_summary(i, g.user["id"]) for i in ids]
    chats.sort(key=lambda c: c["sort"], reverse=True)
    return jsonify(chats)


@app.post("/api/chats/dm")
@require_auth
def create_dm():
    data = request.get_json(silent=True) or {}
    other = db().execute("SELECT id FROM users WHERE username=?", ((data.get("username") or "").strip(),)).fetchone()
    if not other:
        return err("user not found", 404)
    if other["id"] == g.user["id"]:
        return err("you cannot chat with yourself")
    a, b = sorted([g.user["id"], other["id"]])
    key = f"{a}:{b}"
    d = db()
    row = d.execute("SELECT id FROM chats WHERE dm_key=?", (key,)).fetchone()
    if not row:
        cur = d.execute(
            "INSERT INTO chats(type,dm_key,created_by,created) VALUES('dm',?,?,?)",
            (key, g.user["id"], time.time()),
        )
        cid = cur.lastrowid
        d.executemany("INSERT INTO members(chat_id,user_id) VALUES(?,?)", [(cid, a), (cid, b)])
        d.commit()
    else:
        cid = row["id"]
    return jsonify(chat_summary(cid, g.user["id"]))


@app.post("/api/chats/group")
@require_auth
def create_group():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    usernames = data.get("usernames") or []
    if not name or len(name) > 40:
        return err("group name required (max 40 characters)")
    if not isinstance(usernames, list) or not usernames or len(usernames) > 99:
        return err("add at least one member (max 99)")
    d = db()
    ids = {g.user["id"]}
    for u in usernames:
        row = d.execute("SELECT id FROM users WHERE username=?", (str(u).strip(),)).fetchone()
        if not row:
            return err(f"user not found: {u}", 404)
        ids.add(row["id"])
    if len(ids) < 2:
        return err("add at least one other member")
    cur = d.execute(
        "INSERT INTO chats(type,name,created_by,created) VALUES('group',?,?,?)",
        (name, g.user["id"], time.time()),
    )
    cid = cur.lastrowid
    d.executemany("INSERT INTO members(chat_id,user_id) VALUES(?,?)", [(cid, i) for i in ids])
    d.commit()
    return jsonify(chat_summary(cid, g.user["id"]))


@app.get("/api/chats/<int:chat_id>/messages")
@require_auth
def get_messages(chat_id):
    if not is_member(chat_id, g.user["id"]):
        return err("not a member of this chat", 403)
    after = request.args.get("after", type=int, default=0)
    d = db()
    rows = d.execute(
        "SELECT * FROM (SELECT m.*, u.username AS sender FROM messages m JOIN users u ON u.id=m.sender_id "
        "WHERE m.chat_id=? AND m.id>? ORDER BY m.id DESC LIMIT 100) ORDER BY id ASC",
        (chat_id, after),
    ).fetchall()
    members = [(r["user_id"], r["last_read"]) for r in d.execute(
        "SELECT user_id, last_read FROM members WHERE chat_id=?", (chat_id,)).fetchall()]
    # read-receipt state for the caller's own messages (so ticks update on old messages too)
    my_msgs = d.execute(
        "SELECT id FROM messages WHERE chat_id=? AND sender_id=? ORDER BY id DESC LIMIT 100",
        (chat_id, g.user["id"]),
    ).fetchall()
    receipts = {}
    for r in my_msgs:
        others = [lr for uid, lr in members if uid != g.user["id"]]
        receipts[r["id"]] = sum(1 for lr in others if lr >= r["id"])
    return jsonify({
        "messages": [message_dict(r, members) for r in rows],
        "receipts": receipts,
        "members": [{"id": m["id"], "username": m["username"]} for m in d.execute(
            "SELECT u.id, u.username FROM members mm JOIN users u ON u.id=mm.user_id WHERE mm.chat_id=?",
            (chat_id,)).fetchall()],
    })


@app.post("/api/chats/<int:chat_id>/messages")
@require_auth
def send_message(chat_id):
    if not is_member(chat_id, g.user["id"]):
        return err("not a member of this chat", 403)
    d = db()
    body, image_name = "", None
    if request.files.get("image"):
        f = request.files["image"]
        data = f.read(MAX_IMAGE_BYTES + 1)
        if len(data) > MAX_IMAGE_BYTES:
            return err("image too large (max 5 MB)", 413)
        ext = detect_image_ext(data[:16])
        if not ext:
            return err("unsupported image type (use PNG, JPG, GIF or WebP)", 415)
        image_name = f"{secrets.token_hex(16)}.{ext}"
        with open(os.path.join(UPLOAD_DIR, image_name), "wb") as out:
            out.write(data)
        body = (request.form.get("body") or "").strip()
    else:
        payload = request.get_json(silent=True) or {}
        body = (payload.get("body") or request.form.get("body") or "").strip()
    if not body and not image_name:
        return err("empty message")
    if len(body) > 4000:
        return err("message too long (max 4000 characters)")
    cur = d.execute(
        "INSERT INTO messages(chat_id,sender_id,body,image,created) VALUES(?,?,?,?,?)",
        (chat_id, g.user["id"], body or None, image_name, time.time()),
    )
    # sender has implicitly read everything up to their own message
    d.execute("UPDATE members SET last_read=MAX(last_read,?) WHERE chat_id=? AND user_id=?",
              (cur.lastrowid, chat_id, g.user["id"]))
    d.commit()
    row = d.execute(
        "SELECT m.*, u.username AS sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?",
        (cur.lastrowid,),
    ).fetchone()
    members = [(r["user_id"], r["last_read"]) for r in d.execute(
        "SELECT user_id, last_read FROM members WHERE chat_id=?", (chat_id,)).fetchall()]
    return jsonify(message_dict(row, members)), 201


@app.post("/api/chats/<int:chat_id>/read")
@require_auth
def mark_read(chat_id):
    if not is_member(chat_id, g.user["id"]):
        return err("not a member of this chat", 403)
    d = db()
    latest = d.execute("SELECT COALESCE(MAX(id),0) m FROM messages WHERE chat_id=?", (chat_id,)).fetchone()["m"]
    d.execute("UPDATE members SET last_read=MAX(last_read,?) WHERE chat_id=? AND user_id=?",
              (latest, chat_id, g.user["id"]))
    d.commit()
    return jsonify({"ok": True, "last_read": latest})


# ---------- images ----------
@app.get("/uploads/<name>")
def uploads(name):
    user = current_user()
    if not user:
        abort(401)
    if not re.fullmatch(r"[0-9a-f]{32}\.(png|jpg|gif|webp)", name):
        abort(404)
    allowed = db().execute(
        "SELECT 1 FROM messages m JOIN members mm ON mm.chat_id=m.chat_id "
        "WHERE m.image=? AND mm.user_id=?", (name, user["id"])).fetchone()
    if not allowed:
        abort(403)
    resp = send_from_directory(UPLOAD_DIR, name)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.after_request
def headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
