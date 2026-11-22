#!/usr/bin/env python3
"""Question site API: sign up with a name -> answer questions -> admin reviews answers.

Backend only (JSON API). The frontend lives in ../frontend and is hosted separately.
Database: PostgreSQL (Neon) through the DATABASE_URL environment variable.

Run locally:
    pip install -r requirements.txt
    cp .env.example .env      # then fill in DATABASE_URL etc.
    python server.py          # http://127.0.0.1:8000/api/health

Environment variables:
    DATABASE_URL     Neon connection string (required)
    ADMIN_USER       admin username                      (default ADMIN)
    ADMIN_PASSWORD   admin password                      (default ADMIN555 -> CHANGE IT)
    SECRET_KEY       long random string used to sign admin tokens
    FRONTEND_ORIGIN  allowed frontend origin(s), comma separated
                     e.g. https://my-site.vercel.app      (default * = allow all)
    HOST / PORT      bind address (PORT is set by most hosts, e.g. Render)
"""
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row

BASE = os.path.dirname(os.path.abspath(__file__))


def load_dotenv(path):
    """Tiny .env loader (local development only; real env vars win)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv(os.path.join(BASE, ".env"))

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "ADMIN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ADMIN555")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in os.environ.get("FRONTEND_ORIGIN", "*").split(",") if o.strip()]
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0" if "PORT" in os.environ else "127.0.0.1")

MAX_BODY = 64 * 1024
MAX_NAME = 40
MAX_QUESTION = 500
MAX_ANSWER = 2000
ADMIN_TTL = 8 * 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS questions (
  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  text      TEXT    NOT NULL,
  required  BOOLEAN NOT NULL DEFAULT TRUE,
  position  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username     TEXT NOT NULL,
  token_hash   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  submitted_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_token ON users (token_hash);
CREATE TABLE IF NOT EXISTS answers (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  question_id   BIGINT NOT NULL,
  question_text TEXT   NOT NULL,
  answer        TEXT   NOT NULL,
  UNIQUE (user_id, question_id)
);
CREATE INDEX IF NOT EXISTS idx_answers_user ON answers (user_id);
"""

SEED_QUESTIONS = [
    ("ชื่อเล่นและอายุของคุณคือ?", True),
    ("ตอนนี้คุณทำงานหรือเรียนอะไรอยู่?", True),
    ("คุณรู้จักเว็บไซต์นี้จากที่ไหน?", True),
    ("อยากให้เพิ่มอะไรในเว็บไซต์? (เว้นว่างได้)", False),
]


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# ---------------------------------------------------------------- database
def db():
    # autocommit=True: single statements commit immediately, and
    # `with con.transaction():` opens a real transaction for multi-step writes.
    # Tip: use Neon's *pooled* connection string (host contains "-pooler").
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=True, connect_timeout=10)


def init_db():
    with db() as con:
        con.execute(SCHEMA)
        if con.execute("SELECT COUNT(*) AS n FROM questions").fetchone()["n"] == 0:
            with con.transaction():
                for i, (text, req) in enumerate(SEED_QUESTIONS, start=1):
                    con.execute(
                        "INSERT INTO questions (text, required, position) VALUES (%s,%s,%s)",
                        (text, req, i),
                    )


# ---------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _sign(payload):
    key = (SECRET_KEY + "|" + ADMIN_PASSWORD).encode()  # changing the password revokes old tokens
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def make_admin_token():
    exp = str(int(time.time()) + ADMIN_TTL)
    return exp + "." + _sign(exp)


def admin_token_ok(token):
    try:
        exp, sig = token.split(".", 1)
        return exp.isdigit() and int(exp) > time.time() and hmac.compare_digest(sig, _sign(exp))
    except (ValueError, AttributeError):
        return False


CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_name(v):
    if not isinstance(v, str):
        raise ApiError(400, "กรุณาใส่ชื่อก่อนเข้าใช้งาน")
    v = re.sub(r"\s+", " ", v).strip()
    if not v:
        raise ApiError(400, "กรุณาใส่ชื่อก่อนเข้าใช้งาน")
    if len(v) > MAX_NAME or CTRL.search(v):
        raise ApiError(400, "ชื่อต้องยาวไม่เกิน %d ตัวอักษร" % MAX_NAME)
    return v


def clean_text(v, limit, too_long_msg, empty_msg=None):
    if not isinstance(v, str):
        v = ""
    v = CTRL.sub("", v).replace("\r\n", "\n").strip()
    if not v and empty_msg:
        raise ApiError(400, empty_msg)
    if len(v) > limit:
        raise ApiError(400, too_long_msg)
    return v


def csv_safe(v):
    v = v or ""
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def question_rows(con):
    return con.execute("SELECT id, text, required FROM questions ORDER BY position, id").fetchall()


def question_json(r):
    return {"id": r["id"], "text": r["text"], "required": bool(r["required"])}


# ---------------------------------------------------------------- routes
ROUTES = []


def route(method, pattern, need=None):
    def deco(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), need, fn))
        return fn

    return deco


@route("GET", r"/api/health")
def api_health(req, con, body, user):
    con.execute("SELECT 1")
    return {"ok": True}


@route("POST", r"/api/signup")
def api_signup(req, con, body, user):
    name = clean_name(body.get("username"))
    if name.lower() == ADMIN_USER.lower():
        raise ApiError(409, "ชื่อนี้ถูกใช้แล้ว กรุณาใช้ชื่ออื่น")
    token = secrets.token_urlsafe(24)
    try:
        con.execute(
            "INSERT INTO users (username, token_hash, created_at) VALUES (%s,%s,%s)",
            (name, hash_token(token), now()),
        )
    except psycopg.errors.UniqueViolation:
        raise ApiError(409, "ชื่อนี้ถูกใช้แล้ว กรุณาใช้ชื่ออื่น")
    return {"token": token, "username": name}


@route("GET", r"/api/me", need="user")
def api_me(req, con, body, user):
    return {"username": user["username"], "submitted": bool(user["submitted_at"])}


@route("GET", r"/api/questions", need="user")
def api_questions(req, con, body, user):
    return {"questions": [question_json(r) for r in question_rows(con)]}


@route("POST", r"/api/submit", need="user")
def api_submit(req, con, body, user):
    if user["submitted_at"]:
        raise ApiError(409, "คุณส่งคำตอบไปแล้ว")
    items = body.get("answers")
    if not isinstance(items, list):
        raise ApiError(400, "ไม่พบคำตอบ")
    given = {}
    for it in items:
        if isinstance(it, dict) and type(it.get("question_id")) is int:
            given[it["question_id"]] = clean_text(
                it.get("answer"), MAX_ANSWER, "คำตอบยาวเกินไป (สูงสุด %d ตัวอักษร)" % MAX_ANSWER
            )
    questions = question_rows(con)
    if not questions:
        raise ApiError(400, "ยังไม่มีคำถามในระบบ")
    for i, q in enumerate(questions, start=1):
        if q["required"] and not given.get(q["id"]):
            raise ApiError(400, "ข้อ %d ต้องตอบก่อนส่ง" % i)
    try:
        with con.transaction():  # an ApiError raised inside rolls everything back
            cur = con.execute(
                "UPDATE users SET submitted_at=%s WHERE id=%s AND submitted_at IS NULL",
                (now(), user["id"]),
            )
            if cur.rowcount == 0:
                raise ApiError(409, "คุณส่งคำตอบไปแล้ว")
            for q in questions:
                con.execute(
                    "INSERT INTO answers (user_id, question_id, question_text, answer) VALUES (%s,%s,%s,%s)",
                    (user["id"], q["id"], q["text"], given.get(q["id"], "")),
                )
    except psycopg.IntegrityError:
        raise ApiError(409, "คุณส่งคำตอบไปแล้ว")
    return {"ok": True}


# ---- admin
@route("POST", r"/api/admin/login")
def api_admin_login(req, con, body, user):
    name = body.get("username")
    pw = body.get("password")
    user_ok = isinstance(name, str) and hmac.compare_digest(name.encode(), ADMIN_USER.encode())
    pw_ok = isinstance(pw, str) and hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())
    if not (user_ok and pw_ok):
        time.sleep(0.8)
        raise ApiError(401, "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")
    return {"ok": True, "token": make_admin_token()}


@route("POST", r"/api/admin/logout")
def api_admin_logout(req, con, body, user):
    # Tokens are stateless; the frontend just forgets it.
    return {"ok": True}


@route("GET", r"/api/admin/me", need="admin")
def api_admin_me(req, con, body, user):
    return {"ok": True}


@route("GET", r"/api/admin/questions", need="admin")
def api_admin_questions(req, con, body, user):
    return {"questions": [question_json(r) for r in question_rows(con)]}


@route("POST", r"/api/admin/questions", need="admin")
def api_admin_add_question(req, con, body, user):
    text = clean_text(body.get("text"), MAX_QUESTION, "คำถามยาวเกินไป (สูงสุด %d ตัวอักษร)" % MAX_QUESTION, "พิมพ์คำถามก่อนกดเพิ่ม")
    required = bool(body.get("required", True))
    with con.transaction():
        pos = con.execute("SELECT COALESCE(MAX(position), 0) + 1 AS p FROM questions").fetchone()["p"]
        row = con.execute(
            "INSERT INTO questions (text, required, position) VALUES (%s,%s,%s) RETURNING id",
            (text, required, pos),
        ).fetchone()
    return 201, {"id": row["id"]}, {}


@route("PUT", r"/api/admin/questions/(\d+)", need="admin")
def api_admin_update_question(req, con, body, user, qid):
    text = clean_text(body.get("text"), MAX_QUESTION, "คำถามยาวเกินไป (สูงสุด %d ตัวอักษร)" % MAX_QUESTION, "คำถามต้องไม่ว่าง")
    required = bool(body.get("required", True))
    cur = con.execute("UPDATE questions SET text=%s, required=%s WHERE id=%s", (text, required, int(qid)))
    if cur.rowcount == 0:
        raise ApiError(404, "ไม่พบคำถามนี้")
    return {"ok": True}


@route("DELETE", r"/api/admin/questions/(\d+)", need="admin")
def api_admin_delete_question(req, con, body, user, qid):
    con.execute("DELETE FROM questions WHERE id=%s", (int(qid),))
    return {"ok": True}


@route("POST", r"/api/admin/questions/(\d+)/move", need="admin")
def api_admin_move_question(req, con, body, user, qid):
    direction = body.get("dir")
    if direction not in (-1, 1):
        raise ApiError(400, "ทิศทางไม่ถูกต้อง")
    rows = con.execute("SELECT id, position FROM questions ORDER BY position, id").fetchall()
    ids = [r["id"] for r in rows]
    qid = int(qid)
    if qid not in ids:
        raise ApiError(404, "ไม่พบคำถามนี้")
    i = ids.index(qid)
    j = i + direction
    if 0 <= j < len(rows):
        with con.transaction():
            con.execute("UPDATE questions SET position=%s WHERE id=%s", (rows[j]["position"], rows[i]["id"]))
            con.execute("UPDATE questions SET position=%s WHERE id=%s", (rows[i]["position"], rows[j]["id"]))
            if rows[i]["position"] == rows[j]["position"]:
                # equal positions would not swap; renumber to make the order explicit
                order = ids[:]
                order[i], order[j] = order[j], order[i]
                for n, k in enumerate(order, start=1):
                    con.execute("UPDATE questions SET position=%s WHERE id=%s", (n, k))
    return {"ok": True}


@route("GET", r"/api/admin/users", need="admin")
def api_admin_users(req, con, body, user):
    rows = con.execute(
        """SELECT u.id, u.username, u.created_at, u.submitted_at,
                  (SELECT COUNT(*) FROM answers a WHERE a.user_id = u.id) AS answer_count
           FROM users u ORDER BY u.id DESC"""
    ).fetchall()
    return {"users": rows}


@route("GET", r"/api/admin/users/(\d+)", need="admin")
def api_admin_user(req, con, body, user, uid):
    u = con.execute(
        "SELECT id, username, created_at, submitted_at FROM users WHERE id=%s", (int(uid),)
    ).fetchone()
    if not u:
        raise ApiError(404, "ไม่พบผู้ใช้นี้")
    ans = con.execute(
        "SELECT question_id, question_text, answer FROM answers WHERE user_id=%s ORDER BY id", (u["id"],)
    ).fetchall()
    return {"user": u, "answers": ans}


@route("DELETE", r"/api/admin/users/(\d+)", need="admin")
def api_admin_delete_user(req, con, body, user, uid):
    con.execute("DELETE FROM users WHERE id=%s", (int(uid),))
    return {"ok": True}


@route("GET", r"/api/admin/export\.csv", need="admin")
def api_admin_export(req, con, body, user):
    rows = con.execute(
        """SELECT u.username, u.created_at, u.submitted_at, a.question_text, a.answer
           FROM users u LEFT JOIN answers a ON a.user_id = u.id
           ORDER BY u.id, a.id"""
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["username", "signed_up_at", "submitted_at", "question", "answer"])
    for r in rows:
        w.writerow([csv_safe(r["username"]), r["created_at"], r["submitted_at"] or "",
                    csv_safe(r["question_text"]), csv_safe(r["answer"])])
    data = buf.getvalue().encode("utf-8-sig")
    req.send_bytes(200, data, "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="answers.csv"'})
    return None


# ---------------------------------------------------------------- http handler
class Handler(BaseHTTPRequestHandler):
    server_version = "QuestionAPI/2.0"

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")

    def do_OPTIONS(self):  # CORS preflight
        self.send_bytes(204, b"", "text/plain", api=True)

    # -- responses
    def send_cors(self):
        origin = (self.headers.get("Origin") or "").rstrip("/")
        if "*" in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", "*")
        elif origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-User-Token, X-Admin-Token")
        self.send_header("Access-Control-Max-Age", "600")

    def send_bytes(self, status, data, ctype, headers=None, api=True):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_cors()
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def send_json(self, status, obj, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, data, "application/json; charset=utf-8", headers)

    # -- auth
    def require_admin(self):
        if not admin_token_ok(self.headers.get("X-Admin-Token", "")):
            raise ApiError(401, "กรุณาเข้าสู่ระบบแอดมิน")

    def require_user(self, con):
        token = self.headers.get("X-User-Token", "")
        if not token:
            raise ApiError(401, "กรุณาสมัครด้วยชื่อก่อน")
        row = con.execute("SELECT * FROM users WHERE token_hash=%s", (hash_token(token),)).fetchone()
        if not row:
            raise ApiError(401, "กรุณาสมัครด้วยชื่อก่อน")
        return row

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "ข้อมูลไม่ถูกต้อง")
        if length > MAX_BODY:
            raise ApiError(413, "ข้อมูลใหญ่เกินไป")
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise ApiError(400, "รูปแบบข้อมูลไม่ถูกต้อง")
        if not isinstance(data, dict):
            raise ApiError(400, "รูปแบบข้อมูลไม่ถูกต้อง")
        return data

    # -- dispatch
    def handle_any(self, method):
        path = urlparse(self.path).path
        try:
            if path.startswith("/api/"):
                return self.route_api(method, path)
            raise ApiError(404, "ไม่พบหน้านี้ (นี่คือ API เท่านั้น)")
        except ApiError as e:
            self.send_json(e.status, {"error": e.message})
        except psycopg.OperationalError:
            traceback.print_exc()
            self.send_json(503, {"error": "เชื่อมต่อฐานข้อมูลไม่ได้ ลองใหม่อีกครั้ง"})
        except Exception:
            traceback.print_exc()
            self.send_json(500, {"error": "เซิร์ฟเวอร์ผิดพลาด ลองใหม่อีกครั้ง"})

    def route_api(self, method, path):
        matched = False
        for m, rx, need, fn in ROUTES:
            match = rx.match(path)
            if not match:
                continue
            matched = True
            if m != method:
                continue
            if need == "admin":
                self.require_admin()
            body = self.read_json() if method in ("POST", "PUT") else {}
            with db() as con:
                user = self.require_user(con) if need == "user" else None
                result = fn(self, con, body, user, *match.groups())
            if result is None:
                return
            if isinstance(result, tuple):
                status, obj, hdrs = result
                return self.send_json(status, obj, hdrs)
            return self.send_json(200, result)
        raise ApiError(405 if matched else 404, "ไม่รองรับคำขอนี้")


def main():
    if not DATABASE_URL:
        sys.exit("ต้องตั้งค่า DATABASE_URL (Neon connection string) ก่อนรัน — ดู .env.example")
    init_db()
    if "ADMIN_PASSWORD" not in os.environ:
        print("!! แอดมินใช้ค่าเริ่มต้น ADMIN / ADMIN555 — ตั้ง ADMIN_USER และ ADMIN_PASSWORD ก่อนขึ้นเว็บจริง", file=sys.stderr)
    if "SECRET_KEY" not in os.environ:
        print("!! ไม่ได้ตั้ง SECRET_KEY — แอดมินจะต้องล็อกอินใหม่ทุกครั้งที่เซิร์ฟเวอร์รีสตาร์ต", file=sys.stderr)
    if "*" in ALLOWED_ORIGINS:
        print("!! FRONTEND_ORIGIN ยังเป็น * (อนุญาตทุกเว็บ) — ตั้งเป็น URL ของ frontend ตอนขึ้นเว็บจริง", file=sys.stderr)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("API พร้อมที่ http://%s:%d/api/health" % (HOST, PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
