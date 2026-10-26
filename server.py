import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATABASE = Path(os.environ.get("ROADRESCUE_DB", str(ROOT / "roadrescue.sqlite3"))).resolve()
SESSION_COOKIE = "roadrescue_session"
SESSION_DAYS = 7
PERMANENT_ADMIN_EMAIL = os.environ.get("ROADRESCUE_ADMIN_EMAIL", "admin@roadrescue.com").strip().lower()
SECURE_COOKIES = os.environ.get("ROADRESCUE_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}
PERMANENT_ADMIN_PASSWORD = os.environ.get("ROADRESCUE_ADMIN_PASSWORD", "Admin@!23")
PERMANENT_ADMIN_NAME = os.environ.get("ROADRESCUE_ADMIN_NAME", "ADMIN")
MAX_BODY_BYTES = 64 * 1024
DB_LOCK = threading.RLock()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_postgres():
    return DATABASE_URL.startswith(("postgres://", "postgresql://"))


def insert_id(connection, sql, params=()):
    if is_postgres():
        row = connection.execute(sql + " RETURNING id", params).fetchone()
        return row["id"] if isinstance(row, dict) else row[0]
    cursor = connection.execute(sql, params)
    return cursor.lastrowid


class DBConnection:
    """Small adapter so the existing ``?`` placeholders work with psycopg."""

    def __init__(self, raw):
        self.raw = raw

    def _convert(self, sql):
        if isinstance(sql, str) and "?" in sql:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, parameters=()):
        if is_postgres() and isinstance(sql, str) and sql.strip().upper() == "BEGIN IMMEDIATE":
            return self.raw.cursor()
        return self.raw.execute(self._convert(sql), parameters)

    def executescript(self, sql):
        if is_postgres():
            sql = sql.replace("INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
            sql = sql.replace("BLOB", "BYTEA")
            sql = sql.replace("COLLATE NOCASE", "")
        for statement in sql.split(";"):
            statement = statement.strip()
            if statement:
                self.raw.execute(self._convert(statement))

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.raw.__exit__(*args)


def hybrid_row_factory(cursor):
    fields = [column.name for column in cursor.description]

    class HybridRow(dict):
        def __getitem__(self, key):
            if isinstance(key, int):
                return list(self.values())[key]
            return super().__getitem__(key)

    def make_row(values):
        return HybridRow(zip(fields, values))

    return make_row


def get_db():
    if is_postgres():
        import psycopg

        connection = psycopg.connect(DATABASE_URL, row_factory=hybrid_row_factory)
        return DBConnection(connection)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return DBConnection(connection)


def init_db():
    with DB_LOCK, get_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'vendor')),
                status TEXT NOT NULL DEFAULT 'pending',
                availability TEXT NOT NULL DEFAULT 'offline',
                phone TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY,
                reference TEXT NOT NULL UNIQUE,
                customer_name TEXT NOT NULL,
                customer_phone TEXT NOT NULL,
                issue TEXT NOT NULL,
                vehicle TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                message TEXT NOT NULL DEFAULT '',
                payment TEXT NOT NULL,
                 payment_status TEXT NOT NULL DEFAULT 'pending',
                 paid_at TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                assigned_vendor INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                accepted_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS workshops (
                id INTEGER PRIMARY KEY,
                vendor_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                business_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                phone TEXT NOT NULL,
                city TEXT NOT NULL,
                address TEXT NOT NULL,
                services TEXT NOT NULL DEFAULT '',
                listing_enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY,
                vendor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                plan TEXT NOT NULL,
                price_paise INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_payment',
                created_at TEXT NOT NULL,
                starts_at TEXT,
                ends_at TEXT
            );
             CREATE TABLE IF NOT EXISTS payments (
                 id INTEGER PRIMARY KEY,
                 job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                 reference TEXT NOT NULL,
                 amount_paise INTEGER NOT NULL DEFAULT 0,
                 method TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'pending',
                 transaction_ref TEXT,
                 upi_id TEXT,
                 card_last4 TEXT,
                 created_at TEXT NOT NULL,
                 paid_at TEXT
             );
             CREATE TABLE IF NOT EXISTS reviews (
                 id INTEGER PRIMARY KEY,
                 workshop_id INTEGER REFERENCES workshops(id) ON DELETE CASCADE,
                 vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                 job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
                 customer_phone TEXT NOT NULL DEFAULT '',
                 rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                 comment TEXT NOT NULL DEFAULT '',
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS payments_job ON payments(job_id, id DESC);
             CREATE INDEX IF NOT EXISTS reviews_workshop ON reviews(workshop_id, id DESC);

            CREATE INDEX IF NOT EXISTS jobs_status_created ON jobs(status, created_at);
            CREATE INDEX IF NOT EXISTS subscriptions_vendor ON subscriptions(vendor_id, id DESC);
            """
        )
        if not is_postgres():
            user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            if "availability" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN availability TEXT NOT NULL DEFAULT 'offline'")
            job_columns = {row["name"] for row in connection.execute("PRAGMA table_info(jobs)")}
            if "payment_status" not in job_columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending'")
            if "paid_at" not in job_columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN paid_at TEXT")



def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return salt, digest


def verify_password(password, salt, expected_hash):
    _, candidate = password_hash(password, salt)
    return hmac.compare_digest(candidate, expected_hash)


def safe_user(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "status": row["status"],
        "availability": row["effective_availability"] if "effective_availability" in row.keys() else row["availability"],
        "phone": row["phone"],
        "city": row["city"],
    }


def get_session(handler):
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    morsel = cookie.get(SESSION_COOKIE)
    if morsel is None:
        return None
    digest = hashlib.sha256(morsel.value.encode("utf-8")).hexdigest()
    with get_db() as connection:
        row = connection.execute(
            """SELECT s.csrf_token, s.expires_at, u.* FROM sessions s
               JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""",
            (digest,),
        ).fetchone()
    if row is None or row["expires_at"] < now_iso():
        return None
    return {"user": safe_user(row), "csrf": row["csrf_token"], "token_hash": digest}


def require_user(handler, role=None, approved=False, subscription=False):
    session = get_session(handler)
    if session is None:
        raise ApiError(401, "Please sign in to continue.")
    user = session["user"]
    if role and user["role"] != role:
        raise ApiError(403, "This account cannot access that portal.")
    if approved and user["status"] != "approved":
        raise ApiError(403, "Your vendor account is awaiting admin approval.")
    if subscription:
        with get_db() as connection:
            current = connection.execute(
                """SELECT id FROM subscriptions WHERE vendor_id = ? AND status = 'active'
                   AND ends_at > ? ORDER BY id DESC LIMIT 1""",
                (user["id"], now_iso()),
            ).fetchone()
        if current is None:
            raise ApiError(403, "An active workshop subscription is required for this action.")
    return session


def require_csrf(handler, session):
    supplied = handler.headers.get("X-CSRF-Token", "")
    if not supplied or not hmac.compare_digest(supplied, session["csrf"]):
        raise ApiError(403, "The session token is invalid. Refresh and try again.")
    origin = handler.headers.get("Origin")
    if origin and urlsplit(origin).netloc != handler.headers.get("Host"):
        raise ApiError(403, "Cross-origin requests are not allowed.")


def require_admin(handler):
    session = require_user(handler, role="admin")
    require_csrf(handler, session)
    return session


def require_vendor(handler, approved=False, subscription=False):
    session = require_user(handler, role="vendor", approved=approved, subscription=subscription)
    require_csrf(handler, session)
    return session


class RoadRescueHandler(SimpleHTTPRequestHandler):
    server_version = "RoadRescueLocal/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        if self.path.startswith("/api/"):
            super().log_message(fmt, *args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "Invalid request size.")
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "Request body is too large.")
        if length == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "Request body must be valid JSON.")
        if not isinstance(data, dict):
            raise ApiError(400, "Request body must be a JSON object.")
        return data

    def api(self, method, path, data):
        if method == "GET" and path == "/api/setup":
            with get_db() as connection:
                exists = connection.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone()
            return 200, {"needsSetup": exists is None}, []

        if method == "POST" and path == "/api/setup":
            name = clean(data.get("name"), 100)
            email = clean(data.get("email"), 254).lower()
            password = str(data.get("password", ""))
            if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise ApiError(400, "Enter a valid admin name and email address.")
            if len(password) < 12:
                raise ApiError(400, "Admin password must be at least 12 characters.")
            salt, digest = password_hash(password)
            csrf = secrets.token_urlsafe(32)
            token = secrets.token_urlsafe(32)
            with DB_LOCK, get_db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone():
                    raise ApiError(409, "Admin setup has already been completed.")
                user_id = insert_id(
                    connection,
                    """INSERT INTO users(name,email,password_salt,password_hash,role,status,created_at)
                       VALUES(?,?,?,?, 'admin','approved',?)""",
                    (name, email, salt, digest, now_iso()),
                )
                self.create_session(connection, token, csrf, user_id)
                user = safe_user(connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())
            return 201, {"user": user, "csrf": csrf}, self.session_cookie(token)

        if method == "POST" and path == "/api/register/vendor":
            name = clean(data.get("name"), 100)
            email = clean(data.get("email"), 254).lower()
            password = str(data.get("password", ""))
            business = clean(data.get("businessName"), 140)
            phone = clean(data.get("phone"), 24)
            city = clean(data.get("city"), 100)
            address = clean(data.get("address"), 240)
            description = clean(data.get("description"), 500)
            services = clean(data.get("services"), 240)
            if not all((name, business, phone, city, address)) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise ApiError(400, "Complete all required fields with a valid email address.")
            if len(password) < 10:
                raise ApiError(400, "Password must be at least 10 characters.")
            salt, digest = password_hash(password)
            csrf = secrets.token_urlsafe(32)
            token = secrets.token_urlsafe(32)
            try:
                with DB_LOCK, get_db() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    vendor_id = insert_id(
                        connection,
                        """INSERT INTO users(name,email,password_salt,password_hash,role,status,phone,city,created_at)
                           VALUES(?,?,?,?,'vendor','pending',?,?,?)""",
                        (name, email, salt, digest, phone, city, now_iso()),
                    )
                    connection.execute(
                        """INSERT INTO workshops(vendor_id,business_name,description,phone,city,address,services,updated_at)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (vendor_id, business, description, phone, city, address, services, now_iso()),
                    )
                    self.create_session(connection, token, csrf, vendor_id)
                    user = safe_user(connection.execute("SELECT * FROM users WHERE id=?", (vendor_id,)).fetchone())
            except sqlite3.IntegrityError:
                raise ApiError(409, "An account already uses that email address.")
            return 201, {"user": user, "csrf": csrf}, self.session_cookie(token)

        if method == "POST" and path == "/api/login":
            raw_login = clean(data.get("email"), 254).lower()
            password = str(data.get("password", ""))
            email = raw_login
            if raw_login in ("admin", PERMANENT_ADMIN_NAME.lower()) and password == PERMANENT_ADMIN_PASSWORD:
                email = PERMANENT_ADMIN_EMAIL
            if email == PERMANENT_ADMIN_EMAIL and password == PERMANENT_ADMIN_PASSWORD:
                self.ensure_permanent_admin()
            with get_db() as connection:
                row = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row is None:
                password_hash(password, b"roadrescue-demo-salt")
                raise ApiError(401, "Email or password is incorrect.")
            _, candidate = password_hash(password, row["password_salt"])
            if not hmac.compare_digest(candidate, row["password_hash"]):
                raise ApiError(401, "Email or password is incorrect.")
            csrf = secrets.token_urlsafe(32)
            token = secrets.token_urlsafe(32)
            with get_db() as connection:
                self.create_session(connection, token, csrf, row["id"])
            return 200, {"user": safe_user(row), "csrf": csrf}, self.session_cookie(token)

        if method == "POST" and path in ("/api/admin/login", "/api/admin/signin", "/api/admin/sign-in"):
            return self.role_login(data, "admin")

        if method == "POST" and path in ("/api/vendor/login", "/api/vendor/signin", "/api/vendor/sign-in"):
            return self.role_login(data, "vendor")

        if method == "GET" and path == "/api/me":
            session = get_session(self)
            if session is None:
                raise ApiError(401, "You are not signed in.")
            return 200, {"user": session["user"], "csrf": session["csrf"]}, []

        if method == "POST" and path in ("/api/logout", "/api/admin/logout", "/api/admin/signout", "/api/admin/sign-out",
                                        "/api/vendor/logout", "/api/vendor/signout", "/api/vendor/sign-out"):
            session = require_user(self)
            require_csrf(self, session)
            if path.startswith("/api/admin/") and session["user"]["role"] != "admin":
                raise ApiError(403, "This account cannot access that portal.")
            if path.startswith("/api/vendor/") and session["user"]["role"] != "vendor":
                raise ApiError(403, "This account cannot access that portal.")
            return self.perform_logout(session)

        if method == "POST" and path == "/api/jobs":
            return self.create_job(data)

        if method == "GET" and path == "/api/workshops":
            with get_db() as connection:
                rows = connection.execute(
                    """SELECT w.id,w.vendor_id,w.business_name,w.description,w.phone,w.city,w.address,w.services,
                              COALESCE(r.average_rating, 0) AS average_rating,
                              COALESCE(r.review_count, 0) AS review_count
                       FROM workshops w JOIN users u ON u.id=w.vendor_id
                       JOIN subscriptions s ON s.vendor_id=w.vendor_id
                       LEFT JOIN (
                           SELECT workshop_id, ROUND(AVG(rating), 1) AS average_rating, COUNT(*) AS review_count
                           FROM reviews GROUP BY workshop_id
                       ) r ON r.workshop_id=w.id
                       WHERE w.listing_enabled=1 AND u.status='approved' AND s.status='active' AND s.ends_at>?
                       GROUP BY w.id ORDER BY w.city,w.business_name""",
                    (now_iso(),),
                ).fetchall()
            return 200, {"workshops": [dict(row) for row in rows]}, []

        if method == "GET" and path.startswith("/api/jobs/"):
            reference = clean(unquote(path.rsplit("/", 1)[-1]), 40)
            with get_db() as connection:
                row = connection.execute(
                    """SELECT j.reference,j.issue,j.vehicle,j.location,j.status,j.created_at,
                              j.payment,j.payment_status,j.paid_at,j.assigned_vendor,
                              w.id AS workshop_id,w.business_name AS workshop_name,w.phone AS workshop_phone
                       FROM jobs j LEFT JOIN workshops w ON w.vendor_id=j.assigned_vendor
                       WHERE j.reference=?""",
                    (reference,),
                ).fetchone()
            if row is None:
                raise ApiError(404, "Request not found.")
            return 200, {"job": dict(row)}, []

        if method == "GET" and path == "/api/admin/dashboard":
            require_user(self, role="admin")
            return 200, self.admin_dashboard(), []

        if method == "POST" and path.startswith("/api/admin/vendors/") and path.endswith("/status"):
            require_admin(self)
            vendor_id = path.split("/")[4]
            status = data.get("status")
            if status not in ("approved", "rejected"):
                raise ApiError(400, "Choose approved or rejected.")
            with get_db() as connection:
                cursor = connection.execute(
                    "UPDATE users SET status=? WHERE id=? AND role='vendor'",
                    (status, vendor_id),
                )
            if not cursor.rowcount:
                raise ApiError(404, "Vendor account not found.")
            return 200, {"ok": True}, []

        if method == "POST" and path.startswith("/api/admin/vendors/") and path.endswith("/availability"):
            require_admin(self)
            vendor_id = path.split("/")[4]
            availability = data.get("availability")
            if availability not in ("online", "offline"):
                raise ApiError(400, "Choose online or offline.")
            with get_db() as connection:
                vendor = connection.execute(
                    """SELECT u.status,EXISTS(
                           SELECT 1 FROM subscriptions s WHERE s.vendor_id=u.id AND s.status='active' AND s.ends_at>?
                       ) AS has_active_subscription FROM users u WHERE u.id=? AND u.role='vendor'""",
                    (now_iso(), vendor_id),
                ).fetchone()
                if vendor is None:
                    raise ApiError(404, "Vendor account not found.")
                if availability == "online" and (vendor["status"] != "approved" or not vendor["has_active_subscription"]):
                    raise ApiError(409, "Only an approved vendor with an active subscription can be online.")
                connection.execute("UPDATE users SET availability=? WHERE id=?", (availability, vendor_id))
            return 200, {"ok": True, "availability": availability}, []

        if method == "POST" and path.startswith("/api/admin/subscriptions/") and path.endswith("/activate"):
            require_admin(self)
            subscription_id = path.split("/")[4]
            starts = datetime.now(timezone.utc)
            ends = starts + timedelta(days=30)
            with get_db() as connection:
                cursor = connection.execute(
                    """UPDATE subscriptions SET status='active',starts_at=?,ends_at=?
                       WHERE id=? AND status='pending_payment'
                       AND vendor_id IN (SELECT id FROM users WHERE status='approved')""",
                    (starts.isoformat(timespec="seconds"), ends.isoformat(timespec="seconds"), subscription_id),
                )
            if not cursor.rowcount:
                raise ApiError(409, "Subscription is not pending, or the vendor is not approved.")
            return 200, {"ok": True}, []

        if method == "GET" and path == "/api/vendor/dashboard":
            session = require_user(self, role="vendor")
            return 200, self.vendor_dashboard(session["user"]["id"]), []

        if method == "POST" and path == "/api/vendor/availability":
            availability = data.get("availability")
            if availability not in ("online", "offline"):
                raise ApiError(400, "Choose online or offline.")
            session = require_vendor(
                self,
                approved=availability == "online",
                subscription=availability == "online",
            )
            with get_db() as connection:
                connection.execute("UPDATE users SET availability=? WHERE id=?", (availability, session["user"]["id"]))
            return 200, {"ok": True, "availability": availability}, []

        if method == "POST" and path == "/api/vendor/workshop":
            session = require_vendor(self, approved=True, subscription=True)
            return self.save_workshop(session["user"]["id"], data)

        if method == "POST" and path == "/api/vendor/subscription":
            session = require_vendor(self, approved=True)
            plan = data.get("plan")
            plans = {"starter": (49900, "Starter"), "growth": (99900, "Growth"), "pro": (199900, "Pro")}
            if plan not in plans:
                raise ApiError(400, "Choose an available subscription plan.")
            price, plan_name = plans[plan]
            with get_db() as connection:
                pending = connection.execute(
                    "SELECT id FROM subscriptions WHERE vendor_id=? AND status='pending_payment' LIMIT 1",
                    (session["user"]["id"],),
                ).fetchone()
                active = connection.execute(
                    "SELECT id FROM subscriptions WHERE vendor_id=? AND status='active' AND ends_at>? LIMIT 1",
                    (session["user"]["id"], now_iso()),
                ).fetchone()
                if active:
                    raise ApiError(409, "Your workshop already has an active subscription.")
                if pending:
                    raise ApiError(409, "You already have a subscription awaiting payment confirmation.")
                subscription_id = insert_id(
                    connection,
                    """INSERT INTO subscriptions(vendor_id,plan,price_paise,status,created_at)
                       VALUES(?,?,?,'pending_payment',?)""",
                    (session["user"]["id"], plan_name, price, now_iso()),
                )
            return 201, {"ok": True, "subscriptionId": subscription_id, "status": "pending_payment"}, []

        if method == "POST" and path.startswith("/api/vendor/jobs/") and path.endswith("/accept"):
            session = require_vendor(self, approved=True, subscription=True)
            job_id = path.split("/")[4]
            with DB_LOCK, get_db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                vendor = connection.execute(
                    "SELECT availability FROM users WHERE id=? AND role='vendor'",
                    (session["user"]["id"],),
                ).fetchone()
                if vendor is None or vendor["availability"] != "online":
                    raise ApiError(409, "Go online before accepting roadside requests.")
                cursor = connection.execute(
                    """UPDATE jobs SET status='accepted',assigned_vendor=?,accepted_at=?
                       WHERE id=? AND status='open' AND assigned_vendor IS NULL""",
                    (session["user"]["id"], now_iso(), job_id),
                )
            if not cursor.rowcount:
                raise ApiError(409, "That request has already been taken or is no longer open.")
            return 200, {"ok": True}, []

        if method == "POST" and path.startswith("/api/vendor/jobs/") and path.endswith("/complete"):
            session = require_vendor(self, approved=True)
            job_id = path.split("/")[4]
            with get_db() as connection:
                cursor = connection.execute(
                    """UPDATE jobs SET status='completed',completed_at=?
                       WHERE id=? AND assigned_vendor=? AND status='accepted'""",
                    (now_iso(), job_id, session["user"]["id"]),
                )
            if not cursor.rowcount:
                raise ApiError(409, "Only your accepted requests can be marked complete.")
            return 200, {"ok": True}, []

        if method == "POST" and path.startswith("/api/admin/jobs/") and path.endswith("/cancel"):
            require_admin(self)
            job_id = path.split("/")[4]
            with get_db() as connection:
                cursor = connection.execute(
                    "UPDATE jobs SET status='cancelled' WHERE id=? AND status IN ('open','accepted')",
                    (job_id,),
                )
            if not cursor.rowcount:
                raise ApiError(409, "Request could not be cancelled.")
            return 200, {"ok": True}, []

        if method == "POST" and path in ("/api/payments", "/api/payment"):
            return self.create_payment(data)

        if method == "GET" and (path.startswith("/api/payments/") or path.startswith("/api/payment/")):
            reference = clean(unquote(path.rsplit("/", 1)[-1]), 40)
            return 200, {"payments": self.list_payments(reference)}, []

        if method == "POST" and path in ("/api/reviews", "/api/review"):
            return self.create_review(data)

        if method == "GET" and path.startswith("/api/workshops/") and path.endswith("/reviews"):
            workshop_id = path.split("/")[3]
            return 200, {"reviews": self.list_reviews(workshop_id)}, []

        if method == "GET" and path == "/api/workshops":
            with get_db() as connection:
                rows = connection.execute(
                    """SELECT w.id,w.vendor_id,w.business_name,w.description,w.phone,w.city,w.address,w.services,
                              COALESCE(r.average_rating, 0) AS average_rating,
                              COALESCE(r.review_count, 0) AS review_count
                       FROM workshops w JOIN users u ON u.id=w.vendor_id
                       JOIN subscriptions s ON s.vendor_id=w.vendor_id
                       LEFT JOIN (
                           SELECT workshop_id, ROUND(AVG(rating), 1) AS average_rating, COUNT(*) AS review_count
                           FROM reviews GROUP BY workshop_id
                       ) r ON r.workshop_id=w.id
                       WHERE w.listing_enabled=1 AND u.status='approved' AND s.status='active' AND s.ends_at>?
                       GROUP BY w.id ORDER BY w.city,w.business_name""",
                    (now_iso(),),
                ).fetchall()
            return 200, {"workshops": [dict(row) for row in rows]}, []


        raise ApiError(404, "API route not found.")

    def create_payment(self, data):
        reference = clean(data.get("reference"), 40)
        if not reference:
            raise ApiError(400, "Service request reference is required.")
        method_raw = str(data.get("method", "")).strip().lower().replace(" ", "").replace("-", "").replace("_", "")
        method_map = {
            "upi": "upi", "upion-site": "upi", "upionsite": "upi",
            "card": "card", "cardonsite": "card",
            "cash": "cash", "cashonsite": "cash",
        }
        method = method_map.get(method_raw)
        if method is None:
            raise ApiError(400, "Choose UPI, card, or cash payment.")
        amount = data.get("amount", 0)
        try:
            amount_paise = int(amount)
        except (TypeError, ValueError):
            raise ApiError(400, "Payment amount must be a whole number in paise.")
        if amount_paise < 0:
            raise ApiError(400, "Payment amount cannot be negative.")

        upi_id = clean(data.get("upiId") or data.get("upi_id"), 100)
        card_number = str(data.get("cardNumber") or data.get("card_number") or "").replace(" ", "").replace("-", "")
        card_last4 = card_number[-4:] if len(card_number) >= 4 else None

        with DB_LOCK, get_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute("SELECT * FROM jobs WHERE reference=?", (reference,)).fetchone()
            if job is None:
                raise ApiError(404, "Service request not found.")
            status = "pending"
            transaction_ref = None
            paid_at = None
            label = "UPI on-site"
            if method == "upi":
                if "@" not in upi_id:
                    raise ApiError(400, "Enter a valid UPI ID.")
                status = "paid"
                transaction_ref = "UPI-" + secrets.token_hex(6).upper()
                paid_at = now_iso()
                label = "UPI paid"
            elif method == "card":
                if len(card_number) < 12 or not card_number.isdigit():
                    raise ApiError(400, "Enter a valid card number.")
                status = "paid"
                transaction_ref = "CARD-" + secrets.token_hex(6).upper()
                paid_at = now_iso()
                label = "Card paid"
            elif method == "cash":
                status = "pending_on_site"
                label = "Cash on-site"
            payment_id = insert_id(
                connection,
                """INSERT INTO payments(job_id,reference,amount_paise,method,status,transaction_ref,upi_id,card_last4,created_at,paid_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job["id"], reference, amount_paise, method, status, transaction_ref, upi_id or None, card_last4, now_iso(), paid_at),
            )
            connection.execute(
                "UPDATE jobs SET payment=?, payment_status=?, paid_at=? WHERE id=?",
                (label, status, paid_at, job["id"]),
            )
        return 201, {
            "paymentId": payment_id,
            "reference": reference,
            "method": method,
            "status": status,
            "transactionRef": transaction_ref,
            "paidAt": paid_at,
        }, []

    def list_payments(self, reference):
        reference = clean(reference, 40)
        with get_db() as connection:
            job = connection.execute("SELECT id FROM jobs WHERE reference=?", (reference,)).fetchone()
            if job is None:
                raise ApiError(404, "Service request not found.")
            rows = connection.execute(
                "SELECT * FROM payments WHERE reference=? ORDER BY id DESC", (reference,)
            ).fetchall()
        return [dict(row) for row in rows]


    def create_review(self, data):
        reference = clean(data.get("reference"), 40)
        phone = clean(data.get("phone"), 24)
        comment = clean(data.get("comment"), 1000)
        try:
            rating = int(data.get("rating"))
        except (TypeError, ValueError):
            raise ApiError(400, "Rating must be a number from 1 to 5.")
        if rating < 1 or rating > 5:
            raise ApiError(400, "Rating must be between 1 and 5.")
        if not reference:
            raise ApiError(400, "Service request reference is required.")
        with DB_LOCK, get_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute("SELECT * FROM jobs WHERE reference=?", (reference,)).fetchone()
            if job is None:
                raise ApiError(404, "Service request not found.")
            if phone and job["customer_phone"] != phone:
                raise ApiError(403, "Phone number does not match this service request.")
            if job["assigned_vendor"] is None:
                raise ApiError(409, "This request has not been assigned to a workshop yet.")
            workshop = connection.execute(
                "SELECT id, vendor_id FROM workshops WHERE vendor_id=?", (job["assigned_vendor"],)
            ).fetchone()
            if workshop is None:
                raise ApiError(404, "Workshop not found.")
            existing = connection.execute("SELECT id FROM reviews WHERE job_id=?", (job["id"],)).fetchone()
            if existing is not None:
                raise ApiError(409, "A review has already been submitted for this request.")
            review_id = insert_id(
                connection,
                """INSERT INTO reviews(workshop_id,vendor_id,job_id,customer_phone,rating,comment,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (workshop["id"], workshop["vendor_id"], job["id"], job["customer_phone"], rating, comment, now_iso()),
            )
        return 201, {"reviewId": review_id, "workshopId": workshop["id"], "rating": rating}, []

    def list_reviews(self, workshop_id):
        with get_db() as connection:
            rows = connection.execute(
                "SELECT * FROM reviews WHERE workshop_id=? ORDER BY id DESC", (workshop_id,)
            ).fetchall()
        return [dict(row) for row in rows]


    def ensure_permanent_admin(self):
        with DB_LOCK, get_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM users WHERE email=?", (PERMANENT_ADMIN_EMAIL,)).fetchone()
            if row is None:
                salt, digest = password_hash(PERMANENT_ADMIN_PASSWORD)
                connection.execute(
                    "INSERT INTO users(name,email,password_salt,password_hash,role,status,created_at) VALUES(?,?,?,?,'admin','approved',?)",
                    (PERMANENT_ADMIN_NAME, PERMANENT_ADMIN_EMAIL, salt, digest, now_iso()),
                )
            else:
                salt, digest = password_hash(PERMANENT_ADMIN_PASSWORD)
                connection.execute(
                    "UPDATE users SET password_salt=?,password_hash=?,role='admin',status='approved',name=? WHERE id=?",
                    (salt, digest, PERMANENT_ADMIN_NAME, row["id"]),
                )

    def perform_logout(self, session):
        with get_db() as connection:
            if session["user"]["role"] == "vendor":
                connection.execute("UPDATE users SET availability='offline' WHERE id=?", (session["user"]["id"],))
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (session["token_hash"],))
        return 200, {"ok": True}, [("Set-Cookie", self.session_cookie_value("", max_age=0))]

    def role_login(self, data, role):
        raw_identifier = clean(data.get("email") or data.get("username"), 254).lower()
        password = str(data.get("password", ""))
        email = raw_identifier
        if role == "admin" and raw_identifier in ("admin", PERMANENT_ADMIN_NAME.lower(), PERMANENT_ADMIN_EMAIL) and password == PERMANENT_ADMIN_PASSWORD:
            email = PERMANENT_ADMIN_EMAIL
        if role == "admin" and email == PERMANENT_ADMIN_EMAIL and password == PERMANENT_ADMIN_PASSWORD:
            with DB_LOCK, get_db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                if row is None:
                    salt, digest = password_hash(password)
                    user_id = insert_id(
                        connection,
                        "INSERT INTO users(name,email,password_salt,password_hash,role,status,created_at) VALUES(?,?,?,?,'admin','approved',?)",
                        (PERMANENT_ADMIN_NAME, email, salt, digest, now_iso()),
                    )
                    row = connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                else:
                    salt, digest = password_hash(password)
                    connection.execute(
                        "UPDATE users SET password_salt=?,password_hash=?,role='admin',status='approved',name=? WHERE id=?",
                        (salt, digest, PERMANENT_ADMIN_NAME, row["id"]),
                    )
                    row = connection.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
        else:
            with get_db() as connection:
                row = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if row is None:
                password_hash(password, b"roadrescue-demo-salt")
                raise ApiError(401, "Email or password is incorrect.")
            if not verify_password(password, row["password_salt"], row["password_hash"]):
                raise ApiError(401, "Email or password is incorrect.")
        if row["role"] != role:
            raise ApiError(403, "This account cannot access that portal.")
        csrf = secrets.token_urlsafe(32)
        token = secrets.token_urlsafe(32)
        with get_db() as connection:
            self.create_session(connection, token, csrf, row["id"])
        return 200, {"user": safe_user(row), "csrf": csrf}, self.session_cookie(token)

    def create_session(self, connection, token, csrf, user_id):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)",
            (token_hash, user_id, csrf, expires),
        )

    def session_cookie_value(self, token, max_age=SESSION_DAYS * 24 * 60 * 60):
        value = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        if SECURE_COOKIES:
            value += "; Secure"
        return value

    def session_cookie(self, token):
        return [("Set-Cookie", self.session_cookie_value(token))]

    def create_job(self, data):
        name = clean(data.get("name"), 100)
        phone = clean(data.get("phone"), 24)
        issue = clean(data.get("issue"), 80)
        vehicle = clean(data.get("vehicle"), 140)
        location = clean(data.get("location"), 240)
        payment = clean(data.get("payment"), 40)
        message = clean(data.get("message"), 1000)
        if not all((name, phone, issue, location)):
            raise ApiError(400, "Name, phone, service, and location are required.")
        digits = re.sub(r"\D", "", phone)
        if len(digits) not in (10, 12) or (len(digits) == 10 and digits[0] not in "6789"):
            raise ApiError(400, "Enter a valid Indian mobile number.")
        reference = f"RR-{datetime.now().year}-{secrets.token_hex(4).upper()}"
        latitude = safe_coordinate(data.get("latitude"), -90, 90)
        longitude = safe_coordinate(data.get("longitude"), -180, 180)
        with get_db() as connection:
            job_id = insert_id(
                connection,
                """INSERT INTO jobs(reference,customer_name,customer_phone,issue,vehicle,location,latitude,longitude,message,payment,status,payment_status,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,'open','pending',?)""",
                (reference, name, phone, issue, vehicle or "Not provided", location, latitude, longitude, message, payment or "UPI on-site", now_iso()),
            )
        return 201, {"reference": reference, "id": job_id, "status": "open"}, []

    def admin_dashboard(self):
        with get_db() as connection:
            vendors = connection.execute(
                """SELECT u.id,u.name,u.email,u.phone,u.city,u.status,u.availability,u.created_at,
                          CASE WHEN u.status='approved' AND EXISTS(
                              SELECT 1 FROM subscriptions s WHERE s.vendor_id=u.id AND s.status='active' AND s.ends_at>?
                          ) THEN u.availability ELSE 'offline' END AS effective_availability,
                          EXISTS(SELECT 1 FROM subscriptions s WHERE s.vendor_id=u.id AND s.status='active' AND s.ends_at>?) AS has_active_subscription,
                          w.business_name,w.address,w.services
                   FROM users u LEFT JOIN workshops w ON w.vendor_id=u.id
                   WHERE u.role='vendor' ORDER BY u.created_at DESC"""
                , (now_iso(), now_iso())
            ).fetchall()
            subscriptions = connection.execute(
                """SELECT s.*,u.name AS vendor_name,u.email AS vendor_email,w.business_name
                   FROM subscriptions s JOIN users u ON u.id=s.vendor_id
                   LEFT JOIN workshops w ON w.vendor_id=s.vendor_id ORDER BY s.id DESC"""
            ).fetchall()
            jobs = connection.execute(
                """SELECT j.*,u.name AS vendor_name,w.business_name
                   FROM jobs j LEFT JOIN users u ON u.id=j.assigned_vendor
                   LEFT JOIN workshops w ON w.vendor_id=j.assigned_vendor
                   ORDER BY j.created_at DESC LIMIT 100"""
            ).fetchall()
            clients = connection.execute(
                """SELECT customer_phone,MAX(customer_name) AS customer_name,COUNT(*) AS request_count,
                          MAX(created_at) AS last_request,GROUP_CONCAT(DISTINCT issue) AS services
                   FROM jobs GROUP BY customer_phone ORDER BY last_request DESC"""
            ).fetchall()
            counts = {
                "openJobs": connection.execute("SELECT COUNT(*) FROM jobs WHERE status='open'").fetchone()[0],
                "pendingVendors": connection.execute("SELECT COUNT(*) FROM users WHERE role='vendor' AND status='pending'").fetchone()[0],
                "pendingSubscriptions": connection.execute("SELECT COUNT(*) FROM subscriptions WHERE status='pending_payment'").fetchone()[0],
                "onlineVendors": connection.execute(
                    """SELECT COUNT(*) FROM users u WHERE u.role='vendor' AND u.status='approved'
                       AND u.availability='online' AND EXISTS(
                           SELECT 1 FROM subscriptions s WHERE s.vendor_id=u.id AND s.status='active' AND s.ends_at>?
                       )""",
                    (now_iso(),),
                ).fetchone()[0],
                "activeWorkshops": connection.execute(
                    """SELECT COUNT(DISTINCT w.id) FROM workshops w JOIN users u ON u.id=w.vendor_id
                       JOIN subscriptions s ON s.vendor_id=w.vendor_id
                       WHERE w.listing_enabled=1 AND u.status='approved' AND s.status='active' AND s.ends_at>?""",
                    (now_iso(),),
                ).fetchone()[0],
            }
        return {
            "counts": counts,
            "vendors": [dict(row) for row in vendors],
            "clients": [dict(row) for row in clients],
            "subscriptions": [dict(row) for row in subscriptions],
            "jobs": [dict(row) for row in jobs],
        }

    def vendor_dashboard(self, vendor_id):
        with get_db() as connection:
            vendor = connection.execute(
                """SELECT u.*,CASE WHEN u.status='approved' AND EXISTS(
                       SELECT 1 FROM subscriptions s WHERE s.vendor_id=u.id AND s.status='active' AND s.ends_at>?
                   ) THEN u.availability ELSE 'offline' END AS effective_availability
                   FROM users u WHERE u.id=? AND u.role='vendor'""",
                (now_iso(), vendor_id),
            ).fetchone()
            workshop = connection.execute("SELECT * FROM workshops WHERE vendor_id=?", (vendor_id,)).fetchone()
            subscription = connection.execute(
                "SELECT * FROM subscriptions WHERE vendor_id=? ORDER BY id DESC LIMIT 1",
                (vendor_id,),
            ).fetchone()
            jobs = connection.execute(
                """SELECT j.id,j.reference,j.issue,j.vehicle,j.location,j.status,j.created_at,
                          j.accepted_at,j.completed_at,
                          CASE WHEN j.assigned_vendor=? THEN j.customer_name ELSE '' END AS customer_name,
                          CASE WHEN j.assigned_vendor=? THEN j.customer_phone ELSE '' END AS customer_phone,
                          w.business_name AS vendor_business
                   FROM jobs j LEFT JOIN workshops w ON w.vendor_id=j.assigned_vendor
                         WHERE (j.status='open' AND ?='online') OR j.assigned_vendor=?
                   ORDER BY CASE WHEN j.status='open' THEN 0 ELSE 1 END,j.created_at DESC LIMIT 100""",
                     (vendor_id, vendor_id, vendor["effective_availability"], vendor_id),
            ).fetchall()
        return {
            "user": safe_user(vendor),
            "workshop": dict(workshop) if workshop else None,
            "subscription": dict(subscription) if subscription else None,
            "jobs": [dict(row) for row in jobs],
        }

    def save_workshop(self, vendor_id, data):
        business = clean(data.get("businessName"), 140)
        description = clean(data.get("description"), 500)
        phone = clean(data.get("phone"), 24)
        city = clean(data.get("city"), 100)
        address = clean(data.get("address"), 240)
        services = clean(data.get("services"), 240)
        enabled = 1 if data.get("listingEnabled") else 0
        if not all((business, phone, city, address)):
            raise ApiError(400, "Business name, phone, city, and address are required.")
        with get_db() as connection:
            connection.execute(
                """UPDATE workshops SET business_name=?,description=?,phone=?,city=?,address=?,services=?,listing_enabled=?,updated_at=?
                   WHERE vendor_id=?""",
                (business, description, phone, city, address, services, enabled, now_iso(), vendor_id),
            )
        return 200, {"ok": True}, []

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api("GET", parsed.path)
            return
        return self.serve_static(parsed.path)

    def serve_static(self, url_path):
        decoded = unquote(url_path)
        if decoded == "/":
            decoded = "/index.html"
        path_parts = Path(decoded).parts
        file_name = Path(decoded).name.lower()
        database_names = {DATABASE.name.lower(), "roadrescue.sqlite3"}
        sensitive_database = file_name.endswith((".sqlite", ".sqlite3", ".db")) or any(
            file_name.startswith(name + "-") for name in database_names
        )
        if file_name.endswith((".py", ".pyc", ".pyo")) or sensitive_database or "__pycache__" in decoded.lower() or any(part.startswith(".") for part in path_parts):
            self.send_error(404)
            return
        candidate = (ROOT / decoded.lstrip("/")).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            self.send_error(404)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") or content_type in ("application/javascript", "application/json") else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlsplit(self.path)
        if not parsed.path.startswith("/api/"):
            self.send_json(404, {"error": "Not found."})
            return
        self.handle_api("POST", parsed.path)

    def do_HEAD(self):
        self.send_error(405, "HEAD requests are not supported.")

    def handle_api(self, method, path):
        try:
            data = self.read_json() if method == "POST" else {}
            status, result, headers = self.api(method, path, data)
            self.send_json(status, result, headers)
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except Exception as error:
            if "Integrity" in type(error).__name__ or "UniqueViolation" in type(error).__name__:
                self.send_json(409, {"error": "That record already exists or conflicts with current data."})
            else:
                self.log_error("Unexpected API error on %s", path)
                self.send_json(500, {"error": "An unexpected server error occurred."})


def clean(value, limit):
    if not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()[:limit]


def safe_coordinate(value, minimum, maximum):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if minimum <= number <= maximum else None


def main():
    init_db()
    host = os.environ.get("ROADRESCUE_HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
    port = int(os.environ.get("PORT", os.environ.get("ROADRESCUE_PORT", "8000")))
    server = ThreadingHTTPServer((host, port), RoadRescueHandler)
    print(f"RoadRescue app running at http://{host}:{port}")
    print(f"Local database: {DATABASE}")
    print(f"Permanent admin login: {PERMANENT_ADMIN_EMAIL} or {PERMANENT_ADMIN_NAME} / {PERMANENT_ADMIN_PASSWORD}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping RoadRescue app.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()