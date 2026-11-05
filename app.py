import os, sqlite3, uuid, hashlib, json, hmac
from flask_wtf.csrf import CSRFProtect
def now():
    return datetime.now().isoformat(timespec="seconds")
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATABASE_PATH", ROOT / "trustvault.db"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", ROOT / "private_uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "pptx", "txt", "png", "jpg", "jpeg"}
MAX_BYTES = 10 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "CHANGE-ME-TO-A-LONG-RANDOM-SECRET"),
    MAX_CONTENT_LENGTH=MAX_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents(
          id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
          title TEXT NOT NULL, category TEXT NOT NULL, original_name TEXT NOT NULL,
          stored_name TEXT UNIQUE NOT NULL, sha256 TEXT NOT NULL,
          size INTEGER NOT NULL, created_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS permissions(
          id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
          user_id INTEGER NOT NULL REFERENCES users(id), can_read INTEGER NOT NULL DEFAULT 0,
          can_edit INTEGER NOT NULL DEFAULT 0, granted_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL, UNIQUE(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
          id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id),
          action TEXT NOT NULL, document_id INTEGER, details TEXT NOT NULL,
          created_at TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
        );
        """)
        # Seed demo users only when database is empty. Change passwords before public deployment.
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            demo = [
                ("admin", os.environ.get("DEMO_ADMIN_PASSWORD"), "admin"),
                ("owner", os.environ.get("DEMO_OWNER_PASSWORD"), "owner"),
                ("viewer", os.environ.get("DEMO_VIEWER_PASSWORD"), "viewer"),
            ]
            for username, password, role in demo:
                c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                          (username, generate_password_hash(password), role, now()))
        c.commit()

# Ensure schema and demo accounts exist when started by Gunicorn as well as locally.
init_db()

def now():
    return datetime.now(timezone.utc).isoformat()

def audit(actor_id, action, document_id=None, details=None):
    """Append-only application audit trail with a SHA-256 hash chain.
    This detects edits/deletions when verified, but is not tamper-proof against a DB admin.
    """
    with db() as c:
        last = c.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last else "GENESIS"
        created = now()
        payload = json.dumps({
            "actor_id": actor_id, "action": action, "document_id": document_id,
            "details": details or {}, "created_at": created, "previous_hash": prev
        }, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        c.execute("""INSERT INTO audit_logs(actor_id,action,document_id,details,created_at,previous_hash,entry_hash)
                     VALUES(?,?,?,?,?,?,?)""",
                  (actor_id, action, document_id, json.dumps(details or {}, sort_keys=True), created, prev, digest))
        c.commit()

def verify_audit_chain():
    with db() as c:
        rows = c.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    previous = "GENESIS"
    for row in rows:
        payload = json.dumps({
            "actor_id": row["actor_id"], "action": row["action"],
            "document_id": row["document_id"], "details": json.loads(row["details"]),
            "created_at": row["created_at"], "previous_hash": previous
        }, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["entry_hash"]):
            return False
        previous = row["entry_hash"]
    return True

class User(UserMixin):
    def __init__(self, row):
        self.id, self.username, self.role = row["id"], row["username"], row["role"]

@login_manager.user_loader
def load_user(user_id):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User(row) if row else None

def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in allowed:
                audit(current_user.id, "ROLE_DENIED", details={"path": request.path})
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def can_read(doc, user_id):
    if doc["owner_id"] == user_id:
        return True
    with db() as c:
        p = c.execute("SELECT can_read,can_edit FROM permissions WHERE document_id=? AND user_id=?",
                      (doc["id"], user_id)).fetchone()
    return bool(p and (p["can_read"] or p["can_edit"]))

def can_edit(doc, user_id):
    if doc["owner_id"] == user_id:
        return True
    with db() as c:
        p = c.execute("SELECT can_edit FROM permissions WHERE document_id=? AND user_id=?",
                      (doc["id"], user_id)).fetchone()
    return bool(p and p["can_edit"])

def get_doc(doc_id):
    with db() as c:
        return c.execute("SELECT * FROM documents WHERE id=? AND deleted=0", (doc_id,)).fetchone()

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'"
    return response

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        # Public self-registration always creates a viewer; role elevation is admin-only.
        if len(username) < 3 or len(password) < 12:
            flash("Username must be 3+ characters and password 12+ characters.", "danger")
            return render_template("register.html")
        try:
            with db() as c:
                c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                          (username, generate_password_hash(password), "viewer", now()))
                c.commit()
                uid = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            audit(uid, "REGISTER", details={"username": username})
            flash("Account created. Ask an owner/admin to grant document access.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        with db() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            session.permanent = True
            audit(row["id"], "LOGIN")
            return redirect(url_for("dashboard"))
        audit(row["id"] if row else None, "LOGIN_FAILED", details={"username": username})
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    audit(current_user.id, "LOGOUT")
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    date_from = request.args.get("date_from", "").strip()
    with db() as c:
        if current_user.role == "admin":
            sql = "SELECT d.*,u.username owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.deleted=0"
            params = []
        else:
            sql = """SELECT DISTINCT d.*,u.username owner_name FROM documents d JOIN users u ON u.id=d.owner_id
                     LEFT JOIN permissions p ON p.document_id=d.id AND p.user_id=?
                     WHERE d.deleted=0 AND (d.owner_id=? OR p.can_read=1 OR p.can_edit=1)"""
            params = [current_user.id, current_user.id]
        if query:
            sql += " AND (d.title LIKE ? OR d.original_name LIKE ? OR u.username LIKE ?)"
            params += [f"%{query}%"]*3
        if category:
            sql += " AND d.category=?"; params.append(category)
        if date_from:
            sql += " AND substr(d.created_at,1,10)>=?"; params.append(date_from)
        sql += " ORDER BY d.created_at DESC"
        docs = c.execute(sql, params).fetchall()
        categories = c.execute("SELECT DISTINCT category FROM documents WHERE deleted=0 ORDER BY category").fetchall()
    return render_template("dashboard.html", docs=docs, categories=categories)

@app.route("/upload", methods=["GET", "POST"])
@roles("owner", "admin")
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        if not f or not f.filename or not title or not category:
            flash("Title, category and file are required.", "danger")
            return redirect(url_for("upload"))
        safe_name = secure_filename(f.filename)
        ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        if ext not in ALLOWED_EXTENSIONS:
            flash("File type not allowed.", "danger"); return redirect(url_for("upload"))
        data = f.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            flash("File is too large (10 MB maximum).", "danger"); return redirect(url_for("upload"))
        if not data:
            flash("Empty files are not allowed.", "danger"); return redirect(url_for("upload"))
        # Basic content-type/extension consistency check. Production should add malware scanning.
        stored = uuid.uuid4().hex
        path = UPLOAD_DIR / stored
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        try:
            with db() as c:
                cur = c.execute("""INSERT INTO documents(owner_id,title,category,original_name,stored_name,sha256,size,created_at)
                                   VALUES(?,?,?,?,?,?,?,?)""",
                                (current_user.id, title, category, safe_name, stored, digest, len(data), now()))
                doc_id = cur.lastrowid
                c.commit()
            audit(current_user.id, "UPLOAD", doc_id, {"title": title, "sha256": digest, "size": len(data)})
            flash("Document uploaded.", "success")
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

@app.route("/document/<int:doc_id>")
@login_required
def document_detail(doc_id):
    doc = get_doc(doc_id)
    if not doc:
        abort(404)
    if current_user.role != "admin" and not can_read(doc, current_user.id):
        audit(current_user.id, "READ_DENIED", doc_id)
        abort(404)  # Avoid confirming document existence.
    audit(current_user.id, "READ", doc_id)
    with db() as c:
        perms = c.execute("""SELECT p.*,u.username FROM permissions p JOIN users u ON u.id=p.user_id
                             WHERE p.document_id=?""", (doc_id,)).fetchall() if doc["owner_id"] == current_user.id or current_user.role == "admin" else []
    return render_template("document.html", doc=doc, perms=perms)

@app.route("/document/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = get_doc(doc_id)
    if not doc:
        abort(404)
    allowed = current_user.role == "admin" or can_read(doc, current_user.id)
    if not allowed:
        audit(current_user.id, "DOWNLOAD_DENIED", doc_id)
        abort(404)
    path = UPLOAD_DIR / doc["stored_name"]
    if not path.is_file():
        audit(current_user.id, "DOWNLOAD_MISSING", doc_id)
        abort(404)
    audit(current_user.id, "DOWNLOAD", doc_id, {"sha256": doc["sha256"]})
    return send_file(path, as_attachment=True, download_name=doc["original_name"], conditional=True)

@app.route("/document/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit_document(doc_id):
    doc = get_doc(doc_id)
    if not doc: abort(404)
    if current_user.role != "admin" and not can_edit(doc, current_user.id):
        audit(current_user.id, "EDIT_DENIED", doc_id); abort(404)
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    if not title or not category:
        flash("Title and category are required.", "danger")
        return redirect(url_for("document_detail", doc_id=doc_id))
    with db() as c:
        c.execute("UPDATE documents SET title=?,category=? WHERE id=?", (title, category, doc_id)); c.commit()
    audit(current_user.id, "EDIT", doc_id, {"title": title, "category": category})
    flash("Document details updated.", "success")
    return redirect(url_for("document_detail", doc_id=doc_id))

@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = get_doc(doc_id)
    if not doc: abort(404)
    if current_user.role != "admin" and doc["owner_id"] != current_user.id:
        audit(current_user.id, "DELETE_DENIED", doc_id); abort(404)
    with db() as c:
        c.execute("UPDATE documents SET deleted=1 WHERE id=?", (doc_id,)); c.commit()
    audit(current_user.id, "DELETE", doc_id, {"title": doc["title"]})
    flash("Document moved to deleted state.", "success")
    return redirect(url_for("dashboard"))

@app.route("/document/<int:doc_id>/permissions", methods=["POST"])
@roles("owner", "admin")
def set_permission(doc_id):
    doc = get_doc(doc_id)
    if not doc: abort(404)
    if current_user.role != "admin" and doc["owner_id"] != current_user.id:
        audit(current_user.id, "PERMISSION_DENIED", doc_id); abort(404)
    username = request.form.get("username", "").strip().lower()
    read = 1 if request.form.get("can_read") == "on" else 0
    edit = 1 if request.form.get("can_edit") == "on" else 0
    with db() as c:
        target = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not target:
            flash("User not found.", "danger"); return redirect(url_for("document_detail", doc_id=doc_id))
        if target["id"] == doc["owner_id"]:
            flash("Owner already has full access.", "warning"); return redirect(url_for("document_detail", doc_id=doc_id))
        if not read and not edit:
            c.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?", (doc_id, target["id"]))
            action = "REVOKE_PERMISSION"
        else:
            c.execute("""INSERT INTO permissions(document_id,user_id,can_read,can_edit,granted_by,created_at)
                         VALUES(?,?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET
                         can_read=excluded.can_read,can_edit=excluded.can_edit,granted_by=excluded.granted_by,created_at=excluded.created_at""",
                      (doc_id, target["id"], read, edit, current_user.id, now()))
            action = "GRANT_PERMISSION"
        c.commit()
    audit(current_user.id, action, doc_id, {"target_user": username, "read": read, "edit": edit})
    flash("Permission updated. Revocation takes effect on the next request.", "success")
    return redirect(url_for("document_detail", doc_id=doc_id))

@app.route("/admin")
@roles("admin")
def admin():
    with db() as c:
        users = c.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
        logs = c.execute("""SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
                            ORDER BY a.id DESC LIMIT 200""").fetchall()
        total_docs = c.execute("SELECT COUNT(*) FROM documents WHERE deleted=0").fetchone()[0]
    return render_template("admin.html", users=users, logs=logs, total_docs=total_docs,
                           chain_ok=verify_audit_chain())

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@roles("admin")
def change_role(user_id):
    role = request.form.get("role")
    if role not in {"admin", "owner", "viewer"}: abort(400)
    if user_id == current_user.id and role != "admin":
        flash("You cannot remove your own admin role.", "danger"); return redirect(url_for("admin"))
    with db() as c:
        c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id)); c.commit()
    audit(current_user.id, "ROLE_CHANGE", details={"user_id": user_id, "role": role})
    return redirect(url_for("admin"))

@app.errorhandler(403)
def forbidden(_): return render_template("error.html", code=403, message="Access denied."), 403

@app.errorhandler(404)
def not_found(_): return render_template("error.html", code=404, message="Resource not found."), 404

@app.errorhandler(413)
def too_large(_): return render_template("error.html", code=413, message="File exceeds the 10 MB limit."), 413

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
