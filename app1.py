# app.py — HAESSA Component Dashboard (Option C2)
# Complete single-file Flask app (drop-in). Backup DB before use.
import os
import json
from functools import wraps
from datetime import datetime, date
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, request, redirect, url_for, flash, current_app, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

def compute_component_status(haessa_delivery, cted_due, haessa_order, cted_order):
    # Normalize
    haessa_delivery = haessa_delivery or None
    cted_due = cted_due or None
    haessa_order = haessa_order or None
    cted_order = cted_order or None

    # RULE 4 – If HAESSA order missing but CTED order exists → urgent
    if haessa_order is None and cted_order is not None:
        return ("HAESSA to place order urgently", "darkorange")

    # RULE 5 – If CTED order is missing
    if cted_order is None:
        return ("CTED has not placed order", "lightsalmon")

    # RULE 3 – If any date missing
    if haessa_delivery is None or cted_due is None:
        return ("Incomplete details supplied", "yellow")

    # RULE 1 – Late
    if haessa_delivery > cted_due:
        return ("Late", "red")

    # RULE 2 – On time
    if haessa_delivery <= cted_due:
        return ("On time", "green")

    # Fallback
    return ("Unknown", "grey")




# ----------------
# Config
# ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("HAESSA_SECRET", "haessa_secret_key")

base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, "components.db")

app.config.update({
    "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
    "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"check_same_thread": False}},
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
})
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

print(f"✅ Using SQLite database: {db_path}")

# ----------------
# Models
# ----------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="viewer")

    # audit fields
    updated_at = db.Column(db.DateTime)
    updated_by = db.Column(db.String(100))

    def set_password(self, raw):
        self.password = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password, raw)


class Components(db.Model):
    __tablename__ = "components"
    id = db.Column(db.Integer, primary_key=True)
    Item_no = db.Column(db.String(50))
    Coach_no = db.Column(db.String(50))
    Section = db.Column(db.String(100))
    Component = db.Column(db.String(100))
    Supplier = db.Column(db.String(100))
    Quantity = db.Column(db.Integer, default=9999)
    Lead_time = db.Column(db.Integer)
    CTED_order_date = db.Column(db.String(50), default="1/1/1900")
    CTED_due_date = db.Column(db.String(50), default="1/1/1900")
    HAESSA_order_date = db.Column(db.String(50), default="1/1/1900")
    HEASSA_pay_date = db.Column(db.String(50), default="1/1/1900")
    HAESSA_delivery_date = db.Column(db.String(50), default="1/1/1900")
    Component_status = db.Column(db.String(50))
    Notes = db.Column(db.String(200))

    def safe_date(self, value):
        if not value:
            return None
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"):
                try:
                    return datetime.strptime(s, fmt).date()
                except ValueError:
                    continue
        return None


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    action = db.Column(db.String(200))
    target_type = db.Column(db.String(100))
    target_id = db.Column(db.String(50))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    route = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------
# Helpers
# ----------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


def log_action(username, action, target_type, target_id=None, old=None, new=None):
    """Record an audit log entry and commit immediately."""
    try:
        entry = AuditLog(
            username=username,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            old_value=json.dumps(old, default=str, indent=2) if old else None,
            new_value=json.dumps(new, default=str, indent=2) if new else None,
            route=request.path,
            ip_address=request.remote_addr,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # keep app working even if logging fails
        print("⚠️ Failed to write audit log:", e)
        db.session.rollback()


def is_safe_redirect_url(target):
    if not target:
        return False
    host_url = request.host_url
    test_url = urljoin(host_url, target)
    parsed = urlparse(host_url)
    parsed_test = urlparse(test_url)
    return (parsed.scheme, parsed.netloc) == (parsed_test.scheme, parsed_test.netloc)


def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login", next=request.path))
            if current_user.role not in roles:
                flash("You don’t have permission to access this page.", "danger")
                return redirect(url_for("home"))
            return fn(*args, **kwargs)
        return decorated
    return wrapper


# SQLite safe column add helper
def ensure_sqlite_columns():
    """Add users.updated_at and users.updated_by if missing (SQLite)."""
    try:
        with app.app_context():
            result = db.session.execute(text("PRAGMA table_info('users')")).fetchall()
            cols = [r[1] for r in result]
            if "updated_at" not in cols:
                db.session.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
                db.session.commit()
                print("✅ Added users.updated_at")
            if "updated_by" not in cols:
                db.session.execute(text("ALTER TABLE users ADD COLUMN updated_by VARCHAR(100)"))
                db.session.commit()
                print("✅ Added users.updated_by")
    except Exception as e:
        # Don't crash on alter table if DB already has columns or PRAGMA errors
        print("⚠️ Could not add column to users:", e)
        db.session.rollback()


# App bootstrap
def init_app():
    print("💥 init_app() running")
    with app.app_context():
        db.create_all()
        # attempt to add missing user audit columns (safe)
        ensure_sqlite_columns()
        # create default admin if missing
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password(os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin@123"))
            admin.updated_at = datetime.utcnow()
            admin.updated_by = "system"
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created")
        # seed sample components (if none)
        if Components.query.count() == 0:
            sample = Components(
                Item_no="C001",
                Coach_no="10M50832T",
                Section="Electrical",
                Component="Power Supply Unit",
                Supplier="TransTech Ltd",
                Quantity=4,
                Lead_time=30,
                CTED_order_date="2025-10-15",
                CTED_due_date="2025-11-15",
                HAESSA_order_date="2025-10-20",
                HAESSA_delivery_date="2025-11-10",
                HEASSA_pay_date="2025-11-05",
                Component_status="Delivered",
                Notes="Seed entry"
            )
            db.session.add(sample)
            db.session.commit()
            print("✅ Sample component added")


init_app()


# Make datetime available in templates
@app.context_processor
def inject_globals():
    return {"datetime": datetime, "current_app": current_app}


# ----------------
# Routes - core
# ----------------
@app.route("/")
@login_required
def home():
    components = Components.query.order_by(Components.id.desc()).limit(200).all()
    return render_template("home.html", components=components)


# -- Components CRUD
@app.route("/component/add", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def add_component():
    if request.method == "POST":
        c = Components(
            Item_no=request.form.get("Item_no"),
            Coach_no=request.form.get("Coach_no"),
            Section=request.form.get("Section"),
            Component=request.form.get("Component"),
            Supplier=request.form.get("Supplier"),
            Quantity=(request.form.get("Quantity") or None),
            Lead_time=(request.form.get("Lead_time") or None),
            CTED_order_date=request.form.get("CTED_order_date"),
            CTED_due_date=request.form.get("CTED_due_date"),
            HAESSA_order_date=request.form.get("HAESSA_order_date"),
            HAESSA_delivery_date=request.form.get("HAESSA_delivery_date"),
            HEASSA_pay_date=request.form.get("HEASSA_pay_date"),
            Component_status=request.form.get("Component_status"),
            Notes=request.form.get("Notes"),
        )
        db.session.add(c)
        db.session.commit()
        log_action(current_user.username, "Added component", "Component", target_id=c.id, new={
            "Item_no": c.Item_no, "Coach_no": c.Coach_no
        })
        flash("Component added", "success")
        return redirect(url_for("home"))
    return render_template("add_component.html")


@app.route("/component/edit/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def edit_component(id):
    c = Components.query.get_or_404(id)
    if request.method == "POST":
        old = {"Item_no": c.Item_no, "Component": c.Component, "Component_status": c.Component_status}
        c.Item_no = request.form.get("Item_no")
        c.Coach_no = request.form.get("Coach_no")
        c.Component = request.form.get("Component")
        c.Component_status = request.form.get("Component_status")
        db.session.commit()
        log_action(current_user.username, "Edited component", "Component", target_id=c.id, old=old, new={
            "Item_no": c.Item_no, "Component": c.Component, "Component_status": c.Component_status
        })
        flash("Component updated", "success")
        return redirect(url_for("home"))
    return render_template("edit_component.html", component=c)


@app.route("/component/delete/<int:id>", methods=["POST", "GET"])
@login_required
@role_required("admin", "editor")
def delete_component(id):
    c = Components.query.get_or_404(id)
    old = {"id": c.id, "Item_no": c.Item_no}
    db.session.delete(c)
    db.session.commit()
    log_action(current_user.username, "Deleted component", "Component", target_id=id, old=old)
    flash("Component deleted", "info")
    return redirect(url_for("home"))


# ----------------
# Analytics / calendar
# ----------------
@app.route("/analytics")
@login_required
def analytics():
    components = Components.query.all()

    # -------------------------
    # 1. Overall status counts
    # -------------------------
    overall_counts = {}
    for c in components:
        s = (c.Component_status or "Unknown").strip()
        overall_counts[s] = overall_counts.get(s, 0) + 1

    overall = {
        "labels": list(overall_counts.keys()),
        "values": list(overall_counts.values()),
    }

    # -------------------------
    # 2. Per-coach breakdown
    # -------------------------
    coach_data = {}
    for c in components:
        coach = c.Coach_no or "Unknown"
        status = (c.Component_status or "Unknown").strip()

        if coach not in coach_data:
            coach_data[coach] = {}

        coach_data[coach][status] = coach_data[coach].get(status, 0) + 1

    # Convert to flat list usable by template
    per_coach = []
    for coach, stats in coach_data.items():
        per_coach.append({
            "coach": coach,
            "labels": list(stats.keys()),
            "values": list(stats.values())
        })

    # -------------------------
    # 3. Weekly trend (dummy example)
    # -------------------------
    weekly_labels = ["Week 1", "Week 2", "Week 3", "Week 4"]
    weekly_values = [85, 92, 78, 95]  # You can replace with real processing later

    # -------------------------
    # 4. Monthly trend (dummy example)
    # -------------------------
    monthly_labels = ["Jan", "Feb", "Mar", "Apr", "May"]
    monthly_values = [90, 88, 95, 93, 91]

    return render_template(
        "analytics.html",
        overall=overall,
        per_coach=per_coach,
        weekly_labels=weekly_labels,
        weekly_values=weekly_values,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values
    
    
    )
def classify_component(c):
    """
    Determines status caption + color for each component.
    """

    haessa_delivery = c.HAESSA_delivery_date
    cted_due = c.CTED_due_date
    haessa_order = c.HAESSA_order_date
    cted_order = c.CTED_order_date

    # -------------------------------
    # RULE 4 — HAESSA order missing
    # -------------------------------
    if haessa_order is None:
        return {
            "status": "HAESSA to place order urgently",
            "color": "#ff8c00"
        }

    # -------------------------------
    # RULE 5 — CTED order missing
    # -------------------------------
    if cted_order is None:
        return {
            "status": "CTED has not placed order",
            "color": "#ffa500"
        }

    # ------------------------------------
    # RULE 3 — Any date missing (incomplete)
    # ------------------------------------
    if haessa_delivery is None or cted_due is None:
        return {
            "status": "Incomplete details supplied",
            "color": "#ffc107"
        }

    # -------------------------------
    # RULE 1 — Late
    # -------------------------------
    if haessa_delivery > cted_due:
        return {
            "status": "Late",
            "color": "#dc3545"
        }

    # -------------------------------
    # RULE 2 — On time
    # -------------------------------
    return {
        "status": "On Time",
        "color": "#28a745"
    }




@app.route("/calendar")
@login_required
def calendar():
    items = Components.query.all()
    events = []
    for c in items:
        events.append({"title": c.Component or c.Item_no or "Item", "start": (c.CTED_due_date or "")})
    return render_template("calendar.html", events=events)


# ----------------
# Authentication
# ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_action(user.username, "User login", "Auth")
            flash(f"Welcome, {user.username}!", "success")
            next_url = request.args.get("next") or request.form.get("next")
            if next_url and is_safe_redirect_url(next_url):
                return redirect(next_url)
            return redirect(url_for("home"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_action(current_user.username, "User logout", "Auth")
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ----------------
# User management (admin-only)
# ----------------
@app.route("/manage_users")
@login_required
@role_required("admin")
def manage_users():
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()
    sort = request.args.get("sort", "username")
    per_page = min(max(int(request.args.get("per_page", 10)), 1), 100)

    qry = User.query
    if q:
        qry = qry.filter(User.username.ilike(f"%{q}%"))
    if sort == "updated_at":
        qry = qry.order_by(User.updated_at.desc().nullslast())
    elif sort == "role":
        qry = qry.order_by(User.role, User.username)
    else:
        qry = qry.order_by(User.username)

    users = qry.paginate(page=page, per_page=per_page)
    return render_template("manage_users.html", users=users, q=q, sort=sort, per_page=per_page)


@app.route("/users")
@login_required
@role_required("admin")
def users_redirect():
    return redirect(url_for("manage_users"))


@app.route("/add_user", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("add_user"))
        if User.query.filter_by(username=username).first():
            flash("That username already exists.", "warning")
            return redirect(url_for("add_user"))
        new = User(username=username, role=role)
        new.set_password(password)
        new.updated_at = datetime.utcnow()
        new.updated_by = current_user.username if current_user.is_authenticated else "system"
        db.session.add(new)
        db.session.commit()
        log_action(current_user.username if current_user.is_authenticated else "system", "Added user", "User", target_id=new.id, new={"username": new.username, "role": new.role})
        flash("User created", "success")
        return redirect(url_for("manage_users"))
    return render_template("add_user.html")


@app.route("/edit_user/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == "POST":
        old = {"username": user.username, "role": user.role}
        new_username = request.form.get("username", "").strip()
        new_role = request.form.get("role", "").strip()
        new_password = request.form.get("password", "")

        if new_username and new_username != user.username:
            if User.query.filter(User.username == new_username, User.id != user.id).first():
                flash("Username already taken by another user.", "warning")
                return redirect(url_for("edit_user", id=user.id))
            user.username = new_username

        if new_role:
            user.role = new_role

        if new_password and new_password.strip():
            user.set_password(new_password)

        user.updated_at = datetime.utcnow()
        user.updated_by = current_user.username
        db.session.commit()

        log_action(current_user.username, f"Edited user {user.username}", "User", target_id=user.id, old=old, new={"username": user.username, "role": user.role})
        flash("User updated successfully.", "success")
        return redirect(url_for("manage_users"))

    return render_template("edit_user.html", user=user)


@app.route("/delete_user/<int:id>", methods=["POST", "GET"])
@login_required
@role_required("admin")
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.username == "admin":
        flash("Cannot delete the main 'admin' account.", "danger")
        return redirect(url_for("manage_users"))
    old = {"username": user.username, "role": user.role}
    db.session.delete(user)
    db.session.commit()
    log_action(current_user.username, f"Deleted user {user.username}", "User", target_id=id, old=old)
    flash("User deleted.", "info")
    return redirect(url_for("manage_users"))


@app.route("/create_users")
def create_users():
    defaults = [
        {"username": "viewer", "password": "viewer123_HAESSA", "role": "viewer"},
        {"username": "editor", "password": "editor123_HAESSA", "role": "editor"},
        {"username": "admin", "password": os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin@123"), "role": "admin"},
    ]
    created = []
    for u in defaults:
        if not User.query.filter_by(username=u["username"]).first():
            user = User(username=u["username"], role=u["role"])
            user.set_password(u["password"])
            user.updated_at = datetime.utcnow()
            user.updated_by = "system"
            db.session.add(user)
            created.append(u["username"])
    db.session.commit()
    return f"✅ Default users created (if missing): {', '.join(created)}"


@app.route("/audit_logs")
@login_required
@role_required("admin")
def audit_logs():
    page = request.args.get("page", 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template("audit_logs.html", logs=logs)


# ----------------
# Run
# ----------------
if __name__ == "__main__":
    print("🚀 Starting HAESSA server...")
    app.run(debug=True)
