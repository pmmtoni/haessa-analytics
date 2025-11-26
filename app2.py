# app.py — Cleaned HAESSA Component Dashboard (single-file)
import os
import json
import calendar as pycalendar
from collections import defaultdict
from functools import wraps
from datetime import datetime, date, timedelta
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, request, redirect, url_for, flash, current_app, abort,
    jsonify 
)
from markupsafe import Markup

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

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

# -----------------------------
# Jinja Filters
# -----------------------------
@app.template_filter("fromjson")
def fromjson_filter(value):
    """Convert JSON string → Python dict safely in templates."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}

@app.template_filter("audit_diff")
def audit_diff_filter(log):
    """
    Return an HTML snippet highlighting changes (red = old, green = new).
    Accepts either an AuditLog object or dict with old_value/new_value.
    """
    try:
        old_raw = getattr(log, "old_value", None) or "{}"
        new_raw = getattr(log, "new_value", None) or "{}"
        old = json.loads(old_raw)
        new = json.loads(new_raw)
    except Exception:
        old = {}
        new = {}

    out = ["<div class='audit-diff'>"]
    keys = sorted(set(old.keys()) | set(new.keys()))
    if not keys:
        out.append("<em>No details</em>")
    for k in keys:
        ov = old.get(k)
        nv = new.get(k)
        if ov == nv:
            continue
        out.append("<div class='mb-2'>")
        out.append(f"<strong>{k}</strong><br>")
        out.append(f"<div style='display:flex;gap:1rem'><div style='flex:1;padding:.25rem;border-radius:.25rem;background:#ffecec;color:#a94442'>Old: {Markup.escape(str(ov))}</div>")
        out.append(f"<div style='flex:1;padding:.25rem;border-radius:.25rem;background:#e9ffe9;color:#2b7a2b'>New: {Markup.escape(str(nv))}</div></div>")
        out.append("</div><hr/>")
    out.append("</div>")
    return Markup("".join(out))


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
    CTED_order_date = db.Column(db.String(50), default=None)
    CTED_due_date = db.Column(db.String(50), default=None)
    HAESSA_order_date = db.Column(db.String(50), default=None)
    HAESSA_pay_date = db.Column(db.String(50), default=None)
    HAESSA_delivery_date = db.Column(db.String(50), default=None)
    Component_status = db.Column(db.String(50))
    Notes = db.Column(db.String(200))

    def safe_date(self, value):
        """Parse common date strings to date object or return None."""
        if not value:
            return None
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value
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
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # core info
    username = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    target_type = db.Column(db.String(100), nullable=True)
    target_id = db.Column(db.String(50), nullable=True)

    # details
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)

    # request context
    route = db.Column(db.String(200), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)

    @property
    def old_value_json(self):
        try:
            return json.loads(self.old_value or "{}")
        except Exception:
            return {}

    @property
    def new_value_json(self):
        try:
            return json.loads(self.new_value or "{}")
        except Exception:
            return {}


# ----------------
# Helpers
# ----------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


def log_action(username, action, target_type=None, target_id=None, old=None, new=None, route=None, ip_address=None):
    """
    Centralised audit logger. Use everywhere instead of direct model writes.
    Fields:
        username, action, target_type, target_id, old (dict), new (dict), route, ip_address
    """
    try:
        entry = AuditLog(
            username=username or "system",
            action=action or "",
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            old_value=json.dumps(old or {}, default=str),
            new_value=json.dumps(new or {}, default=str),
            route=route or (request.path if request else None),
            ip_address=ip_address or (request.remote_addr if request else None)
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
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


# ----------------
# Business logic: compute status & colour (server-side)
# ----------------
def compute_component_status(component: Components):
    """
    Rules (applied in this order):
    - If CTED_order_date missing -> "CTED has not placed order"
    - If HAESSA_order_date missing and CTED_order_date present -> "HAESSA to place order urgently"
    - If any of (HAESSA_delivery_date, CTED_due_date, Lead_time) missing -> "Incomplete details supplied"
    - If HAESSA_delivery_date > CTED_due_date -> "Late"
    - Else -> "On time"
    """
    haessa_delivery = component.safe_date(component.HAESSA_delivery_date)
    cted_due = component.safe_date(component.CTED_due_date)
    haessa_order = component.safe_date(component.HAESSA_order_date)
    cted_order = component.safe_date(component.CTED_order_date)
    lead_time = component.Lead_time

    if cted_order is None:
        return {"label": "CTED has not placed order", "color": "lightsalmon"}

    if haessa_order is None and cted_order is not None:
        return {"label": "HAESSA to place order urgently", "color": "darkorange"}

    if haessa_delivery is None or cted_due is None or (lead_time is None):
        return {"label": "Incomplete details supplied", "color": "yellow"}

    try:
        if haessa_delivery > cted_due:
            return {"label": "Late", "color": "red"}
    except Exception:
        pass

    try:
        if haessa_delivery <= cted_due:
            return {"label": "On time", "color": "green"}
    except Exception:
        pass

    return {"label": "Unknown", "color": "grey"}


# ----------------
# SQLite housekeeping: ensure audit_log table / columns exist
# ----------------
def ensure_auditlog_columns():
    """
    Ensure audit_log exists and has required columns.
    If an older table named 'audit_logs' exists, rename it.
    Add missing columns with ALTER TABLE when possible.
    """
    try:
        with app.app_context():
            # Create any missing tables first (no-op if present)
            db.create_all()

            # Check for audit_log metadata
            info = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('audit_log','audit_logs')")).fetchall()
            names = {r[0] for r in info}

            # If old table audit_logs exists but not audit_log, rename it
            if "audit_logs" in names and "audit_log" not in names:
                db.session.execute(text("ALTER TABLE audit_logs RENAME TO audit_log"))
                db.session.commit()
                print("✅ Renamed 'audit_logs' → 'audit_log'")

            # Now ensure required columns exist in audit_log
            cols = [r[1] for r in db.session.execute(text("PRAGMA table_info('audit_log')")).fetchall()]
            required = {
                "username": "VARCHAR(120)",
                "action": "VARCHAR(200)",
                "target_type": "VARCHAR(100)",
                "target_id": "VARCHAR(50)",
                "old_value": "TEXT",
                "new_value": "TEXT",
                "route": "VARCHAR(200)",
                "ip_address": "VARCHAR(50)",
                "timestamp": "DATETIME"
            }
            for col, coltype in required.items():
                if col not in cols:
                    # ALTER to add column; timestamp default already may exist
                    db.session.execute(text(f"ALTER TABLE audit_log ADD COLUMN {col} {coltype}"))
                    db.session.commit()
                    print(f"✅ Added audit_log.{col}")
    except Exception as e:
        print("⚠️ Could not ensure audit_log columns:", e)
        db.session.rollback()


# ----------------
# App bootstrap / seed
# ----------------
def init_app():
    print("💥 init_app() running")
    with app.app_context():
        db.create_all()
        # ensure users table extra columns
        try:
            result = db.session.execute(text("PRAGMA table_info('users')")).fetchall()
            cols = [r[1] for r in result]
            if "updated_at" not in cols:
                db.session.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
                db.session.commit()
            if "updated_by" not in cols:
                db.session.execute(text("ALTER TABLE users ADD COLUMN updated_by VARCHAR(100)"))
                db.session.commit()
        except Exception:
            db.session.rollback()

        # ensure audit table and columns
        ensure_auditlog_columns()

        # ensure admin user
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password(os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin@123"))
            admin.updated_at = datetime.utcnow()
            admin.updated_by = "system"
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created")

        # seed sample components if none
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
                HAESSA_pay_date="2025-11-05",
                Component_status="Delivered",
                Notes="Seed entry"
            )
            db.session.add(sample)
            db.session.commit()
            print("✅ Sample component added")


init_app()

# expose datetime and helpers to templates
@app.context_processor
def inject_globals():
    return {
        "datetime": datetime,
        "current_app": current_app,
        "compute_component_status": compute_component_status
    }


# ----------------
# Routes - core
# ----------------
@app.route("/")
@login_required
def home():
    """
    Option B: allow all logged-in users to view the home page.
    Buttons (Add/Edit/Delete) should be shown/hidden by template based on role.
    """
    components = Components.query.order_by(Components.id.desc()).limit(200).all()
    comps = []
    for c in components:
        st = compute_component_status(c)
        comps.append({
            "id": c.id,
            "Item_no": c.Item_no,
            "Coach_no": c.Coach_no,
            "Section": c.Section,
            "Component": c.Component,
            "Component_status": st["label"],
            "status_color": st["color"],
            "CTED_due_date": c.CTED_due_date,
            "HAESSA_delivery_date": c.HAESSA_delivery_date,
            "Lead_time": c.Lead_time,
        })
    return render_template("home.html", components=comps)


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
            CTED_order_date=request.form.get("CTED_order_date") or None,
            CTED_due_date=request.form.get("CTED_due_date") or None,
            HAESSA_order_date=request.form.get("HAESSA_order_date") or None,
            HAESSA_delivery_date=request.form.get("HAESSA_delivery_date") or None,
            HAESSA_pay_date=request.form.get("HAESSA_pay_date") or None,
            Component_status=request.form.get("Component_status"),
            Notes=request.form.get("Notes"),
        )
        computed = compute_component_status(c)
        c.Component_status = computed["label"]
        db.session.add(c)
        db.session.commit()
        log_action(current_user.username, "Added component", "Component", target_id=c.id, new={"Item_no": c.Item_no, "Coach_no": c.Coach_no})
        flash("Component added", "success")
        return redirect(url_for("home"))
    return render_template("add_component.html")


@app.route("/component/edit/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def edit_component(id):
    c = Components.query.get_or_404(id)
    if request.method == "POST":
        old = {
            "Item_no": c.Item_no,
            "Component": c.Component,
            "Component_status": c.Component_status,
            "Coach_no": c.Coach_no,
            "Section": c.Section,
            "Supplier": c.Supplier,
            "Quantity": c.Quantity,
            "Lead_time": c.Lead_time,
            "CTED_order_date": c.CTED_order_date,
            "CTED_due_date": c.CTED_due_date,
            "HAESSA_order_date": c.HAESSA_order_date,
            "HAESSA_delivery_date": c.HAESSA_delivery_date,
            "HAESSA_pay_date": c.HAESSA_pay_date,
            "Notes": c.Notes
        }
        # update fields from form
        c.Item_no = request.form.get("Item_no")
        c.Coach_no = request.form.get("Coach_no")
        c.Section = request.form.get("Section")
        c.Component = request.form.get("Component")
        c.Supplier = request.form.get("Supplier")
        c.Quantity = request.form.get("Quantity") or None
        c.Lead_time = request.form.get("Lead_time") or None
        c.CTED_order_date = request.form.get("CTED_order_date") or None
        c.CTED_due_date = request.form.get("CTED_due_date") or None
        c.HAESSA_order_date = request.form.get("HAESSA_order_date") or None
        c.HAESSA_delivery_date = request.form.get("HAESSA_delivery_date") or None
        c.HAESSA_pay_date = request.form.get("HAESSA_pay_date") or None
        # status not edited by form per your request — but if present, allow it
        c.Component_status = request.form.get("Component_status") or compute_component_status(c)["label"]
        c.Notes = request.form.get("Notes")
        computed = compute_component_status(c)
        c.Component_status = computed["label"]
        db.session.commit()
        log_action(current_user.username, "Edited component", "Component", target_id=c.id, old=old, new={
            "Item_no": c.Item_no,
            "Component": c.Component,
            "Component_status": c.Component_status,
            "Coach_no": c.Coach_no
        })
        flash("Component updated", "success")
        return redirect(url_for("home"))
    st = compute_component_status(c)
    return render_template("edit_component.html", component=c, computed_status=st)


@app.route("/component/delete/<int:id>", methods=["POST", "GET"])
@login_required
@role_required("admin")
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
    comps = Components.query.all()
    category_labels = [
        "Incomplete Order Details",
        "Not Ordered",
        "Being Processed",
        "Paid",
        "Overdue",
        "On Time",
        "Unpaid"
    ]
    coach_summary = defaultdict(lambda: {k: 0 for k in category_labels})
    overall = {k: 0 for k in category_labels}
    monthly_buckets = defaultdict(lambda: {"due_total": 0, "on_time": 0})

    def is_incomplete(c):
        keys = [c.Item_no, c.Coach_no, c.Section, c.Component]
        if any(not k for k in keys):
            return True
        if not c.Lead_time or int(c.Lead_time or 0) == 0:
            return True
        return False

    for c in comps:
        coach = c.Coach_no or "Unknown Coach"
        cted_due = c.safe_date(c.CTED_due_date)
        cted_order = c.safe_date(c.CTED_order_date)
        haessa_order = c.safe_date(c.HAESSA_order_date)
        haessa_delivery = c.safe_date(c.HAESSA_delivery_date)
        haessa_pay = c.safe_date(c.HAESSA_pay_date)
        lead_time = int(c.Lead_time or 0)

        if cted_due:
            key = cted_due.strftime("%Y-%m")
            monthly_buckets[key]["due_total"] += 1
            if haessa_delivery and haessa_delivery <= cted_due:
                monthly_buckets[key]["on_time"] += 1

        if is_incomplete(c):
            cat = "Incomplete Order Details"
        elif (not cted_order) or (not haessa_order):
            cat = "Not Ordered"
        elif cted_order and haessa_order and (not haessa_delivery):
            cat = "Being Processed"
        elif haessa_pay:
            cat = "Paid"
        elif haessa_delivery and cted_due:
            cat = "Overdue" if haessa_delivery > cted_due else "On Time"
        elif (not haessa_pay):
            cat = "Unpaid"
        else:
            cat = "On Time"

        coach_summary[coach][cat] += 1
        overall[cat] += 1

    chart_data = []
    for coach, stats in coach_summary.items():
        total = sum(stats.values())
        if total == 0:
            continue
        labels = list(stats.keys())
        values = [int(stats[k]) for k in labels]
        chart_data.append({
            "coach": str(coach),
            "labels": labels,
            "values": values,
            "total": int(total)
        })

    overall_labels = list(overall.keys())
    overall_values = [int(overall[k]) for k in overall_labels]
    overall_chart = {
        "coach": "Overall HAESSA Summary",
        "labels": overall_labels,
        "values": overall_values,
        "total": int(sum(overall_values))
    }

    N = 12
    today = date.today()
    months = []
    for i in range(N-1, -1, -1):
        year = today.year
        month = today.month - i
        while month <= 0:
            month += 12
            year -= 1
        months.append((year, month))

    monthly_labels = []
    monthly_values = []
    for (y, m) in months:
        key = f"{y}-{m:02d}"
        monthly_labels.append(pycalendar.month_abbr[m] + f" {y}")
        bucket = monthly_buckets.get(key, {"due_total": 0, "on_time": 0})
        due_total = bucket["due_total"] or 0
        on_time = bucket["on_time"] or 0
        pct = round((on_time / due_total * 100), 1) if due_total > 0 else 0.0
        monthly_values.append(pct)

    chart_data = sorted(chart_data, key=lambda x: x["coach"])

    ctx = {
        "chart_data": chart_data,
        "overall_chart": overall_chart,
        "monthly_labels": monthly_labels,
        "monthly_values": monthly_values,
        "generated_by": current_user.username if current_user else "Unknown",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_coaches": len(chart_data)
    }

    return render_template("analytics.html", **ctx)


# ----------------
# Calendar
# ----------------
@app.route("/calendar")
@login_required
def calendar_view():
    comps = Components.query.all()

    total = len(comps)
    overdue = sum(1 for c in comps if c.safe_date(c.HAESSA_delivery_date) and c.safe_date(c.CTED_due_date) and c.safe_date(c.HAESSA_delivery_date) > c.safe_date(c.CTED_due_date))
    delivered = sum(1 for c in comps if c.safe_date(c.HAESSA_delivery_date))
    pending = sum(1 for c in comps if not c.safe_date(c.HAESSA_delivery_date))
    due_today = sum(1 for c in comps if c.safe_date(c.CTED_due_date) == date.today())
    upcoming_week = sum(1 for c in comps if c.safe_date(c.CTED_due_date) and 0 < (c.safe_date(c.CTED_due_date) - date.today()).days <= 7)

    summary = {
        "total": total,
        "overdue": overdue,
        "delivered": delivered,
        "pending": pending,
        "due_today": due_today,
        "upcoming_week": upcoming_week,
    }

    return render_template("calendar.html", summary=summary)


@app.route("/api/events")
@login_required
def api_events():
    events = []
    comps = Components.query.all()
    today = date.today()
    for c in comps:
        due = c.safe_date(c.CTED_due_date)
        if not due:
            continue
        title = f"{c.Component or 'NoComponent'} — {c.Coach_no or 'NoCoach'}"
        status = (c.Component_status or "Unknown").strip()
        color_map = {
            "Overdue": "#dc3545",
            "Due Soon": "#ffc107",
            "On Time": "#28a745",
            "Paid": "#007bff",
            "Being Processed": "#17a2b8",
            "Incomplete Order Details": "#6f42c1",
            "Not Ordered": "#6c757d",
            "Unknown": "#adb5bd"
        }
        derived_status = status
        if c.safe_date(c.HAESSA_delivery_date) and c.safe_date(c.CTED_due_date) and c.safe_date(c.HAESSA_delivery_date) > c.safe_date(c.CTED_due_date):
            derived_status = "Overdue"
        elif due:
            if c.safe_date(c.HAESSA_delivery_date) and c.safe_date(c.HAESSA_delivery_date) <= due:
                derived_status = "On Time"
            elif (due - today).days <= 7:
                derived_status = "Due Soon"

        events.append({
            "id": c.id,
            "title": title,
            "start": due.strftime("%Y-%m-%d"),
            "allDay": True,
            "color": color_map.get(derived_status, "#6c757d"),
            "extendedProps": {
                "component": c.Component or "",
                "coach": c.Coach_no or "",
                "cted_due": c.CTED_due_date or "",
                "haessa_delivery": c.HAESSA_delivery_date or "",
                "pay_date": c.HAESSA_pay_date or "",
                "status": derived_status,
                "notes": c.Notes or ""
            }
        })
    return jsonify(events)


# ----------------
# Users / Auth
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
        qry = qry.order_by(User.updated_at.desc())
    elif sort == "role":
        qry = qry.order_by(User.role, User.username)
    else:
        qry = qry.order_by(User.username)

    users = qry.paginate(page=page, per_page=per_page)
    return render_template("manage_users.html", users=users, q=q, sort=sort, per_page=per_page)


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


# ----------------
# Audit logs view & API
# ----------------
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
