# ================================================================
#  HAESSA Component Dashboard – PostgreSQL/SQLite compatible build
# ================================================================

import os
import json
from datetime import datetime, date, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin
import calendar as pycalendar
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, current_app
)
from markupsafe import Markup

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash


# ---------------------------------------------------------------
#  DATABASE CONFIG (AUTO SWITCH: SQLite locally, PostgreSQL on Render)
# ---------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "haessa_secret_key")

base_dir = os.path.abspath(os.path.dirname(__file__))
sqlite_path = f"sqlite:///{os.path.join(base_dir, 'components.db')}"

DATABASE_URL = os.environ.get("DATABASE_URL", sqlite_path)

# Fix Render’s "postgres://" → "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Allow SQLite threading
if DATABASE_URL.startswith("sqlite"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"check_same_thread": False}
    }

db = SQLAlchemy(app)

print(f"\n📌 Using database: {app.config['SQLALCHEMY_DATABASE_URI']}\n")


# ---------------------------------------------------------------
# LOGIN MANAGER
# ---------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="viewer")

    updated_at = db.Column(db.DateTime)
    updated_by = db.Column(db.String(120))

    def set_password(self, raw):
        self.password = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password, raw)


class Components(db.Model):
    __tablename__ = "components"

    id = db.Column(db.Integer, primary_key=True)
    Item_no = db.Column(db.String(50), nullable=True)
    Coach_no = db.Column(db.String(50))
    Section = db.Column(db.String(100))
    Component = db.Column(db.String(200))
    Supplier = db.Column(db.String(200))
    Quantity = db.Column(db.Integer)
    Lead_time = db.Column(db.Integer)
    CTED_order_date = db.Column(db.String(50))
    CTED_due_date = db.Column(db.String(50))
    HAESSA_order_date = db.Column(db.String(50))
    HAESSA_delivery_date = db.Column(db.String(50))
    HAESSA_pay_date = db.Column(db.String(50))
    Component_status = db.Column(db.String(50))
    Notes = db.Column(db.String(300))

    def safe_date(self, value):
        """Parse flexible date formats."""
        if not value:
            return None
        if isinstance(value, date):
            return value
        try_formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"]
        for fmt in try_formats:
            try:
                return datetime.strptime(value, fmt).date()
            except:
                continue
        return None


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(120))
    action = db.Column(db.String(200))
    target = db.Column(db.String(200))

    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)

    @property
    def old_value_json(self):
        try: return json.loads(self.old_value or "{}")
        except: return {}

    @property
    def new_value_json(self):
        try: return json.loads(self.new_value or "{}")
        except: return {}


# ---------------------------------------------------------------
# UNIFIED AUDIT LOGGER
# ---------------------------------------------------------------
def log_action(username, action, target, old=None, new=None):
    try:
        entry = AuditLog(
            username=username,
            action=action,
            target=target,
            old_value=json.dumps(old or {}, default=str, indent=2),
            new_value=json.dumps(new or {}, default=str, indent=2),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        print("⚠ Audit logging failed:", e)
        db.session.rollback()


# ---------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------
@login_manager.user_loader
def load_user(uid):
    try:
        return User.query.get(int(uid))
    except:
        return None


def safe_redirect(url):
    if not url:
        return False
    host = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, url))
    return (host.scheme, host.netloc) == (test.scheme, test.netloc)


def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*a, **kw):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.role not in roles:
                flash("No permission for this page.", "danger")
                return redirect(url_for("home"))
            return fn(*a, **kw)
        return decorated
    return wrapper


# ---------------------------------------------------------------
# INITIAL SETUP (SAFE FOR POSTGRES + SQLITE)
# ---------------------------------------------------------------
def init_app():
    with app.app_context():
        db.create_all()

        # Ensure admin exists
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("Admin@123")
            admin.updated_at = datetime.utcnow()
            admin.updated_by = "system"
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created")

init_app()


# ---------------------------------------------------------------
# CONTEXT PROCESSORS
# ---------------------------------------------------------------
@app.context_processor
def add_globals():
    return {"datetime": datetime}


# ---------------------------------------------------------------
# ROUTES — HOME PAGE
# ---------------------------------------------------------------
@app.route("/")
@login_required
def home():
    sort = request.args.get("sort", "id")
    direction = request.args.get("dir", "desc")

    sort_column = getattr(Components, sort, Components.id)
    if direction == "desc":
        sort_column = sort_column.desc()

    comps = Components.query.order_by(sort_column).all()

    return render_template("home.html", components=comps, sort=sort, direction=direction)


# ---------------------------------------------------------------
# ADD COMPONENT
# ---------------------------------------------------------------
@app.route("/component/add", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def add_component():

    if request.method == "POST":
        c = Components(
            Item_no=request.form.get("Item_no") or None,
            Coach_no=request.form.get("Coach_no"),
            Section=request.form.get("Section"),
            Component=request.form.get("Component"),
            Supplier=request.form.get("Supplier"),
            Quantity=request.form.get("Quantity") or None,
            Lead_time=request.form.get("Lead_time") or None,
            CTED_order_date=request.form.get("CTED_order_date"),
            CTED_due_date=request.form.get("CTED_due_date"),
            HAESSA_order_date=request.form.get("HAESSA_order_date"),
            HAESSA_delivery_date=request.form.get("HAESSA_delivery_date"),
            HAESSA_pay_date=request.form.get("HAESSA_pay_date"),
            Notes=request.form.get("Notes"),
        )

        db.session.add(c)
        db.session.commit()

        log_action(current_user.username, "Added component", f"Component {c.id}", new=c.Item_no)

        flash("Component added.", "success")
        return redirect(url_for("home"))

    return render_template("add_component.html")


# ---------------------------------------------------------------
# EDIT COMPONENT
# ---------------------------------------------------------------
@app.route("/component/edit/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def edit_component(id):
    c = Components.query.get_or_404(id)

    if request.method == "POST":
        old = {
            "Coach_no": c.Coach_no,
            "Component": c.Component,
            "Supplier": c.Supplier,
        }

        c.Coach_no = request.form.get("Coach_no")
        c.Section = request.form.get("Section")
        c.Component = request.form.get("Component")
        c.Supplier = request.form.get("Supplier")
        c.Quantity = request.form.get("Quantity")
        c.Lead_time = request.form.get("Lead_time")
        c.CTED_order_date = request.form.get("CTED_order_date")
        c.CTED_due_date = request.form.get("CTED_due_date")
        c.HAESSA_order_date = request.form.get("HAESSA_order_date")
        c.HAESSA_delivery_date = request.form.get("HAESSA_delivery_date")
        c.HAESSA_pay_date = request.form.get("HAESSA_pay_date")
        c.Notes = request.form.get("Notes")

        db.session.commit()

        log_action(current_user.username, "Edited component", f"Component {c.id}",
                   old=old, new={"Coach_no": c.Coach_no, "Component": c.Component})

        flash("Component updated.", "success")
        return redirect(url_for("home"))

    return render_template("edit_component.html", component=c)


# ---------------------------------------------------------------
# DELETE COMPONENT (ADMIN ONLY)
# ---------------------------------------------------------------
@app.route("/component/delete/<int:id>")
@login_required
@role_required("admin")
def delete_component(id):
    c = Components.query.get_or_404(id)
    old = {"id": c.id, "Component": c.Component}
    db.session.delete(c)
    db.session.commit()

    log_action(current_user.username, "Deleted component", f"Component {id}", old=old)

    flash("Deleted.", "info")
    return redirect(url_for("home"))


# ===============================================================
#  ANALYTICS ROUTE
# ===============================================================
@app.route("/analytics")
@login_required
def analytics():

    comps = Components.query.all()

    CATEGORY_ORDER = [
        "Incomplete Order Details",
        "Not Ordered",
        "Being Processed",
        "Paid",
        "Overdue",
        "On Time",
        "Unpaid",
    ]

    COLOR_MAP = {
        "Incomplete Order Details": "#6f42c1",
        "Not Ordered": "#6c757d",
        "Being Processed": "#17a2b8",
        "Paid": "#007bff",
        "Overdue": "#dc3545",
        "On Time": "#28a745",
        "Unpaid": "#ffc107",
    }

    coach_summary = defaultdict(lambda: {k: 0 for k in CATEGORY_ORDER})
    overall = {k: 0 for k in CATEGORY_ORDER}

    monthly_buckets = defaultdict(lambda: {"due_total": 0, "on_time": 0})

    for c in comps:

        lead = None
        try:
            lead = int(c.Lead_time) if c.Lead_time else None
        except:
            pass

        cted_order = c.safe_date(c.CTED_order_date)
        cted_due = c.safe_date(c.CTED_due_date)
        h_order = c.safe_date(c.HAESSA_order_date)
        h_delivery = c.safe_date(c.HAESSA_delivery_date)
        h_pay = c.safe_date(c.HAESSA_pay_date)

        # Remove Item_no requirement so autogenerated items not classified as incomplete
        missing = (
            not c.Coach_no or not c.Section or
            not c.Component or not c.Supplier or
            not lead or not cted_due
        )

        if missing:
            category = "Incomplete Order Details"

        elif not cted_order or not h_order:
            category = "Not Ordered"

        elif h_order and cted_order and not h_delivery:
            category = "Being Processed"

        elif h_pay:
            category = "Paid"

        elif h_delivery and h_delivery > cted_due:
            category = "Overdue"

        elif h_delivery and h_delivery <= cted_due:
            category = "On Time"

        else:
            category = "Unpaid"

        coach = c.Coach_no or "Unknown"

        coach_summary[coach][category] += 1
        overall[category] += 1

        # Trendline data
        if cted_due:
            key = cted_due.strftime("%Y-%m")
            monthly_buckets[key]["due_total"] += 1
            if h_delivery and h_delivery <= cted_due:
                monthly_buckets[key]["on_time"] += 1

    # Build charts
    chart_data = []
    for coach, stats in coach_summary.items():
        total = sum(stats.values())
        if total:
            chart_data.append({
                "coach": coach,
                "labels": CATEGORY_ORDER,
                "values": [stats[k] for k in CATEGORY_ORDER],
                "colors": [COLOR_MAP[k] for k in CATEGORY_ORDER],
                "total": total
            })

    overall_chart = {
        "coach": "Overall Summary",
        "labels": CATEGORY_ORDER,
        "values": [overall[k] for k in CATEGORY_ORDER],
        "colors": [COLOR_MAP[k] for k in CATEGORY_ORDER],
        "total": sum(overall.values())
    }

    # Trendline last 12 months
    today = date.today()
    months = []
    for i in range(11, -1, -1):
        y = today.year
        m = today.month - i
        while m <= 0:
            m += 12
            y -= 1
        months.append((y, m))

    monthly_labels = []
    monthly_values = []

    for y, m in months:
        key = f"{y}-{m:02d}"
        bucket = monthly_buckets.get(key, {"due_total": 0, "on_time": 0})
        due = bucket["due_total"]
        on = bucket["on_time"]

        monthly_labels.append(pycalendar.month_abbr[m] + f" {y}")
        monthly_values.append(round(on / due * 100, 1) if due else 0)

    return render_template(
        "analytics.html",
        chart_data=chart_data,
        overall_chart=overall_chart,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values,
        generated_by=current_user.username,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        total_coaches=len(chart_data)
    )


# ===============================================================
# CALENDAR + EVENTS API
# ===============================================================

@app.route("/calendar")
@login_required
def calendar_view():

    comps = Components.query.all()

    summary = {
        "total": len(comps),
        "overdue": sum(
            1 for c in comps
            if c.safe_date(c.HAESSA_delivery_date)
            and c.safe_date(c.CTED_due_date)
            and c.safe_date(c.HAESSA_delivery_date) > c.safe_date(c.CTED_due_date)
        ),
        "delivered": sum(1 for c in comps if c.safe_date(c.HAESSA_delivery_date)),
        "pending": sum(1 for c in comps if not c.safe_date(c.HAESSA_delivery_date)),
        "due_today": sum(
            1 for c in comps if c.safe_date(c.CTED_due_date) == date.today()
        ),
        "upcoming_week": sum(
            1 for c in comps
            if c.safe_date(c.CTED_due_date)
            and 0 < (c.safe_date(c.CTED_due_date) - date.today()).days <= 7
        ),
    }

    return render_template("calendar.html", summary=summary)


@app.route("/api/events")
@login_required
def api_events():

    events = []
    today = date.today()

    for c in Components.query.all():
        due = c.safe_date(c.CTED_due_date)
        if not due:
            continue

        status = c.Component_status or "Unknown"

        events.append({
            "id": c.id,
            "title": f"{c.Component} — {c.Coach_no}",
            "start": due.strftime("%Y-%m-%d"),
            "allDay": True,
            "color": "#dc3545" if status == "Overdue" else "#28a745",
            "extendedProps": {
                "component": c.Component,
                "coach": c.Coach_no,
                "due": c.CTED_due_date,
                "delivery": c.HAESSA_delivery_date,
                "notes": c.Notes or ""
            }
        })

    return jsonify(events)


# ===============================================================
# AUDIT LOGS PAGE
# ===============================================================
@app.route("/audit_logs")
@login_required
@role_required("admin")
def audit_logs():
    page = request.args.get("page", 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template("audit_logs.html", logs=logs)


# ===============================================================
# AUTHENTICATION
# ===============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and user.check_password(request.form["password"]):
            login_user(user)
            log_action(user.username, "User login", "Auth")
            return redirect(url_for("home"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_action(current_user.username, "User logout", "Auth")
    logout_user()
    return redirect(url_for("login"))


# ===============================================================
# USER MANAGEMENT (ADMIN)
# ===============================================================

@app.route("/manage_users")
@login_required
@role_required("admin")
def manage_users():
    page = request.args.get("page", 1, type=int)

    users = User.query.order_by(User.id.asc()).paginate(
        page=page,
        per_page=10,
        error_out=False
    )

    return render_template("manage_users.html", users=users)


@app.route("/add_user", methods=["GET", "POST"])
@login_required
@role_required("admin")   # Only admin can add users
def add_user():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role", "viewer")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
            )
            db.session.add(new_user)
            db.session.commit()
            flash("User added successfully.", "success")
            return redirect(url_for("users"))

    return render_template("add_user.html")


@app.route("/edit_user/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_user(id):

    user = User.query.get_or_404(id)

    if request.method == "POST":

        old = {"username": user.username, "role": user.role}

        user.username = request.form["username"]
        user.role = request.form["role"]
        if request.form["password"]:
            user.set_password(request.form["password"])

        user.updated_at = datetime.utcnow()
        user.updated_by = current_user.username

        db.session.commit()

        log_action(current_user.username, "Edited user", user.username, old=old,
                   new={"username": user.username, "role": user.role})

        flash("Updated.", "success")
        return redirect(url_for("manage_users"))

    return render_template("edit_user.html", user=user)


@app.route("/delete_user/<int:id>")
@login_required
@role_required("admin")
def delete_user(id):

    user = User.query.get_or_404(id)

    if user.username == "admin":
        flash("Cannot delete admin account.", "danger")
        return redirect(url_for("manage_users"))

    old = {"username": user.username, "role": user.role}

    db.session.delete(user)
    db.session.commit()

    log_action(current_user.username, "Deleted user", user.username, old=old)

    flash("User deleted.", "info")
    return redirect(url_for("manage_users"))


# ---------------------------
# Daily CTED Due Summary API
# ---------------------------
@app.route("/daily_summary")
@login_required
def daily_summary():
    today = date.today()

    due_today = Components.query.filter(
        Components.CTED_due_date == today.strftime("%Y-%m-%d")
    ).all()

    results = []
    for c in due_today:
        results.append({
            "id": c.id,
            "item_no": c.Item_no,
            "coach_no": c.Coach_no,
            "section": c.Section,
            "component": c.Component,
            "supplier": c.Supplier,
            "cted_due": c.CTED_due_date,
            "haessa_order": c.HAESSA_order_date,
            "status": c.Component_status,
        })

    return jsonify(results)



# ===============================================================
# RUN
# ===============================================================

if __name__ == "__main__":
    app.run(debug=True)

