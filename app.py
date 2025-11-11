# -*- coding: utf-8 -*-
"""
HAESSA Component Dashboard
Cleaned and simplified single-file Flask app.
Created on Oct 27, 2025 (updated)
@author: Paul
"""

import os
from functools import wraps
from datetime import datetime, timedelta, date
from urllib.parse import urlparse, urljoin

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash


# ----------------------------
# App setup
# ----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("HAESSA_SECRET", "haessa_secret_key")  # set in ENV for prod

# ----------------------------
# Database config (Postgres if DATABASE_URL set, else SQLite)
# ----------------------------
# ------------------------------------------------------------
# ✅ Consistent Local SQLite Database (components.db)
# ------------------------------------------------------------
import os
from flask_sqlalchemy import SQLAlchemy

# Define absolute path to your real database file
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, "components.db")

# Configure Flask SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False}}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)
print(f"✅ Using consistent local SQLite database: {db_path}")


# ----------------------------
# Login manager
# ----------------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ----------------------------
# Models
# ----------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="viewer")  # viewer / editor / admin

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)


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


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# ----------------------------
# Initialize DB and default admin (safe)
# ----------------------------
def ensure_admin_exists():
    try:
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password(os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin@123"))
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created: admin / (password from DEFAULT_ADMIN_PASSWORD or Admin@123)")
    except Exception as e:
        # don't crash app on startup; print helpful message
        print(f"⚠️ Failed to initialize DB or create admin: {e}")


with app.app_context():
    db.create_all()

    # Create admin if missing
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin / Admin@123")

    # Seed sample component data if empty
    if Components.query.count() == 0:
        sample_components = [
            Components(
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
                Notes="Delivered ahead of schedule"
            ),
            Components(
                Item_no="C002",
                Coach_no="10M50835T",
                Section="Mechanical",
                Component="Axle Bearing",
                Supplier="Mekano Engineering",
                Quantity=8,
                Lead_time=45,
                CTED_order_date="2025-09-25",
                CTED_due_date="2025-11-09",
                HAESSA_order_date="2025-09-30",
                HAESSA_delivery_date="2025-11-11",
                HEASSA_pay_date="2025-11-10",
                Component_status="Overdue",
                Notes="Delayed due to supplier backlog"
            ),
        ]
        db.session.bulk_save_objects(sample_components)
        db.session.commit()
        print("✅ Sample components added for demo.")
    print("✅ Database initialization step completed.")


# ----------------------------
# Utilities
# ----------------------------
def is_safe_redirect_url(target):
    """Allow only same-host redirects to prevent open redirect vulnerabilities."""
    if not target:
        return False
    host_url = request.host_url  # includes trailing slash
    test_url = urljoin(host_url, target)
    parsed = urlparse(host_url)
    parsed_test = urlparse(test_url)
    return (parsed.scheme, parsed.netloc) == (parsed_test.scheme, parsed_test.netloc)


def role_required(*roles):
    """Decorator that restricts access based on user roles."""
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


# make datetime available to templates
@app.context_processor
def inject_globals():
    return {"datetime": datetime, "current_app": current_app}


# ----------------------------
# Routes - core
# ----------------------------
@app.route("/")
@login_required
def home():
    components = Components.query.all()
    print(f"✅ Render DB path: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"✅ Components found: {Components.query.count()}")
    return render_template("home.html", components=components)


@app.route("/add", methods=["GET", "POST"])
@role_required("editor", "admin")
def add():
    if request.method == "POST":
        new_component = Components(
            Item_no=request.form.get("Item_no"),
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
            HEASSA_pay_date=request.form.get("HEASSA_pay_date"),
            Component_status=request.form.get("Component_status"),
            Notes=request.form.get("Notes"),
        )
        db.session.add(new_component)
        db.session.commit()
        flash("✅ Component added successfully!", "success")
        return redirect(url_for("home"))
    # Provide dropdowns in the add template if needed
    coaches = [c.Coach_no for c in Components.query.distinct(Components.Coach_no).all() if c.Coach_no]
    sections = [c.Section for c in Components.query.distinct(Components.Section).all() if c.Section]
    components = [c.Component for c in Components.query.distinct(Components.Component).all() if c.Component]
    suppliers = [c.Supplier for c in Components.query.distinct(Components.Supplier).all() if c.Supplier]
    return render_template("add.html", coaches=sorted(set(coaches)),
                           sections=sorted(set(sections)),
                           components=sorted(set(components)),
                           suppliers=sorted(set(suppliers)))


@app.route("/edit/<int:id>", methods=["GET", "POST"])
@role_required("editor", "admin")
def edit(id):
    component = Components.query.get_or_404(id)
    if request.method == "POST":
        for field in ["Item_no", "Coach_no", "Section", "Component", "Supplier",
                      "Quantity", "Lead_time", "CTED_order_date", "CTED_due_date",
                      "HAESSA_order_date", "HAESSA_delivery_date", "HEASSA_pay_date",
                      "Component_status", "Notes"]:
            setattr(component, field, request.form.get(field))
        db.session.commit()
        flash("✅ Component updated successfully!", "success")
        return redirect(url_for("home"))
    return render_template("edit.html", component=component)


@app.route("/delete/<int:id>", methods=["POST", "GET"])
@role_required("editor", "admin")
def delete(id):
    component = Components.query.get_or_404(id)
    db.session.delete(component)
    db.session.commit()
    flash("🗑️ Component deleted successfully!", "info")
    return redirect(url_for("home"))


# ----------------------------
# Analytics / Pie / Calendar (simplified)
# ----------------------------
# ---------------------------------------------------------------------
# ✅ ANALYTICS ROUTE WITH REAL-TIME PERFORMANCE DATA
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# ✅ ANALYTICS ROUTE (Dynamic Coaches + Auto Summary)
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# ✅ ANALYTICS ROUTE (Dynamic Coaches + Auto Summary + Progress Tooltip)
# ---------------------------------------------------------------------
@app.route("/analytics")
@login_required
def analytics():
    try:
        components = Components.query.all()
        print(f"✅ Render DB path: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print(f"✅ Components found: {len(components)}")

        def safe_date(v):
            if not v:
                return None
            if isinstance(v, datetime):
                return v.date()
            for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(v.strip(), fmt).date()
                except Exception:
                    continue
            return None

        # --- 1️⃣ Group by coach ---
        coach_groups = {}
        for c in components:
            coach = c.Coach_no or "Unknown"
            status = (c.Component_status or "Unknown").strip()
            coach_groups.setdefault(coach, {}).setdefault(status, 0)
            coach_groups[coach][status] += 1

        chart_data = []
        for coach, statuses in coach_groups.items():
            labels = list(statuses.keys())
            values = list(statuses.values())
            total = sum(values)
            chart_data.append({
                "coach": coach,
                "labels": labels,
                "values": values,
                "total": total
            })

        # --- 2️⃣ Overall chart ---
        all_statuses = {}
        for c in components:
            status = (c.Component_status or "Unknown").strip()
            all_statuses[status] = all_statuses.get(status, 0) + 1

        overall_chart = {
            "labels": list(all_statuses.keys()),
            "values": list(all_statuses.values()),
            "total": sum(all_statuses.values())
        }

        # --- 3️⃣ Dynamic monthly/weekly trends ---
        monthly_counts = {m: {"On Time": 0, "Late": 0} for m in range(1, 13)}
        weekly_counts = {w: {"On Time": 0, "Late": 0} for w in range(1, 5)}

        for c in components:
            due = safe_date(c.CTED_due_date)
            delivered = safe_date(c.HAESSA_delivery_date)
            if not due or not delivered:
                continue
            month = delivered.month
            week = min((delivered.day - 1) // 7 + 1, 4)
            if delivered <= due:
                monthly_counts[month]["On Time"] += 1
                weekly_counts[week]["On Time"] += 1
            else:
                monthly_counts[month]["Late"] += 1
                weekly_counts[week]["Late"] += 1

        monthly_labels = [datetime(2025, m, 1).strftime("%b") for m in range(1, 13)]
        trend_data = {
            "monthly": {
                "On Time": [monthly_counts[m]["On Time"] for m in range(1, 13)],
                "Late": [monthly_counts[m]["Late"] for m in range(1, 13)],
            },
            "weekly": {
                "On Time": [weekly_counts[w]["On Time"] for w in range(1, 5)],
                "Late": [weekly_counts[w]["Late"] for w in range(1, 5)],
            },
            "labels": monthly_labels
        }

        # --- 4️⃣ Performance summary ---
        total_delivered = sum([monthly_counts[m]["On Time"] + monthly_counts[m]["Late"] for m in range(1, 13)])
        total_ontime = sum([monthly_counts[m]["On Time"] for m in range(1, 13)])
        performance_pct = round((total_ontime / total_delivered) * 100, 1) if total_delivered else 0

        summary_color = (
            "bg-success text-white"
            if performance_pct >= 80 else
            "bg-warning text-dark"
            if performance_pct >= 50 else
            "bg-danger text-white"
        )

        progress_tooltip = f"{total_ontime}/{total_delivered} components delivered on time"

        performance_summary = (
            f"✅ Overall Performance: {performance_pct}% On Time Deliveries "
            f"({total_ontime}/{total_delivered} completed)"
        )

        return render_template(
            "analytics.html",
            chart_data=chart_data,
            overall_chart=overall_chart,
            trend_data=trend_data,
            performance_summary=performance_summary,
            performance_pct=performance_pct,
            progress_tooltip=progress_tooltip,
            summary_color=summary_color,
            generated_by=current_user.username,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    except Exception as e:
        print(f"❌ Error in /analytics: {e}")
        return render_template("analytics.html", error="Analytics data unavailable.")

@app.route("/calendar")
@login_required
def calendar():
    components = Components.query.all()
    today = date.today()
    events = []
    for c in components:
        due = c.safe_date(c.CTED_due_date)
        if not due:
            continue
        color = "#dc3545" if due < today else "#007bff"
        events.append({"title": f"{c.Component} (Coach {c.Coach_no})", "start": due.strftime("%Y-%m-%d"), "color": color})
    return render_template("calendar.html", events=events)


# ----------------------------
# Authentication
# ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"Welcome, {user.username}!", "success")
            # handle next safe redirect
            next_url = request.args.get("next") or request.form.get("next")
            if next_url and is_safe_redirect_url(next_url):
                return redirect(next_url)
            return redirect(url_for("home"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/users")
@login_required
@role_required("admin")
def users():
    all_users = User.query.all()
    return render_template("users.html", users=all_users)


@app.route("/create_users")
def create_users():
    # dev utility — create default users if missing
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
            db.session.add(user)
            created.append(u["username"])
    db.session.commit()
    return f"✅ Default users created (if missing): {', '.join(created)}"


# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    # Only used for local debugging. Render / prod uses gunicorn or Render's service.
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
