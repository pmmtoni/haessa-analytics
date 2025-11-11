# -*- coding: utf-8 -*-
"""
HAESSA Component Dashboard
Created on Oct 27, 2025
@author: Paul
"""

import os
from datetime import datetime, timedelta, date
from functools import wraps

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


# ---------------------------------------------------------------------
# ✅ APP CONFIGURATION
# ---------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "haessa_secret_key"

import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

# Detect Render environment
IS_RENDER = os.environ.get("RENDER") is not None
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ✅ Always use /tmp for Render, base dir for local
if IS_RENDER:
    DB_DIR = "/tmp"
else:
    DB_DIR = BASE_DIR

DB_PATH = os.path.join(DB_DIR, "components.db")

# ✅ Make absolutely sure /tmp exists and is writable
try:
    os.makedirs(DB_DIR, exist_ok=True)
    testfile = os.path.join(DB_DIR, "test_write.tmp")
    with open(testfile, "w") as f:
        f.write("ok")
    os.remove(testfile)
    print(f"✅ Database directory verified: {DB_DIR}")
except Exception as e:
    print(f"⚠️ Cannot write to {DB_DIR}: {e}")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ✅ Force DB creation (critical for Render)
with app.app_context():
    try:
        db.create_all()
        from app import User  # import after db defined

        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", role="admin")
            admin.password = generate_password_hash("Admin@123")
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created: admin / Admin@123")
        print(f"✅ Database initialized at {DB_PATH}")
    except Exception as e:
        print(f"⚠️ Database initialization failed: {e}")


# Detect if running on Render (Render environment sets this variable)
IS_RENDER = os.environ.get("RENDER") is not None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ✅ Use /tmp on Render (only writable directory)
if IS_RENDER:
    DB_PATH = "/tmp/components.db"
else:
    DB_PATH = os.path.join(BASE_DIR, "components.db")

# ✅ Make sure directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Log database path for debugging
print(f"✅ Using database path: {DB_PATH}")


# Detect Render environment (Render uses /tmp as writable directory)
# Detect if running on Render (environment variable automatically set)
IS_RENDER = os.environ.get("RENDER") is not None
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Render only allows writes in /tmp, so use that directory
if IS_RENDER:
    DB_PATH = "/tmp/components.db"
else:
    DB_PATH = os.path.join(BASE_DIR, "components.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Ensure database exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)



# ---------------------------------------------------------------------
# ✅ LOGIN MANAGER CONFIG
# ---------------------------------------------------------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ---------------------------------------------------------------------
# ✅ DATABASE MODELS
# ---------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="viewer")  # viewer / editor / admin

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
        """Safely parse a date string into a date object."""
        if not value:
            return None
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str):
            for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(value.strip(), fmt).date()
                except ValueError:
                    continue
        return None


# ---------------------------------------------------------------------
# ✅ INITIALIZE DATABASE AND DEFAULT ADMIN
# ---------------------------------------------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin / Admin@123")
    print(f"✅ Database ready at: {DB_PATH}")


# ---------------------------------------------------------------------
# ✅ ROLE DECORATOR
# ---------------------------------------------------------------------
def role_required(*roles):
    """Decorator that restricts access based on user roles."""
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.role not in roles:
                flash("You don’t have permission to access this page.", "danger")
                return redirect(url_for("home"))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


# ---------------------------------------------------------------------
# ✅ GLOBAL CONTEXT FOR TEMPLATES
# ---------------------------------------------------------------------
@app.context_processor
def inject_globals():
    """Make datetime and current_app available to all templates."""
    return {'datetime': datetime, 'current_app': current_app}


# ---------------------------------------------------------------------
# ✅ ANALYTICS, PIE & CALENDAR ROUTES
# ---------------------------------------------------------------------
@app.route("/analytics")
@login_required
def analytics():
    chart_data = [
        {"coach": "10M50832T", "labels": ["Incomplete Order Details", "Not Ordered",
         "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"],
         "values": [168, 0, 0, 1, 1, 0, 0], "total": 170},
        {"coach": "10M50835T", "labels": ["Incomplete Order Details", "Not Ordered",
         "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"],
         "values": [184, 0, 0, 0, 0, 0, 0], "total": 184},
    ]

    overall_chart = {
        "labels": ["Incomplete Order Details", "Not Ordered",
                   "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"],
        "values": [721, 0, 0, 2, 1, 0, 0],
        "total": 724
    }

    trend_data = {
        "monthly": {"On Time": [80, 82, 85, 87, 90, 93],
                    "Late": [10, 8, 7, 6, 5, 4]},
        "weekly": {"On Time": [92, 88, 90, 91],
                   "Late": [5, 7, 6, 5]}
    }

    return render_template(
        "analytics.html",
        chart_data=chart_data,
        overall_chart=overall_chart,
        trend_data=trend_data,
        generated_by=current_user.username,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )


@app.route("/chart")
@login_required
def chart():
    """Redirect to analytics (alias route)."""
    return redirect(url_for("analytics"))


@app.route("/pie")
@login_required
def pie():
    components = Components.query.all()
    overdue = sum(1 for c in components if c.safe_date(c.CTED_due_date)
                  and c.safe_date(c.HAESSA_delivery_date)
                  and c.safe_date(c.HAESSA_delivery_date) > c.safe_date(c.CTED_due_date))
    late = sum(1 for c in components if c.safe_date(c.CTED_order_date)
               and c.safe_date(c.HAESSA_delivery_date)
               and c.safe_date(c.HAESSA_delivery_date) >
               (c.safe_date(c.CTED_order_date) + timedelta(days=(c.Lead_time or 0))))
    unpaid = sum(1 for c in components if c.safe_date(c.CTED_due_date)
                 and c.safe_date(c.HEASSA_pay_date)
                 and c.safe_date(c.HEASSA_pay_date) >
                 (c.safe_date(c.CTED_due_date) - timedelta(days=(c.Lead_time or 0))))
    total = len(components)
    on_time = max(total - (overdue + late + unpaid), 0)

    labels = ["Overdue", "Late", "Unpaid", "On Time"]
    data = [overdue, late, unpaid, on_time]

    return render_template("pie.html", labels=labels, data=data)


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
        events.append({
            "title": f"{c.Component} (Coach {c.Coach_no})",
            "start": due.strftime("%Y-%m-%d"),
            "color": color
        })

    return render_template("calendar.html", events=events)


# ---------------------------------------------------------------------
# ✅ CORE ROUTES (Home, Add)
# ---------------------------------------------------------------------
@app.route("/")
@login_required
def home():
    components = Components.query.all()
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
            Quantity=request.form.get("Quantity"),
            Lead_time=request.form.get("Lead_time"),
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

    # Dropdown values
    coaches = [c.Coach_no for c in Components.query.distinct(Components.Coach_no).all() if c.Coach_no]
    sections = [c.Section for c in Components.query.distinct(Components.Section).all() if c.Section]
    components = [c.Component for c in Components.query.distinct(Components.Component).all() if c.Component]
    suppliers = [c.Supplier for c in Components.query.distinct(Components.Supplier).all() if c.Supplier]

    return render_template(
        "add.html",
        coaches=sorted(set(coaches)),
        sections=sorted(set(sections)),
        components=sorted(set(components)),
        suppliers=sorted(set(suppliers))
    )


# ---------------------------------------------------------------------
# ✅ AUTHENTICATION ROUTES
# ---------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"Welcome, {user.username}!", "success")
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
    """Utility route to create default users."""
    default_users = [
        {"username": "viewer", "password": "viewer123_HAESSA", "role": "viewer"},
        {"username": "editor", "password": "editor123_HAESSA", "role": "editor"},
        {"username": "admin", "password": "Admin@123", "role": "admin"},
    ]

    for u in default_users:
        if not User.query.filter_by(username=u["username"]).first():
            user = User(
                username=u["username"],
                password=generate_password_hash(u["password"]),
                role=u["role"]
            )
            db.session.add(user)

    db.session.commit()
    return "✅ Default users created successfully!"


# ---------------------------------------------------------------------
# ✅ RUN APP
# ---------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
