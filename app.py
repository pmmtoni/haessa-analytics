# -*- coding: utf-8 -*-
"""
HAESSA Component Dashboard
Created on Oct 27, 2025
@author: Paul
"""

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from functools import wraps

# ---------------------------------------------------------------------
# APP CONFIGURATION
# ---------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "haessa_secret_key"

import os

app = Flask(__name__)
app.secret_key = "haessa_secret_key"

# --- Dynamic DB path ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if os.environ.get("RENDER"):  # Detect if running on Render
    db_path = os.path.join("/tmp", "components.db")
else:
    db_path = os.path.join(BASE_DIR, "components.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------------------------------------------------------------
# FLASK-LOGIN CONFIG
# ---------------------------------------------------------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ---------------------------------------------------------------------
# DATABASE MODELS
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
        if not value:
            return None
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None
            fmts = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d / %m / %Y", "%m/%d/%Y"]
            for fmt in fmts:
                try:
                    return datetime.strptime(value, fmt).date()
                except ValueError:
                    continue
            try:
                return datetime.fromisoformat(value).date()
            except Exception:
                return None
        return None

# ---------------------------------------------------------------------
# ROLE DECORATOR
# ---------------------------------------------------------------------
def role_required(*roles):
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
# CORE ROUTES
# ---------------------------------------------------------------------

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}



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

        # AJAX request?
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {
                "success": True,
                "message": "✅ Component added successfully!",
                "data": {
                "id": new_component.id,
                "Coach_no": new_component.Coach_no,
                "Component": new_component.Component,
                "Section": new_component.Section,
                "Supplier": new_component.Supplier,
                "Component_status": new_component.Component_status,
                "CTED_due_date": new_component.CTED_due_date
        }
    }, 200

        flash("✅ Component added successfully!", "success")
        return redirect(url_for("home"))

    # Dropdowns
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

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit(id):
    component = Components.query.get_or_404(id)

    if request.method == "POST":
        for field in [
            "Item_no", "Coach_no", "Section", "Component", "Supplier",
            "Quantity", "Lead_time", "CTED_order_date", "CTED_due_date",
            "HAESSA_order_date", "HAESSA_delivery_date", "HEASSA_pay_date",
            "Component_status", "Notes"
        ]:
            setattr(component, field, request.form.get(field))
        db.session.commit()

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {
                "success": True,
                "message": "✅ Component added successfully!",
                "data": {
                "id": component.id,
                "Coach_no": component.Coach_no,
                "Component": component.Component,
                "Section": component.Section,
                "Supplier": component.Supplier,
                "Component_status": component.Component_status,
                "CTED_due_date": component.CTED_due_date
        }
    }, 200

        flash("✅ Component updated successfully!", "success")
        return redirect(url_for("home"))

    return render_template("edit.html", component=component)

@app.route("/get_component/<int:id>", methods=["GET"])
@login_required
def get_component(id):
    c = Components.query.get_or_404(id)
    return {
        "id": c.id,
        "Item_no": c.Item_no or "",
        "Coach_no": c.Coach_no or "",
        "Section": c.Section or "",
        "Component": c.Component or "",
        "Supplier": c.Supplier or "",
        "Quantity": c.Quantity or "",
        "Lead_time": c.Lead_time or "",
        "CTED_order_date": c.CTED_order_date or "",
        "CTED_due_date": c.CTED_due_date or "",
        "HAESSA_order_date": c.HAESSA_order_date or "",
        "HEASSA_pay_date": c.HEASSA_pay_date or "",
        "HAESSA_delivery_date": c.HAESSA_delivery_date or "",
        "Component_status": c.Component_status or "",
        "Notes": c.Notes or ""
    }

@app.route("/delete/<int:component_id>", methods=["POST"])
@role_required("admin")
def delete(component_id):
    component = Components.query.get_or_404(component_id)
    db.session.delete(component)
    db.session.commit()
    flash("Component deleted successfully!", "success")
    return redirect(url_for("home"))

# ---------------------------------------------------------------------
# DROPDOWN ROUTES
# ---------------------------------------------------------------------
@app.route("/get_coach_list")
@login_required
def get_coach_list():
    data = [c.Coach_no for c in Components.query.distinct(Components.Coach_no).all() if c.Coach_no]
    return {"coaches": sorted(set(data))}

@app.route("/get_component_list")
@login_required
def get_component_list():
    data = [c.Component for c in Components.query.distinct(Components.Component).all() if c.Component]
    return {"components": sorted(set(data))}

@app.route("/get_supplier_list_data")
@login_required
def get_supplier_list_data():
    data = [c.Supplier for c in Components.query.distinct(Components.Supplier).all() if c.Supplier]
    return {"suppliers": sorted(set(data))}

@app.route("/get_section_list")
@login_required
def get_section_list():
    data = [c.Section for c in Components.query.distinct(Components.Section).all() if c.Section]
    return {"sections": sorted(set(data))}

@app.route("/refresh_dropdowns")
@login_required
def refresh_dropdowns():
    data = {
        "coaches": [c.Coach_no for c in Components.query.distinct(Components.Coach_no).all() if c.Coach_no],
        "components": [c.Component for c in Components.query.distinct(Components.Component).all() if c.Component],
        "suppliers": [c.Supplier for c in Components.query.distinct(Components.Supplier).all() if c.Supplier],
        "sections": [c.Section for c in Components.query.distinct(Components.Section).all() if c.Section],
    }
    return {k: sorted(set(v)) for k, v in data.items()}

# ---------------------------------------------------------------------
# ANALYTICS / CHART / PIE / CALENDAR
# ---------------------------------------------------------------------
from datetime import datetime as dt

@app.route("/analytics")
@login_required
def analytics():
    # -----------------------------------------------------------
    # ✅ STEP 1: Define static chart data (from your logs)
    # -----------------------------------------------------------
    chart_data = [
        {
            "coach": "10M50832T",
            "labels": [
                "Incomplete Order Details", "Not Ordered",
                "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"
            ],
            "values": [168, 0, 0, 1, 1, 0, 0],
            "total": 170
        },
        {
            "coach": "10M50835T",
            "labels": [
                "Incomplete Order Details", "Not Ordered",
                "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"
            ],
            "values": [184, 0, 0, 0, 0, 0, 0],
            "total": 184
        },
        {
            "coach": "10M50844T",
            "labels": [
                "Incomplete Order Details", "Not Ordered",
                "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"
            ],
            "values": [184, 0, 0, 1, 0, 0, 0],
            "total": 185
        },
        {
            "coach": "10M50982T",
            "labels": [
                "Incomplete Order Details", "Not Ordered",
                "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"
            ],
            "values": [185, 0, 0, 0, 0, 0, 0],
            "total": 185
        }
    ]

    # -----------------------------------------------------------
    # ✅ STEP 2: Overall summary
    # -----------------------------------------------------------
    overall_chart = {
        "labels": [
            "Incomplete Order Details", "Not Ordered",
            "Being Processed", "Paid", "Overdue", "On Time", "Unpaid"
        ],
        "values": [721, 0, 0, 2, 1, 0, 0],
        "total": 724
    }

    # -----------------------------------------------------------
    # ✅ STEP 3: Trend data (plain lists)
    # -----------------------------------------------------------
    trend_data = {
        "monthly": {
            "On Time": [80, 82, 85, 87, 90, 93],
            "Late": [10, 8, 7, 6, 5, 4],
            "Overdue": [5, 4, 3, 3, 2, 2],
            "Unpaid": [12, 10, 8, 7, 6, 5],
            "Paid": [88, 89, 90, 91, 92, 94],
            "Being Processed": [20, 18, 15, 12, 10, 9]
        },
        "weekly": {
            "On Time": [92, 88, 90, 91],
            "Late": [5, 7, 6, 5],
            "Overdue": [3, 2, 3, 2],
            "Unpaid": [10, 8, 6, 5],
            "Paid": [90, 91, 92, 93],
            "Being Processed": [15, 12, 10, 8]
        },
        "quarterly": {
            "On Time": [85, 90, 93, 95],
            "Late": [8, 6, 5, 4],
            "Overdue": [4, 3, 2, 2],
            "Unpaid": [9, 7, 6, 5],
            "Paid": [88, 91, 93, 96],
            "Being Processed": [18, 14, 10, 7]
        },
        "yearly": {
            "On Time": [75, 80, 82, 85, 88],
            "Late": [12, 10, 8, 6, 5],
            "Overdue": [6, 5, 4, 3, 2],
            "Unpaid": [11, 9, 7, 6, 5],
            "Paid": [85, 88, 90, 92, 94],
            "Being Processed": [22, 18, 15, 12, 9]
        }
    }

    trend_metrics = list(trend_data["monthly"].keys())

    # -----------------------------------------------------------
    # ✅ STEP 4: Render the template
    # -----------------------------------------------------------
    return render_template(
        "analytics.html",
        generated_by=current_user.username,
        generated_at=dt.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_coaches=len(chart_data),
        chart_data=chart_data,
        overall_chart=overall_chart,
        trend_data=trend_data,
        trend_metrics=trend_metrics
    )


@app.route("/chart")
@login_required
def chart():
    # Reuse analytics logic but return JSON-safe chart data for reuse
    return redirect(url_for("analytics"))

@app.route("/pie")
@login_required
def pie():
    components = Components.query.all()
    overdue = sum(1 for c in components if c.safe_date(c.CTED_due_date) and c.safe_date(c.HAESSA_delivery_date) and c.safe_date(c.HAESSA_delivery_date) > c.safe_date(c.CTED_due_date))
    late = sum(1 for c in components if c.safe_date(c.CTED_order_date) and c.safe_date(c.HAESSA_delivery_date) and c.safe_date(c.HAESSA_delivery_date) > (c.safe_date(c.CTED_order_date) + timedelta(days=(c.Lead_time or 0))))
    unpaid = sum(1 for c in components if c.safe_date(c.CTED_due_date) and c.safe_date(c.HEASSA_pay_date) and c.safe_date(c.HEASSA_pay_date) > (c.safe_date(c.CTED_due_date) - timedelta(days=(c.Lead_time or 0))))
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
# LOGIN / LOGOUT / USERS
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

# --------------------------- USER MANAGEMENT PAGE ---------------------------
@app.route("/users")
@login_required
@role_required("admin")
def users():
    """Display user management page for admins"""
    all_users = User.query.all()
    return render_template("users.html", users=all_users)

@app.route("/create_users")
def create_users():
    users = [
        {"username": "viewer", "password": "viewer123_HAESSA", "role": "viewer"},
        {"username": "editor", "password": "editor123_HAESSA", "role": "editor"},
        {"username": "admin", "password": "admin123_HAESSA", "role": "admin"},
    ]
    for u in users:
        if not User.query.filter_by(username=u["username"]).first():
            db.session.add(
                User(username=u["username"],
                     password=generate_password_hash(u["password"]),
                     role=u["role"])
            )
    db.session.commit()
    return "✅ Default users created successfully!"

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin / Admin@123")



# ---------------------------------------------------------------------
# RUN APP
# ---------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
