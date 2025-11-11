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

# Detect if running on Render
IS_RENDER = os.environ.get("RENDER") is not None
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ✅ Database setup
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Render-provided PostgreSQL URL
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    # Local SQLite fallback
    DB_PATH = os.path.join(BASE_DIR, "components.db")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

print(f"✅ Using database: {app.config['SQLALCHEMY_DATABASE_URI']}")


# ---------------------------------------------------------------------
# ✅ LOGIN MANAGER
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
    role = db.Column(db.String(20), default="viewer")

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
            for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(value.strip(), fmt).date()
                except ValueError:
                    continue
        return None


# ---------------------------------------------------------------------
# ✅ INITIALIZE DATABASE
# ---------------------------------------------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin / Admin@123")
    print("✅ Database initialized successfully.")


# ---------------------------------------------------------------------
# ✅ ROLE DECORATOR
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
# ✅ GLOBAL CONTEXT
# ---------------------------------------------------------------------
@app.context_processor
def inject_globals():
    return {'datetime': datetime, 'current_app': current_app}


# ---------------------------------------------------------------------
# ✅ CORE ROUTES
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
    return render_template("add.html")


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


@app.route("/delete/<int:id>")
@role_required("editor", "admin")
def delete(id):
    component = Components.query.get_or_404(id)
    db.session.delete(component)
    db.session.commit()
    flash("🗑️ Component deleted successfully!", "info")
    return redirect(url_for("home"))


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


# ---------------------------------------------------------------------
# ✅ RUN APP
# ---------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
