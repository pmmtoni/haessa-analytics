
# ================================================================
#  HAESSA Component Dashboard â€“ PostgreSQL/SQLite compatible build
# ================================================================


import calendar
# Replace or add this line (near other datetime imports)
from datetime import date, datetime, timedelta
import pandas as pd  # For date handling
from dateutil.relativedelta import relativedelta  # pip install python-dateutil if needed
from flask import send_file
import os
import json
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

# Context processor to make current year available in ALL templates

@app.context_processor
def inject_current_year():
    return dict(current_year=datetime.utcnow().year)

app.secret_key = os.environ.get("SECRET_KEY", "haessa_secret_key")

base_dir = os.path.abspath(os.path.dirname(__file__))
sqlite_path = f"sqlite:///{os.path.join(base_dir, 'components.db')}"

DATABASE_URL = os.environ.get("DATABASE_URL", sqlite_path)

# Fix Renderâ€™s "postgres://" â†’ "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql+psycopg2://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Allow SQLite threading
if DATABASE_URL.startswith("sqlite"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"check_same_thread": False}
    }

db = SQLAlchemy(app)

print(f"\nðŸ“Œ Using database: {app.config['SQLALCHEMY_DATABASE_URI']}\n")


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
    Coach_Type = db.Column(db.String(100))
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


# In app.py - update your AuditLog model
class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    username = db.Column(db.String(120))
    action = db.Column(db.String(200))        # e.g., "Edited user", "Added component"
    target = db.Column(db.String(200))        # e.g., username or component ID
    details = db.Column(db.Text)              # JSON string of field changes: {"field": {"old": ..., "new": ...}}

    def get_changes(self):
        import json
        if self.details:
            return json.loads(self.details)
        return {}

    @property
    def old_value_json(self):
        try:
            return json.loads(self.old_value or "{}")
        except:
            return {}

    @property
    def new_value_json(self):
        try:
            return json.loads(self.new_value or "{}")
        except:
            return {}


# ---------------------------------------------------------------
# UNIFIED AUDIT LOGGER
# ---------------------------------------------------------------


def log_action(username, action, target, old=None, new=None):
    changes = {}
    if old and new:
        for key in set(old.keys()) | set(new.keys()):
            old_val = old.get(key)
            new_val = new.get(key)
            if old_val != new_val:
                changes[key] = {"old": old_val, "new": new_val}

    audit = AuditLog(
        username=username,
        action=action,
        target=target,
        details=json.dumps(changes) if changes else None
    )
    db.session.add(audit)
    db.session.commit()

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



#from datetime import date

def derive_component_status(c):
    """
    Computes the derived status based on the priority rules you specified.
    Also returns a list of missing fields if the status indicates incomplete data.
    
    Rules (in priority order):
    - Delivered              → if HAESSA_delivery_date is not null
    - Being processed        → if HAESSA_order_date is not null
    - Haessa to order        → if CTED_order_date is not null (but HAESSA_order_date is null)
    - CTED due date not provided → if CTED_due_date is null (but CTED_order_date exists)
    - Lead time not provided → if Lead_time is null (but CTED_order_date exists)
    - CTED to place order    → if CTED_order_date is null
    - Unknown                → if no meaningful dates are present at all
    """
    missing = []

    # Helper to check if a date field is effectively null/empty
    def is_empty_date(val):
        return val is None or (isinstance(val, str) and not val.strip())

    today = date.today()

    # 1. Delivered (highest priority)
    if not is_empty_date(c.HAESSA_delivery_date):
        return "Delivered", missing  # no missing fields needed

    # 2. Being processed
    if not is_empty_date(c.HAESSA_order_date):
        return "Being processed", missing

    # 3. Haessa to order
    if not is_empty_date(c.CTED_order_date):
        if is_empty_date(c.HAESSA_order_date):
            return "Haessa to order", missing

    # 4. CTED due date not provided
    if not is_empty_date(c.CTED_order_date) and is_empty_date(c.CTED_due_date):
        missing.append("CTED_due_date")
        return "CTED due date not provided", missing

    # 5. Lead time not provided
    if not is_empty_date(c.CTED_order_date) and (c.Lead_time is None or c.Lead_time == 0):
        missing.append("Lead_time")
        return "Lead time not provided", missing

    # 6. CTED to place order
    if is_empty_date(c.CTED_order_date):
        missing.append("CTED_order_date")
        return "CTED to place order", missing

    # Final fallback: Unknown (many fields missing)
    if all(is_empty_date(getattr(c, field)) for field in [
        "CTED_order_date", "CTED_due_date", "HAESSA_order_date", "HAESSA_delivery_date"
    ]) and (c.Lead_time is None or c.Lead_time == 0):
        missing = ["CTED_order_date", "CTED_due_date", "HAESSA_order_date", "HAESSA_delivery_date", "Lead_time"]
        return "Unknown", missing

    # If we reach here, use the stored status or fallback
    return c.Component_status or "Unknown", missing
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
            print("âœ… Admin created")


init_app()

from apscheduler.schedulers.background import BackgroundScheduler
#from datetime import date, timedelta
from email_utils import send_email

#from datetime import date, timedelta

def send_daily_summary():
    today = date.today()
    tomorrow = today + timedelta(days=1)
    week_start = today - timedelta(days=today.weekday())  # Monday
    week_end = week_start + timedelta(days=6)  # Sunday
    next_week_start = week_start + timedelta(days=7)
    next_week_end = next_week_start + timedelta(days=6)

    # CRUD activities today
    today_audits = AuditLog.query.filter(AuditLog.timestamp >= today).all()
    adds = len([a for a in today_audits if a.action == "Added component"])
    edits = len([a for a in today_audits if a.action == "Edited component"])
    deletes = len([a for a in today_audits if a.action == "Deleted component"])

    # Actual deliveries today
    actual_deliveries = Components.query.filter(Components.HAESSA_delivery_date == today).all()
    actual_list = "\n".join([f"- {c.Component} (Coach: {c.Coach_no})" for c in actual_deliveries]) or "None"

    # Expected deliveries tomorrow
    expected_tomorrow = Components.query.filter(Components.CTED_due_date == tomorrow).all()
    tomorrow_list = "\n".join([f"- {c.Component} (Coach: {c.Coach_no})" for c in expected_tomorrow]) or "None"

    # Missed deliveries
    missed = Components.query.filter(
        Components.CTED_due_date < today,
        Components.HAESSA_delivery_date == None
    ).all()
    missed_list = "\n".join([f"- {c.Component} (Due: {c.CTED_due_date}, Coach: {c.Coach_no})" for c in missed]) or "None"

    # Expected current week
    current_week_expected = Components.query.filter(
        Components.CTED_due_date >= week_start,
        Components.CTED_due_date <= week_end
    ).all()
    current_week_list = "\n".join([f"- {c.Component} (Due: {c.CTED_due_date}, Coach: {c.Coach_no})" for c in current_week_expected]) or "None"

    # Expected next week
    next_week_expected = Components.query.filter(
        Components.CTED_due_date >= next_week_start,
        Components.CTED_due_date <= next_week_end
    ).all()
    next_week_list = "\n".join([f"- {c.Component} (Due: {c.CTED_due_date}, Coach: {c.Coach_no})" for c in next_week_expected]) or "None"

    body = f"""
HAESSA Daily Summary - {today}

1. CRUD Activities Today:
   - Adds: {adds}
   - Edits: {edits}
   - Deletes: {deletes}

2. Actual Deliveries Today:
   {actual_list}

3. Expected Deliveries Tomorrow:
   {tomorrow_list}

4. Missed Deliveries (Overdue):
   {missed_list}

5. Expected Deliveries Current Week ({week_start} to {week_end}):
   {current_week_list}

6. Expected Deliveries Next Week ({next_week_start} to {next_week_end}):
   {next_week_list}

View Dashboard: http://your-app-url/home
    """

    send_email("pmmtoni@gmail.com", "HAESSA Daily Summary", body)  # Replace with your ADMIN_EMAIL

# Scheduler (add if not already)
scheduler = BackgroundScheduler()
scheduler.add_job(send_daily_summary, 'cron', hour=6, minute=0)  # 6 AM daily
scheduler.start()
# ---------------------------------------------------------------
# CONTEXT PROCESSORS
# ---------------------------------------------------------------
@app.context_processor
def add_globals():
    return {"datetime": datetime}


# ---------------------------------------------------------------
# ROUTES â€” HOME PAGE
# ---------------------------------------------------------------
#from datetime import date, datetime, timedelta  # Add these imports at the top of app.py if missing

@login_required
@role_required("admin", "editor", "viewer")
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()

    # Base query – no status filter yet
    query = Components.query

    if search:
        search_like = f"%{search}%"
        query = query.filter(
            db.or_(
                Components.Component.ilike(search_like),
                Components.Coach_no.ilike(search_like),
                Components.Supplier.ilike(search_like),
                Components.Item_no.ilike(search_like)
            )
        )

    # Get all matching components (status filter applied in Python later)
    components = query.order_by(Components.CTED_due_date.asc()).all()

    today = date.today()

    # Compute derived status and other attributes for every component
    filtered_components = []
    for c in components:
        status_tuple = derive_component_status(c)
        c.display_status = status_tuple[0]
        c.missing_fields = status_tuple[1] if len(status_tuple) > 1 else []

        c.cted_due_date_as_date = None
        if c.CTED_due_date:
            try:
                c.cted_due_date_as_date = datetime.strptime(c.CTED_due_date.strip(), "%Y-%m-%d").date()
            except (ValueError, TypeError):
                pass

        c.is_overdue = (
            c.cted_due_date_as_date is not None
            and c.cted_due_date_as_date < today
            and c.display_status not in ["Completed", "Delivered"]
        )

        # Apply status filter in Python (after derivation)
        if not status_filter or c.display_status.lower() == status_filter.lower():
            filtered_components.append(c)

    overdue_count = len([c for c in filtered_components if c.is_overdue])

    # Status choices: DB + derived (same as before)
    db_statuses = db.session.query(Components.Component_status.distinct())\
                           .filter(Components.Component_status.isnot(None))\
                           .all()
    db_status_list = sorted(set([s[0].strip().title() for s in db_statuses if s[0]]))

    derived_statuses = ["Pending", "Ordered", "Overdue", "Delivered", "Unknown", "Haessa to order", "CTED to place order"]
    status_choices = sorted(set(db_status_list + derived_statuses))

    return render_template(
        "home.html",
        components=filtered_components,          # ← filtered list
        search=search,
        status_filter=status_filter,
        status_choices=status_choices,
        overdue_count=overdue_count
    )



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
            Coach_Type=request.form.get("Coach_Type"),
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

        log_action(current_user.username, "Added component",
                   f"Component {c.id}", new=c.Item_no)

        flash("Component added.", "success")
        return redirect(url_for("home"))

    return render_template("add_component.html")


# ---------------------------------------------------------------
# EDIT COMPONENT
# ---------------------------------------------------------------

@app.route("/edit_component/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "editor")
def edit_component(id):
    component = Components.query.get_or_404(id)

    if request.method == "POST":
        # Capture OLD values for audit log (include ALL fields)
        old = {
            "Item_no": component.Item_no,
            "Coach_no": component.Coach_no,
            "Coach_Type": component.Coach_Type,
            "Component": component.Component,
            "Supplier": component.Supplier,
            "Quantity": component.Quantity,
            "Lead_time": component.Lead_time,
            "CTED_order_date": component.CTED_order_date,
            "CTED_due_date": component.CTED_due_date,
            "HAESSA_order_date": component.HAESSA_order_date,
            "HAESSA_pay_date": component.HAESSA_pay_date,
            "HAESSA_delivery_date": component.HAESSA_delivery_date,
            "Component_status": component.Component_status,
            "Notes": component.Notes,
        }

        # Update ALL fields from form (safe with defaults)
        component.Item_no = request.form.get("Item_no") or component.Item_no
        component.Coach_no = request.form.get("Coach_no") or component.Coach_no
        component.Coach_Type = request.form.get("Coach_Type") or component.Coach_Type
        component.Component = request.form.get("Component") or component.Component
        component.Supplier = request.form.get("Supplier") or component.Supplier
        component.Quantity = request.form.get("Quantity", type=int) or component.Quantity
        component.Lead_time = request.form.get("Lead_time", type=int) or component.Lead_time
        component.CTED_order_date = request.form.get("CTED_order_date") or component.CTED_order_date
        component.CTED_due_date = request.form.get("CTED_due_date") or component.CTED_due_date
        component.HAESSA_order_date = request.form.get("HAESSA_order_date") or component.HAESSA_order_date
        component.HAESSA_pay_date = request.form.get("HAESSA_pay_date") or component.HAESSA_pay_date
        component.HAESSA_delivery_date = request.form.get("HAESSA_delivery_date") or component.HAESSA_delivery_date
        component.Component_status = request.form.get("Component_status") or component.Component_status
        component.Notes = request.form.get("Notes") or component.Notes

        db.session.commit()

        # Capture NEW values for audit log
        new = {
            "Item_no": component.Item_no,
            "Coach_no": component.Coach_no,
            "Coach_Type": component.Coach_Type,
            "Component": component.Component,
            "Supplier": component.Supplier,
            "Quantity": component.Quantity,
            "Lead_time": component.Lead_time,
            "CTED_order_date": component.CTED_order_date,
            "CTED_due_date": component.CTED_due_date,
            "HAESSA_order_date": component.HAESSA_order_date,
            "HAESSA_pay_date": component.HAESSA_pay_date,
            "HAESSA_delivery_date": component.HAESSA_delivery_date,
            "Component_status": component.Component_status,
            "Notes": component.Notes,
        }

        # Log only actual changes
        log_action(
            username=current_user.username,
            action="Edited component",
            target=f"Component {component.id} ({component.Component or 'No name'})",
            old=old,
            new=new
        )

        flash("Component updated successfully!", "success")
        return redirect(url_for("home"))

    # GET: show edit form
    return render_template("edit_component.html", component=component)
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

    log_action(current_user.username, "Deleted component",
               f"Component {id}", old=old)

    flash("Deleted.", "info")
    return redirect(url_for("home"))
#================================================================
#GANTT ROUTE
#================================================================
@app.route("/gantt")
@login_required
def gantt():
    components = Components.query.all()

    today = date.today()

    # Compute display_status and is_overdue (same as in home route)
    for c in components:
        c.display_status = derive_component_status(c)

        c.cted_due_date_as_date = None
        if c.CTED_due_date:
            try:
                c.cted_due_date_as_date = datetime.strptime(c.CTED_due_date, "%Y-%m-%d").date()
            except (ValueError, TypeError):
                pass

        c.is_overdue = (
            c.cted_due_date_as_date is not None
            and c.cted_due_date_as_date < today
            and c.display_status not in ["Completed", "Delivered"]
        )

    # Prepare Gantt data
    gantt_data = []
    for c in components:
        if not c.CTED_due_date:
            continue

        try:
            due_date = datetime.strptime(c.CTED_due_date, "%Y-%m-%d").date()
        except:
            continue

        # Start date (order date or fallback)
        start_date = None
        if c.HAESSA_order_date:
            start_date = datetime.strptime(c.HAESSA_order_date, "%Y-%m-%d").date()
        elif c.CTED_order_date:
            start_date = datetime.strptime(c.CTED_order_date, "%Y-%m-%d").date()
        else:
            start_date = due_date - timedelta(days=7)  # default lead time

        # End date (delivery or due date)
        end_date = due_date
        if c.HAESSA_delivery_date:
            try:
                end_date = datetime.strptime(c.HAESSA_delivery_date, "%Y-%m-%d").date()
            except:
                pass

        # Color by status
        bg_color = "#6c757d"  # gray
        if c.display_status == "Completed":
            bg_color = "#28a745"  # green
        elif c.is_overdue:
            bg_color = "#dc3545"  # red
        elif c.display_status in ["Pending", "Ordered"]:
            bg_color = "#ffc107"  # yellow

        gantt_data.append({
            "task": f"{c.Component or 'Unnamed'} (Coach {c.Coach_no or '?'})",
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
            "bg": bg_color,
            "status": c.display_status
        })

    return render_template("gantt.html", gantt_data=gantt_data, today=today.isoformat())

#==========================================================================
#FAVICON ROUTE
#==========================================================================
from flask import send_from_directory

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')




# ===============================================================
#  ANALYTICS ROUTE
# ===============================================================


@app.route("/analytics")
@login_required
@role_required("admin", "editor")
def analytics():
    components = Components.query.all()

    today = date.today()
    generated_by = current_user.username
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Compute derived status for all components
    for c in components:
        status_tuple = derive_component_status(c)
        c.display_status = status_tuple[0]
        c.missing_fields = status_tuple[1] if len(status_tuple) > 1 else []

    # === Coach & Status Grouping ===
    coach_data = defaultdict(lambda: defaultdict(int))
    status_counts = defaultdict(int)
    due_date_groups = defaultdict(list)  # date → list of 1/0 (on-time)

    for c in components:
        coach = c.Coach_no or "Unknown"
        status = c.display_status  # ← derived status
        coach_data[coach][status] += 1
        status_counts[status] += 1

        # On-time data for trends (only if due date exists)
        if c.CTED_due_date:
            try:
                due_date = datetime.strptime(c.CTED_due_date.strip(), "%Y-%m-%d").date()
                is_on_time = 1 if status in ["Delivered", "Completed"] else 0
                due_date_groups[due_date].append(is_on_time)
            except:
                pass

    # === Coach Chart Data ===
    chart_data = []
    total_coaches = len(coach_data)
    for coach, counts in coach_data.items():
        coach_components = [c for c in components if (c.Coach_no or "Unknown") == coach]
        total = len(coach_components)
        component_details = [{
            "Item_no": c.Item_no or "",
            "Component": c.Component or "",
            "Supplier": c.Supplier or "",
            "Quantity": c.Quantity or "",
            "Lead_time": c.Lead_time,
            "CTED_due_date": c.CTED_due_date or "",
            "display_status": c.display_status
        } for c in coach_components]

        chart_data.append({
            "coach": coach,
            "labels": list(counts.keys()),
            "values": list(counts.values()),
            "total": total,
            "components": component_details
        })

    # Overall chart
    overall_chart = {
        "labels": list(status_counts.keys()),
        "values": list(status_counts.values()),
        "total": len(components)
    }

    # === Supplier Trends (monthly on-time %) ===
    supplier_trends = defaultdict(lambda: defaultdict(list))
    for c in components:
        if c.CTED_due_date and c.Supplier:
            try:
                due_date = datetime.strptime(c.CTED_due_date.strip(), "%Y-%m-%d").date()
                supplier = c.Supplier.strip() or "Unknown"
                month_key = due_date.strftime("%Y-%m")
                is_on_time = 1 if c.display_status in ["Delivered", "Completed"] else 0
                supplier_trends[supplier][month_key].append(is_on_time)
            except:
                pass

    supplier_chart_data = []
    suppliers = sorted(supplier_trends.keys())
    for supplier in suppliers:
        values = []
        for i in range(11, -1, -1):
            month_date = today.replace(day=1) - pd.DateOffset(months=i)
            month_key = month_date.strftime("%Y-%m")
            rates = supplier_trends[supplier].get(month_key, [])
            pct = round(sum(rates) / len(rates) * 100, 1) if rates else 0
            values.append(pct)
        supplier_chart_data.append({
            "supplier": supplier,
            "values": values
        })

    # === Current period alert (<90% on-time) ===
    current_month_key = today.strftime("%Y-%m")
    current_rates = []
    for d, rates in due_date_groups.items():
        if d.strftime("%Y-%m") == current_month_key:
            current_rates.extend(rates)
    current_period_pct = round(sum(current_rates) / len(current_rates) * 100, 1) if current_rates else 100
    show_alert = current_period_pct < 90

    # === DAILY: Last 30 days ===
    daily_labels = []
    daily_values = []
    for offset in range(29, -1, -1):
        d = today - timedelta(days=offset)
        daily_labels.append(d.strftime("%b %d"))
        rates = due_date_groups.get(d, [])
        pct = sum(rates) / len(rates) * 100 if rates else 0
        daily_values.append(round(pct, 1))

    # === WEEKLY: Last 12 weeks ===
    weekly_labels = []
    weekly_values = []
    for week_offset in range(11, -1, -1):
        week_monday = today - timedelta(days=today.weekday()) - timedelta(weeks=week_offset)
        week_sunday = week_monday + timedelta(days=6)
        label = f"{week_monday.strftime('%b %d')}-{week_sunday.strftime('%d')}"
        weekly_labels.append(label)

        week_rates = []
        current = week_monday
        while current <= week_sunday:
            week_rates.extend(due_date_groups.get(current, []))
            current += timedelta(days=1)

        pct = sum(week_rates) / len(week_rates) * 100 if week_rates else 0
        weekly_values.append(round(pct, 1))

    # === MONTHLY: Last 12 months ===
    monthly_labels = []
    monthly_values = []
    for i in range(11, -1, -1):
        month_date = today.replace(day=1) - pd.DateOffset(months=i)
        monthly_labels.append(calendar.month_abbr[month_date.month])

        month_rates = []
        for d, rates in due_date_groups.items():
            if d.strftime("%Y-%m") == month_date.strftime("%Y-%m"):
                month_rates.extend(rates)

        pct = sum(month_rates) / len(month_rates) * 100 if month_rates else 0
        monthly_values.append(round(pct, 1))

    return render_template("analytics.html",
                           chart_data=chart_data,
                           overall_chart=overall_chart,
                           total_coaches=total_coaches,
                           generated_by=generated_by,
                           generated_at=generated_at,
                           daily_labels=daily_labels,
                           daily_values=daily_values,
                           weekly_labels=weekly_labels,
                           weekly_values=weekly_values,
                           monthly_labels=monthly_labels,
                           monthly_values=monthly_values,
                           supplier_chart_data=supplier_chart_data,
                           current_period_pct=current_period_pct,
                           show_alert=show_alert)



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
            "title": f"{c.Component} â€” {c.Coach_no}",
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
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
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
                password=generate_password_hash(password),  # Fixed: Use generate_password_hash directly (assuming you meant password_hash in the model, but code uses password)
                role=role,
            )
            db.session.add(new_user)
            db.session.commit()
            flash("User added successfully.", "success")
            return redirect(url_for("manage_users"))  # Fixed: Changed "users" to "manage_users"

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
            "Coach_Type": c.Coach_Type,
            "component": c.Component,
            "supplier": c.Supplier,
            "cted_due": c.CTED_due_date,
            "haessa_order": c.HAESSA_order_date,
            "status": c.Component_status,
        })

    return jsonify(results)


@app.route('/download_db')
def download_db():
    return send_file('components.db', as_attachment=True)



# ===============================================================
# ABOUT
# ===============================================================

@app.route("/about")
def about():
    return render_template("about.html")

# ===============================================================
# RUN
# ===============================================================


if __name__ == "__main__":
    app.run(debug=True)

