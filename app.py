print(">>> app.py STARTING...")
import sys
sys.stdout.flush()

# =========================
# Imports
# =========================
import os
import base64
import csv
import io
import time
from io import BytesIO
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename

import bcrypt
import requests

import secrets
import hashlib

def generate_email_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

def hash_otp(otp: str):
    return hashlib.sha256(otp.encode()).hexdigest()



from dotenv import load_dotenv
from sqlalchemy import extract, func

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, send_file, abort, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import CSRFProtect
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# 2FA
import pyotp
import qrcode

# PDF / ReportLab
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader, simpleSplit
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF


def paymongo_auth_header(secret_key: str) -> str:
    token = base64.b64encode(f"{secret_key}:".encode()).decode()
    return f"Basic {token}"


# =========================
# App Config
# =========================
load_dotenv()

print("MAIL USER:", os.getenv("MAIL_USERNAME"))
print("MAIL SERVER:", os.getenv("MAIL_SERVER"))
print("MAIL TLS:", os.getenv("MAIL_USE_TLS"))

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
print("DATABASE_URL BEING USED:", app.config["SQLALCHEMY_DATABASE_URI"])
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
    "connect_args": {
        "connect_timeout": 5,
        "options": "-csearch_path=public"
    }
}

# Cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # True if HTTPS in production

# Mail
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT") or 587)
app.config["MAIL_USE_TLS"] = (os.getenv("MAIL_USE_TLS") == "True")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

# Extensions
print(">>> before SQLAlchemy(app)")
db = SQLAlchemy(app)
print(">>> after SQLAlchemy(app)")

# ✅ AUTO CREATE TABLES ON RENDER (PRODUCTION ONLY)
if os.getenv("RENDER"):
    print(">>> Running db.create_all() on Render")
    with app.app_context():
        db.create_all()
        print(">>> Tables created successfully on Render")

csrf = CSRFProtect(app)
mail = Mail(app)

# Rate limiting (DEV SAFE - no Redis needed)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


# =========================
# Uploads (Manual receipts)
# =========================
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "receipts")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB


# =========================
# MODELS
# =========================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)  # email
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    business_name = db.Column(db.String(200))
    password = db.Column(db.LargeBinary(255), nullable=False)

    role = db.Column(db.String(50), nullable=False, default="user")
    is_approved = db.Column(db.Boolean, default=False)

    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected
    rejection_reason = db.Column(db.Text)
    approved_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)

    # 2FA fields
    twofa_enabled = db.Column(db.Boolean, default=False)
    twofa_secret = db.Column(db.String(32))
    twofa_temp_secret = db.Column(db.String(32))

    # Email OTP Verification
    email_otp_hash = db.Column(db.String(255))
    email_otp_expiry = db.Column(db.DateTime)
    email_otp_attempts = db.Column(db.Integer, default=0)
    is_email_verified = db.Column(db.Boolean, default=False)


class Permit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(200), nullable=False)
    owner_name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(300), nullable=False)
    tin = db.Column(db.String(50), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="permits")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected/for_review
    approved_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)
    rejected_reason = db.Column(db.Text)

    type = db.Column(db.String(20), default="new")  # new/renewal
    parent_id = db.Column(db.Integer, db.ForeignKey("permit.id"))

    payment_status = db.Column(db.String(20), default="unpaid")  # unpaid/paid/waived
    payment_required = db.Column(db.Boolean, default=True)

    serial_no = db.Column(db.String(20), unique=True, index=True)  # YYYY-000123


class Business(db.Model):
    __tablename__ = "businesses"
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(150), nullable=False)
    address = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    permit_id = db.Column(db.Integer, db.ForeignKey("permit.id"))

    status = db.Column(db.String(20), default="inactive")  # active/suspended/expired/inactive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    suspended_reason = db.Column(db.Text)
    suspended_at = db.Column(db.DateTime)
    activated_at = db.Column(db.DateTime)


class AdminLog(db.Model):
    __tablename__ = "admin_logs"
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer)
    action = db.Column(db.String(255))
    permit_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemSettings(db.Model):
    __tablename__ = "system_settings"
    id = db.Column(db.Integer, primary_key=True)
    barangay_name = db.Column(db.String(150))
    contact_email = db.Column(db.String(150))
    contact_phone = db.Column(db.String(50))
    registration_open = db.Column(db.Boolean, default=True)
    renewal_open = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    registration_fee = db.Column(db.Numeric(10, 2), default=100.00)
    renewal_fee = db.Column(db.Numeric(10, 2), default=50.00)


class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    permit_id = db.Column(db.Integer, db.ForeignKey("permit.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    amount = db.Column(db.Numeric(10, 2), nullable=False)
    method = db.Column(db.String(20), nullable=False)  # online/manual
    provider = db.Column(db.String(30))  # paymongo/manual
    status = db.Column(db.String(20), default="pending")  # pending/paid/failed/review

    provider_ref = db.Column(db.String(255))
    checkout_session_id = db.Column(db.String(255))

    receipt_path = db.Column(db.String(255))
    reference_no = db.Column(db.String(255))
    notes = db.Column(db.Text)

    paid_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permit = db.relationship("Permit", backref="payments")
    user = db.relationship("User", backref="payments")


# =========================
# LOGIN MANAGER
# =========================
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Unauthorized access", "danger")
            return redirect(url_for("dashboard"))

        # allow admin to reach setup pages even if 2FA disabled
        if request.endpoint not in ("twofa_setup", "twofa_disable", "logout", "twofa_verify", "login"):
            if not current_user.twofa_enabled:
                flash("Admin must enable 2FA first.", "warning")
                return redirect(url_for("twofa_setup"))

        return f(*args, **kwargs)
    return decorated_function


# =========================
# SERIAL HELPERS
# =========================
def generate_serial_for_year(year: int) -> str:
    prefix = f"{year}-"
    last_serial = db.session.query(func.max(Permit.serial_no)) \
        .filter(Permit.serial_no.like(f"{prefix}%")) \
        .scalar()

    last_num = 0
    if last_serial:
        try:
            last_num = int(last_serial.split("-")[1])
        except Exception:
            last_num = 0

    return f"{year}-{last_num + 1:06d}"


def ensure_permit_serial(permit: Permit) -> None:
    if not permit.serial_no:
        permit.serial_no = generate_serial_for_year(datetime.utcnow().year)


# =========================
# PAYMENT HELPERS
# =========================
def compute_permit_fee(permit: Permit) -> float:
    settings = SystemSettings.query.first()
    if not settings:
        return 100.0 if permit.type == "new" else 50.0
    fee = settings.registration_fee if permit.type == "new" else settings.renewal_fee
    try:
        return float(fee or 0)
    except Exception:
        return 0.0


def get_or_create_payment(permit: Permit, method: str, provider: str = None) -> Payment:
    p = Payment.query.filter_by(permit_id=permit.id, user_id=permit.user_id) \
        .order_by(Payment.created_at.desc()).first()
    if p and p.status in ["pending", "review"]:
        return p

    payment = Payment(
        permit_id=permit.id,
        user_id=permit.user_id,
        amount=compute_permit_fee(permit),
        method=method,
        provider=provider,
        status="pending"
    )
    db.session.add(payment)
    db.session.commit()
    return payment


# =========================
# ANALYTICS (MUST BE ABOVE /reports)
# =========================
def calculate_system_analytics():
    total = Permit.query.count()
    approved = Permit.query.filter_by(status="approved").count()
    rejected = Permit.query.filter_by(status="rejected").count()
    pending = Permit.query.filter_by(status="pending").count()

    approval_rate = (approved / total * 100) if total > 0 else 0
    rejection_rate = (rejected / total * 100) if total > 0 else 0

    total_businesses = Business.query.count()
    active_businesses = Business.query.filter_by(status="active").count()
    suspended_businesses = Business.query.filter_by(status="suspended").count()
    expired_businesses = Business.query.filter_by(status="expired").count()

    active_ratio = (active_businesses / total_businesses * 100) if total_businesses > 0 else 0
    expired_ratio = (expired_businesses / total_businesses * 100) if total_businesses > 0 else 0

    this_year = datetime.utcnow().year
    monthly_data = db.session.query(
        extract("month", Permit.created_at).label("month"),
        func.count().label("count")
    ).filter(extract("year", Permit.created_at) == this_year).group_by("month").all()

    monthly_reg_data = [0] * 12
    for row in monthly_data:
        monthly_reg_data[int(row.month) - 1] = row.count

    current_month = datetime.utcnow().month - 1
    this_month = monthly_reg_data[current_month] if current_month >= 0 else 0
    last_month = monthly_reg_data[current_month - 1] if current_month > 0 else 0
    monthly_growth = ((this_month - last_month) / last_month * 100) if last_month > 0 else 0

    trend_factor = monthly_growth * 0.2
    system_health = approval_rate * 0.35 + active_ratio * 0.35 - expired_ratio * 0.15 + trend_factor
    system_health = max(0, min(100, system_health))

    if system_health >= 75:
        insight = "System performance is excellent. Approval efficiency and business activity are strong."
    elif system_health >= 50:
        insight = "System is stable but requires monitoring." if monthly_growth < 0 \
            else "System operating steadily. Moderate approval rate and controlled expirations."
    else:
        insight = "System performance is low. High rejection or expired rates impacting health."

    return {
        "total": total,
        "approved": approved,
        "rejected": rejected,
        "pending": pending,
        "approval_rate": approval_rate,
        "rejection_rate": rejection_rate,
        "active_businesses": active_businesses,
        "suspended_businesses": suspended_businesses,
        "expired_businesses": expired_businesses,
        "monthly_reg_data": monthly_reg_data,
        "monthly_growth": round(monthly_growth, 1),
        "system_health": round(system_health, 1),
        "insight": insight
    }


# =========================
# PDF GENERATION
# =========================
def generate_permit_pdf(permit: Permit):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    ensure_permit_serial(permit)
    db.session.commit()

    settings = SystemSettings.query.first()
    barangay_name = (settings.barangay_name if settings and settings.barangay_name else "BARANGAY LGU3")
    contact_email = (settings.contact_email if settings and settings.contact_email else "lgu3@example.com")
    contact_phone = (settings.contact_phone if settings and settings.contact_phone else "(02) 123-4567")
    city_name = "Quezon City, Philippines"

    margin = 0.75 * inch
    left, right = margin, width - margin
    top, bottom = height - margin, margin

    c.setStrokeColor(colors.HexColor("#1e3a8a"))
    c.setLineWidth(2)
    c.rect(left, bottom, right - left, top - bottom)

    seal_path = os.path.join("static", "seal.png")
    if os.path.exists(seal_path):
        try:
            c.saveState()
            c.setFillAlpha(0.08)
            seal = ImageReader(seal_path)
            seal_size = 380
            c.drawImage(seal, (width - seal_size) / 2, (height - seal_size) / 2,
                        width=seal_size, height=seal_size, mask="auto")
            c.restoreState()
        except Exception:
            pass

    c.setFillColor(colors.HexColor("#0f172a"))
    c.rect(left, top - 1.0 * inch, right - left, 1.0 * inch, fill=1, stroke=0)

    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        try:
            logo = ImageReader(logo_path)
            c.drawImage(logo, left + 10, top - 0.9 * inch, width=60, height=60, mask="auto")
        except Exception:
            pass

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(left + 80, top - 0.42 * inch, barangay_name)

    c.setFont("Helvetica", 10)
    c.drawString(left + 80, top - 0.65 * inch, city_name)
    c.setFillColor(colors.HexColor("#cbd5e1"))
    c.drawString(left + 80, top - 0.82 * inch, f"Email: {contact_email} | Phone: {contact_phone}")

    y = top - 1.45 * inch
    c.setFillColor(colors.HexColor("#0f172a"))
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width / 2, y, "BARANGAY BUSINESS PERMIT")

    stamp_text = "RENEWAL" if (permit.type == "renewal") else "NEW"
    c.saveState()
    c.setStrokeColor(colors.HexColor("#ef4444"))
    c.setFillColor(colors.HexColor("#ef4444"))
    c.setLineWidth(2)
    c.setFont("Helvetica-Bold", 18)
    c.setFillAlpha(0.12)
    c.setStrokeAlpha(0.25)
    c.translate(right - 130, y + 10)
    c.rotate(15)
    c.roundRect(-55, -20, 110, 40, 8, fill=1, stroke=1)
    c.setFillAlpha(0.9)
    c.setStrokeAlpha(1)
    c.setFillColor(colors.white)
    c.drawCentredString(0, -6, stamp_text)
    c.restoreState()

    y -= 0.35 * inch
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.HexColor("#111827"))

    permit_no = permit.serial_no
    issued = datetime.now().strftime("%B %d, %Y")
    expires = permit.expiry_date.strftime("%B %d, %Y")

    c.drawString(left, y, f"Permit No: {permit_no}")
    c.drawRightString(right, y, f"Issue Date: {issued}")

    y -= 0.2 * inch
    c.setStrokeColor(colors.HexColor("#94a3b8"))
    c.setLineWidth(0.8)
    c.line(left, y, right, y)

    y -= 0.35 * inch
    box_top = y
    box_height = 2.55 * inch

    c.setStrokeColor(colors.HexColor("#cbd5e1"))
    c.setLineWidth(1)
    c.roundRect(left, box_top - box_height, right - left, box_height, 10, stroke=1, fill=0)

    label_x = left + 18
    value_x = label_x + 120
    row_y = box_top - 0.45 * inch
    line_gap = 14

    def draw_label(lbl, x, y_):
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(colors.HexColor("#0f172a"))
        c.drawString(x, y_, lbl)

    def draw_wrapped_value(val, x, y_, max_width, font="Helvetica", size=11):
        c.setFont(font, size)
        c.setFillColor(colors.HexColor("#111827"))
        text = val if val else "—"
        lines = simpleSplit(text, font, size, max_width)
        for i, line in enumerate(lines[:3]):
            c.drawString(x, y_ - (i * line_gap), line)
        return len(lines[:3])

    max_val_width = (right - 18) - value_x

    draw_label("Business Name:", label_x, row_y)
    used = draw_wrapped_value(permit.business_name, value_x, row_y, max_val_width)
    row_y -= (used * line_gap) + 10

    draw_label("Owner:", label_x, row_y)
    used = draw_wrapped_value(permit.owner_name, value_x, row_y, max_val_width)
    row_y -= (used * line_gap) + 10

    draw_label("Address:", label_x, row_y)
    used = draw_wrapped_value(permit.address, value_x, row_y, max_val_width)
    row_y -= (used * line_gap) + 10

    draw_label("TIN:", label_x, row_y)
    draw_wrapped_value(permit.tin, value_x, row_y, max_val_width)

    y = box_top - box_height - 0.45 * inch
    c.setFillColor(colors.HexColor("#e2e8f0"))
    c.roundRect(left, y - 0.32 * inch, right - left, 0.55 * inch, 10, fill=1, stroke=0)

    c.setFillColor(colors.HexColor("#0f172a"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left + 16, y - 0.10 * inch, "VALID UNTIL:")
    c.setFillColor(colors.HexColor("#dc2626"))
    c.drawString(left + 120, y - 0.10 * inch, expires)

    y -= 0.70 * inch
    verify_code = f"{permit_no}-{permit.expiry_date.strftime('%Y%m%d')}"
    verify_url = url_for("verify_permit", code=verify_code, _external=True)

    qr_size = 1.2 * inch
    qr = QrCodeWidget(verify_url)
    bounds = qr.getBounds()
    w = bounds[2] - bounds[0]
    h = bounds[3] - bounds[1]
    d = Drawing(qr_size, qr_size, transform=[qr_size / w, 0, 0, qr_size / h, 0, 0])
    d.add(qr)
    renderPDF.draw(d, c, right - qr_size, y - 0.2 * inch)

    c.setFillColor(colors.HexColor("#111827"))
    c.setFont("Helvetica", 10)
    c.drawString(left, y, f"Verification Code: {verify_code}")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer


# =========================
# 2FA ROUTES
# =========================
@app.route("/2fa", methods=["GET", "POST"])
def twofa_verify():
    uid = session.get("twofa_user_id")
    if not uid:
        return redirect(url_for("login"))

    user = User.query.get(uid)
    if not user or not user.twofa_enabled or not user.twofa_secret:
        session.pop("twofa_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(code, valid_window=1):
            session.pop("twofa_user_id", None)
            login_user(user)
            flash("Login successful", "success")
            return redirect(url_for("admin_dashboard" if user.role == "admin" else "dashboard"))
        flash("Invalid verification code.", "danger")

    return render_template("twofa_verify.html")


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def twofa_setup():
    if request.method == "GET":
        secret = pyotp.random_base32()
        current_user.twofa_temp_secret = secret
        db.session.commit()

        issuer = "LGU3 Permit System"
        uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name=issuer)

        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return render_template("twofa_setup.html", qr_b64=qr_b64, secret=secret)

    code = (request.form.get("code") or "").strip().replace(" ", "")
    secret = current_user.twofa_temp_secret
    if not secret:
        flash("2FA setup expired. Try again.", "warning")
        return redirect(url_for("twofa_setup"))

    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        current_user.twofa_secret = secret
        current_user.twofa_enabled = True
        current_user.twofa_temp_secret = None
        db.session.commit()
        flash("2FA enabled successfully.", "success")
        return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "dashboard"))

    flash("Invalid code. Try again.", "danger")
    return redirect(url_for("twofa_setup"))


@app.route("/2fa/disable", methods=["POST"])
@login_required
def twofa_disable():
    if current_user.role == "admin":
        return jsonify(success=False, message="Admins cannot disable 2FA."), 403

    current_user.twofa_enabled = False
    current_user.twofa_secret = None
    current_user.twofa_temp_secret = None
    db.session.commit()
    flash("2FA disabled.", "info")
    return redirect(url_for("dashboard"))


# =========================
# PUBLIC ROUTES
# =========================
@app.route("/")
def home():
    registered_businesses = Business.query.count()
    print("REGISTERED BUSINESSES:", registered_businesses)

    invalid_permits = Permit.query.filter_by(status="rejected").count()

    return render_template(
        "home.html",
        registered_businesses=registered_businesses,
        invalid_permits=invalid_permits
    )

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email_value = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email_value or not password:
            flash("All fields are required", "warning")
            return redirect(url_for("login"))

        # Fetch user
        user = User.query.filter_by(email=email_value).first()

        # Verify password
        ok = False
        if user and user.password:
            try:
                stored = user.password
                if isinstance(stored, str):
                    stored = stored.encode("utf-8")
                ok = bcrypt.checkpw(password.encode("utf-8"), stored)
            except ValueError:
                ok = False

        if not ok:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))

        # =========================
        # 👑 ADMIN FLOW (Google Authenticator Only)
        # =========================
        if user.role == "admin":

            # First time setup
            if not user.twofa_enabled:
                login_user(user)
                flash("Admin must enable 2FA before using admin pages.", "warning")
                return redirect(url_for("twofa_setup"))

            # If 2FA enabled → verify TOTP
            if user.twofa_enabled and user.twofa_secret:
                session["twofa_user_id"] = user.id
                return redirect(url_for("twofa_verify"))

            # Fallback
            login_user(user)
            return redirect(url_for("admin_dashboard"))

        # =========================
        # 👤 USER FLOW
        # =========================

        # Email verification (signup verification)
        if not user.is_email_verified:
            session["verify_user_id"] = user.id
            flash("Please verify your email first.", "warning")
            return redirect(url_for("verify_email"))

        # Admin approval check
        if user.status != "approved":
            if user.status == "pending":
                flash("Your account is pending admin approval.", "warning")
            elif user.status == "rejected":
                flash("Your account was rejected. Please contact the administrator.", "danger")
            else:
                flash("Your account is not approved.", "warning")
            return redirect(url_for("login"))

        # 🔐 USER EMAIL 2FA (Login OTP)
        send_email_otp(user)
        session["login_otp_user_id"] = user.id
        flash("Verification code sent to your email.", "info")
        return redirect(url_for("login_email_otp"))

    return render_template("login.html")

@app.route("/login-otp", methods=["GET", "POST"])
def login_email_otp():
    uid = session.get("login_otp_user_id")
    if not uid:
        return redirect(url_for("login"))

    user = User.query.get(uid)
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = (request.form.get("otp") or "").strip()

        if user.email_otp_attempts >= 5:
            flash("Too many failed attempts.", "danger")
            return redirect(url_for("login"))

        if not user.email_otp_expiry or datetime.utcnow() > user.email_otp_expiry:
            flash("OTP expired. Please login again.", "warning")
            return redirect(url_for("login"))

        if hash_otp(otp_input) == user.email_otp_hash:
            user.email_otp_hash = None
            user.email_otp_expiry = None
            user.email_otp_attempts = 0
            db.session.commit()

            session.pop("login_otp_user_id", None)

            login_user(user)
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))

        else:
            user.email_otp_attempts += 1
            db.session.commit()
            flash("Invalid verification code.", "danger")

    return render_template("login_email_otp.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        business_name = request.form.get("business_name")
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password")

        if not all([first_name, last_name, business_name, email, password]):
            flash("All fields are required.", "warning")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("signup"))

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        new_user = User(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            business_name=business_name,
            password=hashed_pw,
            role="user",
            status="pending",
            is_email_verified=False
        )

        db.session.add(new_user)
        db.session.commit()

        # 🔥 Send Email OTP
        send_email_otp(new_user)

        # Store user ID in session for verification
        session["verify_user_id"] = new_user.id

        flash("Account created. Please verify your email.", "info")
        return redirect(url_for("verify_email"))

    # ✅ THIS RETURN IS IMPORTANT
    return render_template("signup.html")

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    user_id = session.get("verify_user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = (request.form.get("otp") or "").strip()

        if user.email_otp_attempts >= 5:
            flash("Too many failed attempts.", "danger")
            return redirect(url_for("login"))

        if not user.email_otp_expiry or datetime.utcnow() > user.email_otp_expiry:
            flash("OTP expired. Please request a new one.", "warning")
            return redirect(url_for("resend_email_otp"))

        if hash_otp(otp_input) == user.email_otp_hash:
            user.is_email_verified = True
            user.email_otp_hash = None
            user.email_otp_expiry = None
            user.email_otp_attempts = 0
            db.session.commit()

            session.pop("verify_user_id", None)

            flash("Email verified successfully. Awaiting admin approval.", "success")
            return redirect(url_for("login"))

        else:
            user.email_otp_attempts += 1
            db.session.commit()
            flash("Invalid verification code.", "danger")

    return render_template("verify_email.html")

def send_email_otp(user):
    otp = generate_email_otp()

    user.email_otp_hash = hash_otp(otp)
    user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    user.email_otp_attempts = 0
    db.session.commit()

    msg = Message(
        subject="LGU3 Account Verification Code",
        recipients=[user.email],
        body=f"""
Barangay LGU3 Business Permit System

Your verification code is: {otp}

This code will expire in 5 minutes.
Do not share this code with anyone.

If you did not request this, please ignore this email.
"""
    )

    try:
        mail.send(msg)
        print("EMAIL SENT SUCCESSFULLY TO:", user.email)
    except Exception as e:
        print("EMAIL ERROR:", e)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("twofa_user_id", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    today = date.today()
    if current_user.role == "admin":
        permits = Permit.query.order_by(Permit.created_at.desc()).all()
    else:
        permits = Permit.query.filter_by(user_id=current_user.id).order_by(Permit.created_at.desc()).all()
    return render_template("dashboard.html", permits=permits, today=today)


@app.route("/register_business", methods=["GET", "POST"])
@login_required
def register_business():
    settings = SystemSettings.query.first()
    if settings and not settings.registration_open:
        flash("New registrations are currently disabled by the administrator.", "danger")
        return redirect(url_for("dashboard"))

    # ✅ Only approved users can submit business
    if current_user.role == "user" and current_user.status != "approved":
        flash("Your account must be approved by the administrator before registering a business.", "warning")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        business_name = request.form.get("business_name")
        owner_name = request.form.get("owner_name")
        address = request.form.get("address")
        tin = request.form.get("tin")
        expiry_date = request.form.get("expiry_date")

        if not all([business_name, owner_name, address, tin, expiry_date]):
            flash("All fields are required.", "warning")
            return redirect(url_for("register_business"))

        try:
            expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid expiry date.", "danger")
            return redirect(url_for("register_business"))

        new_permit = Permit(
            business_name=business_name,
            owner_name=owner_name,
            address=address,
            tin=tin,
            expiry_date=expiry_date,
            user_id=current_user.id,
            status="pending",
            type="new",
            serial_no=generate_serial_for_year(datetime.utcnow().year)
        )
        db.session.add(new_permit)
        db.session.commit()

        flash("Business registration submitted. Please wait for admin approval.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register_business.html")


@app.route("/renewals")
@login_required
def renewals():
    permits = Permit.query.filter_by(user_id=current_user.id).all()
    return render_template("renewals.html", permits=permits, today=date.today(), timedelta=timedelta)


@app.route("/renew-permit/<int:permit_id>")
@login_required
def renew_permit(permit_id):
    old = Permit.query.get_or_404(permit_id)
    today_ = date.today()

    if old.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("renewals"))

    if old.status != "approved":
        flash("Only approved permits can renew", "warning")
        return redirect(url_for("renewals"))

    if not (old.expiry_date >= today_ and old.expiry_date <= today_ + timedelta(days=30)):
        flash("Renewal allowed only 30 days before expiry", "warning")
        return redirect(url_for("renewals"))

    existing = Permit.query.filter_by(parent_id=old.id, status="pending").first()
    if existing:
        flash("Renewal already pending", "info")
        return redirect(url_for("renewals"))

    new_permit = Permit(
        business_name=old.business_name,
        owner_name=old.owner_name,
        address=old.address,
        tin=old.tin,
        expiry_date=old.expiry_date + timedelta(days=365),
        user_id=current_user.id,
        status="pending",
        type="renewal",
        parent_id=old.id,
        serial_no=generate_serial_for_year(datetime.utcnow().year)
    )
    db.session.add(new_permit)
    db.session.commit()

    flash("Renewal submitted", "success")
    return redirect(url_for("renewals"))


@app.route("/permit-history/<int:permit_id>")
@login_required
def permit_history(permit_id):
    permit = Permit.query.get_or_404(permit_id)
    root_id = permit.parent_id if permit.parent_id else permit.id

    history = Permit.query.filter(
        (Permit.id == root_id) | (Permit.parent_id == root_id)
    ).order_by(Permit.created_at.asc()).all()

    return render_template("permit_history.html", history=history)


@app.route("/permit/<int:permit_id>/download")
@login_required
def download_permit(permit_id):
    permit = Permit.query.get_or_404(permit_id)

    if current_user.role != "admin" and permit.user_id != current_user.id:
        abort(403)
    if permit.status != "approved":
        abort(403)
    if permit.payment_required and permit.payment_status not in ["paid", "waived"]:
        abort(403)

    pdf = generate_permit_pdf(permit)
    fname = permit.serial_no or f"permit_{permit.id}"
    return send_file(pdf, as_attachment=True, download_name=f"{fname}.pdf", mimetype="application/pdf")

@app.route("/admin/generate-permit/<int:permit_id>")
@login_required
def generate_permit(permit_id):
    return download_permit(permit_id)


# =========================
# ADMIN ROUTES
# =========================
@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    total_permits = Permit.query.count()
    pending = Permit.query.filter_by(status="pending").count()
    approved = Permit.query.filter_by(status="approved").count()
    rejected = Permit.query.filter_by(status="rejected").count()

    pending_list = Permit.query.filter(Permit.status.in_(["pending", "for_review"])) \
        .order_by(Permit.created_at.desc()).all()

    this_year = datetime.utcnow().year
    monthly_data = db.session.query(
        extract("month", Permit.created_at).label("month"),
        func.count().label("count")
    ).filter(extract("year", Permit.created_at) == this_year).group_by("month").all()

    monthly_reg_data = [0] * 12
    for row in monthly_data:
        monthly_reg_data[int(row.month) - 1] = row.count

    filter_type = request.args.get("filter", "all")
    page = request.args.get("page", 1, type=int)

    logs_query = db.session.query(AdminLog, User.username, Permit.business_name) \
        .join(User, User.id == AdminLog.admin_id) \
        .join(Permit, Permit.id == AdminLog.permit_id)

    if filter_type == "today":
        logs_query = logs_query.filter(func.date(AdminLog.created_at) == date.today())
    elif filter_type == "week":
        logs_query = logs_query.filter(AdminLog.created_at >= datetime.utcnow() - timedelta(days=7))
    elif filter_type == "month":
        logs_query = logs_query.filter(AdminLog.created_at >= datetime.utcnow() - timedelta(days=30))

    logs_query = logs_query.order_by(AdminLog.created_at.desc())
    pagination = logs_query.paginate(page=page, per_page=5, error_out=False)
    recent_logs = pagination.items

    today_count = Permit.query.filter(func.date(Permit.created_at) == date.today()).count()
    approved_today = Permit.query.filter(func.date(Permit.approved_at) == date.today()).count()
    rejected_today = Permit.query.filter(func.date(Permit.rejected_at) == date.today()).count()

    all_permits = Permit.query.order_by(Permit.created_at.desc()).limit(50).all()
    paid_count = Permit.query.filter(Permit.status == "approved", Permit.payment_status == "paid").count()
    waived_count = Permit.query.filter(Permit.status == "approved", Permit.payment_status == "waived").count()
    unpaid_count = Permit.query.filter(
        Permit.status == "approved",
        Permit.payment_status.notin_(["paid", "waived"])
    ).count()

    return render_template(
        "admin/dashboard.html",
        total_permits=total_permits,
        pending=pending,
        approved=approved,
        rejected=rejected,
        pending_list=pending_list,
        monthly_reg_data=monthly_reg_data,
        recent_logs=recent_logs,
        pagination=pagination,
        today_count=today_count,
        approved_today=approved_today,
        rejected_today=rejected_today,
        pending_users=User.query.filter_by(role="user", status="pending").count(),
        all_permits=all_permits,
        paid_count=paid_count,
        unpaid_count=unpaid_count,
        waived_count=waived_count
    )


@app.route("/admin/approve-permit/<int:permit_id>", methods=["POST"])
@login_required
@admin_required
def approve_permit(permit_id):
    permit = Permit.query.get_or_404(permit_id)

    permit.status = "approved"
    permit.approved_at = datetime.utcnow()
    permit.payment_required = True
    permit.payment_status = "unpaid"
    ensure_permit_serial(permit)

    existing_business = Business.query.filter_by(
        business_name=permit.business_name,
        user_id=permit.user_id
    ).first()

    if existing_business:
        existing_business.status = "active"
        existing_business.permit_id = permit.id
        existing_business.address = permit.address
    else:
        db.session.add(Business(
            business_name=permit.business_name,
            address=permit.address,
            user_id=permit.user_id,
            permit_id=permit.id,
            status="active"
        ))

    db.session.add(AdminLog(admin_id=current_user.id, action="Approved permit", permit_id=permit.id))
    db.session.commit()
    return jsonify(success=True, message="Application approved successfully")


@app.route("/admin/reject-permit/<int:permit_id>", methods=["POST"])
@login_required
@admin_required
def reject_permit(permit_id):
    permit = Permit.query.get_or_404(permit_id)
    reason = (request.form.get("reason") or "").strip()

    if not reason:
        return jsonify(success=False, message="Rejection reason required"), 400

    permit.status = "rejected"
    permit.rejected_at = datetime.utcnow()
    permit.rejected_reason = reason

    db.session.add(AdminLog(admin_id=current_user.id, action=f"Rejected permit - {reason}", permit_id=permit.id))
    db.session.commit()
    return jsonify(success=True, message="Application rejected successfully")


@app.route("/admin/users")
@login_required
@admin_required
def manage_users():
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "all").strip()

    q = User.query.filter(User.role == "user")

    if status != "all":
        q = q.filter(User.status == status)

    if search:
        like = f"%{search}%"
        q = q.filter(
            User.first_name.ilike(like) |
            User.last_name.ilike(like) |
            User.email.ilike(like) |
            User.business_name.ilike(like)
        )

    users = q.order_by(User.id.desc()).all()
    return render_template("admin/users.html", users=users, search=search, status=status)


@app.route("/admin/approve-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def approve_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.role != "user":
        return jsonify(success=False, message="Cannot approve non-user accounts."), 400

    u.status = "approved"
    u.is_approved = True
    u.rejection_reason = None
    u.approved_at = datetime.utcnow()
    u.rejected_at = None

    db.session.commit()
    return jsonify(success=True, message="User approved successfully.")


@app.route("/admin/reject-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def reject_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.role != "user":
        return jsonify(success=False, message="Cannot reject non-user accounts."), 400

    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify(success=False, message="Rejection reason is required."), 400

    u.status = "rejected"
    u.is_approved = False
    u.rejection_reason = reason
    u.rejected_at = datetime.utcnow()

    db.session.commit()
    return jsonify(success=True, message="User rejected successfully.")


@app.route("/admin/bulk-approve", methods=["POST"])
@login_required
@admin_required
def bulk_approve():
    data = request.get_json(silent=True) or {}
    ids = data.get("users", [])

    clean_ids = []
    for x in ids:
        try:
            clean_ids.append(int(x))
        except Exception:
            pass

    if not clean_ids:
        return jsonify(success=False, message="No users selected."), 400

    users = User.query.filter(User.id.in_(clean_ids), User.role == "user").all()
    for u in users:
        u.status = "approved"
        u.is_approved = True
        u.rejection_reason = None
        u.approved_at = datetime.utcnow()
        u.rejected_at = None

    db.session.commit()
    return jsonify(success=True, message=f"Approved {len(users)} user(s).")


@app.route("/admin/dashboard-data")
@login_required
@admin_required
def dashboard_data():
    pending = Permit.query.filter_by(status="pending").count()
    approved = Permit.query.filter_by(status="approved").count()
    rejected = Permit.query.filter_by(status="rejected").count()

    paid = Permit.query.filter(Permit.status == "approved", Permit.payment_status == "paid").count()
    waived = Permit.query.filter(Permit.status == "approved", Permit.payment_status == "waived").count()
    unpaid = Permit.query.filter(
        Permit.status == "approved",
        Permit.payment_status.notin_(["paid", "waived"])
    ).count()

    return jsonify({"pending": pending, "approved": approved, "rejected": rejected, "paid": paid, "unpaid": unpaid, "waived": waived})


@app.route("/admin/businesses")
@login_required
@admin_required
def admin_businesses():
    status_filter = (request.args.get("status") or "").strip()
    search = (request.args.get("search") or "").strip()

    query = Business.query

    if status_filter and status_filter != "all":
        query = query.filter(Business.status == status_filter)

    if search:
        query = query.filter(Business.business_name.ilike(f"%{search}%"))

    businesses = query.order_by(Business.created_at.desc()).all()

    today_ = date.today()
    changed = False

    for b in businesses:
        # ✅ only auto-expire ACTIVE/INACTIVE (not suspended)
        if b.status in ("active", "inactive") and b.permit_id:
            p = Permit.query.get(b.permit_id)
            if p and p.expiry_date and p.expiry_date < today_:
                b.status = "expired"
                changed = True

    if changed:
        db.session.commit()

    return render_template(
        "admin/businesses.html",
        businesses=businesses,
        status_filter=status_filter,
        search=search
    )

@app.route("/admin/businesses/<int:business_id>/suspend", methods=["POST"])
@login_required
@admin_required
def suspend_business(business_id):
    b = Business.query.get_or_404(business_id)

    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify(success=False, message="Suspension reason is required."), 400

    b.status = "suspended"
    b.suspended_reason = reason
    b.suspended_at = datetime.utcnow()

    db.session.add(AdminLog(
        admin_id=current_user.id,
        action=f"Suspended business '{b.business_name}' - {reason}",
        permit_id=b.permit_id
    ))
    db.session.commit()

    return jsonify(success=True, message="Business suspended.")


@app.route("/admin/businesses/<int:business_id>/activate", methods=["POST"])
@login_required
@admin_required
def activate_business(business_id):
    b = Business.query.get_or_404(business_id)

    b.status = "active"
    b.suspended_reason = None
    b.activated_at = datetime.utcnow()

    db.session.add(AdminLog(
        admin_id=current_user.id,
        action=f"Activated business '{b.business_name}'",
        permit_id=b.permit_id
    ))
    db.session.commit()

    return jsonify(success=True, message="Business activated.") 


@app.route("/admin/applications")
@login_required
@admin_required
def admin_applications():
    status = request.args.get("status", "pending")
    search = request.args.get("search", "")
    page = request.args.get("page", 1, type=int)

    query = Permit.query
    if status != "all":
        query = query.filter_by(status=status)

    if search:
        query = query.filter(
            Permit.business_name.ilike(f"%{search}%") |
            Permit.owner_name.ilike(f"%{search}%") |
            Permit.address.ilike(f"%{search}%") |
            Permit.tin.ilike(f"%{search}%")
        )

    pagination = query.order_by(Permit.created_at.desc()).paginate(page=page, per_page=8, error_out=False)
    return render_template(
        "admin/applications.html",
        permits=pagination.items,
        pagination=pagination,
        status=status,
        search=search,
        today=date.today(),
        timedelta=timedelta
    )


@app.route("/admin/payments")
@login_required
@admin_required
def admin_payments():
    status = request.args.get("status", "review")
    search = request.args.get("search", "")
    page = request.args.get("page", 1, type=int)

    q = Payment.query.join(Permit, Payment.permit_id == Permit.id).join(User, Payment.user_id == User.id)
    if status != "all":
        q = q.filter(Payment.status == status)
    if search:
        q = q.filter(
            Permit.business_name.ilike(f"%{search}%") |
            User.email.ilike(f"%{search}%") |
            Payment.reference_no.ilike(f"%{search}%")
        )

    pagination = q.order_by(Payment.created_at.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template("admin/payments.html", payments=pagination.items, pagination=pagination, status=status, search=search)


# =========================
# ADMIN: PAYMENT ACTIONS
# =========================
@app.route("/admin/payments/<int:payment_id>/approve", methods=["POST"])
@login_required
@admin_required
def admin_approve_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    permit = Permit.query.get(payment.permit_id)

    payment.status = "paid"
    payment.paid_at = datetime.utcnow()
    payment.updated_at = datetime.utcnow()

    if permit:
        permit.payment_status = "paid"
        permit.payment_required = True

    db.session.commit()
    return jsonify(success=True, message="Payment approved and marked as PAID.")


@app.route("/admin/payments/<int:payment_id>/waive", methods=["POST"])
@login_required
@admin_required
def admin_waive_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    permit = Permit.query.get(payment.permit_id)

    payment.status = "paid"
    payment.paid_at = datetime.utcnow()
    payment.updated_at = datetime.utcnow()
    payment.method = "manual"
    payment.provider = "waived"
    payment.notes = (payment.notes or "") + "\n[ADMIN] Payment waived."

    if permit:
        permit.payment_status = "waived"
        permit.payment_required = False

    db.session.commit()
    return jsonify(success=True, message="Payment waived. Permit is now downloadable.")


@app.route("/admin/payments/<int:payment_id>/mark-paid", methods=["POST"])
@login_required
@admin_required
def admin_mark_payment_paid(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    permit = Permit.query.get(payment.permit_id)

    payment.status = "paid"
    payment.paid_at = datetime.utcnow()
    payment.updated_at = datetime.utcnow()

    if permit:
        permit.payment_status = "paid"
        permit.payment_required = True

    db.session.commit()
    return jsonify(success=True, message="Payment marked as PAID. Permit is now downloadable.")


@app.route("/admin/payments/<int:payment_id>/reject", methods=["POST"])
@login_required
@admin_required
def admin_reject_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)

    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()

    payment.status = "failed"
    if reason:
        payment.notes = (payment.notes or "") + f"\n[ADMIN REJECT] {reason}"
    payment.updated_at = datetime.utcnow()

    db.session.commit()
    return jsonify(success=True, message="Payment rejected.")


@app.route("/reports")
@login_required
@admin_required
def reports():
    data = calculate_system_analytics()
    return render_template("reports.html", **data)


@app.route("/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings():
    s = SystemSettings.query.first()
    if not s:
        s = SystemSettings()
        db.session.add(s)
        db.session.commit()

    if request.method == "POST":
        s.barangay_name = request.form.get("barangay_name")
        s.contact_email = request.form.get("contact_email")
        s.contact_phone = request.form.get("contact_phone")
        s.registration_open = True if request.form.get("registration_open") else False
        s.renewal_open = True if request.form.get("renewal_open") else False
        db.session.commit()
        flash("Settings updated successfully", "success")
        return redirect(url_for("settings", saved="1"))

    return render_template("settings.html", settings=s)


@app.route("/verify/<code>")
def verify_permit(code):
    try:
        parts = code.split("-")
        serial = f"{parts[0]}-{parts[1]}"
    except Exception:
        return render_template("verify.html", ok=False, message="Invalid verification code.")

    permit = Permit.query.filter_by(serial_no=serial).first()
    if not permit:
        return render_template("verify.html", ok=False, message="Permit not found.")

    expected = f"{permit.serial_no}-{permit.expiry_date.strftime('%Y%m%d')}"
    if code != expected:
        return render_template("verify.html", ok=False, message="Verification code mismatch.")

    if permit.status != "approved":
        return render_template("verify.html", ok=False, message="Permit is not approved.")

    return render_template("verify.html", ok=True, permit=permit, code=code)


@app.context_processor
def inject_year():
    return {"current_year": datetime.utcnow().year}


# =========================
# EXPORT ADMIN LOGS (CSV) - url_for('export_logs')
# =========================
@app.route("/admin/export-logs")
@login_required
@admin_required
def export_logs():
    filter_type = request.args.get("filter", "all")

    logs_query = db.session.query(AdminLog, User.username, Permit.business_name) \
        .join(User, User.id == AdminLog.admin_id) \
        .join(Permit, Permit.id == AdminLog.permit_id)

    if filter_type == "today":
        logs_query = logs_query.filter(func.date(AdminLog.created_at) == date.today())
    elif filter_type == "week":
        logs_query = logs_query.filter(AdminLog.created_at >= datetime.utcnow() - timedelta(days=7))
    elif filter_type == "month":
        logs_query = logs_query.filter(AdminLog.created_at >= datetime.utcnow() - timedelta(days=30))

    logs_query = logs_query.order_by(AdminLog.created_at.desc())

    output = BytesIO()
    text_stream = io.TextIOWrapper(output, encoding="utf-8", newline="")
    writer = csv.writer(text_stream)

    writer.writerow(["Date/Time (UTC)", "Admin", "Business", "Action", "Permit ID"])

    for log, username, business_name in logs_query.all():
        writer.writerow([
            log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else "",
            username or "",
            business_name or "",
            log.action or "",
            log.permit_id or ""
        ])

    text_stream.flush()
    output.seek(0)

    filename = f"admin_logs_{filter_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(output, as_attachment=True, download_name=filename, mimetype="text/csv")


# =========================
# PAYMENTS: BOTH (Manual + PayMongo)
# =========================
@app.route("/permit/<int:permit_id>/pay", methods=["GET"])
@login_required
def pay_permit(permit_id):
    permit = Permit.query.get_or_404(permit_id)

    if current_user.role != "admin" and permit.user_id != current_user.id:
        abort(403)

    if permit.status != "approved":
        flash("Only approved permits can be paid.", "warning")
        return redirect(url_for("dashboard"))

    if permit.payment_status in ["paid", "waived"]:
        flash("This permit is already settled.", "info")
        return redirect(url_for("dashboard"))

    amount = compute_permit_fee(permit)
    return render_template("pay_permit.html", permit=permit, amount=amount)


@app.route("/permit/<int:permit_id>/pay/manual", methods=["POST"])
@login_required
def pay_permit_manual(permit_id):
    permit = Permit.query.get_or_404(permit_id)

    if current_user.role != "admin" and permit.user_id != current_user.id:
        abort(403)

    if permit.status != "approved":
        flash("Only approved permits can be paid.", "warning")
        return redirect(url_for("dashboard"))

    if permit.payment_status in ["paid", "waived"]:
        flash("This permit is already settled.", "info")
        return redirect(url_for("dashboard"))

    ref = (request.form.get("reference_no") or "").strip()
    receipt = request.files.get("receipt")

    if not ref:
        flash("Reference number is required.", "warning")
        return redirect(url_for("pay_permit", permit_id=permit.id))

    if not receipt or receipt.filename == "":
        flash("Receipt upload is required.", "warning")
        return redirect(url_for("pay_permit", permit_id=permit.id))

    ext = os.path.splitext(receipt.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".pdf"]:
        flash("Receipt must be JPG, PNG, or PDF.", "danger")
        return redirect(url_for("pay_permit", permit_id=permit.id))

    filename = f"receipt_{permit.id}_{int(datetime.utcnow().timestamp())}{ext}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    receipt.save(save_path)

    payment = get_or_create_payment(permit, method="manual", provider="manual")
    payment.status = "review"
    payment.reference_no = ref

    # ✅ FIX: store relative-to-static path ONLY
    payment.receipt_path = f"uploads/receipts/{filename}"

    payment.notes = (request.form.get("notes") or "").strip()
    payment.updated_at = datetime.utcnow()
    db.session.commit()

    flash("Payment submitted for review. Please wait for admin confirmation.", "success")
    return redirect(url_for("dashboard"))


@app.route("/permit/<int:permit_id>/pay/online", methods=["POST"])
@login_required
def pay_permit_online(permit_id):
    permit = Permit.query.get_or_404(permit_id)

    if current_user.role != "admin" and permit.user_id != current_user.id:
        abort(403)

    if permit.status != "approved":
        flash("Only approved permits can be paid.", "warning")
        return redirect(url_for("dashboard"))

    if permit.payment_status in ["paid", "waived"]:
        flash("This permit is already settled.", "info")
        return redirect(url_for("dashboard"))

    secret = os.getenv("PAYMONGO_SECRET_KEY")
    if not secret or not secret.startswith("sk_"):
        flash("Invalid PayMongo secret key. Check PAYMONGO_SECRET_KEY in .env", "danger")
        return redirect(url_for("pay_permit", permit_id=permit.id))

    amount_php = compute_permit_fee(permit)
    amount_centavos = int(round(amount_php * 100))

    payment = get_or_create_payment(permit, method="online", provider="paymongo")

    headers = {
        "Authorization": paymongo_auth_header(secret),
        "Content-Type": "application/json"
    }

    payload = {
        "data": {
            "attributes": {
                "amount": amount_centavos,
                "description": f"Permit #{permit.id} - {permit.business_name}",
                "remarks": f"PERMIT-{permit.id}-PAY-{payment.id}"
            }
        }
    }

    try:
        r = requests.post(
            "https://api.paymongo.com/v1/links",
            headers=headers,
            json=payload,
            timeout=30
        )

        data = r.json()

        if r.status_code >= 400:
            detail = "Unknown PayMongo error"
            try:
                detail = data.get("errors", [{}])[0].get("detail", detail)
            except Exception:
                pass
            flash(f"PayMongo error: {detail}", "danger")
            return redirect(url_for("pay_permit", permit_id=permit.id))

        link = data["data"]
        payment.provider_ref = link["id"]         # ✅ store PayMongo Link ID
        payment.status = "pending"
        payment.updated_at = datetime.utcnow()
        db.session.commit()

        checkout_url = link["attributes"]["checkout_url"]
        return redirect(checkout_url)

    except Exception as e:
        flash(f"Payment error: {str(e)}", "danger")
        return redirect(url_for("pay_permit", permit_id=permit.id))


@app.route("/paymongo/success/<int:payment_id>")
@login_required
def paymongo_success(payment_id):
    payment = Payment.query.get_or_404(payment_id)

    if current_user.role != "admin" and payment.user_id != current_user.id:
        abort(403)

    flash("Payment initiated. We will confirm once PayMongo completes processing.", "info")
    return redirect(url_for("dashboard"))


@app.route("/webhooks/paymongo", methods=["POST"])
def paymongo_webhook():
    """
    Since you are using PayMongo Links:
    - We store link["id"] into Payment.provider_ref
    - Webhook handler should attempt to locate payment by that provider_ref
    """
    payload = request.get_json(silent=True) or {}
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}

    # ✅ PayMongo "id" is usually at data["id"]
    paymongo_id = data.get("id") or attributes.get("id")
    status = (attributes.get("status") or "").lower()
    paid = status in ["paid", "succeeded", "success"]

    payment = None
    if paymongo_id:
        payment = Payment.query.filter_by(provider_ref=paymongo_id).first()

    # If not found, acknowledge webhook (don't spam retries)
    if not payment:
        return jsonify(ok=True), 200

    if paid and payment.status != "paid":
        payment.status = "paid"
        payment.paid_at = datetime.utcnow()
        payment.updated_at = datetime.utcnow()

        permit = Permit.query.get(payment.permit_id)
        if permit:
            permit.payment_status = "paid"
            permit.payment_required = True

        db.session.commit()

    return jsonify(ok=True), 200

@app.route("/test-email")
def test_email():
    try:
        msg = Message(
            subject="LGU3 Test Email",
            sender=app.config["MAIL_USERNAME"],
            recipients=["gersonrodavia@gmail.com"],
            body="If you see this, SMTP works."
        )
        mail.send(msg)
        print("EMAIL SENT SUCCESSFULLY")
        return "Email sent!"
    except Exception as e:
        print("EMAIL ERROR:", e)
        return f"Error: {str(e)}"
    
@app.route("/resend-email-otp")
def resend_email_otp():
    uid = session.get("verify_user_id")
    if not uid:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(uid)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    send_email_otp(user)
    flash("A new verification code has been sent to your email.", "info")
    return redirect(url_for("verify_email"))    


# =========================
# INIT / RUN
# =========================
def init_db():
    print(">>> init_db(): enter")
    with app.app_context():
        print(">>> init_db(): before create_all()")
        db.create_all()
        print(">>> init_db(): after create_all()")


if __name__ == "__main__":
    print(">>> main: before init_db()")
    init_db()
    print(">>> main: after init_db()")
    print(">>> main: before app.run()")
    app.run(debug=True, port=5001, host="127.0.0.1", use_reloader=False, threaded=True)