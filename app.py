import os
import time
from datetime import datetime
from functools import wraps

import stripe
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

app = Flask(__name__)

IS_DEV = os.getenv("FLASK_ENV", "development").lower() == "development"

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY and not IS_DEV:
    raise RuntimeError("SECRET_KEY must be set in production")

app.config["SECRET_KEY"] = SECRET_KEY or "dev-secret"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = not IS_DEV
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# ------------------ SIMPLE RATE LIMIT ------------------
LOGIN_ATTEMPTS = {}
LOGIN_WINDOW = 60
LOGIN_MAX = 5

def is_rate_limited(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= LOGIN_MAX

def record_attempt(ip):
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(255))
    stripe_subscription_id = db.Column(db.String(255))


# ------------------ HELPERS ------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        user = current_user()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        user = current_user()
        if not user or not user.is_admin:
            abort(403)
        return f(*a, **k)
    return w


def stripe_value(data, key, default=None):
    if data is None:
        return default
    if isinstance(data, dict):
        return data.get(key, default)
    return getattr(data, key, default)


# ------------------ SECURITY HEADERS ------------------
@app.after_request
def set_secure_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ------------------ ROUTES ------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password_raw = request.form["password"]

        if not email or "@" not in email:
            return render_template("signup.html", error="Invalid email")

        if len(password_raw) < 12:
            return render_template("signup.html", error="Password must be at least 12 characters")

        if User.query.filter_by(email=email).first():
            return render_template("signup.html", error="Email already registered")

        password = generate_password_hash(password_raw)

        user = User(
            email=email,
            password=password,
            is_admin=(User.query.count() == 0),
        )

        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if request.method == "POST":
        if is_rate_limited(ip):
            return render_template("login.html", error="Too many attempts, try later"), 429

        record_attempt(ip)

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())


@app.route("/upgrade")
@login_required
def upgrade():
    return render_template("upgrade.html", user=current_user())


@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    user = current_user()

    checkout_session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        customer_email=user.email,
        client_reference_id=str(user.id),
        metadata={"user_id": str(user.id)},
        success_url=url_for("billing_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=url_for("upgrade", _external=True),
    )

    return jsonify({"url": checkout_session.url})


@app.route("/create-billing-portal", methods=["POST"])
@login_required
def create_billing_portal():
    user = current_user()

    if not user.stripe_customer_id or not user.stripe_subscription_id:
        return jsonify({"error": "Billing not available"}), 400

    try:
        billing_session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=url_for("pro", _external=True),
        )
        return jsonify({"url": billing_session.url})
    except Exception:
        return jsonify({"error": "Unable to open billing portal"}), 500


@app.route("/billing-success")
@login_required
def billing_success():
    return render_template("billing_success.html", user=current_user())


@app.route("/billing-manage")
@login_required
def billing_manage():
    return render_template("billing_manage.html", user=current_user())


@app.route("/pro")
@login_required
def pro():
    if not current_user().is_pro:
        return redirect(url_for("upgrade"))
    return render_template("pro.html", user=current_user())


# ------------------ STRIPE WEBHOOK ------------------
@csrf.exempt
@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    try:
        event_type = event["type"]
        obj = event["data"]["object"]

        if event_type == "checkout.session.completed":
            user_id = stripe_value(obj, "client_reference_id")

            user = db.session.get(User, int(user_id)) if user_id else None

            if user:
                user.is_pro = True
                user.stripe_customer_id = stripe_value(obj, "customer")
                user.stripe_subscription_id = stripe_value(obj, "subscription")
                db.session.commit()

        elif event_type == "customer.subscription.deleted":
            sub_id = stripe_value(obj, "id")
            user = User.query.filter_by(stripe_subscription_id=sub_id).first()
            if user:
                user.is_pro = False
                user.stripe_subscription_id = None
                db.session.commit()

    except Exception:
        db.session.rollback()
        return "Webhook failed", 500

    return "OK", 200


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------ ERRORS ------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(429)
def too_many(e):
    return render_template("429.html"), 429


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# ------------------ INIT ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=IS_DEV)