import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import stripe
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix


load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

IS_DEV = os.getenv("FLASK_ENV", "development").lower() == "development"

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    if IS_DEV:
        secret_key = os.urandom(32).hex()
    else:
        raise RuntimeError("SECRET_KEY not set")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = not IS_DEV
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

logging.basicConfig(level=logging.INFO)


db = SQLAlchemy(app)
csrf = CSRFProtect(app)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(255))
    stripe_subscription_id = db.Column(db.String(255))


def init_database():
    with app.app_context():
        db.create_all()


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)

    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if not user.is_admin:
            return render_template("403.html", user=user, csrf_error=None), 403
        return f(*a, **k)

    return w


def stripe_value(data, key, default=None):
    if data is None:
        return default
    if isinstance(data, dict):
        return data.get(key, default)
    return getattr(data, key, default)


def stripe_configured():
    return bool(stripe.api_key and STRIPE_PRICE_ID)


def require_stripe_config():
    if stripe_configured():
        return None
    app.logger.error("Stripe request blocked because configuration is incomplete.")
    return jsonify({"error": "Stripe is not configured correctly."}), 500


@app.before_request
def enforce_valid_session():
    uid = session.get("user_id")
    if uid and not db.session.get(User, uid):
        session.clear()


@app.route("/")
def home():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password_raw = request.form.get("password", "")

        if not email:
            return render_template("signup.html", error="Email is required.", user=current_user())

        if len(password_raw) < 12:
            return render_template(
                "signup.html",
                error="Password must be at least 12 characters.",
                user=current_user(),
            )

        if User.query.filter_by(email=email).first():
            return render_template(
                "signup.html",
                error="An account with that email already exists.",
                user=current_user(),
            )

        user = User(
            email=email,
            password=generate_password_hash(password_raw),
            is_admin=(User.query.count() == 0),
        )

        db.session.add(user)
        db.session.commit()
        app.logger.info("New user created: %s", email)
        return redirect(url_for("login"))

    return render_template("signup.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            app.logger.info("User logged in: %s", email)
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password.",
            user=None,
        )

    return render_template("login.html", user=None)


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
    config_error = require_stripe_config()
    if config_error:
        return config_error

    user = current_user()

    if user.is_pro:
        return jsonify({"error": "This account already has Pro access."}), 400

    try:
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
    except Exception:
        app.logger.exception("Unable to create Stripe checkout session.")
        return jsonify({"error": "Unable to start Stripe checkout right now."}), 500


@app.route("/create-billing-portal", methods=["POST"])
@login_required
def create_billing_portal():
    config_error = require_stripe_config()
    if config_error:
        return config_error

    user = current_user()

    if not user.stripe_customer_id:
        return jsonify({"error": "No Stripe customer found for this account."}), 400

    if not user.stripe_subscription_id:
        return jsonify({"error": "No active Stripe subscription found for this account."}), 400

    try:
        billing_session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=url_for("pro", _external=True),
            flow_data={
                "type": "subscription_cancel",
                "subscription_cancel": {
                    "subscription": user.stripe_subscription_id,
                },
                "after_completion": {
                    "type": "redirect",
                    "redirect": {
                        "return_url": url_for("billing_manage", _external=True),
                    },
                },
            },
        )
        return jsonify({"url": billing_session.url})
    except Exception:
        app.logger.exception("Unable to create Stripe billing portal session.")
        return jsonify({"error": "Unable to open the billing portal right now."}), 500


@app.route("/billing-success")
@login_required
def billing_success():
    user = current_user()
    session_id = request.args.get("session_id", "").strip()
    payment_status = "pending"

    if session_id and stripe.api_key:
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            if str(stripe_value(checkout_session, "client_reference_id", "")) == str(user.id):
                payment_status = stripe_value(checkout_session, "payment_status", "pending")
        except Exception:
            app.logger.exception("Unable to retrieve Stripe checkout session for billing success page.")
            payment_status = "pending"

    return render_template(
        "billing_success.html",
        user=user,
        payment_status=payment_status,
    )


@app.route("/billing-manage")
@login_required
def billing_manage():
    user = current_user()

    if not stripe.api_key:
        return render_template(
            "billing_manage.html",
            user=user,
            status_message="Stripe is not configured right now.",
            end_date=None,
        )

    if not user.stripe_subscription_id:
        return render_template(
            "billing_manage.html",
            user=user,
            status_message="No active subscription was found for this account.",
            end_date=None,
        )

    try:
        subscription = stripe.Subscription.retrieve(user.stripe_subscription_id)
        cancel_at_period_end = stripe_value(subscription, "cancel_at_period_end", False)
        status = stripe_value(subscription, "status", "")
        cancel_at = stripe_value(subscription, "cancel_at")

        items = stripe_value(subscription, "items")
        items_data = stripe_value(items, "data", []) if items else []

        end_timestamp = cancel_at or stripe_value(subscription, "current_period_end")
        if not end_timestamp and items_data:
            end_timestamp = stripe_value(items_data[0], "current_period_end")

        end_date = None
        if end_timestamp:
            end_date = datetime.fromtimestamp(end_timestamp, tz=timezone.utc).strftime("%d %B %Y")

        if cancel_at_period_end and end_date:
            status_message = "Your subscription has been cancelled and will stay active until:"
        elif status == "canceled":
            status_message = "Your subscription has been cancelled successfully."
        else:
            status_message = "Your billing settings were updated successfully."

        return render_template(
            "billing_manage.html",
            user=user,
            status_message=status_message,
            end_date=end_date if cancel_at_period_end else None,
        )
    except Exception:
        app.logger.exception("Unable to retrieve Stripe subscription for billing management page.")
        return render_template(
            "billing_manage.html",
            user=user,
            status_message="We couldn't load your latest billing status right now.",
            end_date=None,
        )


@app.route("/pro")
@login_required
def pro():
    user = current_user()
    if not user.is_pro:
        return redirect(url_for("upgrade"))
    return render_template("pro.html", user=user)


@csrf.exempt
@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("Stripe webhook hit without webhook secret configured.")
        return "Webhook secret not configured", 500

    payload = request.get_data()
    signature = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, signature, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    event_type = event["type"]
    obj = event["data"]["object"]

    try:
        if event_type == "checkout.session.completed":
            metadata_obj = stripe_value(obj, "metadata")
            user_id = stripe_value(metadata_obj, "user_id") or stripe_value(obj, "client_reference_id")
            customer_id = stripe_value(obj, "customer")
            subscription_id = stripe_value(obj, "subscription")

            if user_id:
                user = db.session.get(User, int(user_id))
                if user:
                    user.is_pro = True
                    user.stripe_customer_id = customer_id
                    user.stripe_subscription_id = subscription_id
                    db.session.commit()

        elif event_type in {"customer.subscription.created", "customer.subscription.updated"}:
            subscription_id = stripe_value(obj, "id")
            customer_id = stripe_value(obj, "customer")
            status = stripe_value(obj, "status")

            user = User.query.filter_by(stripe_subscription_id=subscription_id).first()
            if not user and customer_id:
                user = User.query.filter_by(stripe_customer_id=customer_id).first()

            if user:
                user.is_pro = status in {"active", "trialing"}
                user.stripe_customer_id = customer_id
                user.stripe_subscription_id = subscription_id
                db.session.commit()

        elif event_type == "customer.subscription.deleted":
            subscription_id = stripe_value(obj, "id")
            customer_id = stripe_value(obj, "customer")

            user = User.query.filter_by(stripe_subscription_id=subscription_id).first()
            if not user and customer_id:
                user = User.query.filter_by(stripe_customer_id=customer_id).first()

            if user:
                user.is_pro = False
                user.stripe_subscription_id = None
                db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Stripe webhook processing failed.")
        return "Webhook failed", 500

    return "OK", 200


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template("403.html", user=current_user(), csrf_error=e.description), 400


@app.errorhandler(404)
def handle_404(_):
    return render_template("404.html", user=current_user()), 404


@app.errorhandler(429)
def handle_429(_):
    return render_template("429.html", user=current_user()), 429


@app.errorhandler(500)
def handle_500(_):
    db.session.rollback()
    return render_template("500.html", user=current_user()), 500


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


init_database()

if __name__ == "__main__":
    app.run(debug=IS_DEV)
