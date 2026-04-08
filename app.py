import os
from functools import wraps

import stripe
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

app = Flask(__name__)

# ------------------ CONFIG ------------------
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_pro = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    stripe_customer_id = db.Column(db.String(255), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=True)


# ------------------ HELPERS ------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        user = db.session.get(User, session["user_id"])
        if not user or not user.is_admin:
            abort(403)

        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


# ------------------ ROUTES ------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("signup.html", error="Please fill in all fields")

        if User.query.filter_by(email=email).first():
            return render_template("signup.html", error="User already exists")

        is_first_user = User.query.count() == 0

        user = User(
            email=email,
            password=generate_password_hash(password),
            is_admin=is_first_user,
        )
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", user=user)


@app.route("/account")
@login_required
def account():
    user = current_user()
    return render_template("account.html", user=user)


@app.route("/change-password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def change_password():
    user = current_user()

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not check_password_hash(user.password, current_password):
        return render_template("account.html", user=user, error="Current password is incorrect")

    if len(new_password) < 8:
        return render_template("account.html", user=user, error="New password must be at least 8 characters")

    if new_password != confirm_password:
        return render_template("account.html", user=user, error="New passwords do not match")

    user.password = generate_password_hash(new_password)
    db.session.commit()

    return render_template("account.html", user=user, success="Password updated successfully")


@app.route("/upgrade")
@login_required
def upgrade():
    user = current_user()
    return render_template("upgrade.html", user=user)


@app.route("/pro")
@login_required
def pro_area():
    user = current_user()
    if not user.is_pro:
        return redirect(url_for("upgrade"))
    return render_template("pro.html", user=user)


@app.route("/create-checkout-session", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def create_checkout_session():
    user = current_user()

    checkout_session = stripe.checkout.Session.create(
        mode="subscription",
        payment_method_types=["card"],
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        customer_email=user.email,
        metadata={"user_id": str(user.id)},
        success_url="http://localhost:5000/billing-success",
        cancel_url="http://localhost:5000/upgrade",
    )

    return jsonify({"url": checkout_session.url})


@app.route("/billing-success")
@login_required
def billing_success():
    user = current_user()
    return render_template("billing_success.html", user=user)


# ------------------ WEBHOOK ------------------
@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            STRIPE_WEBHOOK_SECRET,
        )
    except Exception as e:
        print("Webhook signature error:", e)
        return "Invalid", 400

    try:
        print("EVENT TYPE:", event["type"])

        if event["type"] == "checkout.session.completed":
            session_obj = event["data"]["object"]
            print("CHECKOUT SESSION:", session_obj)

            user_id = session_obj.get("metadata", {}).get("user_id")
            customer_id = session_obj.get("customer")
            subscription_id = session_obj.get("subscription")

            if not user_id:
                print("No user_id in metadata")
                return "OK", 200

            user = db.session.get(User, int(user_id))
            if not user:
                print("User not found:", user_id)
                return "OK", 200

            user.is_pro = True

            if customer_id:
                user.stripe_customer_id = customer_id

            if subscription_id:
                user.stripe_subscription_id = subscription_id

            db.session.commit()
            print("User upgraded:", user.email)

        elif event["type"] == "customer.subscription.deleted":
            subscription = event["data"]["object"]
            subscription_id = subscription.get("id")

            user = User.query.filter_by(stripe_subscription_id=subscription_id).first()
            if user:
                user.is_pro = False
                user.stripe_subscription_id = None
                db.session.commit()
                print("Subscription cancelled:", user.email)

        elif event["type"] == "customer.subscription.updated":
            subscription = event["data"]["object"]
            subscription_id = subscription.get("id")
            status = subscription.get("status")

            user = User.query.filter_by(stripe_subscription_id=subscription_id).first()
            if user:
                user.is_pro = status in {"active", "trialing"}
                db.session.commit()
                print("Subscription updated:", user.email, status)

    except Exception as e:
        import traceback
        print("WEBHOOK ERROR:", e)
        traceback.print_exc()
        return "Error", 500

    return "OK", 200


# ------------------ INIT ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
