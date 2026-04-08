from functools import wraps
import os
import secrets

import stripe
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ------------------ CONFIG ------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
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

stripe.api_key = "sk_test_your_key_here"


# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_pro = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)


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
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[
            {
                "price": "price_REPLACE_ME",
                "quantity": 1,
            }
        ],
        mode="subscription",
        success_url="http://localhost:5000/success",
        cancel_url="http://localhost:5000/upgrade",
    )
    return jsonify({"url": checkout_session.url})


@app.route("/success")
@login_required
def success():
    user = current_user()
    user.is_pro = True
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/admin")
@admin_required
def admin_panel():
    user = current_user()
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin.html", user=user, users=users)


@app.route("/admin/toggle-pro/<int:user_id>", methods=["POST"])
@admin_required
def toggle_pro(user_id):
    target_user = db.session.get(User, user_id)
    if target_user:
        target_user.is_pro = not target_user.is_pro
        db.session.commit()
    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle-admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    target_user = db.session.get(User, user_id)
    acting_user = current_user()

    if target_user and target_user.id != acting_user.id:
        target_user.is_admin = not target_user.is_admin
        db.session.commit()

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    target_user = db.session.get(User, user_id)
    acting_user = current_user()

    if target_user and target_user.id != acting_user.id:
        db.session.delete(target_user)
        db.session.commit()

    return redirect(url_for("admin_panel"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------ ERROR PAGES ------------------
@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template("500.html"), 500


# ------------------ INIT ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
