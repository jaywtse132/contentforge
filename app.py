from flask import Flask, render_template, request, redirect, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import stripe
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ------------------ CONFIG ------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

stripe.api_key = "sk_test_your_key_here"

# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)

# ------------------ HELPERS ------------------
def login_required():
    return "user_id" in session

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return redirect('/dashboard' if "user_id" in session else '/login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session.clear()
            session['user_id'] = user.id
            return redirect('/dashboard')

        return render_template('login.html', error="Invalid email or password")

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            return render_template('signup.html', error="Please fill in all fields")

        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error="User already exists")

        hashed_password = generate_password_hash(password)

        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if not login_required():
        return redirect('/login')

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


@app.route('/upgrade')
def upgrade():
    if not login_required():
        return redirect('/login')

    return render_template('upgrade.html')


@app.route('/create-checkout-session', methods=['POST'])
@limiter.limit("10 per hour")
def create_checkout_session():
    if not login_required():
        abort(403)

    session_checkout = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': 'price_REPLACE_ME',
            'quantity': 1,
        }],
        mode='subscription',
        success_url='http://localhost:5000/success',
        cancel_url='http://localhost:5000/cancel',
    )
    return jsonify({'url': session_checkout.url})


@app.route('/success')
def success():
    if not login_required():
        return redirect('/login')

    user = User.query.get(session['user_id'])
    if user:
        user.is_pro = True
        db.session.commit()

    return redirect('/dashboard')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ------------------ INIT ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
