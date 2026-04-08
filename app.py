from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os

app = Flask(__name__)
app.secret_key = "super-secret-key"

# DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# Stripe (replace later)
stripe.api_key = "sk_test_your_key_here"

# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    if "user_id" in session:
        return redirect('/dashboard')
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/dashboard')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "User already exists"

        hashed_password = generate_password_hash(password)

        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


@app.route('/upgrade')
def upgrade():
    if "user_id" not in session:
        return redirect('/login')

    return render_template('upgrade.html')


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
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
    user = User.query.get(session['user_id'])
    user.is_pro = True
    db.session.commit()
    return redirect('/dashboard')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ------------------ INIT ------------------
if __name__ == '__main__':
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
            print("Database created")

    app.run(debug=True)
