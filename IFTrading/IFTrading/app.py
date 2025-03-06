import os
import random
from flask import Flask, render_template, request, url_for, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime


app = Flask(__name__)

# Configuration for database and security
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:password@localhost/IFT_Trading"
app.config["SECRET_KEY"] = "YOUR_SECRET_KEY_HERE"

# Yahoo SMTP Configuration
app.config["MAIL_SERVER"] = "smtp.mail.yahoo.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

# Hardcoded Yahoo Email Credentials (Needs Security Improvement Later)
app.config["MAIL_USERNAME"] = "snperry890@yahoo.com"
app.config["MAIL_PASSWORD"] = "lcogyejknxhbwrof"
app.config["MAIL_DEFAULT_SENDER"] = "snperry890@yahoo.com"

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Hashing Functions
def hash_data(data):
    return bcrypt.generate_password_hash(data).decode('utf-8')

def check_hashed_data(hashed_data, original_data):
    return bcrypt.check_password_hash(hashed_data, original_data)

# UserRoles Model
class UserRoles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(20), unique=True, nullable=False)
    permissions = db.Column(db.String(30), nullable=False)

# Users Model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('user_roles.id'), nullable=False, default=2)
    full_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(255), nullable=True)
    ssn = db.Column(db.String(255), unique=True, nullable=True)
    dob = db.Column(db.String(255), nullable=True)
    citizenship = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Stocks Model
class Stock(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    ticker = db.Column(db.String(100), nullable=False) 
    company = db.Column(db.String(100), nullable=False) 
    price = db.Column(db.Float, nullable=False)
    shares = db.Column(db.String(100), nullable=False) 
    marketcap = db.Column(db.String(100), nullable=True)
    volume = db.Column(db.String(100), nullable=True)

    def __init__(self, ticker, company, price, shares, marketcap, volume):
        self.ticker = ticker
        self.company = company
        self.price = price
        self.shares = shares
        self.marketcap = marketcap
        self.volume = volume

# Admin access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_role = UserRoles.query.filter_by(role_name="admin").first()
        if not current_user.is_authenticated or current_user.role_id != admin_role.id:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Initialize database & Admin
with app.app_context():
    db.create_all()
    if not UserRoles.query.filter_by(role_name="admin").first():
        db.session.add(UserRoles(role_name="admin", permissions="all"))
        db.session.commit()
    
    admin_role = UserRoles.query.filter_by(role_name="admin").first()
    
    if not Users.query.filter_by(username="admin").first():
        db.session.add(Users(
            username="admin",
            full_name="Admin User",
            email="admin@example.com",
            password=bcrypt.generate_password_hash("admin123").decode('utf-8'),
            phone=hash_data("1234567890"),
            ssn=hash_data("000-00-0000"),
            dob=hash_data("2000-01-01"),
            citizenship="USA",
            role_id=admin_role.id
        ))
        db.session.commit()

def send_otp(email):
    """Generate and send a 6-digit OTP via email"""
    otp = random.randint(100000, 999999)
    session["otp_code"] = otp

    msg = Message(
        "Your Verification Code",
        sender=app.config["MAIL_DEFAULT_SENDER"],
        recipients=[email]
    )
    msg.body = f"Your verification code is: {otp}. Enter this code to access your account."

    try:
        mail.send(msg)
    except Exception:
        flash("Failed to send verification email. Please check your email configuration.", "danger")

@app.route('/verify', methods=["GET", "POST"])
def verify():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form.get("otp")

        if int(entered_otp) == session.get("otp_code"):
            user = Users.query.get(session["pending_user_id"])
            login_user(user)
            session.pop("otp_code", None)
            session.pop("pending_user_id", None)

            return redirect(url_for("admin") if user.role_id == UserRoles.query.filter_by(role_name="admin").first().id else url_for("portfolio"))
        else:
            flash("Invalid code. Please try again.", "danger")

    return render_template('verify.html')

@app.route('/resend_otp')
def resend_otp():
    if "pending_user_id" in session:
        user = Users.query.get(session["pending_user_id"])
        send_otp(user.email)
        flash("A new verification code has been sent to your email.", "info")
    return redirect(url_for("verify"))

# Routes
@app.route('/')
@login_required
def home():
    return redirect(url_for("admin") if current_user.role_id == UserRoles.query.filter_by(role_name="admin").first().id else url_for("portfolio"))

@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_template('admin.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_email = request.form.get("username_email")
        password = request.form.get("password")

        user = Users.query.filter((Users.username == username_email) | (Users.email == username_email)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["pending_user_id"] = user.id
            send_otp(user.email)
            return redirect(url_for("verify"))

    return render_template('login.html')

@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        phone, ssn, dob = map(hash_data, [request.form.get("phone"), request.form.get("ssn"), request.form.get("dob")])
        citizenship = request.form.get("citizenship")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            return "Passwords do not match!"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        default_role = UserRoles.query.filter_by(role_name="user").first()
        if not default_role:
            default_role = UserRoles(role_name="user", permissions="basic")
            db.session.add(default_role)
            db.session.commit()

        db.session.add(Users(
            full_name=full_name,
            username=username,
            email=email,
            phone=phone,
            ssn=ssn,
            dob=dob,
            citizenship=citizenship,
            password=hashed_password,
            role_id=default_role.id
        ))
        db.session.commit()

        return redirect(url_for("login"))

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', full_name=current_user.full_name, email=current_user.email, citizenship=current_user.citizenship)

@app.route('/portfolio')
@login_required
def portfolio():
    return render_template('portfolio.html')

@app.route('/buy', methods=["GET","POST"])
def buy():
    if request.method == "POST":
        return redirect(url_for('buying_stock'))

@app.route('/buying_stock')
def buying_stock():
    return render_template('buy.html')

@app.route('/sell', methods=["GET","POST"])
def sell():
    if request.method == "POST":
        return redirect(url_for('selling_stock'))

@app.route('/selling_stock')
def selling_stock():
    return render_template('sell.html')

@app.route('/stocks')
def stocks():
    return render_template('stocks.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route("/admin/add_stock", methods=["GET", "POST"])
@login_required
@admin_required
def add_stock(): 
    if request.method == 'POST':
        ticker = request.form['ticker']
        company = request.form['company']
        price = request.form['price']
        shares = request.form['shares']
        marketcap = request.form['marketcap']
        volume = request.form['volume']

        new_stock = Stock(ticker, company, price, shares, marketcap, volume)
        db.session.add(new_stock)
        db.session.commit() 
        flash('Stock added successfully!')
        return redirect(url_for('admin'))
    return render_template("add_stock.html")

if __name__ == '__main__':
    app.run(debug=True)