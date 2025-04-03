import os
import random
from flask import Flask, render_template, request, url_for, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
import re
from sqlalchemy import Numeric
import threading
import time

app = Flask(__name__)

# Configuration for database and security
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:password@localhost/IFT_Trading"
app.config["SECRET_KEY"] = "YOUR_SECRET_KEY_HERE"

# Create a serializer for secure token generation
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Yahoo SMTP Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"  # ✅ Change Yahoo to Gmail
app.config["MAIL_PORT"] = 587                 # ✅ Same as before
app.config["MAIL_USE_TLS"] = True             # ✅ Keep TLS enabled
app.config["MAIL_USE_SSL"] = False            # ✅ Keep SSL disabled

# Hardcoded Yahoo Email Credentials (Needs Security Improvement Later)
app.config["MAIL_USERNAME"] = "ifttrading0@gmail.com"
app.config["MAIL_PASSWORD"] = "doyl ipwa tvii axiu"
app.config["MAIL_DEFAULT_SENDER"] = "ifttrading0@gmail.com"

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)
price_thread = None  # global or module-level variable to track our thread

# Hashing Functions
def hash_data(data):
    return bcrypt.generate_password_hash(data).decode('utf-8')

def check_hashed_data(hashed_data, original_data):
    return bcrypt.check_password_hash(hashed_data, original_data)

# Disable the default unauthorized message
login_manager.login_message = None

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
    balance = db.Column(db.Float, nullable=False, default=10000.0)

# Portfolio Model
class Portfolio(db.Model):
    portfolio_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    quantity_owned = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Orders Model
class Orders(db.Model):
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    order_type = db.Column(db.String(10), nullable=False) 
    quantity = db.Column(db.Integer, nullable=False)
    price_at_order = db.Column(db.DECIMAL(10, 2), nullable=False)
    order_status = db.Column(db.String(20), nullable=False, default="Pending")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cancel_timestamp = db.Column(db.DateTime, nullable=True)

# Transactions Model
class Transactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    ticker = db.Column(db.String(10),nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # Buy or Sell
    quantity = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.DECIMAL(10, 2), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cancel_timestamp = db.Column(db.DateTime, nullable=True)

# Scheduling Model
class TradingSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stop_time = db.Column(db.DateTime, nullable=False)
    resume_time = db.Column(db.DateTime, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Stocks Model
class Stock(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    ticker = db.Column(db.String(100), nullable=False) 
    company = db.Column(db.String(100), nullable=False) 
    price = db.Column(Numeric(10, 2), nullable=False)
    volume = db.Column(Numeric(10), nullable=False)

    def __init__(self, ticker, company, price, volume):
        self.ticker = ticker
        self.company = company
        self.price = price
        self.volume = volume

@app.before_request
def start_price_thread():
    global price_thread
    # Only start the thread if it hasn't been started before
    if price_thread is None or not price_thread.is_alive():
        price_thread = threading.Thread(target=randomize_stock_prices, daemon=True)
        price_thread.start()
        print("Background price thread started!")

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
    
    # Ensure 'admin' role exists
    if not UserRoles.query.filter_by(role_name="admin").first():
        db.session.add(UserRoles(id=1, role_name="admin", permissions="all"))
        db.session.commit()

    # ✅ Ensure 'user' role exists
    if not UserRoles.query.filter_by(role_name="user").first():
        db.session.add(UserRoles(id=2, role_name="user", permissions="basic"))
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

def randomize_stock_prices():
    while True:
        with app.app_context():
            stocks = Stock.query.all()
            for stock in stocks:
                old_price = float(stock.price)
                direction = random.choice([-1, 1])
                change_percent = random.uniform(0.05, 0.08)
                new_price = old_price * (1 + direction * change_percent)
                if new_price < 0.01:
                    new_price = 0.01

                stock.price = new_price

                print(f"Updated {stock.ticker} from {old_price} to {new_price}")

            db.session.commit()

        time.sleep(5)

@app.route('/verify', methods=["GET", "POST"])
def verify():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if "otp_attempts" not in session:
        session["otp_attempts"] = 0  # Initialize if not set

    if request.method == "POST":
        entered_otp = request.form.get("otp")

        if int(entered_otp) == session.get("otp_code"):
            # Correct OTP → Reset failed attempts
            session.pop("otp_attempts", None)  
            session.pop('_flashes', None)

            user = Users.query.get(session["pending_user_id"])
            login_user(user)

            # Remove OTP session values
            session.pop("otp_code", None)
            session.pop("pending_user_id", None)

            return redirect(url_for("admin") if user.role_id == UserRoles.query.filter_by(role_name="admin").first().id else url_for("portfolio"))

        # Incorrect OTP → Increase failed attempt count
        session["otp_attempts"] += 1

        # After 3 failed OTP attempts, redirect to failed_login page
        if session["otp_attempts"] >= 3:
            session.pop("otp_attempts", None)  # Reset after lockout
            return redirect(url_for("failed_login"))

        flash("Invalid verification code. Please try again.", "danger")

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
    if "login_attempts" not in session:
        session["login_attempts"] = 0  # Initialize if not set

    if request.method == "POST":
        username_email = request.form.get("username_email")
        password = request.form.get("password")

        user = Users.query.filter((Users.username == username_email) | (Users.email == username_email)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Correct login → Reset failed attempts
            session.pop("login_attempts", None)  
            session.pop('_flashes', None)

            # Proceed to 2FA
            session["pending_user_id"] = user.id
            send_otp(user.email)
            return redirect(url_for("verify"))

        # Incorrect login → Increase failed attempt count
        session["login_attempts"] += 1

        # After 3 failed attempts, redirect to failed_login page
        if session["login_attempts"] >= 3:
            session.pop("login_attempts", None)  # Reset after lockout
            return redirect(url_for("failed_login"))

        flash("Invalid username or password. Please try again.", "danger")

    return render_template('login.html')

@app.route('/signup', methods=["GET", "POST"])
def signup():
    errors = []

    if request.method == "POST":
        full_name = request.form.get("full_name")
        username = request.form.get("username")  # ✅ FIX: ADD THIS LINE
        email = request.form.get("email")
        phone, ssn, dob = request.form.get("phone"), request.form.get("ssn"), request.form.get("dob")
        citizenship = request.form.get("citizenship")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Ensure username is unique
        if Users.query.filter_by(username=username).first():
            errors.append("Username is already taken.")

        # Ensure passwords match
        if password != confirm_password:
            errors.append("Passwords do not match!")

        # Validate username length (Optional)
        if len(username) < 3 or len(username) > 20:
            errors.append("Username must be between 3 and 20 characters.")

        # Validate password complexity
        password_regex = r"^(?=.*[A-Z].*[A-Z])(?=.*[a-z].*[a-z])(?=.*\d.*\d)(?=.*[@$!%*?&].*[@$!%*?&]).{14,}$"
        if not re.match(password_regex, password):
            errors.append("Password must meet security requirements.")

        # Ensure user is at least 18 years old
        try:
            birth_date = datetime.strptime(dob, "%Y-%m-%d")
            age = (datetime.today() - birth_date).days // 365
            if age < 18:
                errors.append("You must be at least 18 years old to register.")
        except ValueError:
            errors.append("Invalid date of birth format.")

        # Validate phone number (must be exactly 10 digits)
        if not re.fullmatch(r"\d{10}", phone):
            errors.append("Phone number must be exactly 10 digits.")

        # Validate SSN (must be exactly 9 digits)
        if not re.fullmatch(r"\d{9}", ssn):
            errors.append("SSN must be exactly 9 digits.")

        # If errors exist, return them to the user
        if errors:
            return render_template("signup.html", errors=errors)

        # Hash sensitive data before storing
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.add(Users(
            full_name=full_name,
            username=username,  # ✅ FIXED: NOW username IS DEFINED
            email=email,
            phone=hash_data(phone),
            ssn=hash_data(ssn),
            dob=hash_data(dob),
            citizenship=citizenship,
            password=hashed_password
        ))
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template('signup.html', errors=errors)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/profile')
@login_required
def profile():
    user = current_user  # The logged-in user
    return render_template(
        'profile.html',
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        citizenship=user.citizenship,
        created_at=user.created_at,
        updated_at=user.updated_at,
        balance=user.balance
    )

@app.route('/confirm_transaction', methods=["GET", "POST"])
@login_required
def confirm_transaction():
    action = request.form.get("action")
    try:
        amount = float(request.form.get("amount"))
    except (ValueError, TypeError):
        flash("Invalid amount. Please enter a valid number.", "danger")
        return redirect(url_for("profile"))
    
    if amount <= 0:
        flash("Amount must be greater than zero.", "warning")
        return redirect(url_for("profile"))
    
    if action == "deposit":
        current_user.balance += amount
        flash(f"Successfully deposited ${amount:.2f}.", "success")
    elif action == "withdraw":
        if amount > current_user.balance:
            flash("Insufficient funds for withdrawal.", "danger")
            return redirect(url_for("profile"))
        current_user.balance -= amount
        flash(f"Successfully withdrew ${amount:.2f}.", "success")
    else:
        flash("Invalid transaction type.", "danger")
        return redirect(url_for("profile"))
    
    db.session.commit()
    return redirect(url_for("profile"))

@app.route('/portfolio')
@login_required
def portfolio():
    holdings = []
    tickers = db.session.query(Transactions.ticker).filter_by(user_id=current_user.id).distinct()
    for ticker_obj in tickers:
        ticker = ticker_obj[0]
        total_buys = db.session.query(db.func.sum(Transactions.quantity))\
            .filter_by(ticker=ticker, transaction_type='Buy', user_id=current_user.id)\
            .scalar() or 0
        total_sells = db.session.query(db.func.sum(Transactions.quantity))\
            .filter_by(ticker=ticker, transaction_type='Sell', user_id=current_user.id)\
            .scalar() or 0
        net_shares = total_buys - total_sells
        if net_shares > 0:
            stock = Stock.query.filter_by(ticker=ticker).first()
            holdings.append({
                'ticker': ticker,
                'company': stock.company,
                'quantity': net_shares,
                'price': float(stock.price),
                'value': float(net_shares) * float(stock.price)
            })

    # Pass the user’s cash balance to the template
    return render_template('portfolio.html', holdings=holdings, balance=current_user.balance)

@app.route('/confirm_trade', methods=["GET", "POST"])
@login_required
def confirm_trade():
    action = request.form.get("action")
    ticker = request.form.get("ticker")
    try:
        shares = int(request.form.get("shares"))
    except (ValueError, TypeError):
        flash("Invalid number of shares.", "danger")
        return redirect(url_for("stocks"))
    order_type = request.form.get("orderType")
    
    # stock details pulled from db
    stock = Stock.query.filter_by(ticker=ticker).first()
    if not stock:
        flash("Invalid stock ticker!", "danger")
        return redirect(url_for("stocks"))
    
    #total price
    price = float(stock.price)
    total_amount = shares * price
    
    return render_template(
        "confirmation.html", 
        action=action, 
        ticker=ticker, 
        shares=shares, 
        order_type=order_type, 
        price=price, 
        total_amount=total_amount,
        company=stock.company
    )

#looks for downtime interval to determine if trading is allowed
def allow_trade():
    now = datetime.now()
    active_schedule = TradingSchedule.query.filter(TradingSchedule.stop_time <= now, TradingSchedule.resume_time > now).first()
    return active_schedule is None

@app.route("/admin/hours", methods=["GET", "POST"])
@login_required
@admin_required
def hours():
    if request.method == "POST":
        stop_trading_str = request.form.get("stopTrading")
        resume_trading_str = request.form.get("resumeTrading")
        try:
            # Converts datetime-local string to an object
            stop_trading = datetime.strptime(stop_trading_str, "%Y-%m-%dT%H:%M")
            resume_trading = datetime.strptime(resume_trading_str, "%Y-%m-%dT%H:%M")
        except Exception:
            flash("Invalid datetime format.", "danger")
            return redirect(url_for("hours"))

        # date-timelocal validation
        if stop_trading >= resume_trading:
            flash("Stop time must be before resume time.", "danger")
            return redirect(url_for("hours"))
        
        # Sends schedule to database 
        new_schedule = TradingSchedule(stop_time=stop_trading, resume_time=resume_trading)
        db.session.add(new_schedule)                       
        db.session.commit()
        flash("Trading schedule updated successfully!", "success")
        return redirect(url_for("hours"))
    else:
        # Passes schedule to the template so the admin can see it
        schedules = TradingSchedule.query.order_by(TradingSchedule.stop_time.desc()).all()
        return render_template("hours.html", schedules=schedules)


@app.route('/execute_trade', methods=["GET", "POST"])
@login_required
def execute_trade():
    #displays danger message if the user tries to make a trade after market is closed
    if not allow_trade():
         flash("Trading is currently paused due to scheduled downtime.", "danger")
         return redirect(url_for("stocks"))
    
    # code to execute when trading resumes
    action = request.form.get("action")
    ticker = request.form.get("ticker")
    try:
        shares = int(request.form.get("shares"))
    except (ValueError, TypeError):
        flash("Invalid number of shares.", "danger")
        return redirect(url_for("stocks"))
    order_type = request.form.get("order_type")
    
    # Get stock details
    stock = Stock.query.filter_by(ticker=ticker).first()
    if not stock:
        flash("Invalid stock ticker!", "danger")
        return redirect(url_for("stocks"))
    price = float(stock.price)

    # -- 1) Convert stock.volume from string to int
    # If volume is missing or invalid, default to 0
    try:
        current_volume = int(stock.volume)
    except (ValueError, TypeError):
        current_volume = 0
    
    if action == "buy":
        total_cost = shares * price
        user_balance = current_user.balance or 0.0
        if user_balance < total_cost:
            flash("Insufficient funds!", "danger")
            return redirect(url_for("stocks"))
        current_user.balance = user_balance - total_cost

        # Create buy order
        new_order = Orders(
            user_id=current_user.id,
            stock_id=stock.id,
            order_type="Buy",
            quantity=shares,
            price_at_order=price,
            order_status="Completed"
        )
        db.session.add(new_order)
        db.session.commit()

        new_transaction = Transactions(
            user_id=current_user.id,
            order_id=new_order.order_id,
            stock_id=stock.id,
            company_name=stock.company,
            ticker=ticker,
            transaction_type="Buy",
            quantity=shares,
            total_amount=total_cost
        )
        db.session.add(new_transaction)
        db.session.commit()

        portfolio_entry = Portfolio.query.filter_by(user_id=current_user.id, stock_id=stock.id).first()
        if portfolio_entry:
            portfolio_entry.quantity_owned += shares
            portfolio_entry.last_updated = datetime.utcnow()
        else:
            new_portfolio_entry = Portfolio(
                user_id=current_user.id,
                stock_id=stock.id,
                quantity_owned=shares
            )
            db.session.add(new_portfolio_entry)

        # -- 2) Decrease volume by the shares bought
        current_volume -= shares
        if current_volume < 0:
            current_volume = 0
        stock.volume = str(current_volume)  # store as string, as in your model

        db.session.commit()
        flash("Stock purchased successfully!", "success")

    elif action == "sell":
        total_gain = shares * price
        # check if there's enough stock to sell
        user_shares = db.session.query(db.func.sum(Transactions.quantity)).filter_by(
            ticker=ticker, transaction_type='Buy', user_id=current_user.id).scalar() or 0
        sold_shares = db.session.query(db.func.sum(Transactions.quantity)).filter_by(
            ticker=ticker, transaction_type='Sell', user_id=current_user.id).scalar() or 0
        net_shares = user_shares - sold_shares
        if shares > net_shares:
            flash("Not enough shares to sell!", "danger")
            return redirect(url_for("stocks"))
        current_user.balance += total_gain

        new_order = Orders(
            user_id=current_user.id,
            stock_id=stock.id,
            order_type="Sell",
            quantity=shares,
            price_at_order=price,
            order_status="Completed"
        )
        db.session.add(new_order)
        db.session.commit()

        new_transaction = Transactions(
            user_id=current_user.id,
            order_id=new_order.order_id,
            stock_id=stock.id,
            company_name=stock.company,
            ticker=ticker,
            transaction_type="Sell",
            quantity=shares,
            total_amount=total_gain
        )
        db.session.add(new_transaction)
        db.session.commit()

        portfolio_entry = Portfolio.query.filter_by(user_id=current_user.id, stock_id=stock.id).first()
        if portfolio_entry:
            portfolio_entry.quantity_owned -= shares
            if portfolio_entry.quantity_owned <= 0:
                db.session.delete(portfolio_entry)
            else:
                portfolio_entry.last_updated = datetime.utcnow()
            db.session.commit()

        # -- 2) Increase volume by the shares sold
        current_volume += shares
        stock.volume = str(current_volume)

        db.session.commit()
        flash("Stock sold successfully!", "success")
    else:
        flash("Invalid trade action.", "danger")
        return redirect(url_for("stocks"))
    
    return redirect(url_for("portfolio"))


@app.route('/review_cash_transaction', methods=["POST"])
@login_required
def review_cash_transaction():
    """Show a confirmation page for deposit/withdraw before finalizing."""
    action = request.form.get("action")
    amount_str = request.form.get("amount")

    try:
        amount = float(amount_str)
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "danger")
        return redirect(url_for("profile"))

    if amount <= 0:
        flash("Amount must be greater than zero.", "warning")
        return redirect(url_for("profile"))

    # Show a new confirmation page with deposit/withdraw details
    return render_template(
        "confirmation_cash.html",
        action=action,
        amount=amount
    )

@app.route('/execute_cash_transaction', methods=["POST"])
@login_required
def execute_cash_transaction():
    """Perform the actual deposit/withdraw once user confirms."""
    action = request.form.get("action")
    amount_str = request.form.get("amount")

    try:
        amount = float(amount_str)
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "danger")
        return redirect(url_for("profile"))

    if amount <= 0:
        flash("Amount must be greater than zero.", "warning")
        return redirect(url_for("profile"))

    if action == "deposit":
        current_user.balance += amount
        flash(f"Successfully deposited ${amount:.2f}.", "success")
    elif action == "withdraw":
        if amount > current_user.balance:
            flash("Insufficient funds for withdrawal.", "danger")
            return redirect(url_for("profile"))
        current_user.balance -= amount
        flash(f"Successfully withdrew ${amount:.2f}.", "success")
    else:
        flash("Invalid transaction type.", "danger")
        return redirect(url_for("profile"))

    db.session.commit()
    return redirect(url_for("profile"))

@app.route('/stocks')
def stocks():
        stocks_list = Stock.query.all()
        return render_template('stocks.html', stocks=stocks_list)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/history')
@login_required
def history():
    # Pull the user’s transactions in descending chronological order
    user_transactions = Transactions.query \
        .filter_by(user_id=current_user.id) \
        .order_by(Transactions.timestamp.desc()) \
        .all()

    return render_template(
        'history.html',
        username=current_user.username,
        email=current_user.email,
        transactions=user_transactions
    )

@app.route("/admin/add_stock", methods=["GET", "POST"])
@login_required
@admin_required
def add_stock(): 
    if request.method == 'POST':
        ticker = request.form['ticker']
        company = request.form['company']
        price = request.form['price']
        volume = request.form['volume']

        new_stock = Stock(ticker, company, price, volume)
        db.session.add(new_stock)
        db.session.commit()
        flash("Stock added successfully!")
        return redirect(url_for('add_stock'))
    return render_template("add_stock.html")

@app.route("/admin/admin_stock_list")
@login_required
@admin_required
def admin_stock_list():
    stocks_list = Stock.query.all()
    return render_template('admin_stock_list.html', stocks=stocks_list)

@app.route('/failed_login')
def failed_login():
    return render_template('failed_login.html')

@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = Users.query.filter_by(email=email).first()

        if user:
            # Generate a secure token
            token = s.dumps(email, salt="password-reset")

            # Generate reset link
            reset_link = url_for('reset_password', token=token, _external=True)

            # Send email with reset link
            msg = Message("Password Reset Request", sender=app.config["MAIL_DEFAULT_SENDER"], recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "info")
        else:
            flash("Email not found. Please try again.", "danger")

    return render_template("forgotpassword.html")

@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    try:
        # Verify token and extract email
        email = s.loads(token, salt="password-reset", max_age=600)  # 10-minute expiry
    except:
        flash("The reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    user = Users.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # 1️⃣ Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template("resetpassword.html", token=token)

        # 2️⃣ Validate password complexity (14+ chars, 2 uppercase, 2 lowercase, 2 numbers, 2 special characters)
        password_regex = r"^(?=.*[A-Z].*[A-Z])(?=.*[a-z].*[a-z])(?=.*\d.*\d)(?=.*[@$!%*?&].*[@$!%*?&]).{14,}$"
        if not re.match(password_regex, password):
            flash("Password must meet security requirements.", "danger")
            return render_template("resetpassword.html", token=token)

        # 3️⃣ Hash and update password in DB
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()

        flash("Password successfully reset! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("resetpassword.html", token=token)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)