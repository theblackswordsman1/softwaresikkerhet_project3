# app.py
# ----------------------------------------------------------------------------#
# Imports
# ----------------------------------------------------------------------------#

from flask import Flask, render_template, request, make_response, redirect, url_for, flash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import User, Session, OAuthUserData, db, bcrypt  # Import bcrypt
import logging
from logging import Formatter, FileHandler
from forms import RegistrationForm, LoginForm, ForgotForm  # Import forms
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv


# ----------------------------------------------------------------------------#
# App Config.
# ----------------------------------------------------------------------------#

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize Extensions
db.init_app(app)
bcrypt.init_app(app)  # Initialize Bcrypt with the app

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirects to login page if @login_required fails
login_manager.login_message_category = 'info'

# Initialize Limiter
limiter = Limiter(
    app,
    #key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Create the database tables
with app.app_context():
    db.create_all()


# ----------------------------------------------------------------------------#
# Login Manager.
# ----------------------------------------------------------------------------#

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# ----------------------------------------------------------------------------#
# Configure Google OAuth
# ----------------------------------------------------------------------------#

google_bp = make_google_blueprint(
    client_id=Config.GOOGLE_OAUTH_CLIENT_ID,
    client_secret=Config.GOOGLE_OAUTH_CLIENT_SECRET,
    scope=["profile", "email"],
    redirect_url="/google_login/authorized",
    storage=SQLAlchemyStorage(Session, db.session, user=current_user)
)
app.register_blueprint(google_bp, url_prefix="/login")


# ----------------------------------------------------------------------------#
# Controllers.
# ----------------------------------------------------------------------------#

@app.route("/")
def home():
    return render_template("pages/placeholder.home.html")


@app.route("/about")
@login_required
def about():
    return render_template("pages/placeholder.about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        return redirect(url_for("home"))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user
        new_user = User(
            id=str(uuid.uuid4()),  # Generate a unique user ID
            username=form.username.data,
            email=form.email.data
        )
        new_user.set_password(form.password.data)  # Hash and set the password

        # Add to the database
        db.session.add(new_user)
        db.session.commit()

        # Log the user in
        login_user(new_user)
        flash("Registration successful! You are now logged in.", "success")
        return redirect(url_for("home"))

    return render_template("forms/register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Rate limiting to prevent brute-force attacks
def login():
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        return redirect(url_for("home"))

    form = LoginForm()
    if form.validate_on_submit():
        # Encrypt the username to match the stored _username
        encrypted_username = User.encrypt_field(form.username.data)
        user = User.query.filter_by(_username=encrypted_username).first()
        if user:
            # Check if account is locked
            if user.failed_attempts >= Config.LOCKOUT_THRESHOLD:
                if user.last_failed_login_time and datetime.utcnow() - user.last_failed_login_time < Config.LOCKOUT_DURATION:
                    flash("Account locked due to multiple failed login attempts. Please try again later.", "danger")
                    return redirect(url_for("login"))
                else:
                    # Reset failed attempts after lockout duration
                    user.failed_attempts = 0
                    user.last_failed_login_time = None
                    db.session.commit()

            if user.check_password(form.password.data):
                # Reset failed attempts on successful login
                user.failed_attempts = 0
                user.last_failed_login_time = None
                db.session.commit()

                login_user(user)
                flash("Logged in successfully!", "success")
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for("home"))
            else:
                # Increment failed attempts
                user.failed_attempts += 1
                user.last_failed_login_time = datetime.utcnow()
                db.session.commit()

                flash("Invalid username or password.", "danger")
        else:
            flash("Invalid username or password.", "danger")

    return render_template("forms/login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    form = ForgotForm()
    if form.validate_on_submit():
        # Encrypt the email to match the stored _email
        encrypted_email = User.encrypt_field(form.email.data)
        user = User.query.filter_by(_email=encrypted_email).first()
        if user:
            # Implement password reset logic here (e.g., send reset email)
            flash("Password reset instructions have been sent to your email.", "info")
            # Placeholder for actual reset functionality
        return redirect(url_for("forgot"))
    return render_template("forms/forgot.html", form=form)


@app.route("/vunerableblog", methods=["GET", "POST"])
def vunerableblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        # Also vulnerable to SQL injection
        sqlstatement = f"INSERT INTO post (title, content) VALUES ('{title}', '{content}')"
        # Execute the SQL statement using raw SQL (vulnerable)
        # Example (assuming a raw connection is set up):
        # connection.execute(sqlstatement)
        # connection.commit()
        flash("Post submitted (vulnerable to SQL injection).", "warning")
    return render_template("pages/vunerableblog.html")


@app.route("/secureblog", methods=["GET", "POST"])
def secureblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        # Use parameterized queries to prevent SQL injection
        sqlstatement = "INSERT INTO post (title, content) VALUES (:title, :content)"
        # Execute the SQL statement using parameterized queries (secure)
        # Example:
        # db.session.execute(sqlstatement, {'title': title, 'content': content})
        # db.session.commit()
        flash("Post submitted securely.", "success")

    # Add CSP header for the secure blog page
    response = make_response(render_template("pages/secureblog.html"))
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
    return response


# ----------------------------------------------------------------------------#
# OAuth Handlers.
# ----------------------------------------------------------------------------#

@app.route("/oauth/google")
def google_login_route():
    if not google.authorized:  # Check if user is signed in with Google
        return redirect(url_for("google.login"))
    else:
        flash("You are already signed in with Google!", "info")
        return redirect(url_for("home"))


@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "danger")
        return False

    # Get user info from Google
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return False

    user_info = resp.json()
    email = user_info.get("email")
    google_id = user_info.get("id")
    name = user_info.get("name")

    # Check if user exists based on email
    encrypted_email = User.encrypt_field(email)
    user = User.query.filter_by(_email=encrypted_email).first()
    if not user:
        # Create a new user
        encrypted_username = User.encrypt_field(name)
        encrypted_email = User.encrypt_field(email)
        user = User(
            id=google_id,  # Using Google ID as user ID
            username=name,
            email=email  # The setter will handle encryption
            # No password_hash since it's an OAuth user
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Successfully signed in with Google!", "success")
    return False  # Prevent Flask-Dance from saving the OAuth token


# ----------------------------------------------------------------------------#
# Error Handlers.
# ----------------------------------------------------------------------------#

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("errors/500.html"), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


# ----------------------------------------------------------------------------#
# Logging.
# ----------------------------------------------------------------------------#

if not app.debug:
    file_handler = FileHandler("error.log")
    file_handler.setFormatter(
        Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info("errors")
    logging.getLogger('flask_dance').setLevel(logging.DEBUG)

# ----------------------------------------------------------------------------#
# Launch.
# ----------------------------------------------------------------------------#

if __name__ == "__main__":
    app.run(debug=True)
