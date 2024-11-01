#app.py
# ----------------------------------------------------------------------------#
# Imports
# ----------------------------------------------------------------------------#
from datetime import datetime, timedelta

from flask import Flask, render_template, request, make_response, redirect, url_for, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, login_user, logout_user, current_user
from db_init import initialize_database, get_session
from config import Config
from models import User, Session, db
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage

# from flask.ext.sqlalchemy import SQLAlchemy
import logging
from logging import Formatter, FileHandler
from forms import *

# ----------------------------------------------------------------------------#
# DB Setup
# ----------------------------------------------------------------------------#



# ----------------------------------------------------------------------------#
# App Config.
# ----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize the database
db.init_app(app)

# Create the database tables
with app.app_context():
    db.create_all()

# Login manager.
login_manager = LoginManager()
login_manager.init_app(app)


# Configure Google OAuth
google_bp = make_google_blueprint(client_id=Config.GOOGLE_OAUTH_CLIENT_ID,
                                  client_secret=Config.GOOGLE_OAUTH_CLIENT_SECRET,
                                  storage=SQLAlchemyStorage(Session, db.session))
app.register_blueprint(google_bp, url_prefix="/login")



# Automatically tear down SQLAlchemy.
"""
@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()
"""

# Login required decorator.
"""
def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap
"""

# ----------------------------------------------------------------------------#
# DB requests.
# ----------------------------------------------------------------------------#



# ----------------------------------------------------------------------------#
# Controllers.
# ----------------------------------------------------------------------------#


@app.route("/")
def home():
    return render_template("pages/placeholder.home.html")


@app.route("/about")
def about():
    return render_template("pages/placeholder.about.html")


@app.route("/register")
def register():
    form = RegisterForm(request.form)
    return render_template("forms/register.html", form=form)


@app.route("/forgot")
def forgot():
    form = ForgotForm(request.form)
    return render_template("forms/forgot.html", form=form)


@app.route("/vunerableblog", methods=["GET", "POST"])
def vunerableblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        # Also vunerable to SQL injection
        sqlstatement = f"INSERT INTO post (title, content) VALUES ('{title}', '{content}')"
        connection.commit()
    return render_template("pages/vunerableblog.html")


@app.route("/secureblog", methods=["GET", "POST"])
def secureblog():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        sqlstatement = "INSERT INTO post (title, content) VALUES (?, ?)"
    
    # Add CSP header for the secure blog page
    response = make_response(render_template("pages/secureblog.html"))
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
    return response

@app.route("/oauth/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v1/userinfo")
    assert resp.ok, resp.text
    return resp.text

@app.route("/logout")
def logout():
    token = google_bp.token["access_token"]
    resp = google.post(
        "https://accounts.google.com/o/oauth2/revoke",
        params={"token": token},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert resp.ok, resp.text
    logout_user()        # Delete Flask-Login's session cookie
    del google_bp.token  # Delete OAuth token from storage
    return redirect(url_for("home"))


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Error handlers.


@app.errorhandler(500)
def internal_error(error):
    # db_session.rollback()
    return render_template("errors/500.html"), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


if not app.debug:
    file_handler = FileHandler("error.log")
    file_handler.setFormatter(
        Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
    )
    app.logger.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    app.logger.addHandler(file_handler)
    app.logger.info("errors")
    logging.getLogger('flask_dance').setLevel(logging.DEBUG)
    

# ----------------------------------------------------------------------------#
# Launch.
# ----------------------------------------------------------------------------#

# Default port:
if __name__ == "__main__":
    app.run(debug=True)

# Or specify port manually:
"""
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
"""