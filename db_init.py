# db_init.py
from config import Config
from models import db  # Import db from models.py
from flask import Flask

# Initialize Flask and SQLAlchemy with app context
def initialize_database():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = Config.DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)  # Initialize db with Flask app
    
    with app.app_context():
        db.create_all()  # Create all tables in the database
        print("Database initialized with tables.")

def get_session():
    # Use db.session directly from Flask SQLAlchemy, so this function is no longer needed.
    return db.session
