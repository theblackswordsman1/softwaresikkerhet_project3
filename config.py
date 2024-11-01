import os
from cryptography.fernet import Fernet


class Config(object):
    SECRET_KEY = "supersekrit"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    FERNET_SECRET_KEY = Fernet.generate_key()
    DEBUG = True

