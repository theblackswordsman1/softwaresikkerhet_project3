from datetime import datetime
import json
import bcrypt
from cryptography.fernet import Fernet
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin

cipher_suite = Fernet(Config.FERNET_SECRET_KEY)

db = SQLAlchemy()


class Session(OAuthConsumerMixin, db.Model):
    __tablename__ = 'sessions'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String, nullable=False)
    _token = db.Column("token", db.String, unique=True, nullable=False)  # Store token as JSON
    created_at = db.Column(db.DateTime, default=datetime.now)

    @property
    def token(self):
        # Decrypt and deserialize the token JSON string
        decrypted_token = cipher_suite.decrypt(self._token.encode('utf-8')).decode('utf-8')
        return json.loads(decrypted_token)

    @token.setter
    def token(self, value):
        # Serialize and encrypt the token JSON string
        token_json = json.dumps(value)
        self._token = cipher_suite.encrypt(token_json.encode('utf-8')).decode('utf-8')


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    salt = db.Column(db.String, nullable=False)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    @property
    def password(self):
        raise AttributeError("Password is write-only")

    @password.setter
    def password(self, plaintext_password):
        salt = bcrypt.gensalt()
        self.salt = salt.decode('utf-8')
        hashed_password = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)
        self.password_hash = hashed_password.decode('utf-8')

    def verify_password(self, plaintext_password):
        return bcrypt.checkpw(plaintext_password.encode('utf-8'), self.password_hash.encode('utf-8'))