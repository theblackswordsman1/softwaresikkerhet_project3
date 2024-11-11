# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Email, ValidationError
from models import User
from cryptography.fernet import Fernet
from config import Config

cipher_suite = Fernet(Config.FERNET_SECRET_KEY)


class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=1, max=25)]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(), Length(min=6, max=40)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=4, max=40)]
    )
    confirm_password = PasswordField(
        'Repeat Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match')
        ]
    )
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Check if the username already exists."""
        encrypted_username = cipher_suite.encrypt(username.data.encode('utf-8')).decode('utf-8')
        user = User.query.filter_by(_username=encrypted_username).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

    """
    def validate_email(self, email):
        # Check if the email already exists.
        encrypted_email = cipher_suite.encrypt(email.data.encode('utf-8')).decode('utf-8')
        user = User.query.filter_by(_email=encrypted_email).first()
        if user:
            raise ValidationError('Email already registered. Please choose a different one.')
    """

class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=6, max=25)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Login')


class ForgotForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[DataRequired(), Email(), Length(min=6, max=40)]
    )
    submit = SubmitField('Reset Password')

    def validate_email(self, email):
        """Check if the email exists in the database."""
        encrypted_email = cipher_suite.encrypt(email.data.encode('utf-8')).decode('utf-8')
        user = User.query.filter_by(_email=encrypted_email).first()
        if not user:
            raise ValidationError('Email not found. Please check and try again.')
