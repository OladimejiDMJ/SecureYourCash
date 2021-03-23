from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from . import db, login_manager
from datetime import datetime
import json
import uuid
import jwt
from sqlalchemy import or_


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), nullable=False, unique=True)
    first_name = db.Column(db.String(), index=False,
                           unique=False, nullable=True)
    last_name = db.Column(db.String(), index=False,
                          unique=False, nullable=True)
    phone_number = db.Column(db.String(), index=True,
                             unique=True, nullable=False)
    email = db.Column(db.String(), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, default=db.func.now, nullable=False)
    is_phone_verified = db.Column(db.Boolean)
    phone_verified_on = db.Column(db.DateTime, nullable=True)
    is_email_verified = db.Column(db.Boolean)
    email_verified_on = db.Column(db.DateTime, nullable=True)

    @property
    def password(self):
        raise AttributeError("Password not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    @classmethod
    def get_user(cls, email=None, phone_number=None):

        user = cls.query.filter(
            or_(
                cls.email == email,
                cls.phone_number == phone_number
            )
        ).first()
        return user

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @classmethod
    def create_user(cls, email, phone_number, password, last_name=None, first_name=None):
        if cls.get_user(email=email, phone_number=phone_number):
            return False

        user = cls(email=email, last_name=last_name, first_name=first_name,
                   phone_number=phone_number, password=password)

        user.email = user.email.lower().strip()
        user.registered_on = datetime.now()
        user.user_id = uuid.uuid4().hex
        user.password = password
        user.is_verified = False
        return user

    @classmethod
    def login(cls, password, email=None, phone_number=None):
        user = cls.get_user(email=email, phone_number=phone_number)
        if user and user.verify_password(password):
            auth_token = user.generate_auth_token()
            return user, auth_token
        return None, None

    def __repr__(self):
        return "<User {}>".format(self.email)

    def profile(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone_number': self.phone_number,
        }

    def save(self):
        db.session.add(self)
        db.session.commit()

    def set_phone_verified(self):
        self.is_phone_verified = True
        self.phone_verified_on = datetime.now()

    def set_email_verified(self):
        self.is_email_verified = True
        self.email_verified_on = datetime.now()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
