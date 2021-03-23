from flask import Flask
from flask_httpauth import HTTPTokenAuth
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager

from config import config

db = SQLAlchemy()
login_manager = LoginManager()
mail=Mail()
jwt = JWTManager()
# login_manager.login_view = 'auth.login'

def create_app(config_filename):
    app = Flask(__name__)
    app.config.from_object(config[config_filename])
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    config[config_filename].init_app(app)
    
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    from .views import user_app
    app.register_blueprint(user_app)

    return app