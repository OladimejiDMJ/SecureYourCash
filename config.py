import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    @staticmethod
    def init_app(app):
        pass


class Development(Config):
    SECRET_KEY = os.environ["SECRET_KEY"]
    JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
    DEBUG = os.environ["DEBUG"]
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

    #This mail setting will be moved to the mailservice app
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.environ["MAIL_USERNAME"]
    MAIL_PASSWORD = os.environ["MAIL_PASSWORD"]
    SECURITY_PASSWORD_SALT = 'SecureOurCash'
    MAIL_DEFAULT_SENDER = "secureourcash"


class Test(Config):
    # Add a secret key for testing
    SECRET_KEY = "fca409881de74c0900c06066b946bd6dc324f193f0f9fbcd508316fd73db3d6b"
    TESTING = True
    JWT_SECRET_KEY = 't1NP63m4wnBg6nyHYKfmc2TpCOGI4nss'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'test_db.sqlite')
    
    #This mail setting will be moved to the mailservice app
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'laxxydoo1@gmail.com'
    MAIL_PASSWORD = 'Nigeria@1'
    SECURITY_PASSWORD_SALT = 'SecureOurCash'
    



config = {
    'development': Development,
    'test': Test,
    'default': Development
}