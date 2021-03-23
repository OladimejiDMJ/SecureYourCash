import datetime
import logging
import os
import re
import secrets

import requests
from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, Response
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, jwt_required)
from flask_restful import Api, Resource, abort, reqparse, request, url_for

from auth.email import send_confirmation_email
from auth.errors import errors
from auth.models import User
from auth.reset_password import ForgotPassword, ResetPassword
from auth.token import confirm_token, generate_confirmation_token

logging.basicConfig(
    format="%(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG
)

#from auth.mail import send_mail

user_app = Blueprint('user_app', __name__)
# Not sure if this is the right place to put errors=errors
api = Api(user_app, errors=errors)


OTP_ENDPOINT = os.environ["OTP_SERVICE"]


@user_app.after_request
def log_response(response):
    print("running after request")
    logging.info(f"{response}\n {response.json}")
    return response


def abort_template(msg, status_code=400):
    abort(status_code, success=False, message=msg)


def success_template(msg, status_code=200):
    return {
        "success": True,
        "data": msg
    }, status_code


@user_app.route("/get_otp/<phone_number>", methods=["GET", ])
def send_otp(phone_number, skip_check=False):
    if not skip_check:
        user = User.get_user(phone_number=phone_number)
        if not isinstance(user, User):
            abort_template(status_code=403, msg="Invalid user")

    # Generate otp for phone_number and send to phone_number
    otp_response = requests.get(
        f"{OTP_ENDPOINT}/generate?destination={phone_number}")
    if not otp_response != 201:  # returns 201 for successful token generation
        abort_template(msg="Can't generate_otp for user")

    otp = otp_response.json()
    print(otp)
    # send otp via sms channel
    return otp


class SignupAPI(Resource):
    model = User
    userParser = reqparse.RequestParser()
    userParser.add_argument('email', type=str, required=True)
    userParser.add_argument('password', type=str, required=True)
    userParser.add_argument('phone_number', type=str, required=True)

    def post(self):
        """
        Creates new user
            Parameters:
            -email (str)
            -password (str)
            -phone_number(str)
        """
        args = self.userParser.parse_args()
        email = args['email'].lower().strip()
        password = args['password']
        phone_number = args['phone_number'].strip()

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            abort_template(msg="Invalid Email supplied")

        user = self.model.create_user(
            email=email, phone_number=phone_number, password=password)
        if not user:
            abort_template(
                status_code=409, msg="account found on platform, create_user unsuccessful.")

        # New line of codes for confirmation mail
        # token = generate_confirmation_token(user.email)
        # confirm_url = url_for('user_app.confirm_email',
        #                       token=token, _external=True)
        # html_content = f'<p>Welcome! Thanks for signing up. Please follow this link to activate your account:</p><p><a href="{ confirm_url }">{ confirm_url }</a></p><br><p>Cheers!</p>'
        # subject = "Please confirm your email"
        # send_confirmation_email(user.email, subject, html_content)

        send_otp(phone_number=phone_number)
        print("Saving user")
        user.save()  # ensured that all flow is completed before saving user
        return success_template(msg='Account Created, proceed to confirm your account')


class ConfirmOTP(Resource):
    model = User
    userParser = reqparse.RequestParser()
    userParser.add_argument('phone_number', type=str,
                            required=True, location="args")
    userParser.add_argument('otp', type=str, required=True, location="args")

    def get(self):
        args = self.userParser.parse_args()
        phone_number = args['phone_number'].strip()

        otp_response = requests.get(
            f"{OTP_ENDPOINT}/verify?destination={phone_number}&otp={args['otp'].strip()}")
        if otp_response.status_code != 200:  # returns 200 for successful verifications
            abort_template(msg="Invalid token", status_code=400)

        # set user phone_number as verified for successful ones
        user = self.model.get_user(phone_number=phone_number)
        if not user:
            abort_template(msg="User does not exist")

        user.set_email_verified()
        user.save()

        return success_template(msg="Phone verified")


class Confirm_mail(Resource):
    # model=User
    #userParser = reqparse.RequestParser()
    #userParser.add_argument('email', type=str)
    def get(self, token):
        try:
            email = confirm_token(token)
        except:
            abort(400, msg='The confirmation link is invalid or has expired.', )

        user = User.query.filter_by(email=email).first_or_404()
        if user.is_verified:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.is_verified = True
            user.verified_on = datetime.now()
            db.session.add(user)
            db.session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
        return ('Log in to continue')


class LoginAPI(Resource):
    model = User
    userParser = reqparse.RequestParser()
    userParser.add_argument('email', type=str, default="")
    userParser.add_argument('phone_number', type=str, default="")
    userParser.add_argument('password', type=str, required=True)

    def post(self):
        args = self.userParser.parse_args()
        email = args.get('email').lower().strip()
        phone_number = args.get('phone_number').strip()
        password = args['password']

        if not any([email, phone_number]):
            abort_template(status_code=400,
                           msg="phone_number or email must be provided")

        user = self.model.get_user(email=email, phone_number=phone_number)
        if not user:
            abort_template(status_code=422,
                           msg="User does not exist, please signup")

        authorized = user.verify_password(password)
        if not authorized:
            abort_template(status_code=401, msg='Invalid Password for user!')

        # identity passed to jwt is user_id
        expires = datetime.timedelta(days=7)
        access_token = create_access_token(
            identity=str(user.user_id), expires_delta=expires)
        refresh_token = create_refresh_token(
            identity=str(user.user_id), expires_delta=datetime.timedelta(weeks=2))

        return success_template(msg={
            'type': 'Bearer',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': f"{datetime.datetime.now()+expires}"})


class Home(Resource):
    @jwt_required
    def get(self):
        user = get_jwt_identity()
        return "Welcome {}".format(user)

class Profile(Resource):
    model = User

    @jwt_required
    def get(self):
        user = self.model.query.filter_by(user_id=get_jwt_identity()).first()
        return success_template(msg=user.profile())
    
    def put(self):
        pass

api.add_resource(SignupAPI, '/signup')
api.add_resource(ConfirmOTP, '/confirm_otp')
api.add_resource(LoginAPI, '/login')
api.add_resource(Home, '/')
api.add_resource(ForgotPassword, '/forgot_password')
api.add_resource(Confirm_mail, '/confirm_mail/<token>',
                 endpoint="confirm_email")
api.add_resource(ResetPassword, '/reset_password')
api.add_resource(Profile, '/profile')