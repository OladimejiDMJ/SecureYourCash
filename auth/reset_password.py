

from flask import request, render_template
from flask_jwt_extended import create_access_token, decode_token
from .models import User
from flask_restful import Resource,reqparse, request, abort
import datetime
from jwt.exceptions import ExpiredSignatureError, DecodeError,InvalidTokenError
#from .mail import send_mail
from .errors import SchemaValidationError, InternalServerError, EmailDoesnotExistsError, BadTokenError
from .errors import errors
#from .views import validate_email
 

class ForgotPassword(Resource):
  model = User
  userParser = reqparse.RequestParser()
  userParser.add_argument('email', type=str, required=True)
  def post(self):

    args = self.userParser.parse_args()
    email=args['email'].lower()

    try:
      user=User.query.filter_by(email=email).first()
      if not user:
        raise EmailDoesnotExistsError
				
      expires = datetime.timedelta(hours=12)
      reset_token = create_access_token(str(user.id), expires_delta=expires)
      url=request.host_url + 'reset/' + reset_token
      # return send_mail('[SecureOurCash] Reset Your Password',
      #                         sender='SecureOurCash.com',
      #                         recipients=[user.email],
      #                         text_body=render_template('email_templates/reset_password.txt', url=url),
      #                         html_body=render_template('email_templates/reset_password.html',url=url))
      return (url)
    
    except EmailDoesnotExistsError:
      error = errors["EmailDoesnotExistsError"]

    except Exception:
      error = errors["InternalServerError"]

    return error['message'], error['status']

class ResetPassword(Resource):
    def post(self):
        url = request.host_url + 'reset/'
        try:
            body = request.get_json()
            reset_token = body.get('reset_token')
            password = body.get('password')

            if not reset_token or not password:
                abort(400, error="Invalid Email/Password supplied")

            user_id = decode_token(reset_token)['identity']

            user = User.query.filter_by(id=int(user_id)).first()
            user.password = password
            user.save()

            # return send_mail('[SecureOurCash] Password reset successful',
            #                   sender='support@movie-bag.com',
            #                   recipients=[user.email],
            #                   text_body='Password reset was successful',
            #                   html_body='<p>Password reset was successful</p>')
            return "Password reset was successful"
        except ExpiredSignatureError:
            return "Token Expired", 400
        except (DecodeError, InvalidTokenError):
            return "BadTokenError", 400
        except Exception as e:
            raise InternalServerError
			