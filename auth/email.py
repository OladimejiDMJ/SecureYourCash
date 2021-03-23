from flask_mail import Message

from flask import current_app
from auth import mail

def send_confirmation_email(to, subject, template):
    msg = Message( subject, recipients=[to], html=template,sender=current_app.config['MAIL_DEFAULT_SENDER'])
    print(f"\n\n\n\n{msg}\n\n\n\n")
    mail.send(msg)