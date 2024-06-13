import pyotp
from datetime import datetime
from io import BytesIO
import qrcode
from base64 import b64encode
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired

def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6)])

def is_otp_valid(username, secret, user_otp):
  uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="NEXTSAFE")
  totp = pyotp.parse_uri(uri)

  return totp.verify(user_otp)