from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo, DataRequired
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
import random
import os
from dotenv import load_dotenv
load_dotenv()



#Flask application setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key-123'   # secure session cookies and CSRF tokens
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')


csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Database model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

# Flask-WTF forms
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required."),
        Email(message="Enter a valid email address.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=6, message="Password must be at least 6 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Register')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
        InputRequired(message="OTP is required."),
        Length(min=6, max=6, message="OTP must be 6 digits.")
    ])
    submit = SubmitField('Verify')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def generate_otp():
    """Generates a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    """Sends an OTP to the user's email."""
    try:
        msg = Message('Your OTP Code for Verification',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Your one-time password (OTP) is: {otp}"
        mail.send(msg)
        print("OTP email sent successfully to", email)
    except Exception as e:
        print("Email sending failed:", e)
        flash('Failed to send OTP email. Please check your email configuration.', 'danger')

#session handling
@app.after_request
def prevent_caching(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    #if user is alreay logged , then redirecting to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            if existing_user.is_verified:
                flash('Email already registered and verified. Please login.', 'info')
                return redirect(url_for('login'))
            else:
                #otp resend if not registered
                otp = generate_otp()
                session['otp'] = otp
                session['email'] = email
                send_otp_email(email, otp)
                flash('You are already registered but not verified. A new OTP has been sent to your email.', 'warning')
                return redirect(url_for('verify_otp'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        #otp for new users
        otp = generate_otp()
        session['otp'] = otp
        session['email'] = email
        send_otp_email(email, otp)

        flash('Registration successful! Please check your email for the verification OTP.', 'success')
        return redirect(url_for('verify_otp'))

    return render_template('register.html', form=form)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if 'email' not in session:
        flash('Please register first.', 'danger')
        return redirect(url_for('register'))

    if form.validate_on_submit():
        if form.otp.data == session.get('otp'):
            user = User.query.filter_by(email=session['email']).first()
            if user:
                user.is_verified = True
                db.session.commit()
                flash('Account verified successfully. You can now log in.', 'success')
                session.pop('otp', None)
                session.pop('email', None)
                return redirect(url_for('login'))
        
        flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html', form=form, email=session.get('email'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    #if user is alreay logged , then redirecting to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if not user:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        if not bcrypt.check_password_hash(user.password, form.password.data):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Your account is not verified. Please check your email for the OTP.', 'warning')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)