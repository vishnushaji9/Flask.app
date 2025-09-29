SECRET_KEY = 'your-super-secret-key'

SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Flask-Mail Configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'your_email@gmail.com'         # Replace with your email
MAIL_PASSWORD = 'your_app_password_here'       # Use App Password (not your main email password)
