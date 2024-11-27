from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from flask_mail import Mail, Message
import random
import string
import time
import secrets
from werkzeug.security import check_password_hash
from datetime import datetime
   # In-memory storage for OTPs

# Initialize Flask app
from flask_cors import CORS  # Importing CORS

app = Flask(__name__)
otp_store = {}  # In-memory storage for OTPs
user_tokens = {}
CORS(app)  # Enable CORS
db = SQLAlchemy()
bcrypt = Bcrypt(app)
mail = Mail(app)

# App configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Use port 587 for TLS
app.config['MAIL_USE_TLS'] = True  # Enable TLS
app.config['MAIL_USERNAME'] = 'ayusharya.personal@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'uclx fhnh plxf jgjh'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'ayusharya.personal@gmail.com'  # Replace with your email

db.init_app(app)

# Setup LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User model
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    mobile_number = db.Column(db.String(15), nullable=False)
    school_name = db.Column(db.String(100), nullable=False)
    email_id = db.Column(db.String(100), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True)


# OTP model
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Route to send OTP
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        if not data or 'email_id' not in data:
            return jsonify({'error': 'Invalid request, email_id is required'}), 400

        email = data['email_id']
        otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP

        # Store OTP in otp_store with timestamp
        otp_store[email] = {'otp': otp, 'timestamp': time.time()}

        # Sending email
        sender_email = "gehuautocell@gmail.com"
        sender_password = "mbsj lsll aphf dqto"  # Use App Password if using Gmail
        subject = "Your One-Time Password (OTP) for Verification"
        body = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                .email-container {{
                    font-family: Arial, sans-serif;
                    max-width: 500px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    border: 1px solid #e0e0e0;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }}
                .header {{
                    padding: 20px;
                    background-color: #4CAF50;
                    border-radius: 8px 8px 0 0;
                }}
                .header img {{
                    max-width: 100px;

                }}
                .header h2 {{
                    color: white;
                    font-size: 22px;
                    margin: 10px 0;
                }}
                .body-content {{
                    padding: 20px;
                    color: #333;
                }}
                .otp {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #4CAF50;
                    background-color: #f1f8e9;
                    border-radius: 8px;
                    padding: 10px;
                    margin: 20px 0;
                    display: inline-block;
                    letter-spacing: 4px;
                }}
                .message {{
                    font-size: 16px;
                    color: #555;
                    line-height: 1.6;
                }}
                .footer {{
                    font-size: 12px;
                    color: #999;
                    padding: 20px;
                    border-top: 1px solid #e0e0e0;
                    margin-top: 20px;
                }}
                .footer-address {{
                    text-align: left;
                    font-size: 12px;
                    margin-top: 10px;
                    color: #666;
                    line-height: 1.4;
                }}
                .footer-address h4 {{
                    margin: 5px 0;
                    font-weight: bold;
                }}
                .footer-address p {{
                    margin: 0;
                }}
                .copyright {{
                    text-align: center;
                    color: #999;
                    margin-top: 10px;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <img src="https://i.ibb.co/svwHBWv/logo0.png" alt="Logo" />
                    <h2>Welcome to GEyan Portal </h2>
                </div>
                <div class="body-content">
                    <p class="message">Hello User ! </p>
                    <p class="message">Thank you for using our service. To complete your verification, please use the following One-Time Password (OTP):</p>
                    <div class="otp">{otp}</div>
                    <p class="message">This code is valid for the next 10 minutes. For security reasons, please do not share it with anyone.</p>
                    <p class="message">Once verified, you’ll be able to access your account and explore all our features.</p>
                </div>
                <div class="footer">

                    <div class="copyright">
                        © Copyright 2024, All Rights Reserved by Graphic Era 
                    </div>
                </div>
            </div>
        </body>
        </html>"""

        # Create email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        # Connect to the Gmail server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)

        print(f"OTP sent to {email}: {otp}")  # Debugging

        return jsonify({'message': 'OTP sent successfully!'}), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': 'An error occurred on the server'}), 500



# Route to verify OTP and log in
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        if not data or 'email_id' not in data or 'otp' not in data:
            return jsonify({'error': 'Invalid request, email_id and otp are required'}), 400

        email = data['email_id']
        otp = data['otp']

        print(f"Verifying OTP for {email}: {otp}")  # Debugging

        # Check if the email exists in otp_store
        if email in otp_store:
            stored_otp_data = otp_store[email]
            if stored_otp_data['otp'] == otp:
                # Validate OTP expiration (5 minutes)
                if time.time() - stored_otp_data['timestamp'] <= 300:
                    del otp_store[email]  # Clear OTP after successful verification

                    # Check if user exists in the database
                    user = User.query.filter_by(email_id=email).first()
                    if user:
                        login_user(user)  # Log in the user with Flask-Login
                        return jsonify({'message': 'OTP verified and user logged in successfully!'}), 200
                    else:
                        return jsonify({'error': 'User not registered.'}), 404
                else:
                    return jsonify({'error': 'OTP expired. Please request a new one.'}), 400
            else:
                return jsonify({'error': 'Invalid OTP. Please try again.'}), 400
        else:
            return jsonify({'error': 'No OTP request found for this email.'}), 400

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': 'An error occurred on the server'}), 500

def get_id(self):
    try:
        return str(self.id)
    except AttributeError:
        raise NotImplementedError("No `id` attribute - override `get_id`")



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Route to register user
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    mobile_number = data.get('mobile_number')
    email_id = data.get('email_id')
    school_name = data.get('school_name')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, mobile_number=mobile_number, email_id=email_id, school_name=school_name)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# Route to log in user
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


# Route for user dashboard
@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    return jsonify({"message": f"Welcome to the dashboard, {current_user.username}"})


# Route to log out user
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    try:
        logout_user()
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Admin Panel Route
@app.route('/admin')
def admin_panel():
    # Fetch all registered users from the database
    users = User.query.all()
    return render_template('admin.html', users=users)


# Route to delete user in admin panel
@app.route('/admin/delete/<int:id>', methods=['POST'])
def delete_user(id):
    user_to_delete = User.query.get(id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('admin_panel'))  # Redirect back to the admin panel

    return jsonify({"error": "User not found"}), 404


# Route to fetch user data in JSON format
@app.route('/api/users')
def get_users():
    users = User.query.all()
    user_data = [{"id": user.id, "username": user.username, "email_id": user.email_id} for user in users]
    return jsonify(user_data)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist

    app.run(debug=True)
