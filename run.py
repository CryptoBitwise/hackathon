import os
from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager  # Import LoginManager
from config import Config  # Ensure the correct relative import
from app import db, login_manager  # Import login_manager
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin  # Import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import User  # Import User model
from flask import request, jsonify, render_template, flash, redirect, url_for
from app import app, db
from app.models import User, Job
from app.forms import LoginForm, RegistrationForm
from flask_login import current_user, login_user, logout_user, login_required
from flask import request, jsonify, render_template, flash, redirect, url_for

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost:5432/mydatabase'  # Use your actual DB details
    SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()  # Initialize LoginManager
login_manager.login_view = 'login'  # Set the login view (for redirects)
login_manager.login_message_category = 'info'  # Set flash message category

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)  # Initialize Flask-Login

    return app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):  # Inherit from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    user_type = db.Column(db.String(20), nullable=False)  # "client" or "provider"
    # Add more fields: name, location, contact info, etc.

    jobs = db.relationship('Job', backref='client', lazy='dynamic', foreign_keys='Job.client_id')
    provided_jobs = db.relationship('Job', backref='provider', lazy='dynamic', foreign_keys='Job.provider_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    # Add other fields (budget, skills, etc.)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Allow null
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return f'<Job {self.title}>'

# Add other models (Skill, ProviderSkill, etc.) as needed

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    user_type = SelectField('User Type', choices=[('client', 'Client'), ('provider', 'Provider')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    # Custom validation to check if username is already taken
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    # Custom validation to check if email is already taken
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')  # For "Remember Me" functionality
    submit = SubmitField('Login')


@app.route('/')
def index():
    return "Welcome to the Job Connector API!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # Redirect if already logged in
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, user_type=form.user_type.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')  # Flash message
        return redirect(url_for('login'))  # Redirect to login page
    #If it is a get, or the form is not valid.
    return jsonify({'message':'Register endpoint (not fully implemented yet).'}), 501
    #return render_template('register.html', title='Register', form=form)  # Render a template (if using templates)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            # next_page = request.args.get('next') # Handle redirects after login
            # return redirect(next_page) if next_page else redirect(url_for('index'))
            return jsonify({'message':'login endpoint - you would be logged in now.'}), 200
        else:
            # flash('Login Unsuccessful. Please check email and password', 'danger')
            return jsonify({'message':'Login Unsuccessful. Please check email and password'}), 401
    return jsonify({'message':'login endpoint (form handling to be added).'}), 501
    # return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    #return redirect(url_for('index'))
    return jsonify({'message':'logout endpoint'}), 200

@app.route('/api/jobs', methods=['GET', 'POST'])
@login_required # Example of protecting a route
def jobs():
    if request.method == 'GET':
        jobs = Job.query.all()
        jobs_list = [{'id': job.id, 'title': job.title, 'description': job.description,
                      'location': job.location, 'client_id': job.client_id,
                      'provider_id':job.provider_id} for job in jobs]
        return jsonify(jobs_list)

    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'title' not in data or 'description' not in data:
            return jsonify({'message': 'Missing required data'}), 400

        # Use current_user (from Flask-Login) to get the client_id
        new_job = Job(title=data['title'], description=data['description'],
                      location=data.get('location', ''), client_id=current_user.id)
        db.session.add(new_job)
        db.session.commit()
        return jsonify({'message': 'Job created', 'id': new_job.id}), 201


@app.route('/api/jobs/<int:job_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required #Protecting the routes
def get_job(job_id):
    job = Job.query.get_or_404(job_id)

    if request.method == 'GET':
        job_data = {'id': job.id, 'title': job.title, 'description': job.description,
                      'location': job.location, 'client_id': job.client_id, 'provider_id': job.provider_id}
        return jsonify(job_data)

    elif request.method == 'PUT':
        data = request.get_json()
        # Validate and update job attributes...
        if not data:
            return jsonify({'message': 'No input data provided'}), 400

        # Update job attributes
        if 'title' in data:
            job.title = data['title']
        if 'description' in data:
            job.description = data['description']
        if 'location' in data:
            job.location = data['location']
        if 'provider_id' in data:
                # Check if provider ID is valid.
                provider = User.query.get(data['provider_id'])
                if not provider:
                    return jsonify({'message':'Invalid provider_id'}), 400
                job.provider_id = data['provider_id']

        db.session.commit()
        return jsonify({'message': 'Job updated'}), 200

    elif request.method == 'DELETE':

        db.session.delete(job)
        db.session.commit()
        return jsonify({'message': 'Job deleted'}), 200

# Add routes for user profiles, etc.

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)

