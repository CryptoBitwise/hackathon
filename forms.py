from flask import render_template, request, redirect, url_for, flash
from app import app, db
from app.models import User, Job
from app.forms import RegistrationForm, LoginForm, JobForm
from flask_login import login_user, current_user, logout_user, login_required

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, user_type=form.user_type.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/jobs', methods=['GET'])
@login_required
def jobs():
    all_jobs = Job.query.all()
    return render_template('jobs.html', title='Jobs', jobs=all_jobs)

@app.route('/jobs/new', methods=['GET', 'POST'])
@login_required
def create_job():
    if current_user.user_type != 'client':
        flash('Only clients can post jobs.', 'warning')
        return redirect(url_for('jobs'))
    form = JobForm()
    if form.validate_on_submit():
        job = Job(title=form.title.data, description=form.description.data, location=form.location.data, client_id=current_user.id)
        db.session.add(job)
        db.session.commit()
        flash('Your job has been posted!', 'success')
        return redirect(url_for('jobs'))
    return render_template('create_job.html', title='New Job', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

# Add more routes as needed (e.g., for editing jobs, viewing provider profiles, etc.)