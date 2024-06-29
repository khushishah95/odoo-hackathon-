import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'mysecretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
from datetime import datetime
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    height = db.Column(db.Float, nullable=False)
    dietary_preferences = db.Column(db.String(100), nullable=True)
    allergies = db.Column(db.String(100), nullable=True)
    health_goals = db.Column(db.String(100), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FoodItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Float, nullable=False)
    protein = db.Column(db.Float, nullable=False)
    fat = db.Column(db.Float, nullable=False)
    carbs = db.Column(db.Float, nullable=False)
    vitamins = db.Column(db.String(100), nullable=True)
    minerals = db.Column(db.String(100), nullable=True)
from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt
from forms import RegistrationForm, LoginForm, UpdateProfileForm
from models import User, FoodItem

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password, age=form.age.data, gender=form.gender.data, weight=form.weight.data, height=form.height.data, dietary_preferences=form.dietary_preferences.data, allergies=form.allergies.data, health_goals=form.health_goals.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.age = form.age.data
        current_user.weight = form.weight.data
        current_user.height = form.height.data
        current_user.dietary_preferences = form.dietary_preferences.data
        current_user.allergies = form.allergies.data
        current_user.health_goals = form.health_goals.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.age.data = current_user.age
        form.weight.data = current_user.weight
        form.height.data = current_user.height
        form.dietary_preferences.data = current_user.dietary_preferences
        form.allergies.data = current_user.allergies
        form.health_goals.data = current_user.health_goals
    return render_template('profile.html', title='Account', form=form)

@app.route('/diet_plan')
@login_required
def diet_plan():
    # Placeholder for diet plan generation logic
    diet_plan = generate_diet_plan(current_user)
    return render_template('diet_plan.html', title='Diet Plan', diet_plan=diet_plan)

def generate_diet_plan(user):
    # Placeholder function to generate a diet plan based on user profile
    # Example: This can be replaced with a more sophisticated recommendation algorithm
    diet_plan = {
        'breakfast': {'name': 'Oatmeal', 'calories': 150, 'protein': 5, 'fat': 3, 'carbs': 27},
        'lunch': {'name': 'Grilled Chicken Salad', 'calories': 300, 'protein': 30, 'fat': 10, 'carbs': 20},
        'dinner': {'name': 'Quinoa and Vegetables', 'calories': 350, 'protein': 15, 'fat': 10, 'carbs': 50}
    }
    return diet_plan
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, FloatField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    age = IntegerField('Age', validators=[DataRequired()])
    gender = StringField('Gender', validators=[DataRequired()])
    weight = FloatField('Weight (kg)', validators=[DataRequired()])
    height = FloatField('Height (cm)', validators=[DataRequired()])
    dietary_preferences = TextAreaField('Dietary Preferences')
    allergies = TextAreaField('Allergies')
    health_goals = TextAreaField('Health Goals')
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateProfileForm(FlaskForm):
    age = IntegerField('Age', validators=[DataRequired()])
    weight = FloatField('Weight (kg)', validators=[DataRequired()])
    height = FloatField('Height (cm)', validators=[DataRequired()])
    dietary_preferences = TextAreaField('Dietary Preferences')
    allergies = TextAreaField('Allergies')
    health_goals = TextAreaField('Health Goals')
    submit = SubmitField('Update')
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

from models import User, FoodItem
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
