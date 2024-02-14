from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField, SelectField, Form, TextAreaField, validators, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from openai import OpenAI
import openai
import os
from sqlalchemy import or_
import io
import stripe
from dotenv import load_dotenv
from datetime import datetime
from email.message import EmailMessage
import ssl
import smtplib
import json
import jsonify
from sqlalchemy import func
import re
import random
import shelve

# evan's
load_dotenv()
openai.api_key = os.environ["OPENAI_API_KEY"]
client = OpenAI()

app = Flask(__name__)
db = SQLAlchemy()
app.config['SECRET_KEY'] = 'bloopypillows'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///user.db',
    'staff': 'sqlite:///staff.db',
    'used': 'sqlite:///used.db',
    'products': 'sqlite:///products.db',
    'purchase': 'sqlite:///purchase.db',
    'conversations': 'sqlite:///conversations.db',
    'enquiry': 'sqlite:///enquiry.db',
    'feedback': 'sqlite:///feedback.db',
    'support_conversations': 'sqlite:///support_conversations.db'}
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['QUIZ_FILE'] = 'quiz_questions.txt'
db.init_app(app)

stripe.api_key = "sk_test_51OX2l5HNT2ZiDcKekb6Rcip8rncZsq0zwNKzztoyVXBApFS0r7ui9LpW6fnc6xhIOyALoB8iYHuhHHgxgF8mlKze002JRh6Cje"


class User(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    points = db.Column(db.Integer, default=0)
    quiz_attempts = db.relationship('UserQuizAttempt', back_populates='user', lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    purchases = db.relationship('Purchase', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Staff(db.Model):
    __bind_key__ = 'staff'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def password_check(form, field):
    password = field.data
    first_name = form.first_name.data if hasattr(form, 'first_name') else ''
    last_name = form.last_name.data if hasattr(form, 'last_name') else ''
    username = form.username.data if hasattr(form, 'username') else ''

    if any(name.lower() in password.lower() for name in [first_name, last_name, username]):
        raise ValidationError('Password must not contain your name or username.')

    if not re.search(r'\d', password):
        raise ValidationError('Password must contain at least one digit.')

    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')

    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
class NewProducts(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'newproducts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    stock = db.Column(db.Integer)
    description = db.Column(db.String, nullable=False)
    image = db.Column(db.String(300))
    stripe_product_id = db.Column(db.String(200))


class UsedProducts(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    lister_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    lister = db.relationship('User', backref='used_products')
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    condition = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(300))
    description = db.Column(db.String, nullable=False)


class Conversation(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'conversation'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_id = db.Column(db.Integer)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True)


class Message(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Purchase(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Purchase {self.id}>'


class Enquiry(db.Model):
    __bind_key__ = "users"
    __tablename__ = 'enquiry'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='enquiries')


class Feedback(db.Model):
    __bind_key__ = "users"
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='feedbacks')


class SupportConversation(db.Model):
    __bind_key__ = 'support_conversations'
    id = db.Column(db.Integer, primary_key=True)
    enquiry_id = db.Column(db.Integer, nullable=True)
    feedback_id = db.Column(db.Integer, nullable=True)
    messages = db.relationship('SupportMessage', backref='conversation', lazy='dynamic')


class SupportMessage(db.Model):
    __bind_key__ = 'support_conversations'
    __tablename__ = 'support_message'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('support_conversation.id'))
    sender_id = db.Column(db.Integer, nullable=False)
    sender_type = db.Column(db.String(10), nullable=False)
    content = db.Column(db.String(1024), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class QuizQuestion(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(1024), nullable=False)
    options = db.Column(db.String(1024), nullable=False)
    correct_option = db.Column(db.String(1024), nullable=False)
    quiz_attempts = db.relationship('UserQuizAttempt', back_populates='quiz_question', lazy='dynamic')


class UserQuizAttempt(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_question_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    selected_option = db.Column(db.String(1024), nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='quiz_attempts')
    quiz_question = db.relationship('QuizQuestion', back_populates='quiz_attempts')


class CharitableOffer(db.Model):
    __tablename__ = 'charitable_offer'
    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(100), nullable=False)
    offer_description = db.Column(db.String(255), nullable=False)
    points_required = db.Column(db.Integer, nullable=False)
class Review(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('newproducts.id'),
                           nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('NewProducts', backref='reviews')
    user = db.relationship('User', backref='reviews')

class StaffInvitationCode(db.Model):
    __tablename__ = 'staff_invitation_codes'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    invitation_code = db.Column(db.String(120), nullable=False)
class UserSignUpForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), password_check])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
class UserLoginForm(FlaskForm):
    username_or_email = StringField('Username/Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
class UserEditForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')
class UserAddUsed(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    category = SelectField(
        'Category',
        choices=[
            ('Electronics', 'Electronics'),
            ('Furniture', 'Furniture'),
            ('Clothing', 'Clothing'),
            ('Books', 'Books'),
            ('Kitchenware', 'Kitchenware'),
            ('Toys', 'Toys'),
            ('Jewelry', 'Jewelry'),
            ('Sporting Goods', 'Sporting Goods'),
            ('Home Decor', 'Home Decor'),
            ('Automotive', 'Automotive'),
            ('Health & Beauty', 'Health & Beauty'),
            ('Pet Supplies', 'Pet Supplies'),
            ('Office Supplies', 'Office Supplies'),
            ('Gardening Tools', 'Gardening Tools'),
            ('Music Instruments', 'Music Instruments'),
            ('Fitness Equipment', 'Fitness Equipment'),
            ('Art Supplies', 'Art Supplies'),
            ('Baby Products', 'Baby Products'),
            ('Outdoor Gear', 'Outdoor Gear'),
            ('Party Supplies', 'Party Supplies'),
            ('Others', 'Others')
        ],
        validators=[DataRequired()]
    )
    brand = StringField('Brand', validators=[DataRequired()])
    condition = SelectField('Condition', choices=[('Brand New', 'Brand New'), ('Like New', 'Like New'),
                                                  ('Lightly Used', 'Lightly Used'), ('Well Used', 'Well Used'),
                                                  ('Heavily Used', 'Heavily Used')],
                            validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Add')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Verification Code')

class VerifyResetCodeForm(FlaskForm):
    verification_code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify Code')

class NewPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), password_check])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')
class StaffSignUpForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    invitation_code = StringField('Invitation Code', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), password_check])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')
class StaffLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
class StaffEditForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')
class StaffAddProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    category = SelectField(
        'Category',
        choices=[
            ('Electronics', 'Electronics'),
            ('Furniture', 'Furniture'),
            ('Clothing', 'Clothing'),
            ('Books', 'Books'),
            ('Kitchenware', 'Kitchenware'),
            ('Toys', 'Toys'),
            ('Jewelry', 'Jewelry'),
            ('Sporting Goods', 'Sporting Goods'),
            ('Home Decor', 'Home Decor'),
            ('Automotive', 'Automotive'),
            ('Health & Beauty', 'Health & Beauty'),
            ('Pet Supplies', 'Pet Supplies'),
            ('Office Supplies', 'Office Supplies'),
            ('Gardening Tools', 'Gardening Tools'),
            ('Music Instruments', 'Music Instruments'),
            ('Fitness Equipment', 'Fitness Equipment'),
            ('Art Supplies', 'Art Supplies'),
            ('Baby Products', 'Baby Products'),
            ('Outdoor Gear', 'Outdoor Gear'),
            ('Party Supplies', 'Party Supplies'),
            ('Others', 'Others')
        ],
        validators=[DataRequired()]
    )
    brand = StringField('Brand', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Add')

class StaffEditProductform(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    brand = StringField('Brand', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])

class ConfirmDonationForm(FlaskForm):
    submit = SubmitField('Confirm Donation')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login_landing')
def login_landing():
    return render_template('login_landing.html')

@app.route('/sign_up_landing')
def sign_up_landing():
    return render_template('sign_up_landing.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/user_sign_up', methods=['GET', 'POST'])
def user_sign_up():
    form = UserSignUpForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already taken, please try another one.', 'danger')
            return redirect(url_for('user_sign_up'))
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('Username already taken.', 'danger')
            return redirect(url_for('user_sign_up'))
        new_user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        welcome_subject = "Welcome to OnlyGreenThings!"
        welcome_body = """
        Thank you for signing up to be a part of our green community! We hope to bring to you limitless green opportunities, and exciting green deals! Let's all come together to save our earth, and play our part in upholding sustainable principles!


        This is a system generated message. No response is required.
        """
        send_email(form.email.data, welcome_subject, welcome_body)

        flash('You have successfully registered! A welcome email has been sent.', 'success')
        return redirect(url_for('user_login'))

    return render_template('user_sign_up.html', form=form)


def send_email(email_recipient, subject, body):
    email_sender = 'onlygreenthings.ogt@gmail.com'
    email_password = "dceffsbjiyaiomeh"
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_recipient
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_recipient, em.as_string())


@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.username == form.username_or_email.data) |
            (User.email == form.username_or_email.data)
        ).first()
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('This account has been deactivated. Please contact support.', 'danger')
                return redirect(url_for('user_login'))
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('user_account'))
        flash('Invalid username or password', 'danger')
    return render_template('user_login.html', form=form)

@app.route('/user_account', methods=['GET', 'POST'])
def user_account():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to view your account.', 'warning')
        return redirect(url_for('user_login'))
    user = User.query.get(user_id)
    return render_template('user_account.html', user=user)

@app.route('/user_account_information', methods=['GET', 'POST'])
def user_account_information():
    user = User.query.get_or_404(session['user_id'])
    form = UserEditForm(obj=user)
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('Your account information has been updated.', 'success')
        return redirect(url_for('user_account_information'))
    return render_template('user_account_information.html', form=form, user=user)



@app.route('/user_edit', methods=['GET', 'POST'])
def user_edit():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('user_login'))

    user = User.query.get_or_404(session['user_id'])
    form = UserEditForm(obj=user)
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('Account updated successfully.', 'success')
        return redirect(url_for('user_account_information'))

    return render_template('user_edit.html', form=form)

def generate_verification_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_verification_email(email, code):
    subject = "Password Reset Verification Code"
    body = f"Your verification code is {code}."
    send_email(email, subject, body)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('reset_password'))
        verification_code = generate_verification_code()

        session['reset_code'] = verification_code
        session['reset_email'] = form.email.data
        send_verification_email(form.email.data, verification_code)
        flash('A verification code has been sent to your email.', 'info')
        return redirect(url_for('verify_code'))
    return render_template('user_request_reset.html', form=form)

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    form = VerifyResetCodeForm()
    if form.validate_on_submit():
        if form.verification_code.data == session.get('reset_code'):
            return redirect(url_for('new_password'))
        else:
            flash('Invalid verification code.', 'danger')
            return redirect(url_for('reset_password'))
    return render_template('user_verify_code.html', form=form)

@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    form = NewPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=session.get('reset_email')).first()
        if user:
            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been reset successfully.', 'success')
            session.pop('reset_code', None)
            session.pop('reset_email', None)
            return redirect(url_for('user_login'))
        else:
            flash('Error resetting your password.', 'danger')
            return redirect(url_for('home'))
    return render_template('user_new_password.html', form=form)

@app.route('/user_delete')
def user_delete():
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('user_login'))
    user = User.query.get(session['user_id'])
    if user:
        user.is_active = False
        db.session.commit()
        session.clear()
        flash('Your account has been successfully deactivated.', 'success')
        return redirect(url_for('home'))
    flash('An error occurred while deactivating the account.', 'danger')
    return redirect(url_for('home'))


@app.route('/user_used', methods=['GET', 'POST'])
def user_used():
    return render_template('user_used_landing.html')


@app.route('/user_used_browse', methods=['GET', 'POST'])
def user_used_browse():
    if 'user_id' not in session:
        flash('Please log in to view this page.', 'danger')
        return redirect(url_for('user_login'))

    current_user_id = session['user_id']
    listings = UsedProducts.query.filter(UsedProducts.lister_id != current_user_id).all()
    return render_template('user_used_browse.html', listings=listings)


@app.route('/user_add_used', methods=['GET', 'POST'])
def user_add_used():
    form = UserAddUsed()
    if form.validate_on_submit():
        file = form.image.data
        filename = secure_filename(file.filename) if file else None
        if filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
        new_used_product = UsedProducts(
            lister_id=session.get('user_id'),
            name=form.name.data,
            price=form.price.data,
            category=form.category.data,
            brand=form.brand.data,
            condition=form.condition.data,
            description=form.description.data,
            image=filename
        )
        db.session.add(new_used_product)
        db.session.commit()
        flash('Used product added successfully!', 'success')
        return redirect(url_for('user_used'))
    return render_template('user_add_used.html', form=form)


@app.route('/user_used_listings', methods=['GET', 'POST'])
def user_used_listings():
    if 'user_id' not in session:
        flash('Please log in to view this page.', 'danger')
        return redirect(url_for('user_login'))
    current_user_id = session['user_id']
    my_listings = UsedProducts.query.filter_by(lister_id=current_user_id).all()
    return render_template('user_used_listings.html', my_listings=my_listings)


@app.route('/user_used_edit/<int:product_id>', methods=['GET', 'POST'])
def user_used_edit(product_id):
    used_product = UsedProducts.query.get_or_404(product_id)
    if 'user_id' not in session or session['user_id'] != used_product.lister_id:
        flash('You are not authorized to edit this product.', 'danger')
        return redirect(url_for('user_used_listings'))

    form = UserAddUsed(obj=used_product)
    if form.validate_on_submit():
        used_product.name = form.name.data
        used_product.price = form.price.data
        used_product.category = form.category.data
        used_product.brand = form.brand.data
        used_product.condition = form.condition.data
        used_product.description = form.description.data
        if form.image.data:
            file = form.image.data
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            used_product.image = filename
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('user_used_listings'))

    return render_template('user_used_edit.html', form=form, used_product=used_product)


@app.route('/start_conversation/<int:product_id>/<int:recipient_id>', methods=['GET', 'POST'])
def start_conversation(product_id, recipient_id):
    if 'user_id' not in session:
        flash('Please log in to start a conversation.', 'danger')
        return redirect(url_for('user_login'))

    sender_id = session['user_id']
    if sender_id == recipient_id:
        flash('You cannot start a conversation with yourself.', 'danger')
        return redirect(url_for('home'))

    try:
        existing_conversation = Conversation.query.filter(
            Conversation.product_id == product_id,
            or_(Conversation.sender_id == sender_id, Conversation.recipient_id == sender_id),
            or_(Conversation.sender_id == recipient_id, Conversation.recipient_id == recipient_id)
        ).first()

        if existing_conversation:
            return redirect(url_for('view_conversation', conversation_id=existing_conversation.id))

        new_conversation = Conversation(product_id=product_id, sender_id=sender_id, recipient_id=recipient_id)
        db.session.add(new_conversation)
        db.session.commit()

        flash('Conversation started!', 'success')
        return redirect(url_for('view_conversation', conversation_id=new_conversation.id))
    except Exception as e:
        app.logger.error(f'Error starting conversation: {e}')
        flash('An error occurred while starting the conversation.', 'error')
        return redirect(url_for('home'))


@app.route('/send_message/<int:conversation_id>', methods=['POST'])
def send_message(conversation_id):
    if 'user_id' not in session:
        flash('Please log in to send messages.', 'danger')
        return redirect(url_for('user_login'))
    conversation = Conversation.query.get_or_404(conversation_id)
    if session['user_id'] not in [conversation.sender_id, conversation.recipient_id]:
        flash('You do not have permission to send messages in this conversation.', 'danger')
        return redirect(url_for('home'))
    message_content = request.form.get('message')
    if not message_content:
        flash('Message cannot be empty.', 'danger')
        return redirect(url_for('view_conversation', conversation_id=conversation_id))
    new_message = Message(conversation_id=conversation_id, sender_id=session['user_id'], content=message_content)
    db.session.add(new_message)
    db.session.commit()
    flash('Message sent!', 'success')
    return redirect(url_for('view_conversation', conversation_id=conversation_id))


@app.route('/view_conversation/<int:conversation_id>', methods=['GET'])
def view_conversation(conversation_id):
    if 'user_id' not in session:
        flash('Please log in to view conversations.', 'danger')
        return redirect(url_for('user_login'))
    conversation = Conversation.query.get_or_404(conversation_id)
    if session['user_id'] not in [conversation.sender_id, conversation.recipient_id]:
        flash('You do not have permission to view this conversation.', 'danger')
        return redirect(url_for('home'))
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    return render_template('user_used_view_conversations.html', conversation=conversation, messages=messages)


@app.route('/staff_start_support_conversation/<entity_type>/<int:entity_id>', methods=['GET', 'POST'])
def staff_start_support_conversation(entity_type, entity_id):
    if request.method == 'POST':
        message_content = request.form['message']
        if entity_type == 'enquiry':
            conversation = SupportConversation(enquiry_id=entity_id)
        else:
            conversation = SupportConversation(feedback_id=entity_id)
        db.session.add(conversation)
        db.session.flush()

        staff_id = session.get('staff_id')
        message = SupportMessage(conversation_id=conversation.id, sender_id=staff_id, sender_type='staff',
                                 content=message_content)
        db.session.add(message)
        db.session.commit()
        flash('Support conversation started successfully.')
        return redirect(url_for('staff_view_support_conversation', conversation_id=conversation.id))
    return render_template('staff_start_support_conversation.html', entity_type=entity_type, entity_id=entity_id)


@app.route('/staff_send_support_message/<int:conversation_id>', methods=['POST'])
def staff_send_support_message(conversation_id):
    message_content = request.form['message']
    if not message_content.strip():
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('staff_view_support_conversation', conversation_id=conversation_id))
    staff_id = session.get('staff_id')
    if staff_id:
        message = SupportMessage(
            conversation_id=conversation_id,
            sender_id=staff_id,
            sender_type='staff',
            content=message_content
        )
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully.')
    else:
        flash('You must be logged in to send a message.', 'error')
    return redirect(url_for('staff_view_support_conversation', conversation_id=conversation_id))


@app.route('/user_send_support_message/<int:conversation_id>', methods=['POST'])
def user_send_support_message(conversation_id):
    message_content = request.form['message']
    if not message_content.strip():
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('user_view_support_conversation', conversation_id=conversation_id))
    user_id = session.get('user_id')
    if user_id:
        message = SupportMessage(
            conversation_id=conversation_id,
            sender_id=user_id,
            sender_type='user',
            content=message_content
        )
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully.')
    else:
        flash('You must be logged in to send a message.', 'error')
    return redirect(url_for('user_view_support_conversation', conversation_id=conversation_id))


@app.route('/staff_view_support_conversation/<int:conversation_id>')
def staff_view_support_conversation(conversation_id):
    conversation = SupportConversation.query.get_or_404(conversation_id)
    messages = SupportMessage.query.filter_by(conversation_id=conversation_id).order_by(SupportMessage.timestamp).all()
    return render_template('staff_view_support_conversation.html', conversation=conversation, messages=messages)


@app.route('/user_view_support_conversation/<int:conversation_id>')
def user_view_support_conversation(conversation_id):
    conversation = SupportConversation.query.get_or_404(conversation_id)
    messages = SupportMessage.query.filter_by(conversation_id=conversation_id).order_by(SupportMessage.timestamp).all()
    return render_template('user_view_support_conversation.html', conversation=conversation, messages=messages)


@app.route('/user_inbox')
def user_inbox():
    if 'user_id' not in session:
        flash('Please log in to view your inbox.', 'danger')
        return redirect(url_for('user_login'))

    user_id = session['user_id']
    product_conversations = Conversation.query.filter(
        or_(Conversation.sender_id == user_id, Conversation.recipient_id == user_id)
    ).all()

    support_conversations = SupportConversation.query.filter(
        or_(SupportConversation.enquiry_id == user_id,
            SupportConversation.feedback_id == user_id)
    ).all()

    return render_template('user_inbox.html', product_conversations=product_conversations,
                           support_conversations=support_conversations)


@app.route('/staff_inbox')
def staff_inbox():
    if 'staff_id' not in session:
        flash('Please log in to view the inbox.', 'danger')
        return redirect(url_for('staff_login'))

    support_conversations = SupportConversation.query.all()
    return render_template('staff_inbox.html', support_conversations=support_conversations)


@app.route('/user_products', methods=['GET', 'POST'])
def user_products():
    all_products = NewProducts.query.all()
    return render_template('user_products.html', products=all_products)

@app.route('/user_purchase_history')
def user_purchase_history():
    if 'user_id' not in session:
        flash('Please log in to view your purchase history.', 'info')
        return redirect(url_for('user_login'))
    user_purchases = Purchase.query.filter_by(user_id=session['user_id']).all()
    return render_template('user_purchase_history.html', purchases=user_purchases)

@app.route('/user_about_us', methods=['GET', 'POST'])
def user_about_us():
    return render_template('user_about_us.html')

@app.route('/staff_sign_up', methods=['GET', 'POST'])
def staff_sign_up():
    form = StaffSignUpForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        invitation_code = form.invitation_code.data.strip()

        invitation = StaffInvitationCode.query.filter_by(email=email, invitation_code=invitation_code).first()
        if not invitation:
            flash('Invalid invitation code.', 'danger')
            return render_template('staff_sign_up.html', form=form)

        existing_staff = Staff.query.filter_by(email=email).first()
        if existing_staff:
            flash('An account with this email already exists.', 'danger')
            return render_template('staff_sign_up.html', form=form)

        new_staff = Staff(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=email
        )
        new_staff.set_password(form.password.data)
        db.session.add(new_staff)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('staff_login'))
    return render_template('staff_sign_up.html', form=form)


@app.route('/staff_login', methods=['GET', 'POST'])
def staff_login():
    form = StaffLoginForm()
    if form.validate_on_submit():
        staff = Staff.query.filter_by(email=form.email.data).first()
        if staff and staff.check_password(form.password.data):
            session['staff_id'] = staff.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('staff_account'))
        else:
            flash('Invalid login credentials.', 'danger')
    return render_template('staff_login.html', form=form)


@app.route('/staff_account', methods=['GET', 'POST'])
def staff_account():
    return render_template('staff_account.html')


@app.route('/staff_account_information', methods=['GET', 'POST'])
def staff_account_information():
    if 'staff_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('staff_login'))
    staff = Staff.query.get_or_404(session['staff_id'])
    form = StaffEditForm(obj=staff)
    if form.validate_on_submit():
        staff.first_name = form.first_name.data
        staff.last_name = form.last_name.data
        staff.email = form.email.data
        db.session.commit()
        flash('Your account information has been updated.', 'success')
        return redirect(url_for('staff_account_information'))
    return render_template('staff_account_information.html', form=form, staff=staff)


@app.route('/staff_edit', methods=['GET', 'POST'])
def staff_edit():
    if 'staff_id' not in session:
        flash('Please log in as staff to access this page.', 'danger')
        return redirect(url_for('staff_login'))

    staff = Staff.query.get_or_404(session['staff_id'])
    form = StaffEditForm(obj=staff)
    if form.validate_on_submit():
        staff.first_name = form.first_name.data
        staff.last_name = form.last_name.data
        staff.email = form.email.data
        db.session.commit()
        flash('Account updated successfully.', 'success')
        return redirect(url_for('staff_account_information'))
    return render_template('staff_edit.html', form=form)


@app.route('/staff_products')
def staff_products():
    all_products = NewProducts.query.all()
    return render_template('staff_products.html', products=all_products)


@app.route('/staff_add_product', methods=['GET', 'POST'])
def staff_add_product():
    form = StaffAddProductForm()
    if form.validate_on_submit():
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            new_product = NewProducts(
                name=form.name.data,
                price=form.price.data,
                stock=form.stock.data,
                category=form.category.data,
                brand=form.brand.data,
                description=form.description.data,
                image=filename
            )
            stripe_product = stripe.Product.create(name=form.name.data)
            stripe_price = stripe.Price.create(
                product=stripe_product.id,
                unit_amount=int(form.price.data * 100),
                currency='usd',
            )
            new_product.stripe_product_id = stripe_product.id
            db.session.add(new_product)
            db.session.commit()
            flash('New product added successfully!', 'success')
            return redirect(url_for('staff_products'))
    return render_template('staff_add_product.html', form=form)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}


@app.route('/staff_support', methods=['GET', 'POST'])
def staff_support():
    enquiries = Enquiry.query.all()
    feedback_data = Feedback.query.all()
    return render_template('staff_support.html', enquiries=enquiries, feedback_data=feedback_data)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = NewProducts.query.get_or_404(product_id)
    reviews = Review.query.filter_by(product_id=product_id).all()
    user_id = session.get('user_id')
    purchased = False
    if user_id:
        purchased = Purchase.query.filter_by(user_id=user_id, product_name=product.name).first() is not None
    return render_template('user_product_detail.html', product=product, reviews=reviews, purchased=purchased)


@app.route('/product/<int:product_id>/review', methods=['POST'])
def submit_review(product_id):
    if 'user_id' not in session:
        flash('Please log in to submit a review.', 'warning')
        return redirect(url_for('user_login'))

    user_id = session.get('user_id')
    purchased = Purchase.query.filter_by(user_id=user_id, product_name=NewProducts.query.get(product_id).name).first()
    if not purchased:
        flash('You must purchase the product before leaving a review.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    rating = request.form.get('rating')
    comment = request.form.get('message')
    if not comment:
        flash('Review message cannot be empty.', 'warning')
        return redirect(url_for('product_detail', product_id=product_id))

    review = Review(product_id=product_id, user_id=user_id, rating=rating, comment=comment)
    db.session.add(review)
    db.session.commit()
    flash('Review submitted successfully!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))


@app.route('/add_stock/<int:product_id>', methods=['POST'])
def add_stock(product_id):
    product = NewProducts.query.get_or_404(product_id)
    quantity = request.form.get('quantity', type=int)
    product.stock += quantity
    db.session.commit()
    flash(f'{quantity} units added to stock of {product.name}.', 'success')
    return redirect(url_for('staff_products'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}
    quantity = request.form.get('quantity', 1, type=int)
    cart = session['cart']
    product_id_str = str(product_id)
    cart[product_id_str] = cart.get(product_id_str, 0) + quantity
    session['cart'] = cart
    flash('Product added to cart.')
    return redirect(url_for('user_products'))


@app.route('/cart')
def cart():
    if 'cart' not in session or not session['cart']:
        return render_template('user_cart.html', cart_items=None, total_price=0, empty_cart=True)
    cart_items = []
    total_price = 0
    for product_id, quantity in session['cart'].items():
        product = NewProducts.query.get(product_id)
        if product:
            total_price += product.price * quantity
            cart_items.append({'product': product, 'quantity': quantity})
    return render_template('user_cart.html', cart_items=cart_items, total_price=total_price, empty_cart=False)


@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'cart' not in session or str(product_id) not in session['cart']:
        flash('Product not in cart', 'danger')
        return redirect(url_for('cart'))
    session['cart'].pop(str(product_id), None)
    flash('Product removed from cart', 'success')
    return redirect(url_for('cart'))


@app.context_processor
def cart_context():
    cart = session.get('cart', {})
    total_items = sum(cart.values())
    return {'total_items': total_items}


@app.route('/create_individual_checkout_session/<int:product_id>', methods=['POST'])
def create_individual_checkout_session(product_id):
    product = NewProducts.query.get_or_404(product_id)
    stripe_price = stripe.Price.list(product=product.stripe_product_id, limit=1).data[0]
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': stripe_price.id,
            'quantity': 1,
        }],
        mode='payment',
        shipping_address_collection={
            'allowed_countries': ["AU", "AT", "BE", "BR", "BG", "CA", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
                                  "GH", "GI", "GR", "HK", "HU", "IN", "ID", "IE", "IT", "JP", "KE", "LV", "LI", "LT",
                                  "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PL", "PT", "RO", "SG", "SK", "SI",
                                  "ZA", "ES", "SE", "CH", "TH", "AE", "GB", "US"]
        },
        success_url=url_for('checkout_success', _external=True),
        cancel_url=url_for('cart', _external=True),
    )
    return redirect(checkout_session.url, code=303)


@app.route('/create_bulk_checkout_session', methods=['POST'])
def create_bulk_checkout_session():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty', 'error')
        return redirect(url_for('user_products'))

    line_items = []
    for product_id_str, quantity in session['cart'].items():
        product_id = int(product_id_str)
        product = NewProducts.query.get(product_id)
        if not product:
            flash(f'Product with id {product_id} not found.', 'error')
            continue

        stripe_price = stripe.Price.list(product=product.stripe_product_id, limit=1).data[0]
        line_item = {
            'price': stripe_price.id,
            'quantity': quantity,
        }
        line_items.append(line_item)

    if not line_items:
        flash('There are no valid products to checkout.', 'error')
        return redirect(url_for('cart'))

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=line_items,
        mode='payment',
        shipping_address_collection={
            'allowed_countries': ["AU", "AT", "BE", "BR", "BG", "CA", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
                                  "GH", "GI", "GR", "HK", "HU", "IN", "ID", "IE", "IT", "JP", "KE", "LV", "LI", "LT",
                                  "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PL", "PT", "RO", "SG", "SK", "SI",
                                  "ZA", "ES", "SE", "CH", "TH", "AE", "GB", "US"]
        },
        success_url=url_for('checkout_success', _external=True),
        cancel_url=url_for('cart', _external=True),
    )
    return redirect(checkout_session.url, code=303)

@app.route('/checkout_success')
def checkout_success():
    if 'cart' in session and 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        purchases_details = []

        for product_id_str, quantity in session['cart'].items():
            product = NewProducts.query.get(int(product_id_str))
            if product:
                new_purchase = Purchase(
                    user_id=user_id,
                    product_name=product.name,
                    brand=product.brand,
                    price=product.price,
                    quantity=quantity,
                    total_amount=product.price * quantity
                )
                db.session.add(new_purchase)
                purchases_details.append(f"{product.name} - Quantity: {quantity}, Total: ${product.price * quantity}")

                if product.stock >= quantity:
                    product.stock -= quantity
                else:
                    flash(f'Insufficient stock for {product.name}', 'error')

        db.session.commit()
        session.pop('cart', None)
        flash('Checkout successful. Thank you for your purchase!', 'success')

        if purchases_details:
            email_body = f"Dear {user.first_name},\n\n" \
                         f"Thank you for your purchase. Here are the details of your purchase:\n" + \
                         "\n".join(purchases_details) + \
                         "\n\nBest regards,\nOnlyGreenThings Team"
            send_email(user.email, "Your Purchase Details", email_body)

    else:
        flash('No active cart or user session', 'error')

    return redirect(url_for('user_purchase_history'))

GPT_MODEL = "gpt-3.5-turbo-1106"


@app.route("/chatbot", methods=["GET", "POST"])
def chatbot():
    user_input = ""
    bot_response = ""
    if request.method == "POST":
        user_input = request.form["message"]
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input},
        ]
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=messages,
            temperature=0.7,
            max_tokens=60,
            top_p=1,
            frequency_penalty=0,
            stop=["\nUser: ", "\nChatbot:"]
        )
        bot_response = response.choices[0].message.content.strip()
    return render_template(
        "chatbot.html",
        user_input=user_input,
        bot_response=bot_response,
    )


@app.route('/user_support', methods=['GET', 'POST'])
def user_support():
    return render_template('user_support_landing.html')


@app.route('/user_support_enquiries')
def user_support_enquiries():
    enquiries = Enquiry.query.all()
    return render_template('user_support_enquiries.html', enquiries=enquiries)


@app.route('/user_support_create_enquiries', methods=['POST'])
def user_support_create_enquiries():
    name = request.form.get('name')
    phone_number = request.form.get('phone_number')
    email = request.form.get('email')
    message = request.form.get('message')
    enquiry = Enquiry(name=name, phone_number=phone_number, email=email, message=message)
    db.session.add(enquiry)
    db.session.commit()
    flash('Enquiry created successfully!', 'success')
    return redirect(url_for('user_support_enquiries'))


@app.route('/user_support_read_enquiries')
def user_support_read_enquiries():
    with app.app_context():
        enquiries = Enquiry.query.all()
    return render_template('user_support_enquiries.html', enquiries=enquiries)


@app.route('/user_support_update_enquiries/<int:id>', methods=['GET', 'POST'])
def user_support_update_enquiries(id):
    enquiry = Enquiry.query.get_or_404(id)
    if request.method == 'POST':
        enquiry.name = request.form.get('name')
        enquiry.phone_number = request.form.get('phone_number')
        enquiry.email = request.form.get('email')
        enquiry.message = request.form.get('message')
        db.session.commit()
        flash('Enquiry updated successfully!', 'success')
        return redirect(url_for('user_support_enquiries'))
    return render_template('user_support_update_enquiries.html', enquiry=enquiry)


@app.route('/user_support_delete_enquiries/<int:id>')
def user_support_delete_enquiries(id):
    enquiry = Enquiry.query.get_or_404(id)
    db.session.delete(enquiry)
    db.session.commit()
    flash('Enquiry deleted successfully!', 'success')
    return redirect(url_for('user_support_enquiries'))


@app.route('/user_support_feedback', methods=['GET', 'POST'])
def user_support_feedback():
    feedback_data = Feedback.query.all()
    return render_template('user_support_feedback.html', feedback_data=feedback_data)


@app.route('/user_feedback_read_feedback')
def index():
    feedback_data = Feedback.query.all()
    return render_template('user_support_enquiries.html', feedback_data=feedback_data)


@app.route('/user_support_create_feedback', methods=['GET', 'POST'])
def user_support_create_feedback():
    if request.method == 'POST':
        rating = int(request.form['rating'])
        message = request.form['message']
        new_feedback = Feedback(rating=rating, message=message)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
    return render_template('user_support_feedback.html', feedback_data=Feedback.query.all())


@app.route('/user_support_update_feedback/<int:feedback_id>', methods=['GET', 'POST'])
def user_support_update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if request.method == 'POST':
        feedback.rating = int(request.form.get('updated_rating'))
        feedback.message = request.form.get('updated_message')
        db.session.commit()
        flash('Feedback updated successfully!', 'success')
        return redirect(url_for('user_support_feedback'))
    return render_template('user_support_update_feedback.html', feedback=feedback)


@app.route('/user_support_delete_feedback/<int:feedback_id>')
def user_support_delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback deleted successfully!', 'success')
    return redirect(url_for('user_support_feedback'))


@app.route('/quiz')
def show_quiz():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to access the quiz.', 'warning')
        return redirect(url_for('user_login'))
    answered_questions = UserQuizAttempt.query.filter_by(user_id=user_id).with_entities(
        UserQuizAttempt.quiz_question_id)
    question = QuizQuestion.query.filter(~QuizQuestion.id.in_(answered_questions)).order_by(func.random()).first()
    if question:
        options = json.loads(question.options)
        return render_template('user_quiz.html', question=question, options=options)
    else:
        flash('You have answered all available questions. Check back later for more.', 'info')
        return redirect(url_for('user_account'))


@app.route('/quiz/answer', methods=['POST'])
def answer_quiz():
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to be logged in to submit an answer.", "danger")
        return redirect(url_for('user_login'))

    question_id = request.form.get('question_id')
    selected_option_text = request.form.get('option')
    question = QuizQuestion.query.get_or_404(question_id)

    is_correct = selected_option_text == question.correct_option
    if is_correct:
        points_awarded = 2
        user = User.query.get(user_id)
        user.points += points_awarded
        db.session.commit()
        flash(f"Correct! You've earned {points_awarded} points.", "success")
    else:
        flash("Incorrect. Try again!", "danger")

    new_attempt = UserQuizAttempt(
        user_id=user_id,
        quiz_question_id=question.id,
        selected_option=selected_option_text,
        is_correct=is_correct
    )
    db.session.add(new_attempt)
    db.session.commit()

    options = json.loads(question.options)
    selected_option_index = options.index(selected_option_text) + 1 if selected_option_text in options else None
    correct_option_index = options.index(question.correct_option) + 1 if question.correct_option in options else None

    return render_template('user_quiz_answer.html',
                           is_correct=is_correct,
                           selected_option_text=selected_option_text,
                           correct_option_text=question.correct_option,
                           selected_option_index=selected_option_index,
                           correct_option_index=correct_option_index)


def load_quiz_questions():
    with open('quiz_questions.txt', 'r') as file:
        for line in file:
            question, options, correct_option = line.strip().split('|')
            options = json.dumps(options.split(','))
            new_question = QuizQuestion(question=question, options=options, correct_option=correct_option)
            db.session.add(new_question)
        db.session.commit()


@app.route('/give', methods=['GET', 'POST'])
def show_offers():
    user_id = session.get('user_id')
    if 'user_id' not in session:
        flash('Please log in to view this page.', 'warning')
        return redirect(url_for('user_login'))
    offers = CharitableOffer.query.all()
    user = User.query.get(user_id)
    return render_template('user_give.html', offers=offers, user=user)


@app.route('/give/donate/<int:offer_id>', methods=['GET', 'POST'])
def donate(offer_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to donate.', 'warning')
        return redirect(url_for('user_login'))
    offer = CharitableOffer.query.get_or_404(offer_id)
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        if user.points >= offer.points_required:
            user.points -= offer.points_required
            db.session.commit()
            send_donation_confirmation_email(user.email, offer)
            flash('Donation successful! Confirmation has been sent to your email.', 'success')
            return redirect(url_for('show_offers'))
        else:
            flash('You do not have enough points to make this donation.', 'danger')

    return render_template('user_confirm_donation.html', offer=offer, user=user)


@app.route('/send_donation_confirmation_email/<int:offer_id>', methods=['POST'])
def send_donation_confirmation_email(offer_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to donate.', 'warning')
        return redirect(url_for('user_login'))

    user = User.query.get_or_404(user_id)
    offer = CharitableOffer.query.get_or_404(offer_id)

    if user.points >= offer.points_required:
        user.points -= offer.points_required
        db.session.commit()

        subject = "Thank You for Your Donation"
        body = (f"Dear {user.first_name},\n\n"
                f"Thank you for donating {offer.points_required} points to {offer.organization_name}. "
                f"Your generous contribution will help to {offer.offer_description}.\n\n"
                "Best regards,\n"
                "OnlyGreenThings Team")

        send_email(user.email, subject, body)

        flash('Donation successful. A confirmation email has been sent!', 'success')
    else:
        flash('Insufficient points for this donation.', 'danger')

    return redirect(url_for('show_offers'))


def populate_charitable_offers():
    if CharitableOffer.query.first() is None:
        with open('charitable_offers.txt', 'r') as file:
            for line in file:
                organization_name, offer_description, points_required = line.strip().split(
                    '|')
                offer = CharitableOffer(organization_name=organization_name, offer_description=offer_description,
                                        points_required=int(points_required))
                db.session.add(offer)
            db.session.commit()

def load_staff_invitation_codes():
    with open('staff_verification.txt', 'r') as file:
        for line in file:
            email, invitation_code = line.strip().split(',')
            email = email.strip()
            invitation_code = invitation_code.strip()
            if not StaffInvitationCode.query.filter_by(email=email).first():
                new_code = StaffInvitationCode(email=email, invitation_code=invitation_code)
                db.session.add(new_code)
        db.session.commit()

# Start Shahbaz
@app.route('/shahbaz', methods=['GET', 'POST'])
def shahbaz():
    return render_template('productreview.html')
class CreateUserForm(Form):
    user_name = StringField('User Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    phone_number = StringField('Phone Number', [validators.Regexp('^\d{10}$', message="Invalid phone number"), validators.DataRequired()])
    remarks = TextAreaField('Product Review', [validators.DataRequired()])

@app.route('/s_submit_review', methods=['GET', 'POST'])
def s_submit_review():
    create_user_form = CreateUserForm(request.form)

    if request.method == 'POST' and create_user_form.validate():
        user = User(create_user_form.user_name.data, create_user_form.email.data,
                    create_user_form.phone_number.data, create_user_form.remarks.data)

        with shelve.open('product_reviews.db', 'c') as db:
            try:
                reviews_dict = db.get('Reviews', {})
                reviews_dict[user.get_user_id()] = user
                db['Reviews'] = reviews_dict
            except Exception as e:
                print("Error:", e)

        return redirect(url_for('home'))

    return render_template('productreview.html', form=create_user_form)


@app.route('/retrieveReviews')
def retrieve_reviews():
    with shelve.open('product_reviews.db', 'r') as db:
        reviews_dict = db.get('Reviews', {})

    reviews_list = list(reviews_dict.values())

    return render_template('productreview.html', count=len(reviews_list), reviews_list=reviews_list)
# End Shahbaz

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        populate_charitable_offers()
        load_quiz_questions()
        load_staff_invitation_codes()
    app.run(debug=True)
