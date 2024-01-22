from flask import Flask, render_template, redirect, url_for, flash, session, request, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from openai import OpenAI
import openai
import os
import io
import stripe
from dotenv import load_dotenv
from datetime import datetime
import smtplib

#evan's
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
    'feedback': 'sqlite:///feedback.db'}
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db.init_app(app)

stripe.api_key = "sk_test_51OX2l5HNT2ZiDcKekb6Rcip8rncZsq0zwNKzztoyVXBApFS0r7ui9LpW6fnc6xhIOyALoB8iYHuhHHgxgF8mlKze002JRh6Cje"

class User(db.Model):
    __bind__key__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    sent_messages = db.relationship('Message',
                                    primaryjoin="foreign(Message.sender_id) == User.id",
                                    backref='sender',
                                    lazy='dynamic')
    conversations = db.relationship('Conversation',
                                    primaryjoin="or_(foreign(Conversation.sender_id) == User.id, foreign(Conversation.recipient_id) == User.id)",
                                    backref='user',
                                    lazy=True)
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

class NewProducts(db.Model):
    __bind__key__ = 'products'
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
    __bind__key__ = 'used'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    lister_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Foreign key to User table
    lister = db.relationship('User', backref='used_products')  # Relationship to User model
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(300))
    description = db.Column(db.String, nullable=False)
class Conversation(db.Model):
    __bind_key__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_id = db.Column(db.Integer)
    sender_id = db.Column(db.Integer)
    recipient_id = db.Column(db.Integer)
    messages = db.relationship('Message', backref='conversation', lazy=True)
class Message(db.Model):
    __bind_key__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))  # ForeignKey to Conversation table
    sender_id = db.Column(db.Integer)  # You might want to have a ForeignKey to User table here as well
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_name = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('purchases', lazy=True))
    def __repr__(self):
        return f'<Purchase {self.id}>'

class UserSignUpForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
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
    category = StringField('Brand', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Add')

class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')
class StaffSignUpForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
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
    category = StringField('Category', validators=[DataRequired()])
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

#shared routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login_landing')
def login_landing():
    return render_template('login_landing.html')

@app.route('/sign_up_landing')
def sign_up_landing():
    return render_template('sign_up_landing.html')

@app.route('/logout', methods=['GET','POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

#user routes
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
        flash('You have successfully registered!', 'success')
        return redirect(url_for('user_login'))

    return render_template('user_sign_up.html', form=form)

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
    return render_template('user_account.html')

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


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('reset_password'))

        user.set_password(form.new_password.data)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('user_login'))
    return render_template('forgot_password.html', form=form)


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
            description=form.description.data,
            image=filename  # Save the filename
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
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('user_login'))
    used_product = UsedProducts.query.get_or_404(product_id)
    if session['user_id'] != used_product.lister_id:
        flash('You are not authorized to edit this product.', 'danger')
        return redirect(url_for('user_used_listings'))
    form = UserAddUsed(obj=used_product)
    if form.validate_on_submit():
        used_product.name = form.name.data
        used_product.price = form.price.data
        used_product.category = form.category.data
        used_product.description = form.description.data
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('user_used_listings'))
    return render_template('user_used_edit.html', form=form)


@app.route('/start_conversation/<int:product_id>/<int:recipient_id>', methods=['GET', 'POST'])
def start_conversation(product_id, recipient_id):
    if 'user_id' not in session:
        flash('Please log in to start a conversation.', 'danger')
        return redirect(url_for('user_login'))
    sender_id = session['user_id']
    if sender_id == recipient_id:
        flash('You cannot start a conversation with yourself.', 'danger')
        return redirect(url_for('home'))
    # Check if a conversation between these users on this product already exists
    existing_conversation = Conversation.query.filter_by(product_id=product_id, sender_id=sender_id,
                                                         recipient_id=recipient_id).first()
    if existing_conversation:
        return redirect(url_for('view_conversation', conversation_id=existing_conversation.id))
    new_conversation = Conversation(product_id=product_id, sender_id=sender_id, recipient_id=recipient_id)
    db.session.add(new_conversation)
    db.session.commit()
    flash('Conversation started!', 'success')
    return redirect(url_for('view_conversation', conversation_id=new_conversation.id))

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


@app.route('/user_inbox')
def user_inbox():
    if 'user_id' not in session:
        flash('Please log in to view your inbox.', 'danger')
        return redirect(url_for('user_login'))
    user_id = session['user_id']
    conversations = Conversation.query.filter(
        (Conversation.sender_id == user_id) | (Conversation.recipient_id == user_id)
    ).all()
    # Create a list of conversation summaries
    conversations_summary = []
    for convo in conversations:
        other_user_id = convo.recipient_id if convo.sender_id == user_id else convo.sender_id
        other_user = User.query.get(other_user_id)
        product = UsedProducts.query.get(convo.product_id)
        conversations_summary.append({
            "conversation_id": convo.id,
            "other_user": other_user.username,
            "product_name": product.name
        })
    return render_template('user_inbox.html', conversations=conversations_summary)


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


@app.route('/user_confirm_logout')
def user_confirm_logout():
    return render_template('user_confirm_logout.html')

@app.route('/user_about_us', methods=['GET', 'POST'])
def user_about_us():
    return render_template('user_about_us.html')

#staff routes
@app.route('/staff_sign_up', methods=['GET', 'POST'])
def staff_sign_up():
    form = StaffSignUpForm()
    if form.validate_on_submit():
        staff = Staff.query.filter_by(email=form.email.data).first()
        if staff:
            flash('Email already taken, please try another one.', 'danger')
            return redirect(url_for('staff_sign_up'))
        new_staff = Staff(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data
        )
        new_staff.set_password(form.password.data)
        db.session.add(new_staff)
        db.session.commit()
        flash('You have successfully registered!', 'success')
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
                image=filename  # Store just the filename
            )
            # Create Stripe product and save its ID
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
    return render_template('staff_support.html')

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    product = NewProducts.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('staff_products'))

@app.route('/add_stock/<int:product_id>', methods=['POST'])
def add_stock(product_id):
    product = NewProducts.query.get_or_404(product_id)
    quantity = request.form.get('quantity', type=int)
    product.stock += quantity
    db.session.commit()
    flash(f'{quantity} units added to stock of {product.name}.', 'success')
    return redirect(url_for('staff_products'))

@app.route('/staff_confirm_logout')
def staff_confirm_logout():
    return render_template('staff_confirm_logout.html')

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}

    quantity = request.form.get('quantity', 1, type=int)
    cart = session['cart']

    # Convert product_id to string for consistent key handling
    product_id_str = str(product_id)

    cart[product_id_str] = cart.get(product_id_str, 0) + quantity
    session['cart'] = cart

    flash('Product added to cart.')
    return redirect(url_for('user_products'))

@app.route('/cart')
def cart():
    if 'cart' not in session or not session['cart']:
        # Display a message when the cart is empty
        return render_template('cart.html', cart_items=None, total_price=0, empty_cart=True)

    cart_items = []
    total_price = 0
    for product_id, quantity in session['cart'].items():
        product = NewProducts.query.get(product_id)
        if product:
            total_price += product.price * quantity
            cart_items.append({'product': product, 'quantity': quantity})

    return render_template('cart.html', cart_items=cart_items, total_price=total_price, empty_cart=False)


@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'cart' not in session or str(product_id) not in session['cart']:
        flash('Product not in cart', 'danger')
        return redirect(url_for('cart'))

    session['cart'].pop(str(product_id), None)

    flash('Product removed from cart', 'success')
    return redirect(url_for('cart'))

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
            'allowed_countries': ["AU", "AT", "BE", "BR", "BG", "CA", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GH", "GI", "GR", "HK", "HU", "IN", "ID", "IE", "IT", "JP", "KE", "LV", "LI", "LT", "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PL", "PT", "RO", "SG", "SK", "SI", "ZA", "ES", "SE", "CH", "TH", "AE", "GB", "US"]
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
            'allowed_countries': ["AU", "AT", "BE", "BR", "BG", "CA", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GH", "GI", "GR", "HK", "HU", "IN", "ID", "IE", "IT", "JP", "KE", "LV", "LI", "LT", "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PL", "PT", "RO", "SG", "SK", "SI", "ZA", "ES", "SE", "CH", "TH", "AE", "GB", "US"]
        },
        success_url=url_for('checkout_success', _external=True),
        cancel_url=url_for('cart', _external=True),
    )
    return redirect(checkout_session.url, code=303)

@app.route('/checkout_success')
def checkout_success():
    if 'cart' in session and 'user_id' in session:
        for product_id_str, quantity in session['cart'].items():
            product = NewProducts.query.get(int(product_id_str))
            if product:
                # Create a Purchase record
                new_purchase = Purchase(
                    user_id=session['user_id'],
                    product_name=product.name,
                    brand=product.brand,
                    price=product.price,
                    quantity=quantity,
                    total_amount=product.price * quantity
                )
                db.session.add(new_purchase)
                # Optionally, you can also decrement the stock here
                if product.stock >= quantity:
                    product.stock -= quantity
                else:
                    flash(f'Insufficient stock for {product.name}', 'error')
                    # Handle the case where stock is insufficient
        db.session.commit()
        session.pop('cart', None)  # Clear the cart after purchase
        flash('Checkout successful. Thank you for your purchase!', 'success')
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


#sathiya's
class Enquiry(db.Model):
    __bind_key__ = "enquiry"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)

class Feedback(db.Model):
    __bind_key__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(255), nullable=False)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
