from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_mail import Mail, Message
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import stripe

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bloopypillows'

# Configure two different databases
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///user.db',
    'staff': 'sqlite:///staff.db',
    'used': 'sqlite:///used.db',
    'products': 'sqlite:///products.db'
}
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'onlygreenthings@gmail.com'
app.config['MAIL_PASSWORD'] = 'onlygreenthings123'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

db = SQLAlchemy(app)
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
    stripe_product_id = db.Column(db.String(200))

class UsedProducts(db.Model):
    __bind__key__ = 'used'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    lister_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Foreign key to User model
    lister = db.relationship('User', backref='used_products')  # Relationship to User model
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String, nullable=False)
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
    submit = SubmitField('Add')
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
        new_used_product = UsedProducts(
            lister_id=session.get('user_id'),  # Set lister_id to the current user's ID
            name=form.name.data,
            price=form.price.data,
            category=form.category.data,
            description=form.description.data
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

@app.route('/user_products', methods=['GET', 'POST'])
def user_products():
    all_products = NewProducts.query.all()
    return render_template('user_products.html', products=all_products)

@app.route('/user_confirm_logout')
def user_confirm_logout():
    return render_template('user_confirm_logout.html')

@app.route('/user_support', methods=['GET', 'POST'])
def user_support():
    return render_template('user_support.html')

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
    return render_template('user_account_information.html', form=form, user=staff)

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
    return render_template('staff_products.html')

@app.route('/staff_add_product', methods=['GET', 'POST'])
def staff_add_product():
    form = StaffAddProductForm()
    if form.validate_on_submit():
        new_product = NewProducts(
            name=form.name.data,
            price=form.price.data,
            stock=form.stock.data,
            category=form.category.data,
            brand=form.brand.data,
            description=form.description.data
        )
        # Create Stripe product and save its ID
        stripe_product = stripe.Product.create(name=form.name.data)
        stripe_price = stripe.Price.create(
            product=stripe_product.id,
            unit_amount=int(form.price.data * 100),
            currency='usd',
        )
        new_product.stripe_product_id = stripe_product.id  # Now this should work
        db.session.add(new_product)
        db.session.commit()

        flash('New product added successfully!', 'success')
        return redirect(url_for('staff_products'))
    return render_template('staff_add_product.html', form=form)


@app.route('/staff_support', methods=['GET', 'POST'])
def staff_support():
    return render_template('staff_support.html')

@app.route('/staff_about_us', methods=['GET', 'POST'])
def staff_about_us():
    return render_template('staff_about_us.html')

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
        flash('Your cart is empty.', 'info')
        return redirect(url_for('user_products'))

    cart_items = []
    total_price = 0
    for product_id, quantity in session['cart'].items():
        product = NewProducts.query.get(product_id)
        if product:
            total_price += product.price * quantity
            cart_items.append({'product': product, 'quantity': quantity})

    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'cart' not in session or product_id not in session['cart']:
        flash('Product not in cart', 'danger')
        return redirect(url_for('cart'))

    # Decrease the quantity or remove the product if quantity is 1
    if session['cart'][product_id] > 1:
        session['cart'][product_id] -= 1
    else:
        session['cart'].pop(product_id)

    flash('Product removed from cart', 'success')
    return redirect(url_for('cart'))

@app.route('/create-bulk-checkout-session', methods=['POST'])
def create_bulk_checkout_session():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty', 'error')
        return redirect(url_for('user_products'))
    line_items = []
    for product_id, quantity in session['cart'].items():
        product = NewProducts.query.get(product_id)
        stripe_price = stripe.Price.list(product=product.stripe_product_id, limit=1).data[0]
        line_items.append({
            'price': stripe_price.id,
            'quantity': quantity,
        })
    customer_email = request.form.get('email')  # Assuming you're getting this from the form
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=line_items,
        mode='payment',
        customer_email=customer_email,
        success_url=url_for('checkout', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('cart', _external=True),
    )
    return redirect(checkout_session.url, code=303)


def send_invoice_pdf(email, file_path):
    msg = Message('Your Invoice', sender='onlygreenthings.ogt@example.com', recipients=[email])
    msg.body = "Here is your invoice."

    # Generate PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, "Invoice for your recent purchase")
    p.save()

    # Attach PDF
    buffer.seek(0)
    msg.attach("invoice.pdf", "application/pdf", buffer.read())

    mail.send(msg)

@app.route('/checkout')
def checkout():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty.', 'info')
        return redirect(url_for('user_products'))

    cart_items = []
    total_price = 0
    for product_id, quantity in session['cart'].items():
        product = NewProducts.query.get(product_id)
        total_price += product.price * quantity
        cart_items.append({'product': product, 'quantity': quantity})
    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create tables for all binds
    app.run(debug=True)
