from flask import Flask, render_template, g, redirect, url_for, request, flash, session, abort, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from functools import wraps
import urllib.parse
from werkzeug.utils import secure_filename
import secrets
import sib_api_v3_sdk

# Initialize Flask app
app = Flask(__name__)

# Load environment variables for configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_development_only')
app.config['BREVO_API_KEY'] = os.environ.get('BREVO_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com') # Fallback default sender

# Database configuration
DATABASE = 'database.db'

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password, is_admin=0, is_delivery_boy=0, email=None, reset_token=None, reset_token_expires_at=None):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = bool(is_admin)
        self.is_delivery_boy = bool(is_delivery_boy)
        self.email = email
        self.reset_token = reset_token
        self.reset_token_expires_at = reset_token_expires_at

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get(user_id):
        db = get_db()
        user_data = db.execute('SELECT id, username, password, is_admin, is_delivery_boy, email, reset_token, reset_token_expires_at FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'], user_data['is_admin'], user_data['is_delivery_boy'], user_data['email'], user_data['reset_token'], user_data['reset_token_expires_at'])
        return None

    @staticmethod
    def get_by_username(username):
        db = get_db()
        user_data = db.execute('SELECT id, username, password, is_admin, is_delivery_boy, email, reset_token, reset_token_expires_at FROM users WHERE username = ?', (username,)).fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'], user_data['is_admin'], user_data['is_delivery_boy'], user_data['email'], user_data['reset_token'], user_data['reset_token_expires_at'])
        return None

    @staticmethod
    def get_by_email(email):
        db = get_db()
        user_data = db.execute('SELECT id, username, password, is_admin, is_delivery_boy, email, reset_token, reset_token_expires_at FROM users WHERE email = ?', (email,)).fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'], user_data['is_admin'], user_data['is_delivery_boy'], user_data['email'], user_data['reset_token'], user_data['reset_token_expires_at'])
        return None

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Decorator to restrict access to admin users
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Decorator to restrict access to customers
def customer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if current_user.is_admin:
            flash('Admin accounts cannot access customer features.', 'info')
            return redirect(url_for('admin_dashboard'))
        if current_user.is_delivery_boy:
            flash('Delivery accounts cannot access customer features.', 'info')
            return redirect(url_for('delivery_boy_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to restrict access to delivery boys
def delivery_boy_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if not current_user.is_delivery_boy:
            if current_user.is_admin:
                flash('Admin accounts cannot access delivery boy features.', 'info')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('You do not have permission to access this page. Only delivery boys can access this.', 'danger')
                abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Database connection helper function
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

# Close database connection at the end of the request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Initialize the database and tables
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Read schema from schema.sql
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()

        # Check and add missing columns to the users table for password reset
        cursor.execute("PRAGMA table_info(users);")
        user_columns = [col[1] for col in cursor.fetchall()]

        if 'email' not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT;")
            db.execute("UPDATE users SET email = username || '@example.com' WHERE email IS NULL;")
            try:
                db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);")
                print("Added 'email' column and unique constraint to users table.")
            except sqlite3.IntegrityError:
                print("Warning: Could not add unique constraint to 'email' column due to existing duplicate values.")
                print("Please manually clean up duplicate emails in 'users' table if needed.")

        if 'reset_token' not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN reset_token TEXT;")
            print("Added 'reset_token' column to users table.")
        if 'reset_token_expires_at' not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN reset_token_expires_at TEXT;")
            print("Added 'reset_token_expires_at' column to users table.")
        db.commit()

        # Create or update default admin user
        ADMIN_DEFAULT_PASSWORD = "Clickorder0505"
        hashed_password_for_admin = generate_password_hash(ADMIN_DEFAULT_PASSWORD, method='pbkdf2:sha256')

        cursor = db.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()

        if not cursor:
            db.execute("INSERT INTO users (username, password, is_admin, is_delivery_boy, email) VALUES (?, ?, ?, ?, ?)", ('admin', hashed_password_for_admin, 1, 0, 'admin@example.com'))
        elif not cursor['is_admin'] or not cursor['email'] or not check_password_hash(cursor['password'], ADMIN_DEFAULT_PASSWORD):
            update_query = "UPDATE users SET is_admin = 1"
            params = []
            if not cursor['email']:
                update_query += ", email = ?"
                params.append('admin@example.com')
            
            if not check_password_hash(cursor['password'], ADMIN_DEFAULT_PASSWORD):
                update_query += ", password = ?"
                params.append(hashed_password_for_admin)

            update_query += " WHERE username = 'admin'"
            db.execute(update_query, params)
        db.commit()
        print("Database initialization complete.")

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create a notification in the database
def create_notification(user_id, message, order_id=None):
    with app.app_context():
        db = get_db()
        link_url = url_for('order_detail', order_id=order_id) if order_id else '#'
        db.execute(
            'INSERT INTO notifications (user_id, message, link_url, timestamp) VALUES (?, ?, ?, ?)',
            (user_id, message, link_url, datetime.now())
        )
        db.commit()

# Send email using Brevo (formerly Sendinblue) API
def send_email(to_email, subject, body, html_body=None):
    api_key = app.config.get('BREVO_API_KEY')
    default_sender = app.config.get('MAIL_DEFAULT_SENDER')

    if not api_key or not default_sender:
        print("Brevo API key or default sender not configured.")
        return False
    
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = api_key
    
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
    
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"email": default_sender, "name": "CO Shopping"},
        subject=subject,
        html_content=html_body,
        text_content=body
    )

    try:
        api_response = api_instance.send_transac_email(send_smtp_email)
        print(f"Email sent successfully from {default_sender} to {to_email}.")
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

# Context processor to inject global variables into templates
@app.context_processor
def inject_globals():
    cart_count = 0
    is_admin = False
    is_delivery_boy = False
    unread_notification_count = 0
    if current_user.is_authenticated:
        db = get_db()
        cart_count_data = db.execute(
            'SELECT SUM(quantity) AS total_quantity FROM cart_items WHERE user_id = ?',
            (current_user.id,)
        ).fetchone()
        cart_count = cart_count_data['total_quantity'] if cart_count_data and cart_count_data['total_quantity'] else 0
        is_admin = current_user.is_admin
        is_delivery_boy = current_user.is_delivery_boy
        unread_count_data = db.execute(
            'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
            (current_user.id,)
        ).fetchone()
        unread_notification_count = unread_count_data[0] if unread_count_data else 0
    return dict(
        cart_item_count=cart_count,
        is_admin=is_admin,
        is_delivery_boy=is_delivery_boy,
        unread_notification_count=unread_notification_count
    )

# Home page route
@app.route('/')
def index():
    db = get_db()
    query = request.args.get('q')
    category = request.args.get('category')
    sql_query = 'SELECT * FROM products'
    params = []
    conditions = []
    if query:
        conditions.append('(name LIKE ? OR description LIKE ?)')
        params.extend([f'%{query}%', f'%{query}%'])
    if category and category != 'All':
        conditions.append('category = ?')
        params.append(category)
    if conditions:
        sql_query += ' WHERE ' + ' AND '.join(conditions)
    sql_query += ' ORDER BY id DESC'
    products = db.execute(sql_query, params).fetchall()
    categories = db.execute('SELECT DISTINCT category FROM products ORDER BY category').fetchall()
    category_list = [cat['category'] for cat in categories]
    category_list.insert(0, 'All')
    return render_template('index.html',
                           products=products,
                           search_query=query,
                           selected_category=category,
                           categories=category_list)

# Product detail page route
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if product is None:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
    return render_template('product_detail.html', product=product)

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_delivery_boy:
            return redirect(url_for('delivery_boy_dashboard'))
        else:
            return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        db = get_db()

        if not (5 <= len(username) <= 10):
            flash('Username must be between 5 and 10 characters long.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        existing_email = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.', 'warning')
        elif existing_email:
            flash('Email address is already registered. Please use a different one or log in.', 'warning')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            db.execute('INSERT INTO users (username, password, is_admin, is_delivery_boy, email) VALUES (?, ?, ?, ?, ?)', (username, hashed_password, 0, 0, email))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_delivery_boy:
            return redirect(url_for('delivery_boy_dashboard'))
        else:
            return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = User.get_by_username(username)

        if user_data and check_password_hash(user_data.password, password):
            user = User(user_data.id, user_data.username, user_data.password, user_data.is_admin, user_data.is_delivery_boy, user_data.email, user_data.reset_token, user_data.reset_token_expires_at)
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            if user.is_admin:
                return redirect(next_page or url_for('admin_dashboard'))
            elif user.is_delivery_boy:
                return redirect(next_page or url_for('delivery_boy_dashboard'))
            else:
                return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# User logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Add item to cart route
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@customer_required
def add_to_cart(product_id):
    user_id = current_user.id
    db = get_db()
    try:
        quantity = int(request.form.get('quantity', 1))
        if quantity < 1:
            flash('Quantity must be at least 1.', 'warning')
            return redirect(url_for('product_detail', product_id=product_id))
    except ValueError:
        flash('Invalid quantity provided.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    product = db.execute('SELECT id, name FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))

    cart_item = db.execute(
        'SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?',
        (user_id, product_id)
    ).fetchone()

    if cart_item:
        new_quantity = cart_item['quantity'] + quantity
        db.execute(
            'UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?',
            (new_quantity, user_id, product_id)
        )
        flash(f'{quantity} of "{product["name"]}" added. Total in cart: {new_quantity}!', 'success')
    else:
        db.execute(
            'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
            (user_id, product_id, quantity)
        )
        flash(f'"{product["name"]}" added to cart (Quantity: {quantity})!', 'success')
    db.commit()

    return redirect(url_for('product_detail', product_id=product_id))

# View shopping cart route
@app.route('/cart')
@customer_required
def view_cart():
    user_id = current_user.id
    db = get_db()
    cart_items = db.execute(
        '''SELECT ci.product_id AS id, p.name, p.price, ci.quantity, p.image_url
           FROM cart_items ci
           JOIN products p ON ci.product_id = p.id
           WHERE ci.user_id = ?''',
        (user_id,)
    ).fetchall()

    total_price = sum(item['price'] * item['quantity'] for item in cart_items)
    addresses = db.execute('SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, id DESC', (user_id,)).fetchall()

    return render_template('cart.html', cart_items=cart_items, total_price=total_price, addresses=addresses)

# Remove item from cart route
@app.route('/remove_from_cart/<int:product_id>')
@customer_required
def remove_from_cart(product_id):
    user_id = current_user.id
    db = get_db()
    db.execute(
        'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
        (user_id, product_id)
    )
    db.commit()
    flash('Item removed from cart.', 'info')
    return redirect(url_for('view_cart'))

# View addresses route
@app.route('/my_addresses')
@customer_required
def view_addresses():
    user_id = current_user.id
    db = get_db()
    addresses = db.execute('SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, id DESC', (user_id,)).fetchall()
    next_flow = request.args.get('next_flow')
    return render_template('view_addresses.html', addresses=addresses, next_flow=next_flow)


# Add new address route
@app.route('/add_address', methods=['GET', 'POST'])
@customer_required
def add_address():
    if request.method == 'POST':
        user_id = current_user.id
        full_name = request.form['full_name']
        phone_number = request.form.get('phone_number')
        address_line1 = request.form['address_line1']
        address_line2 = request.form.get('address_line2', '')
        zip_code = request.form['zip_code']
        city = request.form.get('city')
        state = request.form.get('state')
        country = request.form.get('country')
        is_default = 'is_default' in request.form

        if not phone_number or not phone_number.isdigit() or len(phone_number) != 10:
            flash('Please enter a valid 10-digit phone number.', 'danger')
            return redirect(url_for('add_address', next=request.args.get('next')))

        if not city or not state or not country:
            flash('Please enter a valid Zip Code and select a City/Area from the dropdown.', 'danger')
            return redirect(url_for('add_address', next=request.args.get('next')))

        db = get_db()
        allowed_pincodes_data = db.execute('SELECT pincode FROM approved_pincodes').fetchall()
        allowed_pincodes = [p['pincode'] for p in allowed_pincodes_data]

        if zip_code not in allowed_pincodes:
            flash(f'We will deliver soon for {zip_code}', 'warning')
            return redirect(url_for('add_address', next=request.args.get('next')))

        if is_default:
            db.execute('UPDATE addresses SET is_default = 0 WHERE user_id = ?', (user_id,))

        cursor = db.execute(
            'INSERT INTO addresses (user_id, full_name, phone_number, address_line1, address_line2, city, state, zip_code, country, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (user_id, full_name, phone_number, address_line1, address_line2, city, state, zip_code, country, is_default)
        )
        new_address_id = cursor.lastrowid
        db.commit()
        flash('Address added successfully!', 'success')

        next_url_param = request.args.get('next')
        if next_url_param == 'checkout':
            return redirect(url_for('view_cart'))
        elif next_url_param == 'buy_now_checkout':
            return redirect(url_for('checkout_review', buy_now_flow='true', shipping_address_id=new_address_id))
        return redirect(url_for('view_addresses'))

    return render_template('add_address.html')

# Edit address route
@app.route('/edit_address/<int:address_id>', methods=['GET', 'POST'])
@customer_required
def edit_address(address_id):
    db = get_db()
    user_id = current_user.id
    address = db.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', (address_id, user_id)).fetchone()

    if not address:
        flash('Address not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('view_addresses'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        phone_number = request.form.get('phone_number')
        address_line1 = request.form['address_line1']
        address_line2 = request.form.get('address_line2', '')
        zip_code = request.form['zip_code']
        city = request.form.get('city')
        state = request.form.get('state')
        country = request.form.get('country')
        is_default = 'is_default' in request.form

        if not phone_number or not phone_number.isdigit() or len(phone_number) != 10:
            flash('Please enter a valid 10-digit phone number.', 'danger')
            return render_template('edit_address.html', address=address)

        if not city or not state or not country:
            flash('Please enter a valid Zip Code and select a City/Area from the dropdown.', 'danger')
            return render_template('edit_address.html', address=address)

        allowed_pincodes_data = db.execute('SELECT pincode FROM approved_pincodes').fetchall()
        allowed_pincodes = [p['pincode'] for p in allowed_pincodes_data]

        if zip_code not in allowed_pincodes:
            flash(f'We will deliver soon for {zip_code}. Please choose a different pincode.', 'warning')
            return render_template('edit_address.html', address=address)

        if is_default:
            db.execute('UPDATE addresses SET is_default = 0 WHERE user_id = ?', (user_id,))

        db.execute(
            'UPDATE addresses SET full_name = ?, phone_number = ?, address_line1 = ?, address_line2 = ?, city = ?, state = ?, zip_code = ?, country = ?, is_default = ? WHERE id = ? AND user_id = ?',
            (full_name, phone_number, address_line1, address_line2, city, state, zip_code, country, is_default, address_id, user_id)
        )
        db.commit()
        flash('Address updated successfully!', 'success')
        return redirect(url_for('view_addresses'))

    return render_template('edit_address.html', address=address)

# Delete address route
@app.route('/delete_address/<int:address_id>', methods=['POST'])
@customer_required
def delete_address(address_id):
    db = get_db()
    user_id = current_user.id
    address = db.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', (address_id, user_id)).fetchone()

    if not address:
        flash('Address not found or you do not have permission to delete it.', 'danger')
        return redirect(url_for('view_addresses'))

    remaining_addresses_count = db.execute('SELECT COUNT(*) FROM addresses WHERE user_id = ?', (user_id,)).fetchone()[0]
    has_orders = db.execute('SELECT COUNT(*) FROM orders WHERE user_id = ?', (user_id,)).fetchone()[0]

    if remaining_addresses_count == 1 and has_orders > 0:
        flash('You cannot delete your last address if you have placed orders. Please add a new address first.', 'danger')
        return redirect(url_for('view_addresses'))

    orders_using_address = db.execute(
        "SELECT COUNT(*) FROM orders WHERE shipping_address_id = ? AND status NOT IN ('Delivered', 'Cancelled')",
        (address_id,)
    ).fetchone()[0]

    if orders_using_address > 0:
        flash(f'This address cannot be deleted as it is linked to {orders_using_address} active order(s).', 'danger')
        return redirect(url_for('view_addresses'))

    db.execute('DELETE FROM addresses WHERE id = ? AND user_id = ?', (address_id, user_id))
    db.commit()
    flash('Address deleted successfully!', 'success')
    return redirect(url_for('view_addresses'))

# Buy now route (direct to checkout for a single item)
@app.route('/buy_now/<int:product_id>', methods=['POST'])
@customer_required
def buy_now(product_id):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))

    try:
        quantity = int(request.form.get('quantity', 1))
        if quantity < 1:
            flash('Quantity must be at least 1.', 'warning')
            return redirect(url_for('product_detail', product_id=product_id))
    except ValueError:
        flash('Invalid quantity provided.', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

    session['buy_now_product'] = {
        'id': product['id'],
        'name': product['name'],
        'price': product['price'],
        'quantity': quantity,
        'image_url': product['image_url']
    }
    flash(f'Proceeding to checkout with {quantity} of "{product["name"]}".', 'info')
    return redirect(url_for('checkout_review', buy_now_flow='true'))

# Checkout review page route
@app.route('/checkout/review', methods=['GET', 'POST'])
@customer_required
def checkout_review():
    user_id = current_user.id
    db = get_db()
    cart_items = []
    total_amount = 0.0
    shipping_address_id = None
    is_buy_now_flow = request.args.get('buy_now_flow') == 'true'

    if is_buy_now_flow and 'buy_now_product' in session:
        product_data = session['buy_now_product']
        cart_items = [product_data]
        total_amount = product_data['price'] * product_data['quantity']
        shipping_address_id = request.args.get('shipping_address_id')
        if not shipping_address_id:
            default_address = db.execute('SELECT id FROM addresses WHERE user_id = ? AND is_default = 1', (user_id,)).fetchone()
            if default_address:
                shipping_address_id = default_address['id']
        if not shipping_address_id:
            flash('Please select a shipping address to proceed with your order.', 'warning')
            return redirect(url_for('view_addresses', next_flow='buy_now_checkout'))
    else:
        shipping_address_id = request.form.get('shipping_address_id')
        cart_items = db.execute(
            '''SELECT ci.product_id AS id, p.name, p.price, ci.quantity, p.image_url
               FROM cart_items ci
               JOIN products p ON ci.product_id = p.id
               WHERE ci.user_id = ?''',
            (user_id,)
        ).fetchall()
        total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

    if not cart_items:
        flash('Your order is empty. Please add products before checking out.', 'warning')
        return redirect(url_for('index'))

    shipping_address = None
    if shipping_address_id:
        shipping_address_row = db.execute(
            'SELECT * FROM addresses WHERE id = ? AND user_id = ?',
            (shipping_address_id, user_id)
        ).fetchone()
        if shipping_address_row:
            shipping_address = dict(shipping_address_row)

    if shipping_address:
        approved_pincodes_data = db.execute('SELECT pincode FROM approved_pincodes').fetchall()
        allowed_pincodes = [p['pincode'] for p in approved_pincodes_data]

        if shipping_address['zip_code'] not in allowed_pincodes:
            flash(f'We will deliver soon for {shipping_address["zip_code"]}. Please select a different address or add a new one.', 'warning')
            if is_buy_now_flow:
                return redirect(url_for('view_addresses', next_flow='buy_now_checkout'))
            return redirect(url_for('view_cart'))
    else:
        flash('Please select a valid shipping address.', 'error')
        if is_buy_now_flow:
            return redirect(url_for('view_addresses', next_flow='buy_now_checkout'))
        return redirect(url_for('view_cart'))

    return render_template(
        'checkout/review.html',
        cart_items=cart_items,
        total_amount=total_amount,
        shipping_address=shipping_address,
        is_buy_now_flow=is_buy_now_flow
    )

# Place order route
@app.route('/checkout/place_order', methods=['POST'])
@customer_required
def checkout_place_order():
    user_id = current_user.id
    shipping_address_id = request.form.get('shipping_address_id')
    payment_method = request.form.get('payment_method')
    is_buy_now_flow = request.form.get('is_buy_now_flow') == 'true'

    db = get_db()
    address = db.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', (shipping_address_id, user_id)).fetchone()
    if not address:
        flash('Invalid shipping address. Please try again.', 'error')
        if is_buy_now_flow:
            return redirect(url_for('view_addresses', next_flow='buy_now_checkout'))
        return redirect(url_for('view_cart'))

    order_items_to_process = []
    if is_buy_now_flow:
        if 'buy_now_product' not in session:
            flash('Buy Now session expired or invalid.', 'error')
            return redirect(url_for('index'))
        product_data = session['buy_now_product']
        order_items_to_process = [product_data]
        session.pop('buy_now_product', None)
    else:
        # Fetch detailed product info from the products table for cart items
        cart_items = db.execute(
            '''SELECT ci.product_id AS id, p.name, p.price, ci.quantity, p.image_url
               FROM cart_items ci
               JOIN products p ON ci.product_id = p.id
               WHERE ci.user_id = ?''',
            (user_id,)
        ).fetchall()
        order_items_to_process = [dict(item) for item in cart_items]


    if not order_items_to_process:
        flash('Your order is empty. Please add products before checking out.', 'warning')
        return redirect(url_for('index'))

    if not payment_method:
        flash('Please select a payment method.', 'warning')
        if is_buy_now_flow:
            session['buy_now_product'] = order_items_to_process[0]
            return redirect(url_for('checkout_review', buy_now_flow='true', shipping_address_id=shipping_address_id))
        return redirect(url_for('checkout_review', shipping_address_id=shipping_address_id))

    order_status = 'Pending'
    if payment_method != 'Cash on Delivery':
        flash('Invalid payment method selected.', 'danger')
        if is_buy_now_flow:
            session['buy_now_product'] = order_items_to_process[0]
            return redirect(url_for('checkout_review', buy_now_flow='true', shipping_address_id=shipping_address_id))
        return redirect(url_for('checkout_review', shipping_address_id=shipping_address_id))

    total_amount = sum(item['price'] * item['quantity'] for item in order_items_to_process)
    order_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        cursor = db.execute(
            'INSERT INTO orders (user_id, order_date, total_amount, status, shipping_address_id, payment_method) VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, order_date, total_amount, order_status, shipping_address_id, payment_method)
        )
        order_id = cursor.lastrowid
        for item in order_items_to_process:
            db.execute(
                # UPDATED: Insert product name and image URL into order_items
                'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase, product_name_at_purchase, product_image_url_at_purchase) VALUES (?, ?, ?, ?, ?, ?)',
                (order_id, item['id'], item['quantity'], item['price'], item['name'], item['image_url'])
            )
        if not is_buy_now_flow:
            db.execute('DELETE FROM cart_items WHERE user_id = ?', (user_id,))

        db.commit()

        create_notification(user_id, f"Your order #{order_id} has been placed successfully!", order_id)
        admin_user = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
        if admin_user:
            create_notification(admin_user['id'], f"New order #{order_id} has been placed by {current_user.username}.", order_id)
        pincode = address['zip_code']
        delivery_boys_to_notify = db.execute('''
            SELECT DISTINCT u.id FROM users u
            JOIN delivery_boys db ON u.id = db.user_id
            JOIN delivery_boy_pincodes dbp ON db.id = dbp.delivery_boy_id
            WHERE dbp.pincode = ?
        ''', (pincode,)).fetchall()

        for dboy in delivery_boys_to_notify:
            create_notification(dboy['id'], f"New order #{order_id} available for pickup in your area ({pincode}).", order_id)
        
        flash('Your order has been placed successfully!', 'success')
        return redirect(url_for('order_detail', order_id=order_id))

    except sqlite3.Error as e:
        db.rollback()
        flash(f'An error occurred during checkout: {e}', 'error')
        if is_buy_now_flow:
            session['buy_now_product'] = order_items_to_process[0]
            return redirect(url_for('checkout_review', buy_now_flow='true', shipping_address_id=shipping_address_id))
        return redirect(url_for('view_cart'))

# View orders route for customers
@app.route('/orders')
@customer_required
def view_orders():
    user_id = current_user.id
    db = get_db()
    orders_raw = db.execute(
        '''SELECT o.id, o.order_date, o.total_amount, o.status, a.full_name, a.address_line1, a.city, o.payment_method
           FROM orders o
           JOIN addresses a ON o.shipping_address_id = a.id
           WHERE o.user_id = ?
           ORDER BY o.order_date DESC''',
        (user_id,)
    ).fetchall()
    orders_with_items = []
    for order_row in orders_raw:
        order = dict(order_row)
        order_items = db.execute(
            # UPDATED: Get name and image directly from order_items table
            '''SELECT oi.quantity, oi.product_name_at_purchase AS name FROM order_items oi
               WHERE oi.order_id = ?''',
            (order['id'],)
        ).fetchall()
        order['order_items'] = order_items
        orders_with_items.append(order)
    return render_template('view_orders.html', orders=orders_with_items)

# Order detail page route for all user types
@app.route('/order_detail/<int:order_id>')
@login_required
def order_detail(order_id):
    db = get_db()
    order_query = '''SELECT o.*,
                          a.full_name, a.phone_number, a.address_line1, a.address_line2, a.city, a.state, a.zip_code, a.country,
                          db.name as delivery_boy_name,
                          db.mobile_number as delivery_boy_phone
                          FROM orders o
                          JOIN addresses a ON o.shipping_address_id = a.id
                          LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.id
                          WHERE o.id = ?'''
    order = db.execute(order_query, (order_id,)).fetchone()

    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('index'))

    has_permission = False
    delivery_boy_id = None
    if current_user.is_admin:
        has_permission = True
    elif current_user.is_delivery_boy:
        dboy_rec = db.execute('SELECT id FROM delivery_boys WHERE user_id = ?', (current_user.id,)).fetchone()
        if dboy_rec:
            delivery_boy_id = dboy_rec['id']
            if order['delivery_boy_id'] == delivery_boy_id:
                has_permission = True
            elif order['status'] == 'Pending' and order['delivery_boy_id'] is None:
                pincodes_data = db.execute('SELECT pincode FROM delivery_boy_pincodes WHERE delivery_boy_id = ?', (delivery_boy_id,)).fetchall()
                serviceable_pincodes = [p['pincode'] for p in pincodes_data]
                if order['zip_code'] in serviceable_pincodes:
                    has_permission = True
    elif order['user_id'] == current_user.id:
        has_permission = True
    
    if not has_permission:
        if current_user.is_delivery_boy:
            is_taken_by_another = order['delivery_boy_id'] is not None and order['delivery_boy_id'] != delivery_boy_id
            is_no_longer_available = order['status'] != 'Pending'
            if is_taken_by_another or is_no_longer_available:
                flash("Sorry, this order has already been taken or is no longer pending.", 'warning')
                return redirect(url_for('delivery_boy_dashboard'))
            else:
                flash('You do not have permission to view this order.', 'danger')
                return redirect(url_for('delivery_boy_dashboard'))
        else:
            flash('You do not have permission to view this order.', 'danger')
            return redirect(url_for('view_orders'))

    order_items = db.execute(
        # UPDATED: Get name and image directly from order_items table
        '''SELECT oi.quantity, oi.price_at_purchase, oi.product_name_at_purchase AS name, oi.product_image_url_at_purchase AS image_url
           FROM order_items oi
           WHERE oi.order_id = ?''',
        (order_id,)
    ).fetchall()

    return render_template('order_detail.html', order=order, order_items=order_items, delivery_boy_id=delivery_boy_id)


# Admin dashboard route
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    total_products = db.execute('SELECT COUNT(*) FROM products').fetchone()[0]
    total_users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_orders = db.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
    pending_orders_count = db.execute("SELECT COUNT(*) FROM orders WHERE status = 'Pending'").fetchone()[0]
    delivered_orders_count = db.execute("SELECT COUNT(*) FROM orders WHERE status = 'Delivered'").fetchone()[0]
    cancelled_orders_count = db.execute("SELECT COUNT(*) FROM orders WHERE status = 'Cancelled'").fetchone()[0]
    leaved_orders_count = db.execute("SELECT COUNT(*) FROM orders WHERE cancellation_reason LIKE 'Left by Delivery Boy%' AND status = 'Pending'").fetchone()[0]

    def attach_items_to_orders(orders_list):
        orders_with_items = []
        for order_row in orders_list:
            order = dict(order_row)
            # UPDATED: Get name directly from order_items table
            order_items = db.execute(
                '''SELECT oi.quantity, oi.product_name_at_purchase AS name FROM order_items oi
                   WHERE oi.order_id = ?''',
                (order['id'],)
            ).fetchall()
            order['order_items'] = order_items
            orders_with_items.append(order)
        return orders_with_items

    base_order_query = '''
        SELECT o.id, o.order_date, o.status, o.cancellation_reason,
            u.username AS customer_name,
            a.full_name AS shipping_name, a.address_line1, a.address_line2, a.city, a.state, a.zip_code,
            db.name AS delivery_boy_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        LEFT JOIN addresses a ON o.shipping_address_id = a.id
        LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.id
    '''

    ongoing_orders_raw = db.execute(f"{base_order_query} WHERE o.status NOT IN ('Delivered', 'Cancelled') ORDER BY o.order_date DESC").fetchall()
    ongoing_orders = attach_items_to_orders(ongoing_orders_raw)

    delivered_orders_raw = db.execute(f"{base_order_query} WHERE o.status = 'Delivered' ORDER BY o.order_date DESC").fetchall()
    delivered_orders = attach_items_to_orders(delivered_orders_raw)

    admin_leaved_reason_pattern = 'Left by Delivery Boy::%'
    leaved_orders_raw = db.execute(
        f"{base_order_query} WHERE o.cancellation_reason LIKE ? AND o.status = 'Pending' AND o.delivery_boy_id IS NULL ORDER BY o.order_date DESC",
        (admin_leaved_reason_pattern,)
    ).fetchall()
    leaved_orders = attach_items_to_orders(leaved_orders_raw)

    cancelled_orders_raw = db.execute(f"{base_order_query} WHERE o.status = 'Cancelled' ORDER BY o.order_date DESC").fetchall()
    cancelled_orders = attach_items_to_orders(cancelled_orders_raw)

    return render_template('admin/dashboard.html',
                           total_products=total_products,
                           total_users=total_users,
                           total_orders=total_orders,
                           pending_orders=pending_orders_count,
                           delivered_orders_count=delivered_orders_count,
                           cancelled_orders_count=cancelled_orders_count,
                           leaved_orders_count=leaved_orders_count,
                           ongoing_orders=ongoing_orders,
                           delivered_orders=delivered_orders,
                           cancelled_orders=cancelled_orders,
                           leaved_orders=leaved_orders)

# Admin product management routes
@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    products = db.execute('SELECT * FROM products ORDER BY id DESC').fetchall()
    return render_template('admin/products.html', products=products)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form.get('category', 'Miscellaneous')
        image_url = None
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = url_for('static', filename=f'uploads/{filename}')
            elif file.filename == '':
                flash('No file selected for upload, or file is empty.', 'warning')
        db = get_db()
        try:
            db.execute(
                'INSERT INTO products (name, description, price, image_url, category) VALUES (?, ?, ?, ?, ?)',
                (name, description, price, image_url, category)
            )
            db.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('admin_products'))
        except sqlite3.Error as e:
            flash(f'Error adding product: {e}', 'danger')
    common_categories = ['All', 'Electronics', 'Audio', 'Wearables', 'Peripherals', 'Displays', 'Computers', 'Storage', 'Food', 'Meat', 'Grocery', 'Medicine', 'Miscellaneous']
    return render_template('admin/add_edit_product.html', product=None, common_categories=common_categories)

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('admin_products'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form.get('category', 'Miscellaneous')
        image_url_to_save = product['image_url']
        if 'delete_current_image_button' in request.form:
            image_url_to_save = None
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url_to_save = url_for('static', filename=f'uploads/{filename}')
            elif file.filename == '' and 'delete_current_image_button' not in request.form:
                pass
        try:
            db.execute(
                'UPDATE products SET name = ?, description = ?, price = ?, image_url = ?, category = ? WHERE id = ?',
                (name, description, price, image_url_to_save, category, product_id)
            )
            db.commit()
            flash('Product updated successfully!', 'success')
            if request.referrer and 'admin/products' not in request.referrer and 'product/' not in request.referrer:
                return redirect(url_for('index'))
            else:
                return redirect(url_for('admin_products'))
        except sqlite3.Error as e:
            flash(f'Error updating product: {e}', 'danger')
            if request.referrer and 'admin/products/edit' in request.referrer:
                return redirect(url_for('admin_edit_product', product_id=product_id))
            else:
                return redirect(url_for('admin_products'))
    common_categories = ['All', 'Electronics', 'Audio', 'Wearables', 'Peripherals', 'Displays', 'Computers', 'Storage', 'Food', 'Meat', 'Grocery', 'Medicine', 'Miscellaneous']
    return render_template('admin/add_edit_product.html', product=product, common_categories=common_categories)

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    try:
        # NOTE: Do NOT delete from order_items here to preserve historical order data.
        # This only deletes the product from the main products table and the cart.
        db.execute('DELETE FROM cart_items WHERE product_id = ?', (product_id,))
        db.execute('DELETE FROM products WHERE id = ?', (product_id,))
        db.commit()
        flash('Product deleted successfully!', 'success')
        if request.referrer and 'admin/products' not in request.referrer and 'product/' not in request.referrer:
            return redirect(url_for('index'))
        else:
            return redirect(url_for('admin_products'))
    except sqlite3.Error as e:
        flash(f'Error deleting product: {e}', 'danger')
        return redirect(url_for('admin_products'))

# Admin user management routes
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    users = db.execute('SELECT id, username, is_admin, is_delivery_boy FROM users ORDER BY id DESC').fetchall()
    return render_template('admin/users.html', users=users)

# Admin order management routes
@app.route('/admin/orders')
@admin_required
def admin_orders():
    db = get_db()
    orders = db.execute(
        '''SELECT o.id, o.order_date, o.total_amount, o.status, o.payment_method,
           u.username, a.full_name AS shipping_name, a.city AS shipping_city
           FROM orders o
           JOIN users u ON o.user_id = u.id
           JOIN addresses a ON o.shipping_address_id = a.id
           ORDER BY o.order_date DESC'''
    ).fetchall()
    return render_template('admin/orders.html', orders=orders)

# Admin pincode management routes
@app.route('/admin/pincodes', methods=['GET', 'POST'])
@admin_required
def admin_pincodes():
    db = get_db()
    if request.method == 'POST':
        if 'add_pincode' in request.form:
            new_pincode = request.form['pincode'].strip()
            if new_pincode:
                try:
                    db.execute('INSERT INTO approved_pincodes (pincode) VALUES (?)', (new_pincode,))
                    db.commit()
                    flash(f'Pincode {new_pincode} added successfully!', 'success')
                except sqlite3.IntegrityError:
                    flash(f'Pincode {new_pincode} already exists.', 'warning')
                except sqlite3.Error as e:
                    flash(f'Error adding pincode: {e}', 'danger')
            else:
                flash('Pincode cannot be empty.', 'danger')
        elif 'delete_pincode' in request.form:
            pincode_id_to_delete = request.form['pincode_id']
            try:
                db.execute('DELETE FROM approved_pincodes WHERE id = ?', (pincode_id_to_delete,))
                db.commit()
                flash('Pincode deleted successfully!', 'success')
            except sqlite3.Error as e:
                flash(f'Error deleting pincode: {e}', 'danger')
        return redirect(url_for('admin_pincodes'))
    pincodes = db.execute('SELECT * FROM approved_pincodes ORDER BY pincode').fetchall()
    return render_template('admin/pincodes.html', pincodes=pincodes)

# Admin delivery boy management routes
@app.route('/admin/delivery_boys')
@admin_required
def admin_delivery_boys():
    db = get_db()
    delivery_boys_raw = db.execute(
        '''SELECT db.id, db.name, db.mobile_number, db.whatsapp_mobile_number, db.email, u.username AS linked_username
           FROM delivery_boys db
           LEFT JOIN users u ON db.user_id = u.id
           ORDER BY db.name'''
    ).fetchall()
    delivery_boys = []
    for dboy_row in delivery_boys_raw:
        dboy = dict(dboy_row)
        dboy_pincodes = db.execute('SELECT pincode FROM delivery_boy_pincodes WHERE delivery_boy_id = ?', (dboy['id'],)).fetchall()
        dboy['pincodes'] = [p['pincode'] for p in dboy_pincodes]
        delivery_boys.append(dboy)
    return render_template('admin/delivery_boys.html', delivery_boys=delivery_boys)

@app.route('/admin/delivery_boys/add', methods=['GET', 'POST'])
@admin_required
def admin_add_delivery_boy():
    if request.method == 'POST':
        name = request.form['name']
        mobile_number = request.form['mobile_number']
        whatsapp_mobile_number = request.form['whatsapp_mobile_number']
        email = request.form['email']
        pincodes_str = request.form['pincodes']
        pincodes = [p.strip() for p in pincodes_str.split(',') if p.strip()]

        db = get_db()
        delivery_boy_data = {
            'name': name, 'mobile_number': mobile_number,
            'whatsapp_mobile_number': whatsapp_mobile_number, 'email': email
        }
        approved_pincodes_data = db.execute('SELECT pincode FROM approved_pincodes').fetchall()
        approved_pincodes_set = {p['pincode'] for p in approved_pincodes_data}
        unapproved_pincodes = [p for p in new_pincodes if p not in approved_pincodes_set]

        if unapproved_pincodes:
            error_message = f"This pincode(s) {', '.join(unapproved_pincodes)} is not yet added or approved. Please approve it first."
            flash('Please correct the errors below.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html',
                                   delivery_boy=delivery_boy_data,
                                   current_pincodes=pincodes_str,
                                   pincode_error=error_message)

        if db.execute('SELECT id FROM delivery_boys WHERE mobile_number = ?', (mobile_number,)).fetchone():
            flash('A delivery boy with this mobile number already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy_data, current_pincodes=pincodes_str)
        if db.execute('SELECT id FROM delivery_boys WHERE email = ?', (email,)).fetchone():
            flash('A delivery boy with this email address already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy_data, current_pincodes=pincodes_str)
        if User.get_by_email(email):
            flash('This email address is already used by an existing user. Please use a different one.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy_data, current_pincodes=pincodes_str)
        if db.execute('SELECT id FROM delivery_boys WHERE whatsapp_mobile_number = ?', (whatsapp_mobile_number,)).fetchone():
            flash('A delivery boy with this WhatsApp mobile number already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy_data, current_pincodes=pincodes_str)

        try:
            cursor = db.execute(
                'INSERT INTO delivery_boys (name, mobile_number, whatsapp_mobile_number, email) VALUES (?, ?, ?, ?)',
                (name, mobile_number, whatsapp_mobile_number, email)
            )
            delivery_boy_id = cursor.lastrowid
            for pincode in pincodes:
                db.execute('INSERT INTO delivery_boy_pincodes (delivery_boy_id, pincode) VALUES (?, ?)', (delivery_boy_id, pincode))
            db.commit()
            flash(f'Delivery boy "{name}" added successfully!', 'success')
            return redirect(url_for('admin_delivery_boys'))
        except sqlite3.Error as e:
            flash(f'Database error adding delivery boy: {e}', 'danger')
            db.rollback()
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy_data, current_pincodes=pincodes_str)

    return render_template('admin/add_edit_delivery_boy.html', delivery_boy=None, current_pincodes='')

@app.route('/admin/delivery_boys/edit/<int:dboy_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_delivery_boy(dboy_id):
    db = get_db()
    delivery_boy_row = db.execute('SELECT * FROM delivery_boys WHERE id = ?', (dboy_id,)).fetchone()
    if not delivery_boy_row:
        flash('Delivery boy not found.', 'danger')
        return redirect(url_for('admin_delivery_boys'))
    delivery_boy = dict(delivery_boy_row)

    if request.method == 'GET':
        current_pincodes_data = db.execute('SELECT pincode FROM delivery_boy_pincodes WHERE delivery_boy_id = ?', (dboy_id,)).fetchall()
        current_pincodes = ', '.join([p['pincode'] for p in current_pincodes_data])
        return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=current_pincodes)

    if request.method == 'POST':
        name = request.form['name']
        mobile_number = request.form['mobile_number']
        whatsapp_mobile_number = request.form['whatsapp_mobile_number']
        email = request.form['email']
        pincodes_str = request.form['pincodes']
        new_pincodes = [p.strip() for p in pincodes_str.split(',') if p.strip()]
        delivery_boy.update({'name': name, 'mobile_number': mobile_number, 'whatsapp_mobile_number': whatsapp_mobile_number, 'email': email})

        approved_pincodes_data = db.execute('SELECT pincode FROM approved_pincodes').fetchall()
        approved_pincodes_set = {p['pincode'] for p in approved_pincodes_data}
        unapproved_pincodes = [p for p in new_pincodes if p not in approved_pincodes_set]

        if unapproved_pincodes:
            error_message = f"This pincode(s) {', '.join(unapproved_pincodes)} is not approved. Please approve it first."
            flash('Please correct the errors below.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str, pincode_error=error_message)

        if db.execute('SELECT id FROM delivery_boys WHERE mobile_number = ? AND id != ?', (mobile_number, dboy_id)).fetchone():
            flash('A delivery boy with this mobile number already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str)
        if db.execute('SELECT id FROM delivery_boys WHERE email = ? AND id != ?', (email, dboy_id)).fetchone():
            flash('A delivery boy with this email address already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str)
        if User.get_by_email(email) and User.get_by_email(email).id != delivery_boy['user_id']:
            flash('This email address is already used by an existing user. Please use a different one.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str)
        if db.execute('SELECT id FROM delivery_boys WHERE whatsapp_mobile_number = ? AND id != ?', (whatsapp_mobile_number, dboy_id)).fetchone():
            flash('A delivery boy with this WhatsApp mobile number already exists.', 'danger')
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str)

        try:
            db.execute(
                'UPDATE delivery_boys SET name = ?, mobile_number = ?, whatsapp_mobile_number = ?, email = ? WHERE id = ?',
                (name, mobile_number, whatsapp_mobile_number, email, dboy_id)
            )
            db.execute('DELETE FROM delivery_boy_pincodes WHERE delivery_boy_id = ?', (dboy_id,))
            for pincode in new_pincodes:
                db.execute('INSERT INTO delivery_boy_pincodes (delivery_boy_id, pincode) VALUES (?, ?)', (dboy_id, pincode))
            db.commit()
            flash(f'Delivery boy "{name}" updated successfully!', 'success')
            return redirect(url_for('admin_delivery_boys'))
        except sqlite3.Error as e:
            flash(f'Error updating delivery boy: {e}', 'danger')
            db.rollback()
            return render_template('admin/add_edit_delivery_boy.html', delivery_boy=delivery_boy, current_pincodes=pincodes_str)

@app.route('/admin/delivery_boys/delete/<int:dboy_id>', methods=['POST'])
@admin_required
def admin_delete_delivery_boy(dboy_id):
    db = get_db()
    try:
        delivery_boy = db.execute('SELECT user_id FROM delivery_boys WHERE id = ?', (dboy_id,)).fetchone()
        if not delivery_boy:
            flash('Delivery boy not found.', 'danger')
            return redirect(url_for('admin_delivery_boys'))
        active_orders_count = db.execute(
            "SELECT COUNT(*) FROM orders WHERE delivery_boy_id = ? AND status NOT IN ('Delivered', 'Cancelled')",
            (dboy_id,)
        ).fetchone()[0]
        if active_orders_count > 0:
            flash(f'This delivery boy cannot be deleted as they have {active_orders_count} active order(s) in progress. Try again later until their deliveries are complete.', 'danger')
            return redirect(url_for('admin_delivery_boys'))
        user_id_to_delete = delivery_boy['user_id']
        db.execute('DELETE FROM delivery_boys WHERE id = ?', (dboy_id,))
        if user_id_to_delete:
            db.execute('DELETE FROM users WHERE id = ?', (user_id_to_delete,))
        db.commit()
        flash('Delivery boy and associated user account (if linked) deleted successfully!', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'An error occurred during deletion: {e}', 'danger')
    return redirect(url_for('admin_delivery_boys'))

@app.route('/admin/delivery_boys/send_link/<int:dboy_id>')
@admin_required
def admin_send_delivery_boy_link(dboy_id):
    db = get_db()
    delivery_boy = db.execute('SELECT id, name, whatsapp_mobile_number, email FROM delivery_boys WHERE id = ?', (dboy_id,)).fetchone()

    if not delivery_boy:
        flash('Delivery boy not found.', 'danger')
        return redirect(url_for('admin_delivery_boys'))

    registration_link = url_for('delivery_boy_register', delivery_boy_id=dboy_id, _external=True)
    whatsapp_message = f"Hello {delivery_boy['name']},\n\nYour registration link for CO Delivery Boy account is: {registration_link}\n\nPlease click the link to set up your login credentials."
    whatsapp_url = f"https://wa.me/{delivery_boy['whatsapp_mobile_number']}?text={urllib.parse.quote(whatsapp_message)}"

    email_subject = "Your CO Delivery Boy Registration Link"
    email_body = f"Hello {delivery_boy['name']},\n\nYour registration link is: {registration_link}\n\nPlease click it to set up your account."
    email_url = f"mailto:{delivery_boy['email']}?subject={urllib.parse.quote(email_subject)}&body={urllib.parse.quote(email_body)}"

    return render_template('admin/send_delivery_boy_link.html',
                           delivery_boy=delivery_boy,
                           registration_link=registration_link,
                           whatsapp_url=whatsapp_url,
                           email_url=email_url)


# Delivery boy registration route
@app.route('/delivery_boy_register/<int:delivery_boy_id>', methods=['GET', 'POST'])
def delivery_boy_register(delivery_boy_id):
    db = get_db()
    dboy = db.execute('SELECT * FROM delivery_boys WHERE id = ?', (delivery_boy_id,)).fetchone()
    if not dboy:
        flash('Invalid registration link or delivery boy not found.', 'danger')
        return redirect(url_for('login'))
    if dboy['user_id']:
        flash('This delivery boy account is already registered. Please log in.', 'info')
        return redirect(url_for('login'))
    if current_user.is_authenticated:
        flash('You are already logged in. Please log out to register a new delivery boy account.', 'warning')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if not (5 <= len(username) <= 10):
            flash('Username must be between 5 and 10 characters long.', 'danger')
            return render_template('delivery_boy_register.html', delivery_boy_id=delivery_boy_id, dboy_name=dboy['name'])
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('delivery_boy_register.html', delivery_boy_id=delivery_boy_id, dboy_name=dboy['name'])
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already taken. Please choose a different one.', 'warning')
            return render_template('delivery_boy_register.html', delivery_boy_id=delivery_boy_id, dboy_name=dboy['name'])
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            cursor = db.execute(
                'INSERT INTO users (username, password, is_admin, is_delivery_boy, email) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, 0, 1, dboy['email'])
            )
            new_user_id = cursor.lastrowid
            db.execute('UPDATE delivery_boys SET user_id = ? WHERE id = ?', (new_user_id, delivery_boy_id))
            db.commit()
            user = User(new_user_id, username, hashed_password, is_admin=0, is_delivery_boy=1)
            login_user(user)
            flash('Delivery boy registration successful! You are now logged in.', 'success')
            return redirect(url_for('delivery_boy_dashboard'))
        except sqlite3.Error as e:
            flash(f'An error occurred during registration: {e}', 'danger')
            db.rollback()
    return render_template('delivery_boy_register.html', delivery_boy_id=delivery_boy_id, dboy_name=dboy['name'])

# Delivery boy dashboard route
@app.route('/delivery_boy_dashboard')
@delivery_boy_required
def delivery_boy_dashboard():
    db = get_db()
    user_id = current_user.id
    delivery_boy_info = db.execute(
        '''SELECT db.id, db.name, db.mobile_number, db.whatsapp_mobile_number, db.email
           FROM delivery_boys db
           WHERE db.user_id = ?''',
        (user_id,)
    ).fetchone()
    if not delivery_boy_info:
        flash('Delivery boy profile not found. Please contact an administrator.', 'error')
        logout_user()
        return redirect(url_for('login'))
    delivery_boy_id = delivery_boy_info['id']
    dboy_pincodes_data = db.execute(
        'SELECT pincode FROM delivery_boy_pincodes WHERE delivery_boy_id = ?',
        (delivery_boy_id,)
    ).fetchall()
    pincode_list = [p['pincode'] for p in dboy_pincodes_data]
    def attach_items_to_orders(orders_list):
        orders_with_items = []
        for order_row in orders_list:
            order = dict(order_row)
            # UPDATED: Use LEFT JOIN to get product info, in case the product was deleted
            order_items = db.execute(
                '''SELECT oi.quantity, oi.product_name_at_purchase AS name FROM order_items oi
                   WHERE oi.order_id = ?''',
                (order['id'],)
            ).fetchall()
            order['order_items'] = order_items
            orders_with_items.append(order)
        return orders_with_items
    base_order_query = '''
        SELECT o.id, o.order_date, o.total_amount, o.status, o.cancellation_reason,
            u.username AS customer_name,
            a.full_name AS shipping_name, a.address_line1, a.address_line2, a.city, a.state, a.zip_code,
            db.name AS delivery_boy_name
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        LEFT JOIN addresses a ON o.shipping_address_id = a.id
        LEFT JOIN delivery_boys db ON o.delivery_boy_id = db.id
    '''
    active_orders_raw = []
    if pincode_list:
        pincode_placeholders = ','.join(['?' for _ in pincode_list])
        sql_query = f'''
            {base_order_query}
            WHERE
                (a.zip_code IN ({pincode_placeholders}) AND o.status = 'Pending' AND o.delivery_boy_id IS NULL)
                OR
                (o.delivery_boy_id = ? AND o.status NOT IN ('Delivered', 'Cancelled'))
            ORDER BY o.order_date DESC
        '''
        params = pincode_list + [delivery_boy_id]
        active_orders_raw = db.execute(sql_query, params).fetchall()
    active_orders = attach_items_to_orders(active_orders_raw)
    delivered_orders_raw = db.execute(f"{base_order_query} WHERE o.delivery_boy_id = ? AND o.status = 'Delivered' ORDER BY o.order_date DESC", (delivery_boy_id,)).fetchall()
    delivered_orders = attach_items_to_orders(delivered_orders_raw)
    cancelled_orders_raw = db.execute(f"{base_order_query} WHERE o.delivery_boy_id = ? AND o.status = 'Cancelled' ORDER BY o.order_date DESC", (delivery_boy_id,)).fetchall()
    cancelled_orders = attach_items_to_orders(cancelled_orders_raw)
    leaved_reason_str = f"Left by Delivery Boy::{delivery_boy_info['name']}::%"
    leaved_orders_raw = db.execute(
        f"{base_order_query} WHERE o.cancellation_reason LIKE ? AND o.status = 'Pending' AND o.delivery_boy_id IS NULL ORDER BY o.order_date DESC",
        (leaved_reason_str,)
    ).fetchall()
    leaved_orders = attach_items_to_orders(leaved_orders_raw)
    leaved_orders_count = len(leaved_orders)
    return render_template('delivery_boy/dashboard.html',
                           delivery_boy_info=delivery_boy_info,
                           pincode_list=pincode_list,
                           active_orders=active_orders,
                           delivered_orders=delivered_orders,
                           cancelled_orders=cancelled_orders,
                           leaved_orders=leaved_orders,
                           leaved_orders_count=leaved_orders_count)

# Delivery boy actions routes
@app.route('/delivery/take_order/<int:order_id>', methods=['POST'])
@delivery_boy_required
def take_order(order_id):
    db = get_db()
    order = db.execute("SELECT status, delivery_boy_id, user_id FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not order or order['status'] != 'Pending' or order['delivery_boy_id'] is not None:
        flash("Sorry, this order has already been taken or is no longer pending.", 'warning')
        return redirect(url_for('delivery_boy_dashboard'))
    dboy_rec = db.execute('SELECT id, name, mobile_number FROM delivery_boys WHERE user_id = ?', (current_user.id,)).fetchone()
    if not dboy_rec:
        flash('Could not identify your delivery profile.', 'danger')
        return redirect(url_for('delivery_boy_dashboard'))
    delivery_boy_id = dboy_rec['id']
    delivery_boy_name = dboy_rec['name']
    new_status = 'Order Picked Up'
    db.execute("UPDATE orders SET status = ?, delivery_boy_id = ? WHERE id = ?", (new_status, delivery_boy_id, order_id))
    db.commit()
    customer_id = order['user_id']
    create_notification(customer_id, f"Your order #{order_id} has been picked up by {delivery_boy_name}.", order_id)
    flash(f"Order #{order_id} has been assigned to you, {delivery_boy_name}!", 'success')
    return redirect(url_for('order_detail', order_id=order_id))

@app.route('/delivery/update_status/<int:order_id>', methods=['POST'])
@delivery_boy_required
def update_order_status(order_id):
    new_status = request.form.get('status')
    if not new_status:
        flash('No status provided.', 'warning')
        return redirect(url_for('order_detail', order_id=order_id))
    db = get_db()
    order = db.execute("SELECT user_id FROM orders WHERE id = ?", (order_id,)).fetchone()
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
    db.commit()
    if order:
        create_notification(order['user_id'], f"The status of your order #{order_id} has been updated to '{new_status}'.", order_id)
    flash(f"Order #{order_id} status updated to '{new_status}'.", 'success')
    return redirect(url_for('order_detail', order_id=order_id))

@app.route('/delivery/cancel_order/<int:order_id>', methods=['POST'])
@delivery_boy_required
def cancel_order_by_dboy(order_id):
    reason = request.form.get('reason')
    if not reason:
        reason = "No reason provided."
    db = get_db()
    order = db.execute('SELECT id, user_id, delivery_boy_id FROM orders WHERE id = ?', (order_id,)).fetchone()
    dboy_rec = db.execute('SELECT id, name, mobile_number FROM delivery_boys WHERE user_id = ?', (current_user.id,)).fetchone()
    if not order or not dboy_rec or order['delivery_boy_id'] != dboy_rec['id']:
        flash('You do not have permission to cancel this order.', 'danger')
        return redirect(url_for('delivery_boy_dashboard'))
    reason_str = f"Cancelled by Delivery Boy::{dboy_rec['name']}::{dboy_rec['mobile_number']}::{reason}"
    db.execute("UPDATE orders SET status = 'Cancelled', cancellation_reason = ? WHERE id = ?", (reason_str, order_id))
    db.commit()
    create_notification(order['user_id'], f"Your order #{order_id} was cancelled by the delivery boy. Reason: {reason}", order_id)
    admin_user = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if admin_user:
        create_notification(admin_user['id'], f"Order #{order_id} was cancelled by delivery boy {dboy_rec['name']}.", order_id)
    flash(f'Order #{order_id} has been cancelled.', 'success')
    return redirect(url_for('delivery_boy_dashboard'))

@app.route('/delivery/leave_order/<int:order_id>', methods=['POST'])
@delivery_boy_required
def leave_order(order_id):
    reason = request.form.get('reason')
    if not reason:
        reason = "No reason provided."
    db = get_db()
    order = db.execute('SELECT id, user_id, delivery_boy_id FROM orders WHERE id = ?', (order_id,)).fetchone()
    dboy_rec = db.execute('SELECT id, name, mobile_number FROM delivery_boys WHERE user_id = ?', (current_user.id,)).fetchone()
    if not order or not dboy_rec or order['delivery_boy_id'] != dboy_rec['id']:
        flash('You do not have permission to leave this order.', 'danger')
        return redirect(url_for('delivery_boy_dashboard'))
    reason_str = f"Left by Delivery Boy::{dboy_rec['name']}::{dboy_rec['mobile_number']}::{reason}"
    db.execute("UPDATE orders SET status = 'Pending', delivery_boy_id = NULL, cancellation_reason = ? WHERE id = ?", (reason_str, order_id))
    db.commit()
    create_notification(order['user_id'], f"Delivery for order #{order_id} was left by the partner. It is now pending again.", order_id)
    admin_user = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if admin_user:
        create_notification(admin_user['id'], f"Order #{order_id} was left by delivery boy {dboy_rec['name']}. Reason: {reason}", order_id)
    flash(f'You have left Order #{order_id}. It is now available for other delivery boys.', 'info')
    return redirect(url_for('delivery_boy_dashboard'))

# Customer order cancellation route
@app.route('/customer/cancel_order/<int:order_id>', methods=['POST'])
@customer_required
def cancel_order_by_customer(order_id):
    reason = request.form.get('reason')
    if not reason:
        flash('A reason is required to cancel the order.', 'danger')
        return redirect(url_for('order_detail', order_id=order_id))
    db = get_db()
    order = db.execute('SELECT id, user_id, status, delivery_boy_id FROM orders WHERE id = ?', (order_id,)).fetchone()
    if not order or order['user_id'] != current_user.id:
        flash('You do not have permission to cancel this order.', 'danger')
        return redirect(url_for('view_orders'))
    if order['status'] == 'Cancelled':
        flash('This order has already been cancelled.', 'warning')
        return redirect(url_for('order_detail', order_id=order_id))
    if order['status'] != 'Pending':
        flash(f"Cannot cancel order. A delivery boy has already processed it (Status: {order['status']}).", 'danger')
        return redirect(url_for('order_detail', order_id=order_id))
    reason_str = f'Cancelled by customer: {reason}'
    db.execute("UPDATE orders SET status = 'Cancelled', cancellation_reason = ? WHERE id = ?", (reason_str, order_id))
    db.commit()
    admin_user = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if admin_user:
        create_notification(admin_user['id'], f"Order #{order_id} was cancelled by customer {current_user.username}. Reason: {reason}", order_id)
    flash('Your order has been successfully cancelled.', 'success')
    return redirect(url_for('order_detail', order_id=order_id))

# Notification routes
@app.route('/notifications')
@login_required
def get_notifications():
    db = get_db()
    notifications = db.execute(
        'SELECT id, message, timestamp, link_url, is_read FROM notifications WHERE user_id = ? ORDER BY timestamp DESC LIMIT 15',
        (current_user.id,)
    ).fetchall()
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', (current_user.id,))
    db.commit()
    return jsonify([{
        'id': n['id'],
        'message': n['message'],
        'timestamp': n['timestamp'],
        'link_url': n['link_url'],
        'is_read': n['is_read']
    } for n in notifications])

@app.route('/notifications/delete/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    db = get_db()
    notification = db.execute(
        'SELECT id FROM notifications WHERE id = ? AND user_id = ?',
        (notification_id, current_user.id)
    ).fetchone()
    if notification:
        db.execute('DELETE FROM notifications WHERE id = ?', (notification_id,))
        db.commit()
        return jsonify({'success': True, 'message': 'Notification deleted.'}), 200
    else:
        return jsonify({'success': False, 'message': 'Notification not found or permission denied.'}), 404

@app.route('/notifications/clear_all', methods=['POST'])
@login_required
def clear_all_notifications():
    db = get_db()
    db.execute('DELETE FROM notifications WHERE user_id = ?', (current_user.id,))
    db.commit()
    return jsonify({'success': True, 'message': 'All notifications cleared.'}), 200

# Forgot username route
@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = User.get_by_email(email)
        flash_message = 'If an account with that email exists, your username has been sent to your email.'
        if user and user.email: # Check if email exists before trying to send
            plain_body = f"Hello,\n\nHere is your username for CO: {user.username}\n\nIf you did not request this, please ignore this email."
            html_body = f"""
            <div style="font-family: sans-serif; line-height: 1.6; color: #333;">
                <p>Hello,</p>
                <p>You recently requested a username reminder for your CO Shopping account.</p>
                <div style="padding: 15px; border: 1px solid #ddd; background-color: #f9f9f9; border-radius: 8px; margin: 20px 0;">
                    <p style="margin: 0; font-size: 16px; font-weight: bold;">Your Username: <span style="color: #007bff;">{user.username}</span></p>
                </div>
                <p>If you did not request this, please ignore this email.</p>
                <p>Thank you,<br>CO Shopping Team.</p>
            </div>
            """
            if not send_email(user.email, "Your CO Shopping Account Username Reminder", plain_body, html_body=html_body):
                flash_message = 'Failed to send email. Please try again later.'
        flash(flash_message, 'info')
        return redirect(url_for('login'))
    return render_template('forgot_username.html')

# Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = User.get_by_email(email)
        db = get_db()
        flash_message = 'If an account with that email exists, a password reset link has been sent to your email.'
        if user and user.email: # Check if email exists before trying to send
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            db.execute('UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?',
                       (token, expires_at.isoformat(), user.id))
            db.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = "CO Shopping Account Password Reset Request"
            plain_body = f"Hello {user.username},\n\nYou have requested a password reset for your CO Shopping account.\n" \
                         f"Please click on the following link to reset your password: {reset_url}\n" \
                         f"This link is valid for 1 hour.\n\n" \
                         f"If you did not request a password reset, please ignore this email.\n\n" \
                         f"Alternatively, copy and paste this URL into your browser: {reset_url}"
            html_body = f"""
            <div style="font-family: sans-serif; line-height: 1.6; color: #333;">
                <p>Hello {user.username},</p>
                <p>You have requested a password reset for your CO Shopping account.</p>
                <p>Please click the button below to reset your password:</p>
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; box-sizing: border-box; width: 100%;">
                    <tbody>
                        <tr>
                            <td align="left" style="font-family: sans-serif; font-size: 14px; vertical-align: top; padding-bottom: 15px;">
                                <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: auto;">
                                    <tbody>
                                        <tr>
                                            <td style="font-family: sans-serif; font-size: 14px; vertical-align: top; border-radius: 5px; text-align: center; background-color: #3498db;">
                                                <a href="{reset_url}" target="_blank" style="border: solid 1px #3498db; border-radius: 5px; box-sizing: border-box; cursor: pointer; text-decoration: none; font-size: 14px; font-weight: bold; margin: 0; padding: 12px 25px; text-transform: capitalize; background-color: #3498db; border-color: #3498db; color: #ffffff;">Reset Your Password</a>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <p>This link is valid for 1 hour.</p>
                <p>If you did not request a password reset, please ignore this email.</p>
                <p>Thank you,<br>CO Shopping Team.</p>
            </div>
            """
            if not send_email(user.email, subject, plain_body, html_body=html_body):
                flash_message = 'Failed to send email. Please try again later.'
        flash(flash_message, 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

# Password reset route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    db = get_db()
    # Corrected: Fetch all columns needed by the User constructor
    user_data = db.execute(
        'SELECT id, username, password, is_admin, is_delivery_boy, email, reset_token, reset_token_expires_at FROM users WHERE reset_token = ?',
        (token,)
    ).fetchone()
    
    user_for_reset = None
    if user_data:
        if user_data['reset_token'] == token and user_data['reset_token_expires_at']:
            try:
                expires_at = datetime.strptime(user_data['reset_token_expires_at'], '%Y-%m-%dT%H:%M:%S.%f')
                if expires_at > datetime.now():
                    # Corrected: Instantiate the User object with all required data
                    user_for_reset = User(
                        user_data['id'],
                        user_data['username'],
                        user_data['password'],
                        user_data['is_admin'],
                        user_data['is_delivery_boy'],
                        user_data['email'],
                        user_data['reset_token'],
                        user_data['reset_token_expires_at']
                    )
                else:
                    flash('Password reset link has expired. Please request a new one.', 'danger')
            except (ValueError, TypeError):
                flash('Invalid reset token or format. Please request a new one.', 'danger')
        else:
            flash('Invalid or expired password reset link.', 'danger')
    else:
        flash('Invalid password reset link.', 'danger')
    
    if not user_for_reset:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?',
                   (hashed_password, user_for_reset.id))
        db.commit()
        flash('Your password has been reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    print(f"Created upload folder: {UPLOAD_FOLDER}")

init_db()

if __name__ == '__main__':
    if not os.path.exists('schema.sql'):
        print("Creating schema.sql for initial database setup...")
        with open('schema.sql', 'w') as f:
            f.write("""
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image_url TEXT,
    category TEXT NOT NULL DEFAULT 'Electronics'
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    is_delivery_boy BOOLEAN NOT NULL DEFAULT 0,
    email TEXT UNIQUE,
    reset_token TEXT,
    reset_token_expires_at TEXT
);
CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    UNIQUE(user_id, product_id)
);
CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    address_line1 TEXT NOT NULL,
    address_line2 TEXT,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    zip_code TEXT NOT NULL,
    country TEXT NOT NULL,
    is_default BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_date TEXT NOT NULL,
    total_amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    shipping_address_id INTEGER NOT NULL,
    payment_method TEXT NOT NULL DEFAULT 'Cash on Delivery',
    delivery_boy_id INTEGER,
    cancellation_reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (shipping_address_id) REFERENCES addresses(id),
    FOREIGN KEY (delivery_boy_id) REFERENCES delivery_boys(id)
);
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price_at_purchase REAL NOT NULL,
    product_name_at_purchase TEXT,
    product_image_url_at_purchase TEXT,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS approved_pincodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pincode TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS delivery_boys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mobile_number TEXT NOT NULL UNIQUE,
    whatsapp_mobile_number TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    user_id INTEGER UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS delivery_boy_pincodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_boy_id INTEGER NOT NULL,
    pincode TEXT NOT NULL,
    FOREIGN KEY (delivery_boy_id) REFERENCES delivery_boys(id) ON DELETE CASCADE,
    UNIQUE(delivery_boy_id, pincode)
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    link_url TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
""")
    app.run(debug=True)
