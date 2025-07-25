from flask import Flask, render_template, redirect, session, url_for,request, flash, jsonify,send_file,Response
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import secrets
import stripe
import uuid
import os
import re
import json
import pytz
from datetime import datetime
from flask_mail import Mail, Message
from google.cloud import firestore
from google.oauth2 import service_account
from datetime import datetime, timedelta
from jinja2 import Template
from tzlocal import get_localzone
from functools import wraps
from dotenv import load_dotenv
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, BooleanField
from translations import translations
from translations_about import translations_about
from translations_dashboard import translations_dashboard
from translations_contact import translations_contact
from translations_privacy import translations_privacy
from translations_register import translations_register
from translations_signin import translations_signin
from translations_pricing import translations_price
from helpers import get_user_conversions,update_user_conversions,get_conversion_context,validate_and_process_pdf
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from datetime import datetime



class RegistrationForm(FlaskForm):
    firstName = StringField('First Name',
                          validators=[DataRequired(), Length(min=2, max=50)],
                          render_kw={'class': 'form-control',
                                   'placeholder': 'Enter first name',
                                   'data-validate': 'required'})
    lastName = StringField('Last Name',
                         validators=[DataRequired(), Length(min=2, max=50)],
                         render_kw={'class': 'form-control',
                                  'placeholder': 'Enter last name'})
    email = StringField('Email',
                       validators=[DataRequired(), Email()],
                       render_kw={'class': 'form-control',
                                'type': 'email',
                                'placeholder': 'Enter email address'})
    password = PasswordField('Password',
                           validators=[DataRequired(), Length(min=8)],
                           render_kw={'class': 'form-control',
                                    'data-validate': 'password'})
    confirmPassword = PasswordField('Confirm Password',
                                  validators=[DataRequired(), EqualTo('password')],
                                  render_kw={'class': 'form-control'})
    termsCheck = BooleanField('Accept Terms and Conditions',
                            validators=[DataRequired()],
                            render_kw={'class': 'form-check-input',
                                     'data-validate': 'required'})
    
class LoginForm(FlaskForm):
    email = StringField('Email Address',
                       validators=[DataRequired(), Email(), Length(max=254)],
                       render_kw={'class': 'form-control',
                                'placeholder': 'Enter email address'})
    password = PasswordField('Password',
                           validators=[DataRequired(), Length(min=8)],
                           render_kw={'class': 'form-control'})
    remember_me = BooleanField('Remember me',
                              render_kw={'class': 'form-check-input'})

    

load_dotenv()
local_timezone = get_localzone().key

if os.getenv('ENVIRONMENT') == 'development':
    db = firestore.Client.from_service_account_json('./serviceAccountKey.json')
else:
    service_account_info = {
        "type": os.getenv('type'),
        "project_id": os.getenv('project_id'),
        "private_key_id": os.getenv('private_key_id'),
        "private_key": os.getenv('private_key').replace('\\n', '\n'),
        "client_email": os.getenv('client_email'),
        "client_id": os.getenv('client_id'),
        "auth_uri": os.getenv('auth_uri'),
        "token_uri": os.getenv('token_uri'),
        "auth_provider_x509_cert_url": os.getenv('auth_provider_x509_cert_url'),
        "client_x509_cert_url": os.getenv('client_x509_cert_url'),
        "universe_domain": os.getenv('universe_domain')
    }

    credentials = service_account.Credentials.from_service_account_info(service_account_info)

    db = firestore.Client(credentials=credentials)

# Initialize Firebase  

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config.setdefault('TIMEZONE', local_timezone)
csrf = CSRFProtect(app)




app.config.update(
    #Mail-server
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT')),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS') == 'True',
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL') == 'True',
    
    #stripe
    STRIPE_PUBLISHABLE_KEY=os.getenv('STRIPE_PUBLISHABLE_KEY'),
    STRIPE_SECRET_KEY=os.getenv('STRIPE_SECRET_KEY'),
    STRIPE_PRICE_ID=os.getenv('STRIPE_PRICE_ID'),
    STRIPE_ENDPOINT_SECRET=os.getenv('STRIPE_ENDPOINT_SECRET'),

    #session
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function


# Create blueprint
mail = Mail(app)


@app.template_filter()
def pluralize(value):
    if value != 1:
        return 's'
    return ''


@app.template_filter()
def time_diff(timestamp):
    if timestamp is None:
        return "unknown"
    
    try:
        # Handle both timestamp (int/float) and ISO string formats
        if isinstance(timestamp, str):
            # Parse ISO string - handle both with and without 'Z' suffix
            iso_string = timestamp.replace('Z', '+00:00') if timestamp.endswith('Z') else timestamp
            dt = datetime.fromisoformat(iso_string)
        else:
            # Handle numeric timestamp
            dt = datetime.fromtimestamp(timestamp)
        
        # Handle timezone
        try:
            tz = pytz.timezone(app.config['TIMEZONE'])
            now = datetime.now(tz)
            
            # Make dt timezone-aware if it isn't already
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=tz)
            else:
                # Convert to the app's timezone if it has a different timezone
                dt = dt.astimezone(tz)
        except (TypeError, pytz.exceptions.UnknownTimeZoneError):
            now = datetime.now()
            # Strip timezone info from dt if now is naive
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
        
        diff = dt - now
        if diff.total_seconds() <= 0:
            return "Time has passed"
        
        total_seconds = int(diff.total_seconds())
        days = total_seconds // (24 * 3600)
        hours = (total_seconds % (24 * 3600)) // 3600
        minutes = (total_seconds % 3600) // 60
        
        # Format the time string
        if days > 0:
            time_str = f"{days} days, {hours} hours and {minutes} minutes"
        elif hours > 0:
            time_str = f"{hours} hours and {minutes} minutes"
        else:
            time_str = f"{minutes} minutes"
        
        return time_str
        
    except Exception as e:
        print(f"Error in time_diff filter: {e}")
        return "unknown"


@app.route('/sitemap_site.xml', methods=['GET'])
def sitemap():
    # Only include the home endpoint
    home_url = url_for('home', _external=True)
    pages = [{
        "loc": home_url,
    }]
    
    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    return Response(sitemap_xml, mimetype='application/xml')


def send_verification_email(email, verification_link, first_name, uid):
    """Send verification email using Flask-Mail with Mailtrap"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <!-- Header -->
            <div style="background: linear-gradient(45deg, #2575fc, #6a11cb); padding: 20px; color: white; text-align: center;">
                <h1 style="margin: 0;">Bank Statement Converter</h1>
            </div>
            
            <!-- Content -->
            <div style="padding: 20px;">
                <h2 style="color: #333; margin-top: 0;">Hello {{ first_name }},</h2>
                <p style="margin: 1em 0;">Thank you for registering for Bank Statement Converter. Your User ID is: <strong>{{ uid }}</strong></p>
                
                <p style="margin: 1em 0;">To complete your registration and verify your email address, please click the button below:</p>
                
                <p style="text-align: center; margin: 1em 0;">
                    <a href="{{ verification_link }}" 
                       style="background: linear-gradient(45deg, #2575fc, #6a11cb); 
                             color: white; 
                             padding: 12px 25px; 
                             text-decoration: none; 
                             border-radius: 5px; 
                             display: inline-block; 
                             margin: 20px 0;
                             box-shadow: 0 2px 5px rgba(0,0,0,0.2);">
                        Verify Email Address
                    </a>
                </p>
                
                <p style="margin: 1em 0;">This verification link will expire in 24 hours.</p>
                <p style="margin: 1em 0;">If you did not create an account, please ignore this email.</p>
                
                <!-- Footer -->
                <div style="margin-top: 30px; font-size: 12px; color: #777;">
                    <p>&copy; {{ current_year }} Bank Statement Converter. All rights reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Render template with variables
    template = Template(html_template)
    html_content = template.render(
        first_name=first_name,
        verification_link=verification_link,
        uid=uid,
        current_year=datetime.now().year
    )
    
    # Create message
    msg = Message(
        sender="support@bankstatementconverter.online",
        subject="Verify Your Bank Statement Converter Account",
        recipients=[email],
        html=html_content
    )
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def add_days_to_timestamp(timestamp=None, days=30):
    dt = datetime.fromtimestamp(timestamp) if timestamp is not None else datetime.now()
    future_dt = dt + timedelta(days=days)
    return future_dt.timestamp()
    

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Simple testing endpoint that returns a JSON response."""
    return {
        "status": "success",
        "message": "The API is working correctly!"
    }

@app.route("/set_lang/<language>")
def set_language(language):
    if language in translations:
        session["lang"] = language  
    referrer = request.referrer 
    return redirect(referrer)
    

@app.route('/')
def home():
    user_conversions = get_user_conversions()
    lang = session.get("lang", "en")  
    text = translations.get(lang, translations["en"])
    
    return render_template('index.html', 
                           text = text,
                         remaining_conversions=user_conversions.get('remaining_conversions'),
                         conversions_reset_time=user_conversions.get('conversions_reset_time'))


@app.route('/convert', methods=['POST'])
def convert():
    try:
        # Get the file
        file = request.files.get('pdf_file')
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        
        # Validate file extension
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Please upload a PDF file'}), 400
        
        # Process PDF
        is_valid, message, processed_file = validate_and_process_pdf(file)
        if not is_valid:
            return jsonify({'error': message}), 400
    
        # Get user conversions
        user_conversions = get_user_conversions()
        
        # Update conversion tracking
        current_timestamp = int(datetime.now().timestamp())
        reset_time_str = user_conversions['conversions_reset_time']
        
        # Convert reset time string to timestamp for comparison
        try:
            reset_timestamp = int(datetime.fromisoformat(reset_time_str.replace('Z', '+00:00')).timestamp())
        except:
            # If parsing fails, create a new reset time
            reset_timestamp = current_timestamp - 1  # Force reset
        
        # Check if reset is needed
        if current_timestamp >= reset_timestamp:
            # Get user's plan to determine conversion limit
            plan = 'free'  # default
            if 'user_id' in session:
                try:
                    user_ref = db.collection('users').document(session['user_id'])
                    user_doc = user_ref.get()
                    if user_doc.exists:
                        user_data = user_doc.to_dict()
                        plan = user_data.get('subscription', {}).get('plan', 'free')
                except Exception as e:
                    print(f"Error getting user plan: {e}")
            
            # Reset conversions based on plan
            new_reset_time = (datetime.now() + timedelta(days=30)).isoformat()
            user_conversions.update({
                'remaining_conversions': 50 if plan == 'premium' else 1,
                'conversions_count': 0,
                'conversions_reset_time': new_reset_time
            })
        else:
            # Check if user has remaining conversions
            if user_conversions['remaining_conversions'] <= 0:
                return jsonify({
                    'error': 'No remaining conversions available',
                    'remaining_conversions': 0
                }), 429
        
        # Update conversion count
        user_conversions['remaining_conversions'] -= 1
        user_conversions['conversions_count'] += 1
        
        # Save the updated conversions
        update_user_conversions(user_conversions)
        
        # Return the CSV file
        processed_file.seek(0)
        return send_file(
            processed_file,
            mimetype='text/csv',
            as_attachment=True,
            download_name='bankstatementconverter.csv'
        )
    
    except Exception as e:
        import traceback
        print(f"Error in convert route: {e}")
        print(f"Full traceback: {traceback.format_exc()}")
        return jsonify({
            'error': str(e),
            'status': 500
        }), 500


@app.route('/verify-email/<token>/<uid>')
def verify_email(token, uid):
    """Handle email verification with proper status checking"""
    try:
        # Get user data
        user_ref = db.collection("users").document(uid)
        user_data = user_ref.get()
        
        # Log document existence
        if not user_data.exists:
            flash("Invalid verification link.", 'error')
            return redirect(url_for('signin'))

        user_doc = user_data.to_dict()
        
        # Check if email is already verified
        if user_doc.get('emailVerified', True):
            flash("Email is already verified.", 'success')
            return redirect(url_for('dashboard'))

        
        # Check token and timestamp validity together
        current_time = datetime.now().timestamp()
        expires_timestamp = current_time + (24 * 60 * 60)
        # time_remaining = max(0, expires_timestamp - current_time)
        
        
        # Combined check for token validity and expiration
        if (user_doc.get('verificationToken') != token or 
            current_time > expires_timestamp):
            flash("Email not verified yet", 'error')
            return redirect(url_for('signin'))

        # Update user data
        updates = {
            'emailVerified': True,
            'active': True,
            'verificationToken': None,
            'verificationExpires': None
        }
        user_ref.update(updates)
        flash("Email verified successfully! You can now log in.", 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        flash(f"An error occurred during verification: {str(e)}", 'error')
        return redirect(url_for('signin'))
    

def create_free_subscription():
    """Create a free subscription plan with basic PDF conversion features"""
    return {
        'plan': 'Free',
        'prompts_limit': 1,
        'features': [
            '1 page per day',
            'PDF to Excel conversion',
            'Basic formatting options'
        ],
        'storage_limit_gb': 0.5,
        'file_size_limit_mb': 5,
        'created_at': firestore.SERVER_TIMESTAMP,
        'status': 'active',
        'last_updated': firestore.SERVER_TIMESTAMP,
        'daily_usage': {
            'pages_processed': 0,
            'last_reset': firestore.SERVER_TIMESTAMP,
            'reset_frequency': 'daily'
        }
}

def create_premium_subscription():
    """Create a premium subscription plan with advanced features"""
    return {
        'plan': 'Premium',
        'prompts_limit': 50,
        'features': [
            '50 pages per day',
            'PDF to Excel conversion',
            'Advanced formatting options',
            'Multiple file formats',
            'Priority processing',
            'Batch processing'
        ],
        'storage_limit_gb': 5,
        'file_size_limit_mb': 50,
        'created_at': firestore.SERVER_TIMESTAMP,
        'status': 'active',
        'last_updated': firestore.SERVER_TIMESTAMP,
        'daily_usage': {
            'pages_processed': 0,
            'last_reset': firestore.SERVER_TIMESTAMP,
            'reset_frequency': 'daily',
            'batch_limit': 10  # Maximum pages per batch
        }
}


@app.route('/register', methods=['GET', 'POST'])
def register():
    lang = session.get("lang", "en")
    text = translations_register.get(lang, translations_register["en"])
    
    form = RegistrationForm()
    
    if request.method == 'POST':
        # Form validation
        if not form.validate_on_submit():
            flash("Please correct the highlighted fields.", 'error')
            return render_template('register.html', form=form,text=text)

        # Get validated form data
        email = form.email.data.lower().strip()  # Normalize email
        password = form.password.data
        
        # Additional validation checks
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$',
                       password):
            flash("Password must contain at least 8 characters, "
                  "including uppercase, lowercase, number and special character.", 'error')
            return render_template('register.html', form=form,text=text)

        try:
            # Check if email exists
            users_ref = db.collection('users')
            doc_ref = users_ref.where('email', '==', email).stream()
            
            if any(doc_ref):
                flash("Email already in use. Please use a different email.", 'error')
                return render_template('register.html', form=form,text=text)

            # Generate unique ID and token
            user_id = str(uuid.uuid4())
            verification_token = secrets.token_urlsafe(32)

            # Prepare user data with validation
            user_data = {
                'firstName': form.firstName.data.strip(),
                'lastName': form.lastName.data.strip(),
                'password': generate_password_hash(password),
                'email': email,
                'createdAt': firestore.SERVER_TIMESTAMP,
                'emailVerified': False,
                'verificationToken': verification_token,
                'verificationExpires': 24,
                'active': False,
                'subscription': create_free_subscription(),
                'conversions': {
                    'remaining_conversions': 1,  # Default number of conversions
                    'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),  # Resets monthly
                    'conversions_count': 0  # Current conversion count
                }
            }

            # Create user document
            db.collection('users').document(user_id).set(user_data)

            verification_link = url_for('verify_email', token=verification_token, uid=user_id, _external=True)
            
            # Send verification email
            if send_verification_email(email, verification_link, form.firstName.data, user_id):
                flash("Registration successful! Please verify your email.", 'success')
            else:
                flash("Registration successful, but we couldn't send the verification email.", 'warning')
            
            return redirect(url_for('signin'))
    

        except Exception as e:
            flash(f"An error occurred: {str(e)}", 'error')
            return render_template('register.html', form=form,text=text)

    return render_template('register.html', form=form,text=text)



@app.route('/login', methods=['GET', 'POST'])
def signin():
    lang = session.get("lang", "en")
    text = translations_signin.get(lang, translations_signin["en"])
    
    form = LoginForm()
    
    if request.method == 'POST':
        
        if form.validate_on_submit():
            try:
                # Get form data
                email = form.email.data.lower().strip()
                password = form.password.data
                remember_me = form.remember_me.data
                
            
                
                # Query Firestore for user
                users_ref = db.collection('users')
                query = users_ref.where(field_path='email', 
                                      op_string='==', 
                                      value=email).limit(1).get()
                
                # Execute query and get results
                user_doc = None
                
                # Check if user exists
                if len(query) > 0:
                    user_doc = query[0]
                    user_data = user_doc.to_dict()
                    
                    
                    # Verify password against stored hash
                    if check_password_hash(user_data.get('password'), password):
                        # Store user data in session
                        session['user_id'] = user_doc.id
                        session['first_name'] = user_data.get('firstName')
                        session['emailVerified'] = user_data.get('emailVerified')
                        
                        # Update last login timestamp
                        user_ref = db.collection('users').document(user_doc.id)
                        user_ref.update({
                            'lastLoginAt': firestore.SERVER_TIMESTAMP
                        })
                        
                        # Handle remember me functionality
                        if remember_me:
                            session.permanent = True
                            app.permanent_session_lifetime = timedelta(days=30)
                        else:
                            session.permanent = False
                        
                        flash("Login successful!", 'success')
                        print(f"Session after login: {dict(session)}")
                        return redirect(url_for('home'))
                    else:
                        print("Password verification failed")
                        flash("Invalid email or password. Please try again.", 'error')
                else:
                    print("User not found")
                    flash("User not found. Please try again.", 'error')
                
                return render_template('signin.html', form=form,text=text)
            
            except Exception as e:
                print(f"Error during login: {str(e)}")
                flash("Login failed. Please try again.", 'error')
                return render_template('signin.html', form=form,text=text)
    
    return render_template('signin.html', form=form,text=text)


@app.route("/config")
def get_publishable_key():
    stripe_config = {"publicKey": os.getenv("STRIPE_PUBLISHABLE_KEY")}
    return jsonify(stripe_config)


@app.route('/create-checkout-session/', methods=['GET'])
def create_checkout_session():
    domain_url = os.getenv("DOMAIN_NAME")+'/'  # Flask runs on port 5000 by default or custom domain???
    try:
        checkout_session = stripe.checkout.Session.create(
            client_reference_id=request.args.get('user_id'),  # Get user_id from the query string
            success_url=domain_url + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=domain_url + 'cancel/',
            payment_method_types=['card'],
            mode='subscription',
            line_items=[
                {
                    'price': os.getenv("STRIPE_PRICE_ID"),  #change this for new price_id for live???
                    'quantity': 1,
                }
            ]
        )
        return jsonify({'sessionId': checkout_session['id']})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    

@app.route("/success")
def success():
    try:
        # Get user data from session
        email = session.get('emailVerified')
        user_id = session.get('user_id')
        
        if not email or not user_id:
            flash("Please verify your email.", 'error')
            return redirect(url_for('home'))
            
        # Get Stripe session ID from URL params
        session_id = request.args.get('session_id')
        if not session_id:
            return redirect(url_for('dashboard'))
            
        # Retrieve the Stripe session to get subscription info
        stripe_session = stripe.checkout.Session.retrieve(session_id)
        subscription_id = stripe_session.subscription
        
        if not subscription_id:
            return redirect(url_for('dashboard'))
            
        # Verify the subscription is active
        subscription = stripe.Subscription.retrieve(subscription_id)
        if subscription.status != 'active':
            return redirect(url_for('dashboard'))
            
        # Update user document in Firestore
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return redirect(url_for('home'))
            
        # Create premium subscription data
        premium_subscription = {
            'plan': 'premium', 
            'prompts_limit': 50,
            'features': [
                '50 pages per day',
                'PDF to Excel conversion',
                'Advanced formatting options',
                'Multiple file formats',
                'Priority processing',
                'Batch processing'
            ],
            'storage_limit_gb': 5,  # 5GB storage
            'file_size_limit_mb': 50,
            'created_at': firestore.SERVER_TIMESTAMP,
            'status': 'active',
            'daily_usage': {
                'pages_processed': 0,
                'last_reset': firestore.SERVER_TIMESTAMP,
                'reset_frequency': 'daily',
                'batch_limit': 10  # Maximum pages per batch
            }
        }
        
        # Create conversions data
        conversions_data = {
            'remaining_conversions': 50,
            'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
            'conversions_count': 0
        }
        
        # Update user document with both subscription and conversions data
        user_ref.update({
            'subscription': premium_subscription,
            'conversions': conversions_data,  # Add this line to update conversions in user doc
            'last_updated': firestore.SERVER_TIMESTAMP
        })
        
        # Update session data
        current_user_data = {
            'email': user_doc.get('email'),
            'createdAt': user_doc.get('createdAt'),
            'lastLoginAt': firestore.SERVER_TIMESTAMP,
            'emailVerified': user_doc.get('emailVerified'),
            'session_id': user_doc.get('session_id', str(uuid.uuid4())),
            'conversions': conversions_data  # Use the new data directly
        }
        
        # Update conversions in session
        session['conversions'] = conversions_data
        session['premium_subscription'] = json.dumps(premium_subscription)
        
        # Update session
        for key, value in current_user_data.items():
            session[key] = value
        
        return redirect(url_for('dashboard'))
        
    except stripe.error.StripeError as e:
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        return redirect(url_for('dashboard'))


    

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    endpoint_secret = os.getenv("WEBHOOK_STRIPE_ENDPOINT_SECRET") #change this after adding domain??
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return jsonify(error=str(e)), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify(error=str(e)), 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Fetch all the required data from session
        client_reference_id = session.get('client_reference_id')
        stripe_customer_id = session.get('customer')
        stripe_subscription_id = session.get('subscription')


    return jsonify(message="Successfully created StripeCustomer..."), 200


@app.route('/cancel/', methods=['GET'])
def cancel():
    flash("Transaction not successful.\nContact us via support@bankstatementconverter.online for support", "error")
    return redirect(url_for('dashboard'))



@app.route('/dashboard')
@require_auth
def dashboard():
    """
    Display user dashboard with profile and subscription information.
    Requires user to be authenticated.
    """
    lang = session.get("lang", "en")
    text = translations_dashboard.get(lang, translations_dashboard["en"])
    
    if 'user_id' not in session:
        flash("Please login to access the dashboard.", 'success')
        return redirect(url_for('signin'))

    try:
        # Get user data from Firestore
        user_ref = db.collection('users').document(session['user_id'])
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            flash("User not found.", 'error')
            return redirect(url_for('signin'))

        user_data = user_doc.to_dict()
        
        # Format dates for display
        formatted_data = {
            'firstName': user_data['firstName'],
            'lastName': user_data['lastName'],
            'email': user_data['email'],
            'subscription': {
                'type': user_data['subscription']['plan'],
                'isActive': user_data['subscription']['status']
            }
        }

        return render_template('dashboard.html', user_data=formatted_data,text=text)

    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect(url_for('signin'))

@app.route('/logout')
def logout():
    """Handle user logout"""
    # Clear session
    session.clear()
    return redirect(url_for('home'))


@app.route('/pricing', methods=['GET'])
def pricing():
    lang = session.get("lang", "en")
    text = translations_price.get(lang, translations_price["en"])
    
    try:
        # First, render the pricing page for all users
        context = {
            'plans': {
                'basic': {
                    'name': 'Basic'
                },
                'premium': {
                    'name': 'Premium'
                }
            }
        }
        
        if 'user_id' in session:
            user_ref = db.collection('users').document(session['user_id'])
            user_doc = user_ref.get()
            
            if user_doc.exists:
                user_data = user_doc.to_dict()
                subscription_status = user_data.get('subscription', {}).get('status')
                stripe_subscription_id = user_data.get('subscription', {}).get('stripe_subscription_id')
                
                if subscription_status == 'premium':
                    try:
                        subscription = stripe.Subscription.retrieve(stripe_subscription_id)
                        if subscription.status != subscription_status:
                            user_ref.set({
                                'subscription': {
                                    'status': subscription.status,
                                    'plan': subscription.plan.id
                                }
                            }, merge=True)
                        subscription_status = subscription.status
                    except stripe.error.StripeError as e:
                        subscription_status = 'error'
                
                context.update({
                    'user_plan': user_data.get('subscription', {}).get('plan'),
                    'subscription_status': subscription_status,
                    'text':text
                })
        
        return render_template('pricing.html', **context)
    
    except Exception as e:
        return render_template('pricing.html', text=text)


@app.route('/about', methods=['GET'])
def about():
    """Endpoint that renders an HTML template."""
    lang = session.get("lang", "en")
    text = translations_about.get(lang, translations_about["en"])
    return render_template('about.html',text=text)


@app.route('/contact', methods=['GET'])
def contact():
    """Endpoint that renders an HTML template."""
    lang = session.get("lang", "en")
    text = translations_contact.get(lang, translations_contact["en"])
    return render_template('contact.html',text=text)


@app.route('/privacy', methods=['GET'])
def privacy():
    lang = session.get("lang", "en")
    text = translations_privacy.get(lang, translations_privacy["en"])
    return render_template('privacy.html',text=text)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

