from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
csrf = CSRFProtect(app)

# Configuration
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max file size
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check if running on Render
is_render = os.environ.get('RENDER', 'false').lower() == 'true'

# Database setup
def get_db_connection():
    """Connect to the database with proper path handling for Render deployment"""
    db_path = 'quantumly.db'
    if is_render:
        # Use persistent disk on Render
        db_path = '/data/quantumly.db'
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Applications table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        last_name TEXT NOT NULL,
        first_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        location TEXT NOT NULL,
        current_company TEXT NOT NULL,
        linkedin TEXT,
        facebook TEXT,
        country_birth TEXT NOT NULL,
        country_residence TEXT NOT NULL,
        us_state TEXT,
        extra_language TEXT,
        education TEXT NOT NULL,
        payrate REAL NOT NULL,
        hours_per_week INTEGER NOT NULL,
        gender TEXT,
        race TEXT,
        veteran_status TEXT,
        photo_path TEXT,
        resume_path TEXT,
        cover_letter_path TEXT,
        proof_residence_path TEXT,
        dl_front_path TEXT,
        dl_back_path TEXT,
        date_submitted TIMESTAMP
    )
    ''')
    
    # Admin users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Create default admin if not exists
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    default_password = os.environ.get('ADMIN_PASSWORD', 'change_me_immediately')
    
    cursor.execute("SELECT COUNT(*) FROM admin_users WHERE username = ?", (admin_username,))
    if cursor.fetchone()[0] == 0:
        # Create a default admin with a hashed password
        hashed_password = generate_password_hash(default_password)
        cursor.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", 
                      (admin_username, hashed_password))
        logger.warning(f"Created default admin user '{admin_username}'. Please change the password immediately!")
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Helpers
def allowed_file(filename):
    """Check if a filename has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# B2 Storage Integration
def get_b2_client():
    """Initialize and return a B2 client using boto3"""
    try:
        return boto3.client(
            's3',
            endpoint_url='s3.us-east-005.backblazeb2.com',  
            aws_access_key_id=os.environ.get('B2_KEY_ID'),
            aws_secret_access_key=os.environ.get('B2_APP_KEY')
        )
    except Exception as e:
        logger.error(f"Failed to initialize B2 client: {e}")
        return None

def upload_file_to_b2(file):
    """Uploads file to Backblaze B2 and returns the public URL"""
    # Check if file exists
    if not file or not file.filename:
        return None
        
    # Get bucket name from environment
    bucket_name = os.environ.get('B2_BUCKET_NAME')
    if not bucket_name:
        logger.error("B2_BUCKET_NAME environment variable not set")
        return None
        
    # Get B2 client
    b2_client = get_b2_client()
    if not b2_client:
        logger.error("Failed to get B2 client")
        return None
        
    try:
        # Create a unique filename to prevent collisions
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        unique_filename = f"{timestamp}_{secure_filename(file.filename)}"
        
        # Reset file pointer to beginning
        file.seek(0)
        
        # Upload the file to B2
        b2_client.upload_fileobj(
            file,
            bucket_name,
            unique_filename,
            ExtraArgs={
                'ContentType': file.content_type
            }
        )
        
        # Return the public URL to the file
        return f"https://f002.backblazeb2.com/file/{bucket_name}/{unique_filename}"
    except Exception as e:
        logger.error(f"Error uploading file to Backblaze B2: {e}")
        return None

# Routes
@app.route('/')
def index():
    """Home page route"""
    return render_template('index.html')

@app.route('/application')
def application():
    """Application form page route"""
    return render_template('application.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
    """Handle application form submission with file uploads to B2"""
    try:
        # Get form data
        form_data = {
            'last_name': request.form['last_name'],
            'first_name': request.form['first_name'],
            'email': request.form['email'],
            'phone': request.form['phone'],
            'location': request.form['location'],
            'current_company': request.form['current_company'],
            'linkedin': request.form.get('linkedin', ''),
            'facebook': request.form.get('facebook', ''),
            'country_birth': request.form['country_birth'],
            'country_residence': request.form['country_residence'],
            'us_state': request.form.get('us_state', ''),
            'extra_language': request.form.get('extra_language', ''),
            'education': request.form['education'],
            'payrate': float(request.form['payrate']),
            'hours_per_week': int(request.form['hours_per_week']),
            'gender': request.form.get('gender', ''),
            'race': request.form.get('race', ''),
            'veteran_status': request.form.get('veteran_status', '')
        }

        # Process file uploads
        file_paths = {}
        required_files = ['resume']  # Add any files that are required
        
        for file_type in ['photo', 'resume', 'cover_letter', 'proof_residence', 'dl_front', 'dl_back']:
            file = request.files.get(file_type)
            
            # Check if required files are present
            if file_type in required_files and (not file or not file.filename):
                flash(f"Please upload your {file_type.replace('_', ' ')}.")
                return redirect(url_for('application'))
                
            if file and file.filename:
                # Check if file type is allowed
                if not allowed_file(file.filename):
                    flash(f"Invalid file type for {file_type}. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}")
                    return redirect(url_for('application'))
                
                # Upload file to B2
                file_url = upload_file_to_b2(file)
                
                if not file_url and file_type in required_files:
                    flash(f"Failed to upload {file_type}. Please try again.")
                    return redirect(url_for('application'))
                
                file_paths[f'{file_type}_path'] = file_url
            else:
                file_paths[f'{file_type}_path'] = None

        # Save form data and file paths to the database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO applications (
                last_name, first_name, email, phone, location, current_company,
                linkedin, facebook, country_birth, country_residence, us_state,
                extra_language, education, payrate, hours_per_week, gender, race,
                veteran_status, photo_path, resume_path, cover_letter_path,
                proof_residence_path, dl_front_path, dl_back_path, date_submitted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            form_data['last_name'], form_data['first_name'], form_data['email'], 
            form_data['phone'], form_data['location'], form_data['current_company'],
            form_data['linkedin'], form_data['facebook'], form_data['country_birth'], 
            form_data['country_residence'], form_data['us_state'],
            form_data['extra_language'], form_data['education'], form_data['payrate'], 
            form_data['hours_per_week'], form_data['gender'], form_data['race'],
            form_data['veteran_status'],
            file_paths.get('photo_path'),
            file_paths.get('resume_path'),
            file_paths.get('cover_letter_path'),
            file_paths.get('proof_residence_path'),
            file_paths.get('dl_front_path'),
            file_paths.get('dl_back_path'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        conn.commit()
        conn.close()
        
        return render_template('success.html')
    
    except Exception as e:
        logger.error(f"Error submitting application: {str(e)}")
        flash(f"Error submitting application. Please try again later.")
        return redirect(url_for('application'))

@app.route('/view_file/<path:file_type>/<int:application_id>')
@login_required
def view_file(file_type, application_id):
    """Redirect to file in B2 storage"""
    # Validate file_type to prevent SQL injection
    valid_file_types = ['photo', 'resume', 'cover_letter', 'proof_residence', 'dl_front', 'dl_back']
    if file_type not in valid_file_types:
        flash("Invalid file type.")
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT {file_type}_path FROM applications WHERE id = ?", (application_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[f"{file_type}_path"]:
        return redirect(result[f"{file_type}_path"])
    else:
        flash(f"{file_type.replace('_', ' ').title()} not found.")
        return redirect(url_for('admin_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle admin login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            
            # Redirect to 'next' parameter if available
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard showing all applications"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY date_submitted DESC")
    applications = cursor.fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', applications=applications)

@app.route('/application_details/<int:id>')
@login_required
def application_details(id):
    """Get application details as JSON"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id = ?", (id,))
    application = cursor.fetchone()
    conn.close()
    
    if application:
        return jsonify({k: application[k] for k in application.keys()})
    return jsonify({"error": "Application not found"}), 404

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({"status": "healthy"})

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file size limit exceeded errors"""
    flash('File too large! Maximum file size is 10MB.')
    return redirect(url_for('application')), 413

if __name__ == '__main__':
    # Use environment variables for deployment configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    # In production, always set debug=False
    if os.environ.get('FLASK_ENV') == 'production':
        debug = False
    
    app.run(host='0.0.0.0', port=port, debug=debug)
