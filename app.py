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

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
csrf = CSRFProtect(app)

# Configuration
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment detection
is_render = os.environ.get('RENDER', 'false').lower() == 'true'

# Database configuration
def get_db_path():
    """Get appropriate database path for environment"""
    if is_render:
        persistent_dir = os.environ.get('RENDER_PERSISTENT_DIR', os.path.dirname(__file__))
        return os.path.join(persistent_dir, 'quantumly.db')
    return 'quantumly.db'

def get_db_connection():
    """Establish database connection with proper path"""
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                last_name TEXT NOT NULL,
                first_name TEXT NOT NULL,
                email TEXT NOT NULL,
                resume_path TEXT NOT NULL,
                date_submitted TIMESTAMP NOT NULL
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Create default admin if needed
        admin_exists = conn.execute(
            "SELECT 1 FROM admin_users WHERE username = 'admin'"
        ).fetchone()
        
        if not admin_exists:
            hashed_pw = generate_password_hash(os.environ.get('ADMIN_INITIAL_PW', 'admin'))
            conn.execute(
                "INSERT INTO admin_users (username, password) VALUES (?, ?)",
                ('admin', hashed_pw)
            )

init_db()

# Backblaze B2 configuration
def get_b2_client():
    """Initialize authenticated B2 client"""
    return boto3.client(
        's3',
        endpoint_url=os.environ.get('B2_ENDPOINT'),
        aws_access_key_id=os.environ.get('B2_KEY_ID'),
        aws_secret_access_key=os.environ.get('B2_APP_KEY')
    )

def upload_to_b2(file):
    """Upload file to B2 and return signed URL"""
    if not file or not file.filename:
        return None

    try:
        b2 = get_b2_client()
        filename = f"{datetime.now().timestamp()}_{secure_filename(file.filename)}"
        
        file.seek(0)
        b2.upload_fileobj(
            Fileobj=file,
            Bucket=os.environ.get('B2_BUCKET'),
            Key=filename,
            ExtraArgs={'ContentType': file.content_type}
        )

        return b2.generate_presigned_url(
            'get_object',
            Params={'Bucket': os.environ.get('B2_BUCKET'), 'Key': filename},
            ExpiresIn=3600  # 1 hour expiration
        )
    except Exception as e:
        logger.error(f"B2 Upload Failed: {str(e)}")
        return None

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in first')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        try:
            # Process form data
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            resume = request.files['resume']

            # Validate resume
            if not (resume and allowed_file(resume.filename)):
                flash('Invalid resume file')
                return redirect(url_for('apply'))

            # Upload resume
            resume_url = upload_to_b2(resume)
            if not resume_url:
                flash('Failed to upload resume')
                return redirect(url_for('apply'))

            # Save to database
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO applications 
                    (first_name, last_name, email, resume_path, date_submitted)
                    VALUES (?, ?, ?, ?, ?)
                ''', (first_name, last_name, email, resume_url, datetime.now()))
                conn.commit()

            return redirect(url_for('application_success'))

        except Exception as e:
            logger.error(f"Application Error: {str(e)}")
            flash('Error submitting application')
            return redirect(url_for('apply'))

    return render_template('apply.html')

@app.route('/success')
def application_success():
    return render_template('success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT * FROM admin_users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db_connection() as conn:
        applications = conn.execute(
            "SELECT * FROM applications ORDER BY date_submitted DESC"
        ).fetchall()
    return render_template('dashboard.html', applications=applications)

@app.route('/view_resume/<int:app_id>')
@login_required
def view_resume(app_id):
    with get_db_connection() as conn:
        resume = conn.execute(
            "SELECT resume_path FROM applications WHERE id = ?",
            (app_id,)
        ).fetchone()

    if not resume or not resume['resume_path']:
        flash('Resume not found')
        return redirect(url_for('dashboard'))

    try:
        # Generate fresh signed URL
        b2 = get_b2_client()
        file_key = resume['resume_path'].split('/')[-1].split('?')[0]
        new_url = b2.generate_presigned_url(
            'get_object',
            Params={'Bucket': os.environ.get('B2_BUCKET'), 'Key': file_key},
            ExpiresIn=3600
        )
        return redirect(new_url)
    except Exception as e:
        logger.error(f"Resume Access Error: {str(e)}")
        flash('Error accessing resume')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
