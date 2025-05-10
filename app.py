from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
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
app.secret_key = secrets.token_hex(16)

# Configuration
UPLOAD_FOLDER = 'uploads'
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
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup
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
    conn = sqlite3.connect('quantumly.db')
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
    cursor.execute("SELECT COUNT(*) FROM admin_users WHERE username = 'admin234'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO admin_users (username, password) VALUES (?, ?)", 
                      ('admin234', 'netflixx254'))
    
    conn.commit()
    conn.close()

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
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_b2(file):
    """Upload file to B2 and return signed URL"""
    if not file or not file.filename:
        return None
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/application')
def application():
    return render_template('application.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
    try:
        b2 = get_b2_client()
        filename = f"{datetime.now().timestamp()}_{secure_filename(file.filename)}"
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
            'payrate': request.form['payrate'],
            'hours_per_week': request.form['hours_per_week'],
            'gender': request.form.get('gender', ''),
            'race': request.form.get('race', ''),
            'veteran_status': request.form.get('veteran_status', '')
        }

        # Create unique application folder
        timestamp = str(int(datetime.now().timestamp()))
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], timestamp)
        os.makedirs(upload_dir, exist_ok=True)

        # Process file uploads
        file_paths = {}
        for file_type in ['photo', 'resume', 'cover_letter', 'proof_residence', 'dl_front', 'dl_back']:
            file = request.files.get(file_type)
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                relative_path = os.path.join(timestamp, filename)
                absolute_path = os.path.join(app.config['UPLOAD_FOLDER'], relative_path)
                file.save(absolute_path)
                file_paths[f'{file_type}_path'] = relative_path
            else:
                file_paths[f'{file_type}_path'] = None

        # Save to database
        conn = sqlite3.connect('quantumly.db')
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
            *form_data.values(),
            file_paths['photo_path'],
            file_paths['resume_path'],
            file_paths['cover_letter_path'],
            file_paths['proof_residence_path'],
            file_paths['dl_front_path'],
            file_paths['dl_back_path'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
        
        conn.commit()
        conn.close()

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
        return render_template('success.html')
    
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
        flash(f"Error submitting application: {str(e)}")
        return redirect(url_for('application'))

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
@app.route('/uploads/<path:filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
        
        conn = sqlite3.connect('quantumly.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?", 
                      (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
            return redirect(url_for('admin_dashboard'))
        else:
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
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('quantumly.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY date_submitted DESC")
    applications = cursor.fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', applications=applications)

@app.route('/application_details/<int:id>')
def application_details(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('quantumly.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id = ?", (id,))
    application = cursor.fetchone()
    conn.close()
    
    if application:
        return jsonify({k: application[k] for k in application.keys()})
    return jsonify({"error": "Application not found"}), 404

@app.route('/logout')
def logout():
    session.clear()
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
    app.run(debug=True)
