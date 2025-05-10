import os
import sqlite3
import logging
from datetime import datetime, timedelta
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException # For handling HTTP errors
from supabase import create_client, Client
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, CSRFError # For CSRF protection

# --- Initialize App and Load Environment Variables ---
load_dotenv()
app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))
app.config['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'production') # Default to production

# CSRF Protection
csrf = CSRFProtect(app)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
DB_NAME = 'quantumly.db' # WARNING: SQLite is NOT recommended for production with concurrent users.
                         # Consider Supabase's own PostgreSQL or Render's managed PostgreSQL.

# --- Supabase Configuration ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_BUCKET_NAME = os.environ.get("SUPABASE_BUCKET_NAME")
SUPABASE_BUCKET_IS_PUBLIC = os.environ.get("SUPABASE_BUCKET_IS_PUBLIC", "false").lower() == "true"
SIGNED_URL_EXPIRY_SECONDS = int(os.environ.get("SIGNED_URL_EXPIRY_SECONDS", 3600))

supabase: Client | None = None
if SUPABASE_URL and SUPABASE_KEY and SUPABASE_BUCKET_NAME:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        app.logger.info("Successfully connected to Supabase.")
    except Exception as e:
        app.logger.error(f"Error connecting to Supabase: {e}")
        supabase = None
else:
    app.logger.warning("Supabase environment variables not fully configured. File operations will be affected.")

# --- Logging Configuration ---
if app.config['FLASK_ENV'] == 'production':
    logging.basicConfig(level=logging.INFO) # Log INFO and above in production
else:
    logging.basicConfig(level=logging.DEBUG) # Log DEBUG and above in development
app.logger.info(f"Application starting in {app.config['FLASK_ENV']} mode.")

# --- Database Setup ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db_command():
    """Clear existing data and create new tables."""
    db = get_db()
    cursor = db.cursor()
    # Drop tables if they exist to ensure a clean state (optional, be careful in prod)
    # cursor.execute("DROP TABLE IF EXISTS applications")
    # cursor.execute("DROP TABLE IF EXISTS admin_users")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, last_name TEXT NOT NULL, first_name TEXT NOT NULL,
        email TEXT NOT NULL, phone TEXT NOT NULL, location TEXT NOT NULL, current_company TEXT NOT NULL,
        linkedin TEXT, facebook TEXT, country_birth TEXT NOT NULL, country_residence TEXT NOT NULL,
        us_state TEXT, extra_language TEXT, education TEXT NOT NULL, payrate REAL NOT NULL,
        hours_per_week INTEGER NOT NULL, gender TEXT, race TEXT, veteran_status TEXT,
        photo_path TEXT, resume_path TEXT, cover_letter_path TEXT, proof_residence_path TEXT,
        dl_front_path TEXT, dl_back_path TEXT, date_submitted TIMESTAMP
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
    )''')

    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if admin_username and admin_password:
        cursor.execute("SELECT COUNT(*) FROM admin_users WHERE username = ?", (admin_username,))
        if cursor.fetchone()[0] == 0:
            hashed_password = generate_password_hash(admin_password)
            cursor.execute("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
                          (admin_username, hashed_password))
            app.logger.info(f"Default admin user '{admin_username}' created.")
    else:
        app.logger.warning("ADMIN_USERNAME or ADMIN_PASSWORD not set, default admin not created.")
    db.commit()
    app.logger.info("Database initialized.")

# Register CLI command to initialize DB: `flask init-db`
@app.cli.command('init-db')
def init_db_cli_command():
    init_db_command()
    print("Initialized the database.")

# Initialize DB if it's empty (e.g., on first run)
# This is a simple check, might need more robust logic for production
with app.app_context():
    conn_check = sqlite3.connect(DB_NAME)
    cursor_check = conn_check.cursor()
    try:
        cursor_check.execute("SELECT COUNT(*) FROM admin_users")
        if cursor_check.fetchone()[0] == 0 and os.environ.get('ADMIN_USERNAME') and os.environ.get('ADMIN_PASSWORD'):
             app.logger.info("Admin users table is empty, attempting to initialize DB.")
             init_db_command()
    except sqlite3.OperationalError: # Table doesn't exist
        app.logger.info("Database tables not found, attempting to initialize DB.")
        init_db_command()
    finally:
        conn_check.close()


# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file_to_supabase(file_storage, base_folder_path_in_bucket):
    if not supabase:
        app.logger.error("Supabase client not initialized. Cannot upload file.")
        return None
    if not file_storage or not file_storage.filename:
        return None # No file provided
    if not allowed_file(file_storage.filename):
        flash(f"File type not allowed for {file_storage.filename}", "warning")
        return None

    filename = secure_filename(file_storage.filename)
    supabase_path = f"{base_folder_path_in_bucket}/{filename}"

    try:
        file_storage.seek(0)
        file_bytes = file_storage.read()
        supabase.storage.from_(SUPABASE_BUCKET_NAME).upload(
            path=supabase_path, file=file_bytes,
            file_options={"content-type": file_storage.mimetype, "upsert": "false"} # upsert=false fails if exists
        )
        app.logger.info(f"Successfully uploaded {filename} to Supabase path: {supabase_path}")
        return supabase_path
    except Exception as e: # Catch more specific Supabase errors if possible
        app.logger.error(f"Error uploading {filename} to Supabase: {e}")
        flash(f"Supabase upload error for {filename}. Please try again.", "danger")
        # If the error indicates the file already exists (if upsert was false and path was not unique)
        # you might want to handle it, e.g. by trying a unique name or informing the user.
        # For now, we assume paths are unique enough due to `application_files_base_path`.
        return None

def get_supabase_file_url(supabase_path):
    if not supabase or not supabase_path:
        return None
    try:
        if SUPABASE_BUCKET_IS_PUBLIC:
            return supabase.storage.from_(SUPABASE_BUCKET_NAME).get_public_url(supabase_path)
        else:
            # Generate a signed URL for private buckets
            response = supabase.storage.from_(SUPABASE_BUCKET_NAME).create_signed_url(supabase_path, SIGNED_URL_EXPIRY_SECONDS)
            return response.get('signedURL') # supabase-py might return dict like {'signedURL': '...'}
    except Exception as e:
        app.logger.error(f"Error generating Supabase file URL for {supabase_path}: {e}")
        return None

# --- Error Handlers ---
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.warning(f"CSRF error: {e.description}")
    flash("CSRF validation failed. Please try submitting the form again.", "danger")
    # Try to redirect to the previous page or a safe default
    return redirect(request.referrer or url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 Not Found: {request.path}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
@app.errorhandler(HTTPException) # Catch other Werkzeug HTTP exceptions
def internal_server_error(e):
    original_exception = getattr(e, "original_exception", e)
    app.logger.error(f"500 Internal Server Error: {request.path} - Error: {original_exception}")
    return render_template('errors/500.html'), 500


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/application', methods=['GET'])
def application_form():
    if not supabase:
        flash("File upload service is currently unavailable. Please try again later or contact support.", "danger")
    return render_template('application.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
    if not supabase:
        flash("Cannot submit application: File storage service is not configured.", "danger")
        return redirect(url_for('application_form'))
    try:
        # Collect and validate form data (add more validation as needed)
        form_data = {
            'last_name': request.form['last_name'], 'first_name': request.form['first_name'],
            'email': request.form['email'], 'phone': request.form['phone'],
            'location': request.form['location'], 'current_company': request.form['current_company'],
            'linkedin': request.form.get('linkedin', ''), 'facebook': request.form.get('facebook', ''),
            'country_birth': request.form['country_birth'], 'country_residence': request.form['country_residence'],
            'us_state': request.form.get('us_state', ''), 'extra_language': request.form.get('extra_language', ''),
            'education': request.form['education'], 'payrate': float(request.form['payrate']),
            'hours_per_week': int(request.form['hours_per_week']), 'gender': request.form.get('gender', ''),
            'race': request.form.get('race', ''), 'veteran_status': request.form.get('veteran_status', '')
        }

        sanitized_email = secure_filename(form_data['email'].split('@')[0] if '@' in form_data['email'] else form_data['email'])
        timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S%f") # Added microseconds for more uniqueness
        application_files_base_path = f"applications/{sanitized_email}_{timestamp_str}"

        file_supabase_paths = {}
        file_fields = ['photo', 'resume', 'cover_letter', 'proof_residence', 'dl_front', 'dl_back']
        for field_name in file_fields:
            file = request.files.get(field_name)
            if file and file.filename:
                supabase_path = upload_file_to_supabase(file, application_files_base_path)
                if supabase_path is None: # Handle upload failure for a specific file
                    flash(f"Failed to upload {field_name}. Please ensure it's an allowed file type and try again.", "warning")
                    # Decide if you want to stop the whole application or proceed without this file
                file_supabase_paths[f'{field_name}_path'] = supabase_path
            else:
                file_supabase_paths[f'{field_name}_path'] = None

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO applications (
                last_name, first_name, email, phone, location, current_company, linkedin, facebook,
                country_birth, country_residence, us_state, extra_language, education, payrate,
                hours_per_week, gender, race, veteran_status, photo_path, resume_path,
                cover_letter_path, proof_residence_path, dl_front_path, dl_back_path, date_submitted
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            *form_data.values(), # This relies on dict insertion order (Python 3.7+)
            file_supabase_paths.get('photo_path'), file_supabase_paths.get('resume_path'),
            file_supabase_paths.get('cover_letter_path'), file_supabase_paths.get('proof_residence_path'),
            file_supabase_paths.get('dl_front_path'), file_supabase_paths.get('dl_back_path'),
            datetime.now()
        ))
        db.commit()
        flash("Application submitted successfully!", "success")
        return render_template('success.html')

    except ValueError as ve:
        app.logger.warning(f"Value error during application submission: {ve}")
        flash(f"Invalid input: {str(ve)}. Please check your form entries.", "danger")
        return redirect(url_for('application_form'))
    except Exception as e:
        app.logger.error(f"Unexpected error submitting application: {e}", exc_info=True)
        flash("An unexpected error occurred. Please try again later.", "danger")
        return redirect(url_for('application_form'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_record = db.execute("SELECT id, username, password_hash FROM admin_users WHERE username = ?", (username,)).fetchone()
        if user_record and check_password_hash(user_record['password_hash'], password):
            session.clear() # Clear old session data
            session['logged_in'] = True
            session['user_id'] = user_record['id']
            session['username'] = user_record['username']
            # Regenerate session ID upon login for security (Flask does this by default on session modification)
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    db = get_db()
    applications_raw = db.execute("SELECT * FROM applications ORDER BY date_submitted DESC").fetchall()
    applications_processed = []
    for app_row in applications_raw:
        app_dict = dict(app_row)
        for key in app_dict.keys():
            if key.endswith('_path') and app_dict[key]:
                app_dict[f'{key}_url'] = get_supabase_file_url(app_dict[key])
            elif key.endswith('_path'):
                 app_dict[f'{key}_url'] = None
        applications_processed.append(app_dict)
    return render_template('admin_dashboard.html', applications=applications_processed)

@app.route('/application_details/<int:id>')
def application_details(id):
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    application_row = db.execute("SELECT * FROM applications WHERE id = ?", (id,)).fetchone()
    if application_row:
        application_dict = dict(application_row)
        for key in application_dict.keys():
            if key.endswith('_path') and application_dict[key]:
                application_dict[f'{key}_url'] = get_supabase_file_url(application_dict[key])
            elif key.endswith('_path'):
                 application_dict[f'{key}_url'] = None
        return jsonify(application_dict)
    return jsonify({"error": "Application not found"}), 404

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    # This block is for local development only.
    # For Render, use a Gunicorn command in your Render Start Command.
    # Example Render Start Command: gunicorn --workers 3 --bind 0.0.0.0:$PORT app:app
    app.logger.info("Starting Flask development server.")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)),
            debug=(app.config['FLASK_ENV'] == 'development'))
