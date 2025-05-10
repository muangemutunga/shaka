import os
import sqlite3
import logging
from datetime import datetime, timedelta
import secrets
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from supabase import create_client, Client
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, CSRFError

# --- Initialize App and Load Environment Variables ---
load_dotenv()
app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))
app.config['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'production')

# CSRF Protection
csrf = CSRFProtect(app)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB max file size
DB_NAME = 'quantumly.db'

# --- Supabase Configuration ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_BUCKET_NAME = os.environ.get("SUPABASE_BUCKET_NAME", "application-files")
SUPABASE_BUCKET_IS_PUBLIC = os.environ.get("SUPABASE_BUCKET_IS_PUBLIC", "false").lower() == "true"
SIGNED_URL_EXPIRY_SECONDS = int(os.environ.get("SIGNED_URL_EXPIRY_SECONDS", 3600))

# --- Logging Configuration ---
if app.config['FLASK_ENV'] == 'production':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
else:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
app.logger.info(f"Application starting in {app.config['FLASK_ENV']} mode.")

# --- Initialize Supabase Client ---
supabase: Client | None = None

def initialize_supabase():
    global supabase
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            app.logger.info("Successfully connected to Supabase.")
            
            # Check if bucket exists, create if it doesn't
            try:
                buckets = supabase.storage.list_buckets()
                bucket_exists = any(bucket['name'] == SUPABASE_BUCKET_NAME for bucket in buckets)
                
                if not bucket_exists:
                    app.logger.info(f"Creating Supabase bucket: {SUPABASE_BUCKET_NAME}")
                    supabase.storage.create_bucket(
                        SUPABASE_BUCKET_NAME,
                        {"public": SUPABASE_BUCKET_IS_PUBLIC}
                    )
                    app.logger.info(f"Successfully created bucket: {SUPABASE_BUCKET_NAME}")
            except Exception as e:
                app.logger.error(f"Error checking/creating Supabase bucket: {e}")
                
            return True
        except Exception as e:
            app.logger.error(f"Error connecting to Supabase: {e}")
            return False
    else:
        app.logger.warning("Supabase environment variables not fully configured.")
        return False

# Initialize Supabase client
if not initialize_supabase():
    app.logger.warning("File storage functionality will be limited without Supabase connection.")

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

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file_to_supabase(file_storage, base_folder_path_in_bucket):
    """Upload a file to Supabase storage with enhanced error handling."""
    if not supabase:
        app.logger.error("Supabase client not initialized. Cannot upload file.")
        return None
        
    if not file_storage or not file_storage.filename:
        return None  # No file provided
        
    if not allowed_file(file_storage.filename):
        flash(f"File type not allowed for {file_storage.filename}", "warning")
        return None
    
    # File size check
    if len(file_storage.read()) > MAX_FILE_SIZE:
        flash(f"File {file_storage.filename} exceeds the maximum allowed size.", "danger")
        return None

    # Generate a unique filename
    original_filename = secure_filename(file_storage.filename)
    file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_filename = f"{uuid.uuid4().hex}.{file_extension}" if file_extension else f"{uuid.uuid4().hex}"
    
    # Upload logic
    try:
        file_storage.seek(0)  # Reset file pointer
        file_bytes = file_storage.read()
        content_type = file_storage.content_type if hasattr(file_storage, 'content_type') else None
        
        upload_options = {
            "content-type": content_type or "application/octet-stream",
            "upsert": True  # Allow overwriting
        }
        
        # Upload the file
        response = supabase.storage.from_(SUPABASE_BUCKET_NAME).upload(
            path=f"{base_folder_path_in_bucket}/{unique_filename}",
            file=file_bytes,
            file_options=upload_options
        )
        
        app.logger.info(f"Successfully uploaded {original_filename} to Supabase.")
        return response['path']
        
    except Exception as e:
        app.logger.error(f"Error uploading file: {e}")
        flash(f"File upload failed. Please try again.", "danger")
        return None

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/application', methods=['GET'])
def application():
    return render_template('application.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
    if not supabase:
        flash("File storage service is unavailable.", "danger")
        return redirect(url_for('application'))
    
    # Process form data and files here...
    return "Application submitted successfully!"
