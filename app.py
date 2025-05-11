import os
import sqlite3
import logging
import secrets
from datetime import datetime
from functools import wraps

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename

# ─── Configuration ──────────────────────────────────────────────────────────────

UPLOAD_FOLDER        = 'uploads'
ALLOWED_EXTENSIONS   = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
DB_PATH             = 'quantumly.db'
GEOIP_API_URL       = 'http://ip-api.com/json/{ip}'

# NEW: List of allowed country codes (ISO 3166-1 alpha-2)
ALLOWED_COUNTRY_CODES = {
    "AL", "AD", "AM", "AT", "AZ", "BY", "BE", "BA", "BG", "HR", "CY",
    "CZ", "DK", "EE", "FI", "FR", "GE", "DE", "GR", "HU", "IS", "IE",
    "IT", "KZ", "XK", "LV", "LI", "LT", "LU", "MT", "MD", "MC", "ME",
    "NL", "MK", "NO", "PL", "PT", "RO", "RU", "SM", "RS", "SK", "SI",
    "ES", "SE", "CH", "TR", "UA", "GB",  # United Kingdom is GB
    "US",  # USA
    "CA"   # Canada
}
# Note: "Kosovo" uses "XK" as a user-assigned code element. ip-api.com might return "KV" or "XK".
# Check what ip-api.com returns for Kosovo if it's critical.
# For Russia (RU), Turkey (TR), Kazakhstan (KZ), Azerbaijan (AZ), Georgia (GE), Armenia (AM) - parts are in Asia,
# but ip-api.com usually assigns them to their primary political/economic continent (often Europe for these).

LOCALHOST_BYPASS     = True  # set False in production

# ─── App & Logging Setup ────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ─── Database Initialization ───────────────────────────────────────────────────
# ... (database init code remains the same) ...
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Applications table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS applications (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        last_name          TEXT NOT NULL,
        first_name         TEXT NOT NULL,
        email              TEXT NOT NULL,
        phone              TEXT NOT NULL,
        location           TEXT NOT NULL,
        current_company    TEXT NOT NULL,
        linkedin           TEXT,
        facebook           TEXT,
        country_birth      TEXT NOT NULL,
        country_residence  TEXT NOT NULL,
        us_state           TEXT,
        extra_language     TEXT,
        education          TEXT NOT NULL,
        payrate            REAL NOT NULL,
        hours_per_week     INTEGER NOT NULL,
        gender             TEXT,
        race               TEXT,
        veteran_status     TEXT,
        photo_path         TEXT,
        resume_path        TEXT,
        cover_letter_path  TEXT,
        proof_residence_path TEXT,
        dl_front_path      TEXT,
        dl_back_path       TEXT,
        date_submitted     TIMESTAMP
    )
    ''')

    # Admin users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS admin_users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    # Default admin
    cur.execute("SELECT COUNT(*) FROM admin_users WHERE username = 'admin234'")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO admin_users (username, password) VALUES (?, ?)",
            ('admin234', 'netflixx254') # Consider hashing passwords in a real app
        )

    conn.commit()
    conn.close()

init_db()

# ─── Utility Functions ─────────────────────────────────────────────────────────

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        # may be comma-separated list
        return forwarded.split(',')[0].strip()
    return request.remote_addr


# MODIFIED: Function to fetch country code
def fetch_country_code(ip):
    """Call GeoIP API to get country code for IP."""
    try:
        resp = requests.get(GEOIP_API_URL.format(ip=ip), timeout=5)
        resp.raise_for_status() # Raise an exception for HTTP errors
        data = resp.json()
        if data.get('status') == 'success':
            country_code = data.get('countryCode')
            logging.info(f"GeoIP success for {ip}: Country Code {country_code}, Country {data.get('country')}")
            return country_code
        else:
            logging.warning(f"GeoIP lookup failed for {ip}: {data}")
    except requests.RequestException as e:
        logging.error(f"GeoIP request error for {ip}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in GeoIP lookup for {ip}: {e}")
    return None


# MODIFIED: Logic to check allowed country
def is_allowed_region():
    """Return True if user is in an allowed country."""
    ip = get_client_ip()
    if LOCALHOST_BYPASS and (ip.startswith('127.') or ip == '::1' or ip.lower() == 'localhost'):
        logging.info(f"Localhost bypass for {ip}")
        return True

    # Use cached result if available
    country_code = session.get('user_country_code') # CHANGED session key name
    if country_code:
        allowed = country_code in ALLOWED_COUNTRY_CODES
        logging.info(f"Using cached country_code {country_code}, allowed: {allowed}")
        return allowed

    # Fetch from GeoIP
    country_code = fetch_country_code(ip) # Use new function
    if country_code:
        session['user_country_code'] = country_code # CHANGED session key name
        is_allowed = country_code in ALLOWED_COUNTRY_CODES
        logging.info(f"IP {ip} mapped to country_code {country_code}, allowed: {is_allowed}")
        return is_allowed
    
    logging.warning(f"Could not determine country for IP {ip}, defaulting to allow access (consider changing for production)")
    return True # Default to allowing access if we can't determine location


# MODIFIED: Decorator and message
def region_required(f):
    """Decorator to restrict routes to allowed regions (countries)."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not is_allowed_region():
            return render_template(
                'restrict.html',
                message="We're sorry, access to this service is not available in your current region." # More generic message
            ), 403
        return f(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    ext = filename.rsplit('.', 1)[-1].lower()
    return '.' in filename and ext in ALLOWED_EXTENSIONS


# ─── Routes ────────────────────────────────────────────────────────────────────
# ... (index, application, submit_application routes remain largely the same,
# but ensure they use the @region_required decorator where needed) ...

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/application')
@region_required # This decorator will now use the country-based logic
def application():
    return render_template('application.html')


@app.route('/submit_application', methods=['POST'])
@region_required # This decorator will now use the country-based logic
def submit_application():
    form = request.form
    files = request.files

    # Collect form fields
    form_data = {
        'last_name':           form['last_name'],
        'first_name':          form['first_name'],
        'email':               form['email'],
        'phone':               form['phone'],
        'location':            form['location'],
        'current_company':     form['current_company'],
        'linkedin':            form.get('linkedin', ''),
        'facebook':            form.get('facebook', ''),
        'country_birth':       form['country_birth'],
        'country_residence':   form['country_residence'],
        'us_state':            form.get('us_state', ''),
        'extra_language':      form.get('extra_language', ''),
        'education':           form['education'],
        'payrate':             float(form['payrate']),
        'hours_per_week':      int(form['hours_per_week']),
        'gender':              form.get('gender', ''),
        'race':                form.get('race', ''),
        'veteran_status':      form.get('veteran_status', '')
    }

    # Prepare file storage
    timestamp  = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], timestamp)
    os.makedirs(upload_dir, exist_ok=True)

    file_paths = {}
    for key in ['photo', 'resume', 'cover_letter', 'proof_residence', 'dl_front', 'dl_back']:
        file = files.get(key)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(upload_dir, filename)
            file.save(save_path)
            file_paths[f"{key}_path"] = os.path.join(timestamp, filename) # Relative path for DB
        else:
            file_paths[f"{key}_path"] = None

    # Insert into DB
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute('''
            INSERT INTO applications (
                last_name, first_name, email, phone, location, current_company,
                linkedin, facebook, country_birth, country_residence, us_state,
                extra_language, education, payrate, hours_per_week, gender, race,
                veteran_status, photo_path, resume_path, cover_letter_path,
                proof_residence_path, dl_front_path, dl_back_path, date_submitted
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            *form_data.values(),
            file_paths['photo_path'],
            file_paths['resume_path'],
            file_paths['cover_letter_path'],
            file_paths['proof_residence_path'],
            file_paths['dl_front_path'],
            file_paths['dl_back_path'],
            datetime.utcnow()
        ))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"DB insert error: {e}")
        flash("An error occurred. Please try again.")
        return redirect(url_for('application'))
    finally:
        if conn:
            conn.close()

    return render_template('success.html')


@app.route('/uploads/<path:filename>')
def serve_file(filename):
    # This needs to be careful. filename currently includes the timestamp directory.
    # send_from_directory expects the directory as first arg, and then the path *within* that directory.
    # Example: if filename is "20230101120000000000/resume.pdf"
    # then it should be send_from_directory(app.config['UPLOAD_FOLDER'], "20230101120000000000/resume.pdf")
    # Or, more robustly:
    # directory_part = os.path.dirname(filename)
    # file_part = os.path.basename(filename)
    # base_upload_dir = app.config['UPLOAD_FOLDER']
    # full_dir_path = os.path.join(base_upload_dir, directory_part)
    # return send_from_directory(full_dir_path, file_part)
    # HOWEVER, given how you store it (os.path.join(timestamp, filename)),
    # filename in the DB IS "timestamp/filename.ext".
    # So `send_from_directory(app.config['UPLOAD_FOLDER'], filename)` should be correct.
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd   = request.form['password']
        conn  = sqlite3.connect(DB_PATH)
        cur   = conn.cursor()
        # IMPORTANT: Store hashed passwords, not plain text! Use werkzeug.security.check_password_hash
        cur.execute(
            "SELECT 1 FROM admin_users WHERE username = ? AND password = ?", # This is insecure
            (uname, pwd)
        )
        valid = cur.fetchone()
        conn.close()

        if valid:
            session['logged_in'] = True
            session['username']  = uname
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')

    return render_template('login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute("SELECT * FROM applications ORDER BY date_submitted DESC")
    apps = cur.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', applications=apps)


@app.route('/application_details/<int:app_id>')
def application_details(app_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
    app_data = cur.fetchone()
    conn.close()

    if not app_data:
        return jsonify({"error": "Not found"}), 404
    
    # Convert row object to dictionary for jsonify
    app_dict = {k: app_data[k] for k in app_data.keys()}

    # Make file paths full URLs if you want to display them or link them directly
    # This is just an example if you want to make them clickable from admin
    base_url = url_for('index', _external=True) # Gets http://localhost:5000/ or similar
    for key in ['photo_path', 'resume_path', 'cover_letter_path', 'proof_residence_path', 'dl_front_path', 'dl_back_path']:
        if app_dict.get(key):
            app_dict[f"{key}_url"] = url_for('serve_file', filename=app_dict[key], _external=True)

    return jsonify(app_dict)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# MODIFIED: Test route for country code
@app.route('/test_geoip')
def test_geoip():
    if not app.debug and not LOCALHOST_BYPASS: # Allow for localhost testing even if debug is false
        return redirect(url_for('index'))
        
    ip = get_client_ip()
    country_code_val = fetch_country_code(ip) # Use new function
    is_allowed_val = country_code_val in ALLOWED_COUNTRY_CODES if country_code_val else "Unknown (country code not found)"
    
    # Get full country name if possible
    full_country_name = "N/A"
    if country_code_val:
        try:
            resp = requests.get(GEOIP_API_URL.format(ip=ip), timeout=3)
            data = resp.json()
            if data.get('status') == 'success':
                full_country_name = data.get('country', 'N/A')
        except:
            pass # Ignore errors here, it's just for display

    return jsonify({
        "ip": ip,
        "detected_country_code": country_code_val,
        "detected_country_name": full_country_name,
        "is_allowed": is_allowed_val,
        "allowed_country_codes_list": sorted(list(ALLOWED_COUNTRY_CODES)),
        "localhost_bypass_active": LOCALHOST_BYPASS and (ip.startswith('127.') or ip == '::1' or ip.lower() == 'localhost')
    })


if __name__ == '__main__':
    # In production, use a WSGI server like gunicorn, remove debug=True
    app.run(debug=True)
