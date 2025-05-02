from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import os
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup
def init_db():
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/application')
def application():
    return render_template('application.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
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
        
        return render_template('success.html')
    
    except Exception as e:
        flash(f"Error submitting application: {str(e)}")
        return redirect(url_for('application'))

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('quantumly.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?", 
                      (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

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
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
