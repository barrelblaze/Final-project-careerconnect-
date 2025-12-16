from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
)
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this in production

# Database setup
DATABASE = 'careerconnect.db'
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table (common for all user types)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('seeker', 'recruiter', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Job seekers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_seekers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            education TEXT,
            experience_years REAL,
            primary_skills TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Recruiters/Companies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recruiters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            company_name TEXT NOT NULL,
            industry_type TEXT,
            company_location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

    # Resumes table
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resumes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on app start
init_db()


# --------- Auth helpers --------- #
def login_required(role=None):
    """Decorator to enforce login and optional role checking."""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            user_role = session.get("role")
            if not user_id:
                flash("Please login to continue", "error")
                return redirect(url_for("login"))
            if role and user_role != role:
                flash("Access denied for this role", "error")
                return redirect(url_for("login"))
            return f(*args, **kwargs)

        return wrapped

    return decorator

@app.route("/")
def home():
    return redirect(url_for("login"))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/seeker/upload_resume', methods=['GET', 'POST'])
@login_required(role='seeker')
def upload_resume():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    # fetch existing resume if any
    resume = cursor.execute('SELECT filename, original_filename FROM resumes WHERE user_id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        if 'resume' not in request.files:
            flash('No file part', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume)

        file = request.files['resume']

        if file.filename == '':
            flash('No selected file', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume)

        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            existing = cursor.execute('SELECT id, filename FROM resumes WHERE user_id = ?', (user_id,)).fetchone()

            if existing:
                # remove previous file if exists
                try:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], existing['filename'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except Exception:
                    pass

                cursor.execute(
                    'UPDATE resumes SET filename = ?, original_filename = ?, uploaded_at = CURRENT_TIMESTAMP WHERE id = ?',
                    (filename, file.filename, existing['id']),
                )
            else:
                cursor.execute(
                    'INSERT INTO resumes (user_id, filename, original_filename) VALUES (?, ?, ?)',
                    (user_id, filename, file.filename),
                )

            conn.commit()

            # fetch updated resume and stay on the same page
            resume = cursor.execute('SELECT filename, original_filename FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
            conn.close()
            flash('Resume uploaded successfully', 'success')
            return render_template('upload_resume.html', resume=resume)
        else:
            flash('File type not allowed. Allowed: pdf, doc, docx, txt', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume)

    conn.close()
    return render_template('upload_resume.html', resume=resume)


@app.route('/uploads/<path:filename>')
@login_required()
def download_resume(filename):
    # allow access only to owner, recruiters, or admin
    user_id = session.get('user_id')
    role = session.get('role')
    conn = get_db()
    cursor = conn.cursor()
    res = cursor.execute('SELECT user_id, original_filename FROM resumes WHERE filename = ?', (filename,)).fetchone()
    conn.close()

    if not res:
        flash('File not found', 'error')
        return redirect(url_for('seeker_dashboard'))

    if res['user_id'] != user_id and role not in ('recruiter', 'admin'):
        flash('Access denied', 'error')
        return redirect(url_for('seeker_dashboard'))

    # Serve inline so PDFs and text can be previewed in-browser
    try:
        response = send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)
        display_name = res.get('original_filename') if res and res.get('original_filename') else filename
        response.headers['Content-Disposition'] = f'inline; filename="{display_name}"'
        return response
    except Exception:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            conn = get_db()
            cursor = conn.cursor()
            user = cursor.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            conn.close()
            
            if user and check_password_hash(user['password_hash'], password):
                # Set session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                # Redirect based on role
                if user['role'] == 'seeker':
                    return redirect(url_for('seeker_dashboard'))
                elif user['role'] == 'recruiter':
                    return redirect(url_for('recruiter_dashboard'))
                elif user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password', 'error')
    
    return render_template("login.html")

@app.route("/register")
def register_choice():
    return render_template("register_choice.html")

@app.route("/register/seeker", methods=['GET', 'POST'])
def register_seeker():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        education = request.form.get('education')
        experience = request.form.get('experience')
        primary_skills = request.form.get('primary_skills')
        
        # Validation
        if not all([username, password, confirm_password, full_name, email, education, experience, primary_skills]):
            flash('All fields are required', 'error')
            return render_template("register_seeker.html")
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template("register_seeker.html")
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Check if username already exists
            existing_user = cursor.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
            ).fetchone()
            
            if existing_user:
                flash('Username already exists', 'error')
                conn.close()
                return render_template("register_seeker.html")
            
            # Hash password
            password_hash = generate_password_hash(password)
            
            # Insert into users table
            cursor.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, password_hash, 'seeker')
            )
            user_id = cursor.lastrowid
            
            # Insert into job_seekers table
            cursor.execute(
                '''INSERT INTO job_seekers 
                   (user_id, full_name, email, education, experience_years, primary_skills) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (user_id, full_name, email, education, float(experience), primary_skills)
            )
            
            conn.commit()
            conn.close()
            
            flash('Register successful, now login', 'success')
            return render_template("register_seeker.html")
            
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template("register_seeker.html")
    
    return render_template("register_seeker.html")

@app.route("/register/company", methods=['GET', 'POST'])
def register_company():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        company_name = request.form.get('company_name')
        industry_type = request.form.get('industry_type')
        company_location = request.form.get('company_location')
        
        # Validation
        if not all([username, password, confirm_password, company_name, industry_type, company_location]):
            flash('All fields are required', 'error')
            return render_template("register_company.html")
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template("register_company.html")
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Check if username already exists
            existing_user = cursor.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
            ).fetchone()
            
            if existing_user:
                flash('Username already exists', 'error')
                conn.close()
                return render_template("register_company.html")
            
            # Hash password
            password_hash = generate_password_hash(password)
            
            # Insert into users table
            cursor.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, password_hash, 'recruiter')
            )
            user_id = cursor.lastrowid
            
            # Insert into recruiters table
            cursor.execute(
                '''INSERT INTO recruiters 
                   (user_id, company_name, industry_type, company_location) 
                   VALUES (?, ?, ?, ?)''',
                (user_id, company_name, industry_type, company_location)
            )
            
            conn.commit()
            conn.close()
            
            flash('Register successful, now login', 'success')
            return render_template("register_company.html")
            
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template("register_company.html")
    
    return render_template("register_company.html")

@app.route("/seeker/dashboard")
@login_required(role="seeker")
def seeker_dashboard():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    profile = cursor.execute(
        """
        SELECT u.username,
               js.full_name,
               js.email,
               js.education,
               js.experience_years,
               js.primary_skills
        FROM users u
        LEFT JOIN job_seekers js ON js.user_id = u.id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()

    # fetch resume if exists
    resume = cursor.execute('SELECT filename, original_filename FROM resumes WHERE user_id = ?', (user_id,)).fetchone()

    conn.close()

    if not profile:
        flash("No profile found. Please complete your profile.", "error")
        profile = {}

    return render_template("seeker_dashboard.html", profile=profile, resume=resume)


@app.route("/seeker/profile", methods=["GET", "POST"])
@login_required(role="seeker")
def seeker_profile():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        education = request.form.get("education")
        experience = request.form.get("experience")
        primary_skills = request.form.get("primary_skills")

        if not all([full_name, email, education, experience, primary_skills]):
            flash("All fields are required", "error")
        else:
            try:
                existing = cursor.execute(
                    "SELECT id FROM job_seekers WHERE user_id = ?", (user_id,)
                ).fetchone()

                if existing:
                    cursor.execute(
                        """
                        UPDATE job_seekers
                        SET full_name = ?, email = ?, education = ?, experience_years = ?, primary_skills = ?
                        WHERE user_id = ?
                        """,
                        (full_name, email, education, float(experience), primary_skills, user_id),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO job_seekers (user_id, full_name, email, education, experience_years, primary_skills)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (user_id, full_name, email, education, float(experience), primary_skills),
                    )

                conn.commit()
                flash("Profile updated successfully", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Failed to update profile: {str(e)}", "error")

    profile = cursor.execute(
        """
        SELECT u.username,
               js.full_name,
               js.email,
               js.education,
               js.experience_years,
               js.primary_skills
        FROM users u
        LEFT JOIN job_seekers js ON js.user_id = u.id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()

    conn.close()

    return render_template("seeker_profile.html", profile=profile or {})

@app.route("/recruiter/dashboard")
@login_required(role="recruiter")
def recruiter_dashboard():
    return render_template("recruiter_dashboard.html")

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
