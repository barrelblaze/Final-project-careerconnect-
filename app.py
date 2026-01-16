from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
    jsonify,
)
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from datetime import datetime
from ai import analyzer
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this in production

# Session configuration - keep users logged in
from datetime import timedelta
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session lasts 7 days
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
    conn = sqlite3.connect(DATABASE, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrent access
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

@app.teardown_appcontext
def close_db(error):
    """Close database connections on app teardown"""
    pass  # SQLite connections close automatically when dereferenced

@app.before_request
def refresh_session():
    """Refresh session on each request to keep it alive"""
    if 'user_id' in session:
        session.modified = True  # Mark session as modified to extend lifetime

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
            job_role TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

    # ensure resumes table has job_role column (for older DBs)
    conn = get_db()
    cur = conn.cursor()
    cols = [c[1] for c in cur.execute("PRAGMA table_info(resumes)").fetchall()]
    if 'job_role' not in cols:
        try:
            cur.execute('ALTER TABLE resumes ADD COLUMN job_role TEXT')
            conn.commit()
        except Exception:
            pass
    conn.close()

    # Job Postings table
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_postings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recruiter_id INTEGER NOT NULL,
            job_title TEXT NOT NULL,
            job_description TEXT NOT NULL,
            required_skills TEXT,
            experience_level TEXT,
            salary_range TEXT,
            job_location TEXT,
            employment_type TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (recruiter_id) REFERENCES recruiters(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

    # Applications table
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            seeker_id INTEGER NOT NULL,
            status TEXT DEFAULT 'applied' CHECK(status IN ('applied', 'shortlisted', 'rejected', 'hired')),
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES job_postings(id) ON DELETE CASCADE,
            FOREIGN KEY (seeker_id) REFERENCES job_seekers(id) ON DELETE CASCADE,
            UNIQUE(job_id, seeker_id)
        )
    ''')
    conn.commit()
    conn.close()

    # Saved Jobs table
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saved_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            seeker_id INTEGER NOT NULL,
            saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES job_postings(id) ON DELETE CASCADE,
            FOREIGN KEY (seeker_id) REFERENCES job_seekers(id) ON DELETE CASCADE,
            UNIQUE(job_id, seeker_id)
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
            
            # Debug logging
            if not user_id:
                print(f"DEBUG: No user_id in session for {request.path}")
                flash("Please login to continue", "error")
                return redirect(url_for("login"))
            
            if role and user_role != role:
                print(f"DEBUG: Role mismatch for {request.path}. Expected: {role}, Got: {user_role}")
                flash("Access denied for this role", "error")
                # Redirect to appropriate dashboard instead of login
                if user_role == "seeker":
                    return redirect(url_for("seeker_dashboard"))
                elif user_role == "recruiter":
                    return redirect(url_for("recruiter_dashboard"))
                return redirect(url_for("login"))
            
            # Refresh session timestamp on each authenticated request
            session.modified = True
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

    # fetch existing resume if any (include saved job_role)
    resume = cursor.execute('SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        if 'resume' not in request.files:
            flash('No file part', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume)

        # optional job role input from user
        job_role = request.form.get('job_role')

        file = request.files['resume']

        if file.filename == '':
            flash('No selected file', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume)

        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            existing = cursor.execute('SELECT id, filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()

            if existing:
                # remove previous file if exists
                try:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], existing['filename'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except Exception:
                    pass

                # preserve existing job_role if user did not submit a new one
                new_job_role = job_role if job_role is not None and job_role != '' else (existing['job_role'] if existing and 'job_role' in existing.keys() else None)
                cursor.execute(
                    'UPDATE resumes SET filename = ?, original_filename = ?, job_role = ?, uploaded_at = CURRENT_TIMESTAMP WHERE id = ?',
                    (filename, file.filename, new_job_role, existing['id']),
                )
            else:
                cursor.execute(
                    'INSERT INTO resumes (user_id, filename, original_filename, job_role) VALUES (?, ?, ?, ?)',
                    (user_id, filename, file.filename, job_role),
                )

            conn.commit()

            # fetch updated resume and stay on the same page (include job_role)
            resume = cursor.execute('SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
            conn.close()

            # run analyzer and pass results to template
            try:
                # get seeker profile basics
                pconn = get_db()
                pc = pconn.cursor()
                prof = pc.execute('SELECT education, experience_years, primary_skills FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
                pconn.close()
                path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                analysis = analyzer.analyze_resume_file(path, profile_skills=(prof['primary_skills'] if prof else ''), experience_years=(prof['experience_years'] if prof else 0), education=(prof['education'] if prof else ''))
                # compute role-specific missing skills / suggestions if job_role provided
                role_missing = None
                role_suggestions = None
                if job_role:
                    # normalize
                    jr = job_role.strip().lower()
                    role_map = getattr(analyzer, 'ROLE_MAP', {})
                    # try direct match to known roles
                    if jr in role_map:
                        required = set(role_map[jr])
                        found = set(analysis.get('extracted_skills', []))
                        missing_for_role = sorted(required - found)
                        role_missing = missing_for_role
                        if missing_for_role:
                            role_suggestions = [f'Add skills: {", ".join(missing_for_role)} to match {job_role} roles']
                        else:
                            role_suggestions = [f'Profile appears to cover common {job_role} skills']
                    else:
                        # no predefined mapping — no role-specific data
                        role_missing = []
                        role_suggestions = [f'No predefined skill mapping for "{job_role}".']
            except Exception:
                analysis = None

            flash('Resume uploaded successfully', 'success')
            return render_template('upload_resume.html', resume=resume, analysis=analysis, role_missing=role_missing, role_suggestions=role_suggestions, role_options=sorted(getattr(analyzer, 'ROLE_MAP', {}).keys()), selected_role=job_role)
        else:
            flash('File type not allowed. Allowed: pdf, doc, docx, txt', 'error')
            conn.close()
            return render_template('upload_resume.html', resume=resume, role_options=sorted(getattr(analyzer, 'ROLE_MAP', {}).keys()))

    conn.close()
    return render_template('upload_resume.html', resume=resume, role_options=sorted(getattr(analyzer, 'ROLE_MAP', {}).keys()))


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
                session.permanent = True  # Make session persistent
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

    # fetch resume if exists (include saved job_role)
    resume = cursor.execute('SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
    selected_role = resume['job_role'] if resume and 'job_role' in resume.keys() and resume['job_role'] else None

    # run analyzer if resume exists
    analysis = None
    if resume:
        # get seeker profile basics
        prof = cursor.execute('SELECT education, experience_years, primary_skills FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
        path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
        
        # Check if file exists
        if os.path.exists(path):
            try:
                analysis = analyzer.analyze_resume_file(
                    path, 
                    profile_skills=(prof['primary_skills'] if prof and prof['primary_skills'] else ''), 
                    experience_years=(prof['experience_years'] if prof and prof['experience_years'] else 0), 
                    education=(prof['education'] if prof and prof['education'] else '')
                )
                print(f"DEBUG: Analysis successful - ATS Score: {analysis.get('ats', {}).get('ats_score', 'N/A')}")
            except Exception as e:
                print(f"ERROR: Analysis failed - {str(e)}")
                import traceback
                traceback.print_exc()
                analysis = None
        else:
            print(f"ERROR: Resume file not found at {path}")
            analysis = None

    # fetch all active job postings
    job_postings = cursor.execute(
        """
        SELECT jp.id, jp.job_title, jp.job_description, jp.required_skills, 
               jp.experience_level, jp.salary_range, jp.job_location, 
               jp.employment_type, r.company_name
        FROM job_postings jp
        JOIN recruiters r ON jp.recruiter_id = r.id
        WHERE jp.is_active = 1
        ORDER BY jp.created_at DESC
        LIMIT 20
        """
    ).fetchall()

    # build seeker skill set (profile + extracted skills)
    seeker_skills = set()
    if profile and 'primary_skills' in profile.keys() and profile['primary_skills']:
        seeker_skills.update([s.strip().lower() for s in profile['primary_skills'].split(',') if s.strip()])
    if analysis and isinstance(analysis, dict) and analysis.get('extracted_skills'):
        seeker_skills.update([s.strip().lower() for s in analysis['extracted_skills'] if s.strip()])

    def compute_match_score(required_skills):
        req = [s.strip().lower() for s in (required_skills or '').split(',') if s.strip()]
        if not req or not seeker_skills:
            return None
        matched = len([s for s in req if s in seeker_skills])
        score = int(round((matched / max(len(req), 1)) * 100))
        return score

    # compute match scores for job postings; applications/saved handled after fetch
    match_scores = {}
    for jp in job_postings:
        match_scores[jp['id']] = compute_match_score(jp['required_skills'])

    # fetch seeker's applications
    applications = []
    applied_job_ids = []
    saved_job_ids = []
    saved_jobs = []
    application_match_scores = {}
    seeker = cursor.execute('SELECT id FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
    if seeker:
        applications = cursor.execute(
            """
            SELECT a.id, a.status, a.applied_at, a.job_id,
                   jp.job_title, jp.required_skills,
                   r.company_name
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            JOIN job_seekers js ON a.seeker_id = js.id
            JOIN recruiters r ON jp.recruiter_id = r.id
            WHERE a.seeker_id = ?
            ORDER BY a.applied_at DESC
            """,
            (seeker['id'],),
        ).fetchall()
        
        # get list of job IDs already applied to
        applied_job_ids = [application['id'] for application in cursor.execute(
            'SELECT job_id as id FROM applications WHERE seeker_id = ?', (seeker['id'],)
        ).fetchall()]

        # get saved jobs
        saved_jobs = cursor.execute(
            """
            SELECT jp.id, jp.job_title, jp.job_location, jp.required_skills, r.company_name
            FROM saved_jobs sj
            JOIN job_postings jp ON sj.job_id = jp.id
            JOIN recruiters r ON jp.recruiter_id = r.id
            WHERE sj.seeker_id = ? AND jp.is_active = 1
            ORDER BY sj.saved_at DESC
            """,
            (seeker['id'],),
        ).fetchall()

        saved_job_ids = [job['id'] for job in cursor.execute(
            'SELECT job_id as id FROM saved_jobs WHERE seeker_id = ?', (seeker['id'],)
        ).fetchall()]

        # compute match scores for applications now that we have them
        for application in applications:
            application_match_scores[application['id']] = compute_match_score(application['required_skills'])

    conn.close()

    if not profile:
        flash("No profile found. Please complete your profile.", "error")
        profile = {}

    return render_template(
        "seeker_dashboard.html",
        profile=profile,
        resume=resume,
        analysis=analysis,
        selected_role=selected_role,
        job_postings=job_postings or [],
        applications=applications or [],
        applied_job_ids=applied_job_ids,
        saved_jobs=saved_jobs or [],
        saved_job_ids=saved_job_ids,
        match_scores=match_scores,
        application_match_scores=application_match_scores,
    )


@app.route('/seeker/analysis/rerun', methods=['POST'])
@login_required(role='seeker')
def rerun_analysis():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    resume = cursor.execute('SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
    if not resume:
        conn.close()
        return jsonify({'error': 'no_resume'}), 400

    try:
        prof = cursor.execute('SELECT education, experience_years, primary_skills FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
        path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
        analysis = analyzer.analyze_resume_file(
            path,
            profile_skills=(prof['primary_skills'] if prof else ''),
            experience_years=(prof['experience_years'] if prof else 0),
            education=(prof['education'] if prof else ''),
        )
    except Exception:
        conn.close()
        return jsonify({'error': 'analysis_failed'}), 500

    conn.close()
    return jsonify(analysis)


@app.route('/seeker/analysis/details')
@login_required(role='seeker')
def analysis_details():
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()
    resume = cursor.execute('SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
    if not resume:
        conn.close()
        flash('No resume found for analysis', 'error')
        return redirect(url_for('seeker_dashboard'))

    # optional job role via query param, fallback to saved resume job_role
    job_role = request.args.get('job_role') or (resume['job_role'] if resume and 'job_role' in resume.keys() and resume['job_role'] else None)

    try:
        prof = cursor.execute('SELECT education, experience_years, primary_skills FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
        path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
        analysis = analyzer.analyze_resume_file(
            path,
            profile_skills=(prof['primary_skills'] if prof else ''),
            experience_years=(prof['experience_years'] if prof else 0),
            education=(prof['education'] if prof else ''),
        )

        # compute role-specific info if requested
        role_missing = None
        role_suggestions = None
        role_options = sorted(getattr(analyzer, 'ROLE_MAP', {}).keys())
        if job_role:
            jr = job_role.strip().lower()
            role_map = getattr(analyzer, 'ROLE_MAP', {})
            if jr in role_map:
                required = set(role_map[jr])
                found = set(analysis.get('extracted_skills', []))
                missing_for_role = sorted(required - found)
                role_missing = missing_for_role
                if missing_for_role:
                    role_suggestions = [f'Add skills: {", ".join(missing_for_role)} to match {job_role} roles']
                else:
                    role_suggestions = [f'Profile appears to cover common {job_role} skills']
            else:
                role_missing = []
                role_suggestions = [f'No predefined skill mapping for "{job_role}".']

    except Exception:
        analysis = None
        role_missing = None
        role_suggestions = None
        role_options = sorted(getattr(analyzer, 'ROLE_MAP', {}).keys())

    conn.close()
    return render_template('analysis_details.html', analysis=analysis, resume=resume, role_missing=role_missing, role_suggestions=role_suggestions, role_options=role_options, selected_role=job_role)


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
    user_id = session.get("user_id")
    sort_by = request.args.get('sort', 'recent')  # Get sort parameter from query string
    conn = get_db()
    cursor = conn.cursor()

    profile = cursor.execute(
        """
        SELECT u.username,
               r.id as recruiter_id,
               r.company_name,
               r.industry_type,
               r.company_location
        FROM users u
        LEFT JOIN recruiters r ON r.user_id = u.id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()

    # fetch job postings for this recruiter
    job_postings = []
    applications = []
    shortlisted_candidates = []
    active_postings_count = 0
    total_applications = 0
    shortlisted_count = 0
    rejected_count = 0
    hired_count = 0
    
    if profile and 'recruiter_id' in profile.keys() and profile['recruiter_id']:
        # Determine ORDER BY clause based on sort_by parameter
        if sort_by == 'applications':
            # Sort by number of applications (most to least)
            job_postings = cursor.execute(
                """
                SELECT jp.id, jp.job_title, jp.job_description, jp.required_skills, jp.experience_level, 
                       jp.salary_range, jp.job_location, jp.employment_type, jp.is_active, jp.created_at,
                       COUNT(a.id) as app_count
                FROM job_postings jp
                LEFT JOIN applications a ON jp.id = a.job_id
                WHERE jp.recruiter_id = ?
                GROUP BY jp.id
                ORDER BY app_count DESC
                """,
                (profile['recruiter_id'],),
            ).fetchall()
        elif sort_by == 'title':
            # Sort by job title (A-Z)
            job_postings = cursor.execute(
                """
                SELECT id, job_title, job_description, required_skills, experience_level, 
                       salary_range, job_location, employment_type, is_active, created_at
                FROM job_postings
                WHERE recruiter_id = ?
                ORDER BY job_title ASC
                """,
                (profile['recruiter_id'],),
            ).fetchall()
        else:
            # Default: sort by recent (newest first)
            job_postings = cursor.execute(
                """
                SELECT id, job_title, job_description, required_skills, experience_level, 
                       salary_range, job_location, employment_type, is_active, created_at
                FROM job_postings
                WHERE recruiter_id = ?
                ORDER BY created_at DESC
                """,
                (profile['recruiter_id'],),
            ).fetchall()

        active_postings_count = sum(1 for jp in job_postings if jp['is_active'] == 1)

        # fetch applications for recruiter's jobs
        applications = cursor.execute(
            """
            SELECT a.id, a.status, a.applied_at,
                   jp.job_title, jp.required_skills,
                   js.full_name as candidate_name, js.email as candidate_email,
                   js.user_id as seeker_user_id, js.primary_skills,
                   js.education, js.experience_years
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            JOIN job_seekers js ON a.seeker_id = js.id
            WHERE jp.recruiter_id = ?
            ORDER BY a.applied_at DESC
            LIMIT 20
            """,
            (profile['recruiter_id'],),
        ).fetchall()
        
        # Compute match scores for applications (skill overlap percentage)
        application_match_scores = {}
        for application in applications:
            try:
                # Get candidate's skills
                candidate_skills = set()
                if application['primary_skills']:
                    candidate_skills.update(skill.strip().lower() for skill in application['primary_skills'].split(','))
                
                # Get job's required skills
                job_skills = set(skill.strip().lower() for skill in (application['required_skills'] or '').split(',') if skill.strip())
                
                # Calculate match percentage
                if job_skills:
                    matched = len(candidate_skills & job_skills)
                    match_percentage = round((matched / len(job_skills)) * 100)
                    application_match_scores[application['id']] = match_percentage
                else:
                    application_match_scores[application['id']] = 0
            except Exception:
                application_match_scores[application['id']] = 0

        # fetch shortlisted candidates
        shortlisted_candidates = cursor.execute(
            """
            SELECT a.id, a.applied_at,
                   jp.job_title,
                   js.full_name as candidate_name, js.email as candidate_email,
                   js.user_id as seeker_user_id, js.primary_skills,
                   js.education, js.experience_years
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            JOIN job_seekers js ON a.seeker_id = js.id
            WHERE jp.recruiter_id = ? AND a.status = 'shortlisted'
            ORDER BY a.applied_at DESC
            LIMIT 10
            """,
            (profile['recruiter_id'],),
        ).fetchall()
        
        # Compute ATS scores for shortlisted candidates
        shortlisted_ats_scores = {}
        for candidate in shortlisted_candidates:
            try:
                # Get resume for this candidate
                resume = cursor.execute(
                    'SELECT filename FROM resumes WHERE user_id = ?',
                    (candidate['seeker_user_id'],)
                ).fetchone()
                
                if resume:
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                    if os.path.exists(resume_path):
                        analysis_result = analyzer.analyze_resume_file(
                            resume_path,
                            profile_skills=candidate['primary_skills'] or '',
                            experience_years=candidate['experience_years'] or 0,
                            education=candidate['education'] or ''
                        )
                        if analysis_result and 'ats' in analysis_result:
                            shortlisted_ats_scores[candidate['id']] = analysis_result['ats']['ats_score']
            except Exception:
                pass  # Skip if analysis fails

        # calculate hiring pipeline metrics
        total_applications = cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            WHERE jp.recruiter_id = ?
            """,
            (profile['recruiter_id'],),
        ).fetchone()['count']

        shortlisted_count = cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            WHERE jp.recruiter_id = ? AND a.status = 'shortlisted'
            """,
            (profile['recruiter_id'],),
        ).fetchone()['count']

        rejected_count = cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            WHERE jp.recruiter_id = ? AND a.status = 'rejected'
            """,
            (profile['recruiter_id'],),
        ).fetchone()['count']

        hired_count = cursor.execute(
            """
            SELECT COUNT(*) as count
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            WHERE jp.recruiter_id = ? AND a.status = 'hired'
            """,
            (profile['recruiter_id'],),
        ).fetchone()['count']

    conn.close()

    if not profile:
        flash("No recruiter profile found.", "error")
        profile = {}

    return render_template(
        "recruiter_dashboard.html", 
        profile=profile, 
        job_postings=job_postings or [], 
        applications=applications or [],
        shortlisted_candidates=shortlisted_candidates or [],
        active_postings_count=active_postings_count,
        total_applications=total_applications,
        shortlisted_count=shortlisted_count,
        rejected_count=rejected_count,
        hired_count=hired_count,
        application_match_scores=application_match_scores,
        shortlisted_ats_scores=shortlisted_ats_scores
    )

@app.route("/recruiter/get_jobs")
@login_required(role="recruiter")
def get_jobs():
    """AJAX endpoint to fetch jobs with sorting"""
    user_id = session.get("user_id")
    sort_by = request.args.get('sort', 'recent')
    conn = get_db()
    cursor = conn.cursor()

    profile = cursor.execute(
        'SELECT id as recruiter_id FROM recruiters WHERE user_id = ?',
        (user_id,)
    ).fetchone()

    if not profile:
        return jsonify({'error': 'Recruiter not found'}), 404

    recruiter_id = profile['recruiter_id']

    # Determine ORDER BY clause based on sort_by parameter
    if sort_by == 'applications':
        job_postings = cursor.execute(
            """
            SELECT jp.id, jp.job_title, jp.job_description, jp.required_skills, jp.experience_level, 
                   jp.salary_range, jp.job_location, jp.employment_type, jp.is_active, jp.created_at,
                   COUNT(a.id) as app_count
            FROM job_postings jp
            LEFT JOIN applications a ON jp.id = a.job_id
            WHERE jp.recruiter_id = ?
            GROUP BY jp.id
            ORDER BY app_count DESC
            """,
            (recruiter_id,),
        ).fetchall()
    elif sort_by == 'title':
        job_postings = cursor.execute(
            """
            SELECT id, job_title, job_description, required_skills, experience_level, 
                   salary_range, job_location, employment_type, is_active, created_at
            FROM job_postings
            WHERE recruiter_id = ?
            ORDER BY job_title ASC
            """,
            (recruiter_id,),
        ).fetchall()
    else:
        job_postings = cursor.execute(
            """
            SELECT id, job_title, job_description, required_skills, experience_level, 
                   salary_range, job_location, employment_type, is_active, created_at
            FROM job_postings
            WHERE recruiter_id = ?
            ORDER BY created_at DESC
            """,
            (recruiter_id,),
        ).fetchall()

    conn.close()

    # Return jobs as JSON
    return jsonify({
        'jobs': [dict(job) for job in job_postings]
    })

@app.route("/recruiter/profile", methods=["GET", "POST"])
@login_required(role="recruiter")
def recruiter_profile():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        company_name = request.form.get("company_name")
        industry_type = request.form.get("industry_type")
        company_location = request.form.get("company_location")

        if not all([company_name, industry_type, company_location]):
            flash("All fields are required", "error")
        else:
            try:
                existing = cursor.execute(
                    "SELECT id FROM recruiters WHERE user_id = ?", (user_id,)
                ).fetchone()

                if existing:
                    cursor.execute(
                        """
                        UPDATE recruiters
                        SET company_name = ?, industry_type = ?, company_location = ?
                        WHERE user_id = ?
                        """,
                        (company_name, industry_type, company_location, user_id),
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO recruiters (user_id, company_name, industry_type, company_location)
                        VALUES (?, ?, ?, ?)
                        """,
                        (user_id, company_name, industry_type, company_location),
                    )

                conn.commit()
                flash("Profile updated successfully", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Failed to update profile: {str(e)}", "error")

    profile = cursor.execute(
        """
        SELECT u.username,
               r.company_name,
               r.industry_type,
               r.company_location
        FROM users u
        LEFT JOIN recruiters r ON r.user_id = u.id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()

    conn.close()

    return render_template("recruiter_profile.html", profile=profile or {})

@app.route("/recruiter/post_job", methods=["GET", "POST"])
@login_required(role="recruiter")
def post_job():
    user_id = session.get("user_id")
    
    if request.method == "POST":
        job_title = request.form.get("job_title")
        job_description = request.form.get("job_description")
        required_skills = request.form.get("required_skills")
        experience_level = request.form.get("experience_level")
        salary_range = request.form.get("salary_range")
        job_location = request.form.get("job_location")
        employment_type = request.form.get("employment_type")

        if not all([job_title, job_description, required_skills, experience_level, job_location, employment_type]):
            error_msg = "All fields are required"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error_msg}), 400
            flash(error_msg, "error")
            return render_template("post_job.html")

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Get recruiter ID
            recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
            if not recruiter:
                error_msg = "Recruiter profile not found"
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': error_msg}), 404
                flash(error_msg, "error")
                return render_template("post_job.html")
            
            cursor.execute(
                """
                INSERT INTO job_postings 
                (recruiter_id, job_title, job_description, required_skills, experience_level, salary_range, job_location, employment_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (recruiter['id'], job_title, job_description, required_skills, experience_level, salary_range, job_location, employment_type),
            )
            conn.commit()
            
            # Get the newly inserted job ID
            job_id = cursor.lastrowid
            
            # Fetch the complete job data with company info
            job = cursor.execute(
                """
                SELECT jp.id, jp.job_title, jp.job_location, jp.employment_type, 
                       jp.experience_level, jp.salary_range, jp.required_skills, 
                       jp.job_description, r.company_name
                FROM job_postings jp
                JOIN recruiters r ON jp.recruiter_id = r.id
                WHERE jp.id = ?
                """,
                (job_id,)
            ).fetchone()
            
            conn.close()
            
            # If AJAX request, return JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'message': 'Job posted successfully!',
                    'job': dict(job) if job else {}
                }), 201
            
            # Otherwise, redirect
            flash("Job posted successfully!", "success")
            return redirect(url_for("recruiter_dashboard"))
        except Exception as e:
            conn.rollback()
            conn.close()
            error_msg = f"Failed to post job: {str(e)}"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error_msg}), 500
            flash(error_msg, "error")
        
        return render_template("post_job.html")

    return render_template("post_job.html")

@app.route("/recruiter/job/<int:job_id>/applications")
@login_required(role="recruiter")
def recruiter_job_applications(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    # Ensure this job belongs to the logged-in recruiter
    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        flash("Recruiter profile not found.", "error")
        return redirect(url_for("recruiter_dashboard"))

    job = cursor.execute(
        """
        SELECT jp.id, jp.job_title, jp.job_location, jp.employment_type, jp.experience_level,
               jp.salary_range, jp.required_skills, jp.job_description, jp.created_at
        FROM job_postings jp
        WHERE jp.id = ? AND jp.recruiter_id = ?
        """,
        (job_id, recruiter['id'])
    ).fetchone()

    if not job:
        conn.close()
        flash("Job not found or you do not have access.", "error")
        return redirect(url_for("recruiter_dashboard"))

    applications = cursor.execute(
        """
        SELECT a.id, a.status, a.applied_at,
               js.full_name as candidate_name, js.email as candidate_email,
               js.user_id as seeker_user_id, js.primary_skills,
               js.education, js.experience_years
        FROM applications a
        JOIN job_seekers js ON a.seeker_id = js.id
        WHERE a.job_id = ?
        ORDER BY a.applied_at DESC
        """,
        (job_id,)
    ).fetchall()

    # Compute ATS scores for applications
    application_ats_scores = {}
    for application in applications:
        try:
            # Get resume for this candidate
            resume = cursor.execute(
                'SELECT filename FROM resumes WHERE user_id = ?',
                (application['seeker_user_id'],)
            ).fetchone()
            
            if resume:
                resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                if os.path.exists(resume_path):
                    analysis_result = analyzer.analyze_resume_file(
                        resume_path,
                        profile_skills=application['primary_skills'] or '',
                        experience_years=application['experience_years'] or 0,
                        education=application['education'] or ''
                    )
                    if analysis_result and 'ats' in analysis_result:
                        application_ats_scores[application['id']] = analysis_result['ats']['ats_score']
        except Exception:
            pass  # Skip if analysis fails

    conn.close()

    return render_template("job_applications.html", job=job, applications=applications or [], application_ats_scores=application_ats_scores)

@app.route("/recruiter/edit_job/<int:job_id>", methods=["GET", "POST"])
@login_required(role="recruiter")
def edit_job(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        flash("Recruiter profile not found.", "error")
        return redirect(url_for("recruiter_dashboard"))

    job = cursor.execute(
        "SELECT * FROM job_postings WHERE id = ? AND recruiter_id = ?",
        (job_id, recruiter['id'])
    ).fetchone()

    if not job:
        conn.close()
        flash("Job not found or you do not have access.", "error")
        return redirect(url_for("recruiter_dashboard"))

    if request.method == "POST":
        job_title = request.form.get("job_title")
        job_description = request.form.get("job_description")
        required_skills = request.form.get("required_skills")
        experience_level = request.form.get("experience_level")
        salary_range = request.form.get("salary_range")
        job_location = request.form.get("job_location")
        employment_type = request.form.get("employment_type")

        if not all([job_title, job_description, required_skills, experience_level, job_location, employment_type]):
            flash("All fields are required", "error")
            conn.close()
            return render_template("edit_job.html", job=job)

        try:
            cursor.execute(
                """
                UPDATE job_postings
                SET job_title = ?, job_description = ?, required_skills = ?, experience_level = ?,
                    salary_range = ?, job_location = ?, employment_type = ?
                WHERE id = ? AND recruiter_id = ?
                """,
                (job_title, job_description, required_skills, experience_level, salary_range, job_location, employment_type, job_id, recruiter['id'])
            )
            conn.commit()
            flash("Job updated successfully!", "success")
            conn.close()
            return redirect(url_for("recruiter_dashboard"))
        except Exception as e:
            conn.rollback()
            flash(f"Failed to update job: {str(e)}", "error")
            conn.close()
            return render_template("edit_job.html", job=job)

    conn.close()
    return render_template("edit_job.html", job=job)

@app.route("/recruiter/toggle_job_active/<int:job_id>", methods=["POST"])
@login_required(role="recruiter")
def toggle_job_active(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        flash("Recruiter profile not found.", "error")
        return redirect(url_for("recruiter_dashboard"))

    job = cursor.execute('SELECT id, is_active FROM job_postings WHERE id = ? AND recruiter_id = ?', (job_id, recruiter['id'])).fetchone()
    if not job:
        conn.close()
        flash("Job not found or you do not have access.", "error")
        return redirect(url_for("recruiter_dashboard"))

    try:
        new_status = 0 if job['is_active'] == 1 else 1
        cursor.execute('UPDATE job_postings SET is_active = ? WHERE id = ?', (new_status, job_id))
        conn.commit()
        flash("Job status updated.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to update status: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for("recruiter_dashboard"))

@app.route("/recruiter/delete_job/<int:job_id>", methods=["POST"])
@login_required(role="recruiter")
def delete_job(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Recruiter profile not found.'}), 404
        flash("Recruiter profile not found.", "error")
        return redirect(url_for("recruiter_dashboard"))

    job = cursor.execute('SELECT id FROM job_postings WHERE id = ? AND recruiter_id = ?', (job_id, recruiter['id'])).fetchone()
    if not job:
        conn.close()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Job not found or you do not have access.'}), 404
        flash("Job not found or you do not have access.", "error")
        return redirect(url_for("recruiter_dashboard"))

    try:
        # Remove related applications and saved jobs to avoid orphans
        cursor.execute('DELETE FROM applications WHERE job_id = ?', (job_id,))
        cursor.execute('DELETE FROM saved_jobs WHERE job_id = ?', (job_id,))
        cursor.execute('DELETE FROM job_postings WHERE id = ?', (job_id,))
        conn.commit()
        conn.close()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Job deleted successfully.'}), 200
        
        flash("Job deleted successfully.", "success")
    except Exception as e:
        conn.rollback()
        conn.close()
        error_msg = f"Failed to delete job: {str(e)}"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg}), 500
        flash(error_msg, "error")

    return redirect(url_for("recruiter_dashboard"))

@app.route("/recruiter/all_candidates")
@login_required(role="recruiter")
def all_candidates():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    try:
        recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
        if not recruiter:
            conn.close()
            return redirect(url_for("recruiter_dashboard"))

        # Fetch all candidates who applied to recruiter's jobs
        candidates = cursor.execute(
            """
            SELECT DISTINCT
                   js.id as seeker_id, js.full_name, js.email,
                   js.primary_skills, js.experience_years, js.user_id,
                   COUNT(a.id) as application_count
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            JOIN job_seekers js ON a.seeker_id = js.id
            WHERE jp.recruiter_id = ?
            GROUP BY js.id
            ORDER BY js.full_name
            """,
            (recruiter['id'],),
        ).fetchall()

        # Compute ATS scores for all candidates
        candidate_ats_scores = {}
        for candidate in candidates:
            try:
                resume = cursor.execute(
                    'SELECT filename FROM resumes WHERE user_id = ?',
                    (candidate['user_id'],)
                ).fetchone()
                
                if resume:
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                    if os.path.exists(resume_path):
                        analysis_result = analyzer.analyze_resume_file(
                            resume_path,
                            profile_skills=candidate['primary_skills'] or '',
                            experience_years=candidate['experience_years'] or 0,
                        )
                        if analysis_result and 'ats' in analysis_result:
                            candidate_ats_scores[candidate['seeker_id']] = analysis_result['ats']['ats_score']
            except Exception as e:
                print(f"Error analyzing candidate {candidate.get('seeker_id')}: {str(e)}")
                pass

        conn.close()
        return render_template("all_candidates.html", candidates=candidates or [], candidate_ats_scores=candidate_ats_scores)
    except Exception as e:
        conn.close()
        print(f"Error in all_candidates: {str(e)}")
        return render_template("all_candidates.html", candidates=[], candidate_ats_scores={})

@app.route("/recruiter/all_shortlisted")
@login_required(role="recruiter")
def all_shortlisted():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        return redirect(url_for("recruiter_dashboard"))

    # Fetch all shortlisted candidates
    candidates = cursor.execute(
        """
        SELECT a.id as application_id,
               js.full_name, js.email, js.user_id as seeker_user_id,
               js.primary_skills, js.experience_years,
               jp.job_title, a.applied_at
        FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        JOIN job_seekers js ON a.seeker_id = js.id
        WHERE jp.recruiter_id = ? AND a.status = 'shortlisted'
        ORDER BY a.applied_at DESC
        """,
        (recruiter['id'],),
    ).fetchall()

    # Compute ATS scores
    candidate_ats_scores = {}
    for candidate in candidates:
        try:
            resume = cursor.execute(
                'SELECT filename FROM resumes WHERE user_id = ?',
                (candidate['seeker_user_id'],)
            ).fetchone()
            
            if resume:
                resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                if os.path.exists(resume_path):
                    analysis_result = analyzer.analyze_resume_file(
                        resume_path,
                        profile_skills=candidate['primary_skills'] or '',
                        experience_years=candidate['experience_years'] or 0,
                    )
                    if analysis_result and 'ats' in analysis_result:
                        candidate_ats_scores[candidate['application_id']] = analysis_result['ats']['ats_score']
        except Exception:
            pass

    conn.close()
    return render_template("all_shortlisted.html", candidates=candidates or [], candidate_ats_scores=candidate_ats_scores)

@app.route("/recruiter/analytics")
@login_required(role="recruiter")
def analytics():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    recruiter = cursor.execute('SELECT id FROM recruiters WHERE user_id = ?', (user_id,)).fetchone()
    if not recruiter:
        conn.close()
        return redirect(url_for("recruiter_dashboard"))

    # Get various analytics metrics
    total_jobs = cursor.execute(
        'SELECT COUNT(*) as count FROM job_postings WHERE recruiter_id = ?',
        (recruiter['id'],)
    ).fetchone()['count']
    
    active_jobs = cursor.execute(
        'SELECT COUNT(*) as count FROM job_postings WHERE recruiter_id = ? AND is_active = 1',
        (recruiter['id'],)
    ).fetchone()['count']
    
    total_applications = cursor.execute(
        """
        SELECT COUNT(*) as count FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        WHERE jp.recruiter_id = ?
        """,
        (recruiter['id'],)
    ).fetchone()['count']
    
    shortlisted = cursor.execute(
        """
        SELECT COUNT(*) as count FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        WHERE jp.recruiter_id = ? AND a.status = 'shortlisted'
        """,
        (recruiter['id'],)
    ).fetchone()['count']
    
    rejected = cursor.execute(
        """
        SELECT COUNT(*) as count FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        WHERE jp.recruiter_id = ? AND a.status = 'rejected'
        """,
        (recruiter['id'],)
    ).fetchone()['count']
    
    hired = cursor.execute(
        """
        SELECT COUNT(*) as count FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        WHERE jp.recruiter_id = ? AND a.status = 'hired'
        """,
        (recruiter['id'],)
    ).fetchone()['count']

    conn.close()

    analytics_data = {
        'total_jobs': total_jobs,
        'active_jobs': active_jobs,
        'total_applications': total_applications,
        'shortlisted': shortlisted,
        'rejected': rejected,
        'hired': hired,
        'conversion_rate': round((hired / max(total_applications, 1)) * 100, 1) if total_applications > 0 else 0,
    }

    return render_template("analytics.html", analytics=analytics_data)

@app.route("/seeker/apply/<int:job_id>", methods=["POST"])
@login_required(role="seeker")
def apply_job(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    # Check if seeker has uploaded a resume
    resume = cursor.execute('SELECT id FROM resumes WHERE user_id = ?', (user_id,)).fetchone()
    if not resume:
        conn.close()
        flash("Please upload a resume before applying to jobs.", "error")
        return redirect(url_for("seeker_dashboard"))

    # Get seeker_id from job_seekers table
    seeker = cursor.execute('SELECT id FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
    if not seeker:
        conn.close()
        flash("Profile not found. Please complete your profile.", "error")
        return redirect(url_for("seeker_profile"))

    try:
        # Insert application
        cursor.execute(
            """
            INSERT INTO applications (job_id, seeker_id, status)
            VALUES (?, ?, 'applied')
            """,
            (job_id, seeker['id']),
        )
        conn.commit()
        flash("Application submitted successfully!", "success")
    except Exception as e:
        conn.rollback()
        if "UNIQUE constraint failed" in str(e):
            flash("You have already applied to this job.", "warning")
        else:
            flash(f"Failed to apply: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for("seeker_dashboard"))

@app.route("/recruiter/view_candidate/<int:seeker_user_id>")
@login_required(role="recruiter")
def view_candidate(seeker_user_id):
    conn = get_db()
    cursor = conn.cursor()

    # Get application_id from query param (if viewing from specific application)
    application_id = request.args.get('application_id', type=int)

    # Fetch candidate profile
    candidate = cursor.execute(
        """
        SELECT js.id, js.full_name, js.email, js.education, js.experience_years, js.primary_skills,
               u.username
        FROM job_seekers js
        JOIN users u ON js.user_id = u.id
        WHERE u.id = ?
        """,
        (seeker_user_id,),
    ).fetchone()

    if not candidate:
        conn.close()
        flash("Candidate not found.", "error")
        return redirect(url_for("recruiter_dashboard"))

    # Fetch application details if application_id provided
    application = None
    if application_id:
        application = cursor.execute(
            """
            SELECT a.id, a.status, a.applied_at, jp.job_title
            FROM applications a
            JOIN job_postings jp ON a.job_id = jp.id
            WHERE a.id = ?
            """,
            (application_id,)
        ).fetchone()

    # Fetch resume
    resume = cursor.execute(
        'SELECT filename, original_filename, job_role FROM resumes WHERE user_id = ?',
        (seeker_user_id,)
    ).fetchone()

    analysis = None
    if resume:
        try:
            path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
            analysis = analyzer.analyze_resume_file(
                path,
                profile_skills=(candidate['primary_skills'] if candidate else ''),
                experience_years=(candidate['experience_years'] if candidate else 0),
                education=(candidate['education'] if candidate else '')
            )
        except Exception:
            analysis = None

    conn.close()

    return render_template(
        "view_candidate.html",
        candidate=candidate,
        resume=resume,
        analysis=analysis,
        application=application
    )

@app.route("/recruiter/update_application_status/<int:application_id>", methods=["POST"])
@login_required(role="recruiter")
def update_application_status(application_id):
    status = request.form.get("status")
    
    if status not in ['applied', 'shortlisted', 'rejected', 'hired']:
        flash("Invalid status.", "error")
        return redirect(url_for("recruiter_dashboard"))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            'UPDATE applications SET status = ? WHERE id = ?',
            (status, application_id)
        )
        conn.commit()
        flash(f"Application status updated to {status}!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to update status: {str(e)}", "error")
    finally:
        conn.close()

    # Redirect back to the candidate view if coming from there
    referer = request.referrer
    if referer and 'view_candidate' in referer:
        return redirect(referer)
    
    return redirect(url_for("recruiter_dashboard"))

@app.route("/job/<int:job_id>")
@login_required()
def job_details(job_id):
    conn = get_db()
    cursor = conn.cursor()

    job = cursor.execute(
        """
        SELECT jp.*, r.company_name, r.industry_type, r.company_location
        FROM job_postings jp
        JOIN recruiters r ON jp.recruiter_id = r.id
        WHERE jp.id = ?
        """,
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        flash("Job not found.", "error")
        return redirect(url_for("seeker_dashboard"))

    # Check if current user has applied (only for seekers)
    has_applied = False
    is_saved = False
    if session.get('role') == 'seeker':
        user_id = session.get('user_id')
        seeker = cursor.execute('SELECT id FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
        if seeker:
            application = cursor.execute(
                'SELECT id FROM applications WHERE job_id = ? AND seeker_id = ?',
                (job_id, seeker['id'])
            ).fetchone()
            has_applied = application is not None

            saved = cursor.execute(
                'SELECT id FROM saved_jobs WHERE job_id = ? AND seeker_id = ?',
                (job_id, seeker['id'])
            ).fetchone()
            is_saved = saved is not None

    conn.close()

    return render_template("job_details.html", job=job, has_applied=has_applied, is_saved=is_saved)

@app.route("/seeker/save_job/<int:job_id>", methods=["POST"])
@login_required(role="seeker")
def save_job(job_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    seeker = cursor.execute('SELECT id FROM job_seekers WHERE user_id = ?', (user_id,)).fetchone()
    if not seeker:
        conn.close()
        return jsonify({'error': 'Profile not found'}), 400

    try:
        # Check if already saved
        existing = cursor.execute(
            'SELECT id FROM saved_jobs WHERE job_id = ? AND seeker_id = ?',
            (job_id, seeker['id'])
        ).fetchone()

        if existing:
            # Unsave
            cursor.execute('DELETE FROM saved_jobs WHERE id = ?', (existing['id'],))
            conn.commit()
            conn.close()
            return jsonify({'status': 'unsaved'})
        else:
            # Save
            cursor.execute(
                'INSERT INTO saved_jobs (job_id, seeker_id) VALUES (?, ?)',
                (job_id, seeker['id'])
            )
            conn.commit()
            conn.close()
            return jsonify({'status': 'saved'})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/seeker/all_jobs")
@login_required(role="seeker")
def all_jobs():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch all active job postings
        jobs = cursor.execute(
            """
            SELECT jp.id, jp.job_title, jp.job_location, jp.employment_type,
                   jp.experience_level, jp.salary_range, jp.required_skills,
                   jp.job_description, r.company_name,
                   CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END as already_applied,
                   CASE WHEN sj.id IS NOT NULL THEN 1 ELSE 0 END as is_saved
            FROM job_postings jp
            JOIN recruiters r ON jp.recruiter_id = r.id
            LEFT JOIN applications a ON a.job_id = jp.id AND a.seeker_id = (
                SELECT id FROM job_seekers WHERE user_id = ?
            )
            LEFT JOIN saved_jobs sj ON sj.job_id = jp.id AND sj.seeker_id = (
                SELECT id FROM job_seekers WHERE user_id = ?
            )
            WHERE jp.is_active = 1
            ORDER BY jp.id DESC
            """,
            (user_id, user_id),
        ).fetchall()

        # Get seeker profile and resume skills
        seeker = cursor.execute(
            'SELECT id, primary_skills FROM job_seekers WHERE user_id = ?',
            (user_id,)
        ).fetchone()

        seeker_skills = set()
        if seeker:
            if seeker['primary_skills']:
                seeker_skills.update(skill.strip().lower() for skill in seeker['primary_skills'].split(','))
            
            # Add skills from resume if available
            try:
                resume = cursor.execute(
                    'SELECT filename FROM resumes WHERE user_id = ?',
                    (user_id,)
                ).fetchone()
                
                if resume:
                    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
                    if os.path.exists(resume_path):
                        analysis_result = analyzer.analyze_resume_file(
                            resume_path,
                            profile_skills=seeker['primary_skills'] or '',
                            experience_years=0,
                        )
                        if analysis_result and 'extracted_skills' in analysis_result:
                            seeker_skills.update(skill.lower() for skill in analysis_result['extracted_skills'])
            except Exception as e:
                print(f"Error extracting resume skills: {str(e)}")
                pass

        # Compute match scores
        match_scores = {}
        for job in jobs:
            try:
                job_skills = set(skill.strip().lower() for skill in (job['required_skills'] or '').split(',') if skill.strip())
                if job_skills:
                    matched = len(seeker_skills & job_skills)
                    match_percentage = round((matched / len(job_skills)) * 100)
                    match_scores[job['id']] = match_percentage
                else:
                    match_scores[job['id']] = 0
            except Exception:
                match_scores[job['id']] = 0

        conn.close()
        return render_template("all_jobs.html", jobs=jobs or [], match_scores=match_scores)
    except Exception as e:
        conn.close()
        print(f"Error in all_jobs: {str(e)}")
        return render_template("all_jobs.html", jobs=[], match_scores={})

@app.route("/seeker/my_applications")
@login_required(role="seeker")
def my_applications():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    seeker = cursor.execute(
        'SELECT id FROM job_seekers WHERE user_id = ?',
        (user_id,)
    ).fetchone()

    if not seeker:
        conn.close()
        return redirect(url_for("seeker_dashboard"))

    # Fetch all applications for this seeker
    applications = cursor.execute(
        """
        SELECT a.id, a.applied_at, a.status,
               jp.job_title, jp.job_location, jp.employment_type,
               r.company_name
        FROM applications a
        JOIN job_postings jp ON a.job_id = jp.id
        JOIN recruiters r ON jp.recruiter_id = r.id
        WHERE a.seeker_id = ?
        ORDER BY a.applied_at DESC
        """,
        (seeker['id'],)
    ).fetchall()

    conn.close()
    return render_template("my_applications.html", applications=applications or [])

@app.route("/seeker/withdraw_application/<int:application_id>", methods=["POST"])
@login_required(role="seeker")
def withdraw_application(application_id):
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    # Verify the application belongs to this seeker
    application = cursor.execute(
        """
        SELECT a.id, a.status, js.user_id
        FROM applications a
        JOIN job_seekers js ON a.seeker_id = js.id
        WHERE a.id = ? AND js.user_id = ?
        """,
        (application_id, user_id)
    ).fetchone()

    if not application:
        conn.close()
        flash("Application not found.", "error")
        return redirect(url_for("my_applications"))

    # Only allow withdrawal if status is 'applied' (not shortlisted/hired/rejected)
    if application['status'] != 'applied':
        conn.close()
        flash("Cannot withdraw application with current status.", "error")
        return redirect(url_for("my_applications"))

    # Delete the application
    cursor.execute('DELETE FROM applications WHERE id = ?', (application_id,))
    conn.commit()
    conn.close()

    flash("Application withdrawn successfully.", "success")
    return redirect(url_for("my_applications"))

@app.route("/seeker/my_saved_jobs")
@login_required(role="seeker")
def my_saved_jobs():
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    seeker = cursor.execute(
        'SELECT id FROM job_seekers WHERE user_id = ?',
        (user_id,)
    ).fetchone()

    if not seeker:
        conn.close()
        return redirect(url_for("seeker_dashboard"))

    # Fetch all saved jobs for this seeker
    saved_jobs = cursor.execute(
        """
        SELECT jp.id, jp.job_title, jp.job_location, jp.employment_type,
               jp.experience_level, jp.salary_range, jp.required_skills,
               r.company_name, sj.saved_at,
               CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END as already_applied
        FROM saved_jobs sj
        JOIN job_postings jp ON sj.job_id = jp.id
        JOIN recruiters r ON jp.recruiter_id = r.id
        LEFT JOIN applications a ON a.job_id = jp.id AND a.seeker_id = ?
        WHERE sj.seeker_id = ?
        ORDER BY sj.saved_at DESC
        """,
        (seeker['id'], seeker['id'])
    ).fetchall()

    conn.close()
    return render_template("my_saved_jobs.html", saved_jobs=saved_jobs or [])

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("login"))

@app.errorhandler(Exception)
def handle_error(error):
    """Global error handler to prevent session loss on errors"""
    print(f"ERROR: {str(error)}")
    import traceback
    traceback.print_exc()
    
    # Don't clear session on errors
    user_id = session.get("user_id")
    user_role = session.get("role")
    
    if user_id:
        # User is logged in, redirect to appropriate dashboard without error message
        if user_role == "seeker":
            return redirect(url_for("seeker_dashboard"))
        elif user_role == "recruiter":
            return redirect(url_for("recruiter_dashboard"))
    
    # User not logged in
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
