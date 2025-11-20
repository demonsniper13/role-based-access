from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import datetime
import json
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_lab.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin', 'user', 'manager', etc.
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_key_data = db.Column(db.Text, nullable=False)  # JSON: {role: encrypted_key}
    allowed_roles = db.Column(db.Text, nullable=False)  # JSON array of roles
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    owner = db.relationship('User', backref=db.backref('files', lazy=True))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # 'upload', 'download', 'view', 'delete'
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    file = db.relationship('File', backref=db.backref('audit_logs', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encryption Utilities
class EncryptionManager:
    @staticmethod
    def generate_key():
        """Generate a new AES-256 key"""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_file(file_data, key):
        """Encrypt file data using AES-256"""
        fernet = Fernet(key)
        return fernet.encrypt(file_data)
    
    @staticmethod
    def decrypt_file(encrypted_data, key):
        """Decrypt file data using AES-256"""
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
    
    @staticmethod
    def encrypt_key_for_role(symmetric_key, role, master_password):
        """Encrypt the symmetric key for a specific role using PBKDF2"""
        # Derive a key from role and master password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=role.encode(),
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        fernet = Fernet(key)
        return fernet.encrypt(symmetric_key)
    
    @staticmethod
    def decrypt_key_for_role(encrypted_key, role, master_password):
        """Decrypt the symmetric key for a specific role"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=role.encode(),
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_key)

# Master password for role-based key encryption (in production, store securely)
MASTER_PASSWORD = "secure-master-password-change-in-production"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Hash password using bcrypt
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        user = User(username=username, email=email, password_hash=password_hash, role=role)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log_audit('login', None, f'User {username} logged in')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', None, f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.all()
    user_files = [f for f in files if f.owner_id == current_user.id]
    
    # Admin can see all files, others see files based on their role
    if current_user.role == 'admin':
        accessible_files = [f for f in files if f.owner_id != current_user.id]
    else:
        accessible_files = [f for f in files if current_user.role in json.loads(f.allowed_roles)]
    
    return render_template('dashboard.html', 
                         user_files=user_files, 
                         accessible_files=accessible_files,
                         user_role=current_user.role)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        allowed_roles = request.form.getlist('allowed_roles')
        
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file:
            # Automatically add uploader's role to allowed roles if not present
            if current_user.role not in allowed_roles:
                allowed_roles.append(current_user.role)
            
            # Always add admin role to ensure admin can access everything
            if 'admin' not in allowed_roles:
                allowed_roles.append('admin')
            
            # Generate symmetric key
            symmetric_key = EncryptionManager.generate_key()
            
            # Read file data
            file_data = file.read()
            
            # Encrypt file
            encrypted_data = EncryptionManager.encrypt_file(file_data, symmetric_key)
            
            # Encrypt key for each allowed role
            encrypted_keys = {}
            for role in allowed_roles:
                encrypted_keys[role] = base64.b64encode(
                    EncryptionManager.encrypt_key_for_role(symmetric_key, role, MASTER_PASSWORD)
                ).decode('utf-8')
            
            # Save encrypted file
            encrypted_filename = f"encrypted_{datetime.datetime.now().timestamp()}_{secure_filename(file.filename)}"
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save to database
            db_file = File(
                filename=secure_filename(file.filename),
                original_filename=file.filename,
                encrypted_filename=encrypted_filename,
                owner_id=current_user.id,
                encrypted_key_data=json.dumps(encrypted_keys),
                allowed_roles=json.dumps(allowed_roles),
                file_size=len(file_data)
            )
            db.session.add(db_file)
            db.session.commit()
            
            log_audit('upload', db_file.id, f'Uploaded file: {file.filename}')
            flash('File uploaded and encrypted successfully!')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)
    allowed_roles = json.loads(file_record.allowed_roles)
    
    # Admin has access to everything
    # Owner has access to their files
    # Others need their role in allowed_roles
    is_admin = current_user.role == 'admin'
    is_owner = file_record.owner_id == current_user.id
    has_role_access = current_user.role in allowed_roles
    
    if not (is_admin or is_owner or has_role_access):
        flash('You do not have permission to access this file')
        return redirect(url_for('dashboard'))
    
    # Get encrypted key for user's role
    encrypted_keys = json.loads(file_record.encrypted_key_data)
    
    # Determine which role's key to use for decryption
    # Admin always uses admin key (which should always exist now)
    # Others use their own role's key
    role_to_use = 'admin' if is_admin else current_user.role
    
    if role_to_use not in encrypted_keys:
        flash('Key not available for your role')
        return redirect(url_for('dashboard'))
    
    # Decrypt the symmetric key
    encrypted_key_b64 = encrypted_keys[role_to_use]
    encrypted_key = base64.b64decode(encrypted_key_b64)
    symmetric_key = EncryptionManager.decrypt_key_for_role(encrypted_key, role_to_use, MASTER_PASSWORD)
    
    # Read and decrypt file
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = EncryptionManager.decrypt_file(encrypted_data, symmetric_key)
    
    log_audit('download', file_id, f'Downloaded file: {file_record.filename}')
    
    # Create in-memory file for download (no temporary files)
    file_stream = BytesIO(decrypted_data)
    file_stream.seek(0)
    
    return send_file(file_stream, as_attachment=True, download_name=file_record.filename)

@app.route('/audit_logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Access denied. Admin role required.')
        return redirect(url_for('dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)

def log_audit(action, file_id, details):
    """Helper function to log audit events"""
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        file_id=file_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: username='admin', password='admin123'")
    app.run(debug=True)

