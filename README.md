# Information Security Lab - File Encryption and Access Control System

A secure file management system that implements encryption, role-based access control, and comprehensive audit logging for information security lab purposes.

## Features

### 1. User Registration and Role Assignment
- Users can register with username, email, and password
- Role-based access control (Admin, Manager, User)
- Passwords are hashed using bcrypt (PBKDF2-SHA256) before storage

### 2. File Upload and Encryption
- Files are encrypted using AES-256 encryption
- Each file gets a unique symmetric key
- The symmetric key is encrypted separately for each role that has access
- Role-based key encryption using PBKDF2-HMAC-SHA256

### 3. Secure Storage
- Encrypted files stored as ciphertext in the uploads directory
- Metadata stored in SQLite database:
  - File name, owner, allowed roles
  - Encrypted keys for each role
  - File size and upload timestamp

### 4. Access Control Verification
- System verifies user role before granting access
- Only authorized users receive the decrypted key for their role
- Unauthorized users cannot decrypt files

### 5. Audit and Logging
- All file operations are logged (upload, download, login, logout)
- Logs include: user, action, file, timestamp, IP address
- Admin interface to view audit logs

## Installation

### Step 1: Create a Virtual Environment

**On Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

**On Windows (Command Prompt):**
```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate.bat
```

**On Linux/Mac:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

**Note:** If you get an execution policy error on Windows PowerShell, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 2: Install Dependencies

Once the virtual environment is activated (you'll see `(venv)` in your terminal), install the required packages:

```bash
pip install -r requirements.txt
```

### Step 3: Run the Application

```bash
python app.py
```

### Step 4: Access the Application

- Open your browser and go to `http://localhost:5000`
- Default admin credentials:
  - Username: `admin`
  - Password: `admin123`

### Deactivating the Virtual Environment

When you're done working, you can deactivate the virtual environment:

```bash
deactivate
```

## Project Structure

```
.
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   └── audit_logs.html
├── static/               # CSS and static files
│   └── style.css
├── uploads/              # Encrypted file storage (created automatically)
└── security_lab.db       # SQLite database (created automatically)
```

## Security Features

### Password Hashing
- Uses Werkzeug's `generate_password_hash` with PBKDF2-SHA256
- Passwords are never stored in plaintext

### File Encryption
- **Symmetric Encryption**: AES-256 (Fernet) for file encryption
- **Key Management**: Each file has a unique symmetric key
- **Role-based Key Encryption**: Symmetric keys are encrypted using PBKDF2-HMAC-SHA256 with role-specific salts

### Access Control
- Role-based access control (RBAC)
- Users can only access files if their role is in the allowed roles list
- File owners always have access to their files

### Audit Logging
- Comprehensive logging of all security-relevant events
- Tracks: user actions, file operations, IP addresses, timestamps
- Admin-only access to audit logs

## Usage

1. **Register a new user:**
   - Go to Register page
   - Fill in username, email, password, and select a role
   - Click Register

2. **Login:**
   - Use your credentials to login

3. **Upload a file:**
   - Go to Dashboard → Upload
   - Select a file
   - Choose which roles should have access
   - Click "Upload and Encrypt"

4. **Download a file:**
   - View files in Dashboard
   - Click Download on any accessible file
   - File is automatically decrypted for you

5. **View Audit Logs (Admin only):**
   - Admin users can access Audit Logs from the navigation menu
   - View all security events and file operations

## Security Considerations

⚠️ **Important Notes for Production:**

1. **Change the SECRET_KEY** in `app.py` to a secure random value
2. **Change the MASTER_PASSWORD** in `app.py` to a strong password and store it securely (e.g., environment variable)
3. **Use HTTPS** in production
4. **Implement rate limiting** for login attempts
5. **Use a production-grade database** (PostgreSQL, MySQL) instead of SQLite
6. **Implement session management** with secure cookies
7. **Add file type validation** and virus scanning
8. **Implement backup and recovery** procedures
9. **Use environment variables** for sensitive configuration
10. **Regular security audits** and updates

## Technologies Used

- **Backend**: Flask (Python)
- **Database**: SQLite (SQLAlchemy ORM)
- **Authentication**: Flask-Login
- **Password Hashing**: bcrypt (via Werkzeug)
- **Encryption**: cryptography library (Fernet/AES-256, PBKDF2)
- **Frontend**: HTML, CSS, JavaScript

## License

This project is created for educational purposes as part of an Information Security Lab.

