# Quick Start Guide

Follow these steps to get the Information Security Lab project running:

## Prerequisites
- Python 3.7 or higher installed on your system
- Check Python version: `python --version` or `python3 --version`

## Step-by-Step Instructions

### Step 1: Open Terminal/PowerShell
- Open PowerShell or Command Prompt in the project directory
- Or right-click in the project folder and select "Open in Terminal"

### Step 2: Create Virtual Environment
```powershell
python -m venv venv
```

### Step 3: Activate Virtual Environment

**For PowerShell:**
```powershell
.\venv\Scripts\Activate.ps1
```

**If you get an execution policy error, run this first:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**For Command Prompt (cmd):**
```cmd
venv\Scripts\activate.bat
```

**You should see `(venv)` in your terminal prompt when activated.**

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

Wait for all packages to install. This may take a minute.

### Step 5: Run the Application
```powershell
python app.py
```

You should see output like:
```
 * Running on http://127.0.0.1:5000
```

### Step 6: Access the Application
1. Open your web browser
2. Go to: `http://localhost:5000` or `http://127.0.0.1:5000`
3. You should see the login page

### Step 7: Login
- **Default Admin Account:**
  - Username: `admin`
  - Password: `admin123`

## What to Do Next

1. **Register a new user:**
   - Click "Register" in the navigation
   - Fill in the form and select a role (User, Manager, or Admin)
   - Click Register

2. **Upload a file:**
   - After logging in, go to Dashboard
   - Click "Upload New File"
   - Select a file and choose which roles can access it
   - Click "Upload and Encrypt"

3. **Download a file:**
   - View files in the Dashboard
   - Click "Download" on any file you have access to

4. **View Audit Logs (Admin only):**
   - Admin users can click "Audit Logs" in the navigation
   - View all security events and file operations

## Stopping the Application

- Press `Ctrl + C` in the terminal to stop the server

## Deactivating Virtual Environment

When you're done working:
```powershell
deactivate
```

## Troubleshooting

**Problem: "python is not recognized"**
- Make sure Python is installed and added to PATH
- Try using `python3` instead of `python`

**Problem: "pip is not recognized"**
- Make sure pip is installed: `python -m ensurepip --upgrade`
- Or use: `python -m pip install -r requirements.txt`

**Problem: Port 5000 already in use**
- Change the port in `app.py` (last line): `app.run(debug=True, port=5001)`

**Problem: Database errors**
- Delete `security_lab.db` and restart the application (it will be recreated)

## Next Time You Run

1. Activate virtual environment: `.\venv\Scripts\Activate.ps1`
2. Run application: `python app.py`

That's it! The virtual environment and dependencies are already set up.

