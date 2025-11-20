# Complete Project Explanation

## Overview

This is a **secure file management system** that implements **multi-layer encryption** and **role-based access control**. The system ensures that files are encrypted at rest, and only authorized users can decrypt and access them.

---

## 🔐 What is Encrypted?

### 1. **User Passwords** (Hashed, not encrypted)
- **What**: User passwords during registration
- **Method**: PBKDF2-SHA256 hashing (via Werkzeug)
- **Where**: Stored in `security_lab.db` → `User` table → `password_hash` column
- **Why**: Passwords are never stored in plaintext. Hashing is one-way - you can't reverse it to get the original password
- **Process**: 
  ```
  User enters password → Hash with PBKDF2-SHA256 → Store hash in database
  Login: User enters password → Hash it → Compare with stored hash
  ```

### 2. **Uploaded Files** (Encrypted)
- **What**: The actual file content (PDF, DOCX, images, etc.)
- **Method**: AES-256 encryption using Fernet (symmetric encryption)
- **Where**: Stored in `uploads/` folder as encrypted binary files
- **Key**: Each file gets a unique 256-bit symmetric key
- **Process**:
  ```
  Original File → Generate unique AES-256 key → Encrypt file → Save encrypted file
  ```

### 3. **Symmetric Keys** (Encrypted for each role)
- **What**: The AES-256 key used to encrypt the file
- **Method**: Encrypted separately for each role using PBKDF2-HMAC-SHA256
- **Where**: Stored in `security_lab.db` → `File` table → `encrypted_key_data` column (JSON format)
- **Why**: Different roles get different encrypted versions of the same key. Only users with the correct role can decrypt their version of the key
- **Process**:
  ```
  File's AES-256 key → Encrypt for "user" role → Encrypt for "manager" role → Encrypt for "admin" role
  → Store all encrypted keys in database
  ```

---

## 📊 Complete System Flow

### **Phase 1: User Registration**

```
1. User fills registration form (username, email, password, role)
   ↓
2. System checks if username/email already exists
   ↓
3. Password is HASHED using PBKDF2-SHA256
   ↓
4. User record created in database:
   - username (plaintext)
   - email (plaintext)
   - password_hash (hashed password)
   - role (plaintext: 'admin', 'user', 'manager')
   ↓
5. User can now login
```

**What's stored in database:**
- ✅ Username: `"john_doe"` (plaintext)
- ✅ Email: `"john@example.com"` (plaintext)
- ✅ Password Hash: `"pbkdf2:sha256:260000$..."` (hashed, cannot be reversed)
- ✅ Role: `"user"` (plaintext)

---

### **Phase 2: File Upload Process**

This is the most complex part with multiple encryption layers:

```
STEP 1: User selects file and roles
   ↓
   User uploads "document.pdf"
   Selects roles: "user", "manager"
   ↓

STEP 2: System automatically adds roles
   ↓
   - Adds uploader's role (if not selected)
   - Always adds "admin" role
   Final roles: ["user", "manager", "admin"] + uploader's role
   ↓

STEP 3: Generate symmetric key
   ↓
   System generates a unique 256-bit AES key
   Example: b'xK8...' (random, unique for this file)
   ↓

STEP 4: Encrypt the file
   ↓
   Original file data → AES-256 encryption → Encrypted ciphertext
   ↓

STEP 5: Encrypt the symmetric key for each role
   ↓
   For each role in ["user", "manager", "admin"]:
   
   a) Derive role-specific key using PBKDF2:
      - Input: MASTER_PASSWORD + role name (as salt)
      - Output: Role-specific encryption key
   
   b) Encrypt the file's symmetric key with role-specific key
      - Input: File's AES-256 key
      - Encryption: Fernet (AES-128 in CBC mode)
      - Output: Encrypted key for this role
   
   Result: {
     "user": "gAAAAABh...",      (encrypted key for user role)
     "manager": "gAAAAABi...",   (encrypted key for manager role)
     "admin": "gAAAAABj..."      (encrypted key for admin role)
   }
   ↓

STEP 6: Save encrypted file
   ↓
   Encrypted file saved to: uploads/encrypted_1234567890.123_document.pdf
   (This is binary encrypted data - not readable)
   ↓

STEP 7: Save metadata to database
   ↓
   File record created:
   - filename: "document.pdf"
   - encrypted_filename: "encrypted_1234567890.123_document.pdf"
   - owner_id: 1
   - encrypted_key_data: '{"user":"gAAAAABh...","manager":"gAAAAABi...","admin":"gAAAAABj..."}'
   - allowed_roles: '["user","manager","admin"]'
   - file_size: 1024000
   ↓

STEP 8: Log audit event
   ↓
   Audit log: "User john_doe uploaded file: document.pdf"
```

**What's stored where:**

| Data | Location | Format | Encrypted? |
|------|----------|--------|------------|
| Original file | ❌ Not stored | - | - |
| Encrypted file | `uploads/` folder | Binary ciphertext | ✅ Yes (AES-256) |
| File's symmetric key | Database | JSON with encrypted keys | ✅ Yes (PBKDF2 + Fernet) |
| File metadata | Database | Plaintext | ❌ No |
| Allowed roles | Database | JSON array | ❌ No |

---

### **Phase 3: File Download/Access Process**

When a user wants to download a file:

```
STEP 1: User clicks "Download" on a file
   ↓

STEP 2: Access control check
   ↓
   System checks:
   - Is user the file owner? → Allow
   - Is user an admin? → Allow
   - Is user's role in allowed_roles? → Allow
   - Otherwise → Deny
   ↓

STEP 3: Get encrypted key for user's role
   ↓
   From database, get encrypted_key_data:
   {
     "user": "gAAAAABh...",
     "manager": "gAAAAABi...",
     "admin": "gAAAAABj..."
   }
   
   If user is admin → use "admin" key
   Otherwise → use user's role key (e.g., "user")
   ↓

STEP 4: Decrypt the symmetric key
   ↓
   a) Derive role-specific key using PBKDF2:
      - Input: MASTER_PASSWORD + role name
      - Output: Same role-specific key as during encryption
   
   b) Decrypt the encrypted key:
      - Input: Encrypted key from database
      - Decryption: Fernet decryption
      - Output: Original file's AES-256 symmetric key
   ↓

STEP 5: Read encrypted file from disk
   ↓
   Read: uploads/encrypted_1234567890.123_document.pdf
   (This is binary encrypted data)
   ↓

STEP 6: Decrypt the file
   ↓
   Encrypted file data + Symmetric key → AES-256 decryption → Original file data
   ↓

STEP 7: Send decrypted file to user
   ↓
   File is decrypted in memory and sent to browser
   (Never saved as plaintext on disk)
   ↓

STEP 8: Log audit event
   ↓
   Audit log: "User john_doe downloaded file: document.pdf"
```

**Security Note**: The file is only decrypted in memory during download. The encrypted version remains on disk.

---

## 🔑 Encryption Details

### **Layer 1: File Encryption (AES-256)**

```
Algorithm: Fernet (AES-128 in CBC mode with HMAC)
Key Size: 256 bits (32 bytes)
Key Generation: Cryptographically secure random
Purpose: Encrypt the actual file content
```

**How it works:**
- Fernet generates a random 256-bit key
- File is encrypted using AES-128 in CBC mode
- HMAC is added for authentication
- Result: Encrypted file that cannot be read without the key

### **Layer 2: Key Encryption (PBKDF2 + Fernet)**

```
Algorithm: PBKDF2-HMAC-SHA256 + Fernet
Iterations: 100,000
Salt: Role name (e.g., "user", "admin")
Purpose: Encrypt the file's symmetric key for each role
```

**How it works:**
1. **Key Derivation (PBKDF2)**:
   ```
   Input: MASTER_PASSWORD + Role name (salt)
   Process: 100,000 iterations of HMAC-SHA256
   Output: 256-bit role-specific key
   ```

2. **Key Encryption (Fernet)**:
   ```
   Input: File's symmetric key (256 bits)
   Encryption Key: Role-specific key from step 1
   Process: Fernet encryption
   Output: Encrypted key for this role
   ```

**Why this approach?**
- Each role gets a different encrypted version of the same file key
- A "user" cannot decrypt a "manager's" encrypted key (different PBKDF2 output)
- Even if someone steals the database, they need the MASTER_PASSWORD to decrypt keys
- Role-based access: Only users with the correct role can decrypt their version of the key

---

## 🗄️ Database Structure

### **User Table**
```sql
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash (Hashed password)
- role ('admin', 'user', 'manager')
- created_at
```

### **File Table**
```sql
- id (Primary Key)
- filename (Original filename)
- original_filename
- encrypted_filename (Name in uploads/ folder)
- owner_id (Foreign Key → User)
- encrypted_key_data (JSON: {"role": "encrypted_key", ...})
- allowed_roles (JSON: ["user", "manager", "admin"])
- file_size
- uploaded_at
```

### **AuditLog Table**
```sql
- id (Primary Key)
- user_id (Foreign Key → User)
- action ('upload', 'download', 'login', 'logout')
- file_id (Foreign Key → File, nullable)
- details (Text description)
- ip_address
- timestamp
```

---

## 🔒 Security Mechanisms

### **1. Password Security**
- ✅ Passwords are hashed (not encrypted)
- ✅ One-way function (cannot be reversed)
- ✅ Uses PBKDF2-SHA256 with salt
- ✅ Even database admins cannot see passwords

### **2. File Security**
- ✅ Files encrypted with AES-256
- ✅ Each file has unique key
- ✅ Encrypted files stored on disk
- ✅ Original files never stored

### **3. Key Security**
- ✅ File keys encrypted separately for each role
- ✅ Uses PBKDF2 for key derivation (100,000 iterations)
- ✅ Role-based access control
- ✅ MASTER_PASSWORD required to decrypt keys

### **4. Access Control**
- ✅ Role-based access control (RBAC)
- ✅ Uploader always has access
- ✅ Admin always has access to all files
- ✅ Others need role in allowed_roles list

### **5. Audit Trail**
- ✅ All actions logged
- ✅ Tracks: user, action, file, timestamp, IP
- ✅ Admin-only access to logs
- ✅ Helps detect security incidents

---

## 📈 Data Flow Diagram

### **Upload Flow:**
```
User → Select File → Select Roles
  ↓
System → Add Uploader Role + Admin Role
  ↓
System → Generate AES-256 Key
  ↓
System → Encrypt File (AES-256)
  ↓
System → Encrypt Key for Each Role (PBKDF2 + Fernet)
  ↓
System → Save Encrypted File (uploads/)
  ↓
System → Save Metadata + Encrypted Keys (Database)
  ↓
System → Log Audit Event
```

### **Download Flow:**
```
User → Click Download
  ↓
System → Check Access (Role/Owner/Admin)
  ↓
System → Get Encrypted Key for User's Role (Database)
  ↓
System → Decrypt Key (PBKDF2 + Fernet)
  ↓
System → Read Encrypted File (uploads/)
  ↓
System → Decrypt File (AES-256)
  ↓
System → Send Decrypted File to User (Memory only)
  ↓
System → Log Audit Event
```

---

## 🎯 Key Concepts Explained

### **Why Two Layers of Encryption?**

1. **File Encryption (AES-256)**:
   - Protects file content from unauthorized access
   - Even if someone steals the encrypted file, they can't read it

2. **Key Encryption (PBKDF2 + Fernet)**:
   - Protects the file's key
   - Enables role-based access
   - Different roles get different encrypted keys
   - Requires MASTER_PASSWORD to decrypt keys

### **Why Role-Based Key Encryption?**

Instead of storing one encrypted key, we store multiple:
- One encrypted key for "user" role
- One encrypted key for "manager" role  
- One encrypted key for "admin" role

**Benefits:**
- A "user" cannot decrypt a "manager's" key (different PBKDF2 output)
- Fine-grained access control
- Can revoke access by removing role from allowed_roles
- Admin always has access (admin key always included)

### **What if MASTER_PASSWORD is Compromised?**

If someone gets the MASTER_PASSWORD:
- ✅ They can decrypt keys for all roles
- ✅ They can decrypt all files
- ⚠️ This is why MASTER_PASSWORD must be kept secret
- 💡 In production: Store in environment variable, use key management service

### **What if Database is Stolen?**

If someone steals the database:
- ✅ They get encrypted keys (but can't decrypt without MASTER_PASSWORD)
- ✅ They get encrypted files (but can't decrypt without keys)
- ✅ They get metadata (filenames, owners, roles)
- ❌ They cannot decrypt files without MASTER_PASSWORD

---

## 🔍 Example Scenario

**Scenario**: User "Alice" (role: "manager") uploads "secret.pdf" and allows "user" and "manager" roles.

**What happens:**

1. **Upload**:
   - File encrypted with key: `K_file`
   - `K_file` encrypted for "user" → `E_user(K_file)`
   - `K_file` encrypted for "manager" → `E_manager(K_file)`
   - `K_file` encrypted for "admin" → `E_admin(K_file)` (auto-added)
   - Encrypted file saved: `uploads/encrypted_xxx_secret.pdf`
   - Database stores: `{"user": "E_user(K_file)", "manager": "E_manager(K_file)", "admin": "E_admin(K_file)"}`

2. **User "Bob" (role: "user") downloads**:
   - System checks: Is "user" in allowed_roles? ✅ Yes
   - Gets: `E_user(K_file)` from database
   - Decrypts: `D_user(E_user(K_file))` → `K_file`
   - Reads encrypted file
   - Decrypts file: `D(K_file, encrypted_file)` → Original file
   - Sends to Bob

3. **User "Charlie" (role: "admin") downloads**:
   - System checks: Is admin? ✅ Yes (always allowed)
   - Gets: `E_admin(K_file)` from database
   - Decrypts: `D_admin(E_admin(K_file))` → `K_file`
   - Decrypts file and sends to Charlie

4. **User "Dave" (role: "manager") tries to download**:
   - System checks: Is "manager" in allowed_roles? ✅ Yes
   - Gets: `E_manager(K_file)` from database
   - Decrypts and sends file

5. **User "Eve" (role: "user") tries to download but file only allows "admin"**:
   - System checks: Is "user" in allowed_roles? ❌ No
   - Access denied

---

## 📝 Summary

**What is encrypted:**
1. ✅ User passwords (hashed with PBKDF2-SHA256)
2. ✅ Uploaded files (encrypted with AES-256)
3. ✅ File encryption keys (encrypted with PBKDF2 + Fernet for each role)

**What is NOT encrypted (stored as plaintext):**
- ❌ Usernames
- ❌ Email addresses
- ❌ User roles
- ❌ File metadata (filename, owner, allowed roles)
- ❌ Audit logs

**Security guarantees:**
- ✅ Files cannot be read without proper role
- ✅ Keys cannot be decrypted without MASTER_PASSWORD
- ✅ Passwords cannot be recovered (hashing is one-way)
- ✅ Access is controlled by role
- ✅ All actions are logged

This multi-layer encryption approach ensures that even if one layer is compromised, the data remains protected by other layers.

