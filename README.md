# SecureShare 🔐
### Secure File Storage and Controlled Sharing Using Cryptography

**Live Demo:** https://secure-share-ew33.onrender.com

SecureShare is a web-based application developed for the **Cryptography and Network Security** course. It allows registered users to upload files that are encrypted before storage, share files with other registered users, and revoke access when needed.

The project combines authenticated access, authenticated encryption, integrity verification, and access-control mechanisms in a clean, responsive web interface.

## ✨ Features

- **User Authentication:** Registration and login with password hashing using Argon2id.
- **AES-256-GCM Encryption:** Encrypts uploaded file contents before storing them.
- **Secure File Storage:** Stores encrypted file data using MongoDB GridFS.
- **Controlled File Sharing:** Share files with registered users using their email addresses.
- **Access Revocation:** Revoke a recipient's access to a previously shared file.
- **Authorization Checks:** Restricts file downloads to the owner or a recipient with an active share.
- **File Integrity Verification:** Uses SHA-256 hashes to verify downloaded file contents.
- **Audit Logging:** Records events such as uploads, downloads, sharing, and access revocation.
- **Dashboard:** Displays file statistics, sharing information, database status, and recent activity.
- **Input Validation:** Validates registration details and uploaded files.
- **Session Security:** Uses Flask-Login, HTTP-only session cookies, and CSRF protection for applicable forms.

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, Bootstrap, Jinja2 |
| Backend | Python, Flask |
| Database | MongoDB Atlas |
| File Storage | MongoDB GridFS |
| Encryption | AES-256-GCM |
| Password Hashing | Argon2id |
| Integrity Verification | SHA-256 |
| Authentication | Flask-Login |
| Form Security | Flask-WTF and CSRF protection |
| Rate Limiting | Flask-Limiter |
| Deployment | Render |
| Production Server | Gunicorn |
| Testing | Pytest |

## 🔐 Security Workflow

1. A user registers and their password is hashed before being stored.
2. The authenticated user uploads a file.
3. The application encrypts the file using AES-256-GCM and a randomly generated nonce.
4. The encrypted file is stored in MongoDB GridFS, while its metadata and SHA-256 hash are stored in MongoDB.
5. The owner can share the file with another registered user.
6. When a download is requested, the application verifies ownership or an active share before retrieving and decrypting the file.
7. The application verifies the decrypted file's SHA-256 hash before returning it.
8. The owner can revoke a share, preventing subsequent downloads through that share.

**Security note:** SecureShare performs encryption on the server before storage. It is not end-to-end encryption because the server handles the encryption and decryption keys.

## 🏗️ Project Structure

```text
SecureShare/
├── app.py
├── config.py
├── extensions.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── PROJECT_PLAN.md
├── routes/
│   ├── __init__.py
│   ├── auth.py
│   ├── dashboard.py
│   └── files.py
├── services/
│   ├── encryption.py
│   └── storage.py
├── security/
│   ├── __init__.py
│   └── user.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── my_files.html
│   └── shared_files.html
├── static/
│   ├── css/
│   ├── js/
│   └── images/
├── tests/
│   ├── test_encryption.py
│   ├── test_storage.py
│   └── test_file_security.py
└── reports/
```

## ⚙️ Local Installation

### Prerequisites

- Python 3.10 or a compatible Python version
- MongoDB Atlas account
- Git

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SecureShare
```

Replace the placeholder with your actual GitHub repository URL.

### 2. Create and activate a virtual environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows**

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file in the project root. Generate your own secrets and add your MongoDB Atlas connection string.

```env
APP_SECRET_KEY=your_generated_application_secret
MASTER_KEY=your_generated_base64_master_key
MONGO_URI=your_mongodb_atlas_connection_string
MONGO_DB_NAME=secureshare
FLASK_DEBUG=1
SESSION_COOKIE_SECURE=0
```

The values above are placeholders. Generate secure keys using Python and use your own database credentials.

**Important:** Keep `.env` private. Never commit it to GitHub or share your secret keys. Back up the master key securely; changing it will prevent decryption of files encrypted with the previous key.

### 5. Run the application

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## 🧪 Running Tests

Run the test suite with:

```bash
python -m pytest -v
```

The project has a recorded test run of **17 passing tests** covering:

- AES-GCM encryption and decryption
- Rejection of incorrect keys and tampered ciphertext
- File integrity verification
- File access control and revoked-share restrictions
- Upload validation
- Authentication and session handling
- Duplicate registration validation
- GridFS storage helper configuration

The storage-helper test uses a mock; it does not replace a full integration test against a live GridFS database.

## ☁️ Deployment

SecureShare is deployed using Render.

- **Live application:** https://secure-share-ew33.onrender.com
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app`

Production environment variables are configured in the Render dashboard. Debug mode is disabled in production, and secure session cookies are enabled over HTTPS.

The application uses MongoDB Atlas and GridFS for persistent database-backed file storage.

## ⚠️ Security and Deployment Considerations

- Uploaded file contents are encrypted before being stored.
- The master encryption key must remain private and should be backed up securely.
- Database access should be restricted with appropriate MongoDB Atlas network-access rules and credentials.
- The application's configured upload limit is 16 MB.
- A successful test run does not replace end-to-end security testing or an independent security audit.
- Flask-Limiter's default in-memory storage is not persistent across worker restarts. A persistent shared backend is recommended for production rate limiting.
- Render's free services may spin down after inactivity, so the first request after a period of inactivity may take longer.

## 🎯 Project Objective

The objective of SecureShare is to demonstrate how cryptographic techniques and web security controls can be integrated into a practical file-sharing application. It illustrates encryption at rest, password hashing, authenticated access, integrity verification, controlled sharing, access revocation, and security event logging.

## 👩‍💻 Academic Project

**Project:** SecureShare — Secure File Storage and Controlled Sharing  
**Subject:** Cryptography and Network Security  
**Purpose:** B.Tech semester project
