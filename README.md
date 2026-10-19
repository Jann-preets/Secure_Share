# SecureShare 🔐

**A Secure File Storage and Sharing System Using Cryptography**

SecureShare is a web application developed as a semester project for **Cryptography and Network Security**. It allows registered users to upload files, store them in encrypted form, share them with other registered users, and revoke access when required.

The project demonstrates how cryptographic techniques and web application security controls can be combined to protect stored files and control access.

## Features

- **User authentication:** Registration, login and logout.
- **Password security:** Password hashing using Argon2id.
- **File encryption:** AES-256-GCM authenticated encryption for uploaded file contents.
- **Secure file storage:** Encrypted file data stored using MongoDB GridFS.
- **Controlled sharing:** Share files with registered users through their email addresses.
- **Access revocation:** Revoke a recipient's access to a previously shared file.
- **Integrity verification:** SHA-256 hashes used to verify downloaded file contents.
- **Access control:** Ownership and active sharing permissions checked before downloads.
- **Audit logging:** Records events such as uploads, downloads, sharing and revocation.
- **Dashboard:** Displays file statistics, database status and recent activity.
- **Security controls:** CSRF protection, request-size limits, rate-limiting support and secure session-cookie settings.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, Bootstrap, Jinja2 |
| Database | MongoDB Atlas |
| File storage | MongoDB GridFS |
| Encryption | AES-256-GCM |
| Integrity checking | SHA-256 |
| Password hashing | Argon2id |
| Authentication | Flask-Login |
| Security | Flask-WTF, Flask-Limiter |
| Testing | Pytest, Mongomock |

## Architecture

The application follows a modular Flask architecture.

1. **Presentation layer:** HTML templates, Bootstrap and JavaScript provide the user interface.
2. **Application layer:** Flask routes handle authentication, dashboard operations, uploads, downloads, sharing and revocation.
3. **Security layer:** AES-GCM encryption protects file contents; Argon2id hashes passwords; authorization checks control access.
4. **Storage layer:** MongoDB stores user accounts, file metadata, share permissions and audit records. GridFS stores encrypted file data.

### File upload workflow

1. The user selects a file and submits it.
2. The application validates the filename and file size.
3. The file contents are encrypted using AES-256-GCM with a randomly generated nonce.
4. The encrypted contents are stored in GridFS.
5. File metadata, including the owner, nonce, size and SHA-256 hash, is saved in MongoDB.
6. An audit event is recorded.

### File download workflow

1. The user requests a file download.
2. The application checks whether the user owns the file or has an active share.
3. The encrypted data is retrieved from GridFS.
4. The application decrypts and authenticates the ciphertext.
5. The SHA-256 hash of the recovered content is compared with the stored hash.
6. The file is returned only if the checks succeed.

### Sharing and revocation workflow

The owner can share a file with another registered user. The recipient can access it while the share remains active. When the owner revokes access, subsequent download requests are denied by the server.

## Security Design

- **AES-256-GCM:** Provides confidentiality and authenticated encryption for file contents.
- **Random nonce:** A fresh 12-byte nonce is generated for each encryption operation.
- **Argon2id:** Passwords are hashed rather than stored as plaintext.
- **SHA-256:** Used as an additional check that the decrypted file matches its stored integrity reference.
- **Authorization checks:** Downloads require ownership or an active share.
- **Environment-based secrets:** Application and encryption keys are configured through environment variables.

**Important security note:** This implementation uses server-side encryption with a master key configured on the server. It is not end-to-end encryption. Anyone with sufficient access to the application server and its encryption key may be able to decrypt stored files. Protect the master key and never commit it to source control.

## Prerequisites

- Python 3.10 or a compatible newer version
- pip
- A MongoDB Atlas account or another compatible MongoDB deployment
- Git (recommended)

## Installation and Setup

### 1. Clone or open the project

```bash
git clone <your-repository-url>
cd BPP
```

If you already have the project locally, open its folder in VS Code and navigate to it in the terminal.

### 2. Create a virtual environment

On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file in the project root. Use `.env.example` as a template.

Generate fresh keys with:

```bash
python -c "import secrets,base64; print('APP_SECRET_KEY=' + secrets.token_hex(32)); print('MASTER_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Copy the generated values into `.env`, then configure your MongoDB connection:

```dotenv
APP_SECRET_KEY=<your-generated-application-secret>
MASTER_KEY=<your-generated-base64-encoded-32-byte-key>
MONGO_URI=<your-mongodb-connection-string>
MONGO_DB_NAME=secureshare
FLASK_DEBUG=0
```

Replace the placeholders with your own values. Do not share your actual secrets or commit `.env` to Git.

**Key management warning:** Losing or changing the master key can make previously encrypted files unrecoverable. Keep protected backups of the key and never regenerate it for an existing database unless you have a proper re-encryption plan.

### 5. Start the application

```bash
python app.py
```

Open the local application at:

`http://127.0.0.1:5000`

The health endpoint is available at:

`http://127.0.0.1:5000/health`

The health endpoint reports application status and the MongoDB connection status.

## Running Tests

Activate the virtual environment and run:

```bash
python -m pytest -v
```

The current test suite contains six tests covering:

- Successful encryption and decryption
- Rejection of an incorrect encryption key
- Detection of tampered ciphertext
- GridFS collection configuration
- Denial of unauthorized private-file downloads
- Denial of downloads after a share has been revoked

These tests cover selected security behaviors, not every possible failure or attack. Complete the manual verification checklist before treating the project as fully verified.

## Project Structure

```text
BPP/
├── app.py
├── config.py
├── extensions.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── security/
│   └── user.py
├── services/
│   ├── encryption.py
│   └── storage.py
├── routes/
│   ├── auth.py
│   ├── dashboard.py
│   └── files.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
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

## Limitations and Future Improvements

- Use a persistent rate-limit storage backend for multi-worker or production deployments.
- Add broader automated tests for uploads, integrity failures, registration, sharing and revocation.
- Improve encryption-key rotation and recovery procedures.
- Add additional monitoring and security review before any production deployment.
- Configure HTTPS and secure cookies when deployed over HTTPS.
- Consider client-side encryption if end-to-end confidentiality becomes a requirement.

## Academic Context

**Subject:** Cryptography and Network Security  
**Project:** SecureShare — Secure File Storage and Sharing System

This project demonstrates practical applications of authenticated encryption, password hashing, integrity verification, access control and secure web development.

---

*SecureShare is an academic project and should undergo further testing and security review before production use.*
