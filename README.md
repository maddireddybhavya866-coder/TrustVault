# TrustVault – Secure Document Sharing

A learning/demo Flask application for document-level access control and audit logging.

## Features
- Authentication with hashed passwords.
- Roles: administrator, owner, viewer.
- Per-document read/edit grants and immediate revocation on subsequent requests.
- Private file storage using random server-side filenames.
- Upload extension allowlist and 10 MB limit.
- Server-side authorization on read, edit, delete and download routes.
- Search by title/filename/owner, category and upload date.
- Audit events with a SHA-256 hash chain and verification indicator.
- Automated tests for cross-user denial, grant/revoke and audit tampering.

## Run locally (Python 3.10+)
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
```
Set a strong secret before running:
```powershell
$env:SECRET_KEY="replace-with-a-long-random-secret"
```
Initialize and start:
```bash
python -c "from app import init_db; init_db()"
python app.py
```x
Open http://127.0.0.1:5000
Demo accounts:
Configure demo account passwords using environment variables before
the first database initialization. Never commit credentials to GitHub.

## Tests
```bash
pytest -q
```

## Deployment notes
- Use a persistent disk/volume for both `DATABASE_PATH` and `UPLOAD_DIR`; ephemeral filesystems lose data on restart.
- Set `SECRET_KEY` to a cryptographically random secret.
- Set `COOKIE_SECURE=1` behind HTTPS.
- Set `FLASK_DEBUG=0`.
- Use a managed database and private object storage for production.
- Do not expose `private_uploads/` as a static/public directory.
- Configure backups, rate limiting, CSRF protection, malware scanning and external immutable audit storage before real confidential use.

## Important limitations to disclose
This is a challenge starter, not a production-certified document vault. The upload validator checks extension and size, not actual file signatures or malware. Audit hash chaining detects many database edits but cannot stop a privileged database operator from rewriting the entire chain. CSRF protection, rate limiting, email verification, password reset, malware scanning, backup/restore, file versioning and external immutable audit storage are not implemented in this starter. Do not use real confidential documents.

## Role model
- Admin: global document visibility and administrative user/audit dashboard.
- Owner: upload/manage own documents; grant/revoke document-level read/edit access.
- Viewer: access only documents explicitly shared with them.
- Edit permission includes read permission.
