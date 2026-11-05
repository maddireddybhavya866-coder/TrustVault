# TrustVault

A secure document sharing web application built with Flask. It supports role-based access control so that admins, owners, and viewers each get the right level of access to documents.

**Live demo:** https://trustvault-6fr7.onrender.com
(Free hosting: the first load may take 30 to 60 seconds.)

## Features

- User registration and login
- Role-based access: admin, owner, viewer
- Upload and share documents securely
- Admin panel to manage users
- Security tests with pytest

## Tech Stack

- Python, Flask, Flask-Login
- SQLite
- HTML, CSS (Jinja templates)
- Gunicorn, deployed on Render

## Run locally

1. Clone the repository
2. Create a virtual environment and activate it
3. Install dependencies: `pip install -r requirements.txt`
4. Set environment variables: `SECRET_KEY`, `DEMO_ADMIN_PASSWORD`, `DEMO_OWNER_PASSWORD`, `DEMO_VIEWER_PASSWORD`
5. Run: `python app.py`

## Run tests

pytest

## Author

Bhavya Sri