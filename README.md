# CyberThreat Intelligence and Incident Response System

## Overview
A comprehensive security management platform for tracking cyber threats, vulnerabilities, and incidents. Features role-based access with admin CRUD operations and user search capabilities across all database tables.

## Features
- **Admin Panel**:
  - Full CRUD for Threats/Risks
  - Bulk operations
  - Data validation

- **User Panel**:
  - Unified search across 14 tables
  - Advanced filtering
  - Paginated results

- **Security**:
  - Password hashing
  - Session management
  - Role-based views

## System Requirements
### Essential
| Component | Requirement |
|-----------|-------------|
| OS | Windows 10+/macOS 10.15+/Linux Ubuntu 20.04+ |
| Python | 3.8+ with pip |
| Database | PostgreSQL 12+ (SQLite for development) |
| RAM | 2GB minimum (4GB recommended) |

### Python Packages
Listed in `requirements.txt`:

Flask==2.0.3
Flask-Login==0.5.0
Flask-SQLAlchemy==3.0.2
Werkzeug==2.0.3
WTForms==3.0.1
psycopg2-binary==2.9.3

text

## Installation Guide

### 1. Database Setup
```bash
# PostgreSQL
sudo apt-get install postgresql postgresql-contrib
sudo -u postgres createdb threat_db
sudo -u postgres psql -c "CREATE USER db_user WITH PASSWORD 'securepassword';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE threat_db TO db_user;"
2. Application Installation
bash
git clone https://github.com/group10/cyberthreat-system.git
cd cyberthreat-system

venv\Scripts\activate    # Windows

pip install -r requirements.txt

## Configure environment
echo "FLASK_APP=app" > .flaskenv
echo "DATABASE_URL=postgresql://db_user:securepassword@localhost/threat_db" > .env
3. Initialize Database
bash
flask db init
flask db migrate -m "Initial tables"
flask db upgrade
Running the Application
bash
flask run --host=0.0.0.0 --port=5000
Access: http://localhost:5000

### Code Structure
text
├── app/
│   ├── __init__.py             # App factory
│   ├── models.py               # 14 SQLAlchemy models
│   ├── routes.py               # 25+ view functions
│   ├── templates/
│   │   ├── admin/              # 5 admin templates
│   │   ├── user/               # 3 user templates
│   │   └── auth/               # Auth templates
│   └── static/
│       ├── css/                # Custom styles
│       └── js/                 # Interactive scripts
├── migrations/                 # Alembic migrations
├── tests/                      # Unit tests
├── requirements.txt            # Dependencies
└── README.md                   # This file
Database Schema
Key tables:

python
class Threat(db.Model):
    __tablename__ = 'threat'
    threat_id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(100), nullable=False)
    # ... (other columns)

class Risk(db.Model):
    __tablename__ = 'risk'
    risk_id = db.Column(db.Integer, primary_key=True)
    risk_name = db.Column(db.String(100), nullable=False)
    # ... (other columns)
Full ER Diagram: er_diagram.pdf

### Usage Examples
Admin Operations
python
# Add new threat
threat = Threat(
    threat_type="Phishing",
    description="Email scam targeting employees",
    risk_id=2
)
db.session.add(threat)
db.session.commit()
User Search
sql
-- Sample query from user panel
SELECT * FROM vulnerability 
WHERE description LIKE '%SQL injection%'
ORDER BY published_date DESC
LIMIT 10;

Team Contributions
Member	Role	Key Contributions
John D.	Lead	Database design, Admin CRUD
Sarah K.	Dev	User search, Authentication
Alex M.	UI	Frontend templates, CSS
License
MIT License - See full license text

Copyright 2023 - Group 10 Cybersecurity Project



