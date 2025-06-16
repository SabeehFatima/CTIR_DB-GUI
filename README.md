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


## Installation Guide

### 1. Database Setup
Run these on bash
# PostgreSQL
sudo apt-get install postgresql postgresql-contrib
sudo -u postgres createdb threat_db
sudo -u postgres psql -c "CREATE USER db_user WITH PASSWORD 'securepassword';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE threat_db TO db_user;"

### 2. Application Installation
git clone https://github.com/group10/cyberthreat-system.git
cd cyberthreat-system

### Setup Virtual Environment
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

### Usage Examples
Admin Operations
# Add new threat
threat = Threat(
    threat_type="Phishing",
    description="Email scam targeting employees",
    risk_id=2
)
db.session.add(threat)
db.session.commit()

### User Search

-- Sample query from user panel
SELECT * FROM vulnerability 
WHERE description LIKE '%SQL injection%'
ORDER BY published_date DESC
LIMIT 10;

## Team Contributions

| Member    | Role           | Key Contributions |
|-----------|----------------|-------------------|
| **Ejaz**  | Frontend Dev   | - Designed admin/user panel interfaces<br>- Implemented interactive CRUD forms<br>- Created search functionality UI |
| **Tayyaba** | Frontend Dev  | - Built authentication screens (login/register)<br>- Developed dashboard layouts<br>- Optimized mobile responsiveness |
| **Sabeeh** | Backend Dev   | - Implemented database models (14 tables)<br>- Created API endpoints for CRUD operations<br>- Developed role-based authentication system |
| **Laiba**  | Project Integrator | - Merged frontend/backend components<br>- Resolved system dependencies<br>- Performed end-to-end testing<br>- Prepared deployment packages |


