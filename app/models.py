from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Threat(db.Model):
    threat_id = db.Column(db.Integer, primary_key=True)  # primary key
    threat_type = db.Column(db.String(100), nullable=False)  # threat type
    description = db.Column(db.Text)
    date_detected = db.Column(db.DateTime)
    risk_id = db.Column(db.Integer)
    malware_id = db.Column(db.Integer)

    def __repr__(self):
        return f'<Threat {self.threat_id} - {self.threat_type}>'

class Risk(db.Model):
    __tablename__ = 'risk' 
    risk_id = db.Column(db.Integer, primary_key=True)
    risk_name = db.Column(db.String(100), nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<Risk {self.risk_id} - {self.risk_name}>'

class Vulnerability(db.Model):
    __tablename__ = 'vulnerability'
    
    vulnerability_id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20))
    description = db.Column(db.Text)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.risk_id'))
    published_date = db.Column(db.Date)
    
    risk = db.relationship('Risk', backref='vulnerability')

class Malware(db.Model):
    __tablename__ = 'malware'
    
    malware_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    family = db.Column(db.String(100))
    behavior_desc = db.Column(db.Text)

class Incident(db.Model):
    __tablename__ = 'incident'
    incident_id = db.Column(db.Integer, primary_key=True)
    incident_date = db.Column(db.DateTime)
    AffectedSystem_IP = db.Column(db.String(45))  
    exploit_id = db.Column(db.Integer)
    threat_id = db.Column(db.Integer)
    AffectedSystem_OS = db.Column(db.String(100))
    AffectedSystem_host = db.Column(db.String(100))
    source_id = db.Column(db.Integer)


class Exploit(db.Model):
    __tablename__ = 'exploit'
    exploit_id = db.Column(db.Integer, primary_key=True)
    exploit_type = db.Column(db.String(100), nullable=False)
    exploit_description = db.Column(db.Text)
    date = db.Column(db.DateTime)
    vulnerability_id = db.Column(db.Integer)

class DataSource(db.Model):
    __tablename__ = 'data_source'
    source_id = db.Column(db.String(100), primary_key=True)
    platform_name = db.Column(db.String(100), nullable=False)
    URL = db.Column(db.String(255), unique=True)
    data_format = db.Column(db.String(50))
    organization = db.Column(db.String(100))
    reliability_score = db.Column(db.Numeric(3,2), default=0.00)

class Attacker(db.Model):
    __tablename__ = 'attacker'
    attacker_id = db.Column(db.Integer, primary_key=True)
    attacker_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50))

class IncidentResponse(db.Model):
    __tablename__ = 'incident_response'
    response_id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer)
    response_action = db.Column(db.Text)
    response_date = db.Column(db.DateTime)