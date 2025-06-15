from flask import render_template, redirect, url_for, flash, request, abort, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.main import bp
from app import db, login_manager
import traceback
from app.models import (
    User,Threat, Risk, Vulnerability, Malware,
    Incident, Exploit, IncidentResponse, Attacker, DataSource
)
from urllib.parse import urlparse
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from app.utils import roles_required
from datetime import datetime
from sqlalchemy import or_, cast, String
from app.utils import call_stored_procedure

# Login and registration forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Auth routes
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('main.login'))
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.dashboard')
        return redirect(next_page)
    return render_template('login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@bp.route('/')
def index():
    return render_template('home.html')

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        is_first_user = User.query.count() == 0
        role = 'admin' if is_first_user else 'user'
        user = User(username=form.username.data, role=role)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now registered!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)


@bp.route('/user_panel', methods=['GET'])
@login_required
def user_panel():
    keyword = request.args.get('search', '').strip()
    table = request.args.get('table', '').strip().lower()
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Configuration for searchable tables
    table_configs = {
        'threat': {
            'display_name': 'Threats',
            'fields': ['threat_type', 'description', 'date_detected'],
            'search_fields': ['threat_type', 'description'],
            'model': Threat
        },
        'risk': {
            'display_name': 'Risks',
            'fields': ['risk_name', 'risk_level'],
            'search_fields': ['risk_name', 'risk_level'],
            'model': Risk
        },
        'malware': {
            'display_name': 'Malware',
            'fields': ['name', 'family', 'behavior_desc'],
            'search_fields': ['name', 'family', 'behavior_desc'],
            'model': Malware
        },
        'vulnerability': {
            'display_name': 'Vulnerabilities',
            'fields': ['cve_id', 'description', 'published_date'],
            'search_fields': ['cve_id', 'description'],
            'model': Vulnerability
        },
        'incident': {
        'display_name': 'Incidents',
        'fields': ['incident_id', 'incident_date', 'AffectedSystem_IP', 'AffectedSystem_OS', 'AffectedSystem_host'],
        'search_fields': ['AffectedSystem_IP', 'AffectedSystem_OS', 'AffectedSystem_host'],
         'model': Incident
       },
        'exploit': {
            'display_name': 'Exploits',
            'fields': ['exploit_id', 'exploit_type', 'exploit_description', 'date'],
            'search_fields': ['exploit_type', 'exploit_description'],
            'model': Exploit
        },
        'data_source': {
            'display_name': 'Data Sources',
            'fields': ['source_id', 'platform_name', 'URL', 'data_format', 'organization', 'reliability_score'],
            'search_fields': ['platform_name', 'URL', 'data_format', 'organization'],
            'model': DataSource
        },
        'attacker': {
            'display_name': 'Attackers',
            'fields': ['attacker_id', 'attacker_name', 'status'],
            'search_fields': ['attacker_name', 'status'],
            'model': Attacker
        },
        'incident_response': {
            'display_name': 'Incident Responses',
            'fields': ['response_id', 'incident_id', 'response_action', 'response_date'],
            'search_fields': ['response_action'],
            'model': IncidentResponse
        },
    }

    data = []
    pagination = None
    selected_table = table
    table_config = table_configs.get(table)

    if keyword and table_config:
        model = table_config['model']
        search_fields = table_config['search_fields']
        fields = table_config['fields']
        table_display = table_config['display_name']

        # Build search conditions safely by casting non-string fields to String
        conditions = []
        for field in search_fields:
            if hasattr(model, field):
                column = getattr(model, field)
                # Check column type to decide if casting is needed
                try:
                    # Cast non-string columns to String for ilike
                    if not hasattr(column.type, 'python_type') or \
                       column.type.python_type not in [str]:
                        conditions.append(cast(column, String).ilike(f'%{keyword}%'))
                    else:
                        conditions.append(column.ilike(f'%{keyword}%'))
                except Exception as e:
                    current_app.logger.error(f"Error processing field '{field}': {e}")

        try:
            query = model.query.filter(or_(*conditions)) if conditions else model.query
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)

            # Convert SQLAlchemy objects to dicts for template rendering
            for item in pagination.items:
                item_dict = {}
                for field in fields:
                    try:
                        value = getattr(item, field)
                        # Format datetime fields for display
                        if value and hasattr(value, 'strftime'):
                            if 'date' in field:
                                value = value.strftime('%Y-%m-%d')
                            elif 'time' in field:
                                value = value.strftime('%Y-%m-%d %H:%M')
                        item_dict[field] = value
                    except Exception as e:
                        current_app.logger.error(f"Error accessing field '{field}': {e}")
                        item_dict[field] = 'N/A'
                data.append(item_dict)

        except Exception as e:
            current_app.logger.error(f"Error searching {table_display}: {e}")
            current_app.logger.error(traceback.format_exc())
            flash(f"An error occurred while searching {table_display}.", "danger")
    else:
        fields = []
        table_display = ''

    return render_template('user_panel.html',
                           table=table,
                           keyword=keyword,
                           data=data,
                           pagination=pagination,
                           selected_table=selected_table,
                           fields=fields,
                           table_display=table_display)


@bp.route('/admin_panel')
@login_required
@roles_required('admin')
def admin_panel():
    threat_search = request.args.get('threat_search', '').strip()
    risk_search = request.args.get('risk_search', '').strip()

    if threat_search:
        threats = Threat.query.filter(
            or_(
                Threat.threat_id.like(f'%{threat_search}%'),
                Threat.threat_type.ilike(f'%{threat_search}%'),
                Threat.description.ilike(f'%{threat_search}%'),
                Threat.risk_id.like(f'%{threat_search}%'),
                Threat.malware_id.like(f'%{threat_search}%')
            )
        ).all()
    else:
        threats = Threat.query.all()

    if risk_search:
        risks = Risk.query.filter(
            or_(
                cast(Risk.risk_id, String).like(f'%{risk_search}%'),
                Risk.risk_name.ilike(f'%{risk_search}%'),
                Risk.risk_level.ilike(f'%{risk_search}%')
            )
        ).all()
    else:
        risks = Risk.query.all()

    return render_template('admin_panel.html', 
                           threats=threats, 
                           risks=risks, 
                           threat_search=threat_search, 
                           risk_search=risk_search)

@bp.route('/insert_threat', methods=['POST'])
@login_required
@roles_required('admin')
def insert_threat():
    threat_id = request.form.get('threat_id')
    threat_type = request.form.get('threat_type')
    description = request.form.get('description')
    date_detected = request.form.get('date_detected')
    risk_id = request.form.get('risk_id')
    malware_id = request.form.get('malware_id')

    if date_detected:
        try:
            date_detected = datetime.strptime(date_detected, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('main.admin_panel'))
    else:
        date_detected = None

    try:
        threat = Threat(
            threat_id=int(threat_id) if threat_id else None,
            threat_type=threat_type,
            description=description,
            date_detected=date_detected,
            risk_id=int(risk_id) if risk_id else None,
            malware_id=int(malware_id) if malware_id else None
        )
        db.session.add(threat)
        db.session.commit()
        flash('Threat inserted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error inserting threat: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/update_threat', methods=['POST'])
@login_required
@roles_required('admin')
def update_threat():
    threat_id = request.form.get('threat_id')
    if not threat_id or not threat_id.isdigit():
        flash('Invalid Threat ID.', 'danger')
        return redirect(url_for('main.admin_panel'))
    threat_id = int(threat_id)

    threat_type = request.form.get('threat_type')
    description = request.form.get('description')
    date_detected = request.form.get('date_detected')
    risk_id = request.form.get('risk_id')
    malware_id = request.form.get('malware_id')

    if date_detected:
        try:
            date_detected = datetime.strptime(date_detected, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('main.admin_panel'))
    else:
        date_detected = None

    threat = Threat.query.get(threat_id)
    if not threat:
        flash('Threat not found.', 'danger')
        return redirect(url_for('main.admin_panel'))

    threat.threat_type = threat_type
    threat.description = description
    threat.date_detected = date_detected
    threat.risk_id = int(risk_id) if risk_id else None
    threat.malware_id = int(malware_id) if malware_id else None

    try:
        db.session.commit()
        flash('Threat updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating threat: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/delete_threat', methods=['POST'])
@login_required
@roles_required('admin')
def delete_threat():
    threat_id = request.form.get('threat_id')
    if not threat_id or not threat_id.isdigit():
        flash('Invalid Threat ID.', 'danger')
        return redirect(url_for('main.admin_panel'))
    threat_id = int(threat_id)

    threat = Threat.query.get(threat_id)
    if not threat:
        flash('Threat not found.', 'danger')
        return redirect(url_for('main.admin_panel'))

    try:
        db.session.delete(threat)
        db.session.commit()
        flash('Threat deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting threat: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/insert_risk', methods=['POST'])
@login_required
@roles_required('admin')
def insert_risk():
    risk_id = request.form.get('risk_id')
    risk_name = request.form.get('risk_name')
    risk_level = request.form.get('risk_level')

    try:
        risk = Risk(
            risk_id=int(risk_id) if risk_id else None,
            risk_name=risk_name,
            risk_level=risk_level
        )
        db.session.add(risk)
        db.session.commit()
        flash('Risk inserted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error inserting risk: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/update_risk', methods=['POST'])
@login_required
@roles_required('admin')
def update_risk():
    risk_id = request.form.get('risk_id')
    if not risk_id or not risk_id.isdigit():
        flash('Invalid Risk ID.', 'danger')
        return redirect(url_for('main.admin_panel'))
    risk_id = int(risk_id)

    risk_name = request.form.get('risk_name')
    risk_level = request.form.get('risk_level')

    risk = Risk.query.get(risk_id)
    if not risk:
        flash('Risk not found.', 'danger')
        return redirect(url_for('main.admin_panel'))

    risk.risk_name = risk_name
    risk.risk_level = risk_level

    try:
        db.session.commit()
        flash('Risk updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating risk: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/delete_risk', methods=['POST'])
@login_required
@roles_required('admin')
def delete_risk():
    risk_id = request.form.get('risk_id')
    if not risk_id or not risk_id.isdigit():
        flash('Invalid Risk ID.', 'danger')
        return redirect(url_for('main.admin_panel'))
    risk_id = int(risk_id)

    risk = Risk.query.get(risk_id)
    if not risk:
        flash('Risk not found.', 'danger')
        return redirect(url_for('main.admin_panel'))

    try:
        db.session.delete(risk)
        db.session.commit()
        flash('Risk deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting risk: {e}', 'danger')

    return redirect(url_for('main.admin_panel'))

@bp.route('/api/search_threats')
@login_required
@roles_required('admin')
def api_search_threats():
    query = request.args.get('q', '').strip()
    
    if query:
        threats = Threat.query.filter(
            or_(
                Threat.threat_id.like(f'%{query}%'),
                Threat.threat_type.ilike(f'%{query}%'),
                Threat.description.ilike(f'%{query}%'),
                Threat.risk_id.like(f'%{query}%'),
                Threat.malware_id.like(f'%{query}%')
            )
        ).all()
    else:
        threats = Threat.query.all()
    
    threats_data = []
    for threat in threats:
        threats_data.append({
            'threat_id': threat.threat_id,
            'threat_type': threat.threat_type,
            'description': threat.description,
            'date_detected': threat.date_detected.isoformat() if threat.date_detected else None,
            'risk_id': threat.risk_id,
            'malware_id': threat.malware_id
        })
    
    return jsonify({
        'threats': threats_data,
        'count': len(threats_data),
        'query': query
    })

@bp.route('/api/search_risks')
@login_required
@roles_required('admin')
def api_search_risks():
    query = request.args.get('q', '').strip()
    
    if query:
        risks = Risk.query.filter(
            or_(
                Risk.risk_id.like(f'%{query}%'),
                Risk.risk_name.ilike(f'%{query}%'),
                Risk.risk_level.ilike(f'%{query}%')
            )
        ).all()
    else:
        risks = Risk.query.all()
    
    risks_data = []
    for risk in risks:
        risks_data.append({
            'risk_id': risk.risk_id,
            'risk_name': risk.risk_name,
            'risk_level': risk.risk_level
        })
    
    return jsonify({
        'risks': risks_data,
        'count': len(risks_data),
        'query': query
    })