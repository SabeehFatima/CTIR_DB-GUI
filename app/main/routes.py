from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from app.main import bp
from app import db, login_manager
from app.models import User
from urllib.parse import urlparse
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from app.utils import roles_required
from flask import render_template, abort
from app.main import bp


# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from sqlalchemy import text

def call_stored_procedure(proc_name, *args):
    placeholders = ','.join([f':arg{i}' for i in range(len(args))])
    sql = f"CALL {proc_name}({placeholders})"
    params = {f'arg{i}': arg for i, arg in enumerate(args)}
    with db.engine.connect() as conn:
        result = conn.execute(text(sql), params)
        rows = result.fetchall()  # fetch all rows returned by the procedure
    return rows


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

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@bp.route('/')
def index():
    return render_template('home.html')

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

# Admin panel route - only accessible to admins
@bp.route('/admin_panel')
@login_required
@roles_required('admin')
def admin_panel():
    if current_user.role != 'admin':
        abort(403)
    threats = call_stored_procedure('search_threat', '')  # call search_threat proc
    threats_list = [dict(row._mapping) for row in threats]
    return render_template('admin_panel.html', threats=threats_list)


@bp.route('/insert_threat', methods=['POST'])
@login_required
@roles_required('admin')
def insert_threat():
    id = request.form.get('id')
    name = request.form.get('name')
    description = request.form.get('description')
    try:
        call_stored_procedure('insert_threat', id, name, description)
        flash('Threat inserted successfully!', 'success')
    except Exception as e:
        flash(f'Error inserting threat: {e}', 'danger')
    return redirect(url_for('main.admin_panel'))


@bp.route('/update_threat', methods=['POST'])
@login_required
@roles_required('admin')
def update_threat():
    id = request.form.get('id')
    name = request.form.get('name')
    description = request.form.get('description')
    try:
        call_stored_procedure('update_threat', id, name, description)
        flash('Threat updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating threat: {e}', 'danger')
    return redirect(url_for('main.admin_panel'))


@bp.route('/delete_threat', methods=['POST'])
@login_required
@roles_required('admin')
def delete_threat():
    id = request.form.get('id')
    try:
        call_stored_procedure('delete_threat', id)
        flash('Threat deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting threat: {e}', 'danger')
    return redirect(url_for('main.admin_panel'))
