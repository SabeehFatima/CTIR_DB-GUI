from flask import Flask, redirect, url_for
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_talisman import Talisman
from flask_migrate import Migrate
from datetime import datetime

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
talisman = Talisman()

class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login'))

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:s4a5b6a7@localhost/ctir_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.jinja_env.globals['now'] = datetime.now

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    talisman.init_app(app)

    login_manager.login_view = 'main.login'

    # Import models here to avoid circular imports
    from app.models import Threat

    admin = Admin(app, name='My Admin Panel', template_mode='bootstrap4')
    admin.add_view(AdminModelView(Threat, db.session))

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app
