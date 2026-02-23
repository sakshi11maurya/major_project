from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from config import Config
from models import db, User, Alert

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/monitor')
@login_required
def monitor():
    import psutil
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    return render_template('monitor.html', cpu=cpu, ram=ram, disk=disk)

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash("Access Denied! Admins only.")
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

@app.route('/generate_alert')
@login_required
def generate_alert():

    if current_user.role != 'admin':
        flash("Only Admin can generate alerts!")
        return redirect(url_for('dashboard'))

    import psutil
    cpu = psutil.cpu_percent()

    if cpu > 0:
        new_alert = Alert(
            message="High CPU Usage Detected!",
            level="High"
        )
        db.session.add(new_alert)
        db.session.commit()

    flash("Security Scan Completed!")
    return redirect(url_for('alerts'))

@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.all()
    return render_template('alerts.html', alerts=all_alerts)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        # Create default user if not exists
        if not User.query.filter_by(username='user').first():
            user = User(username='user', role='user')
            user.set_password('user123')
            db.session.add(user)
            db.session.commit()
    app.run(debug=True)
