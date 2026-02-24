from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
import models
from datetime import datetime, timedelta
import threading
import time
import psutil

app = Flask(__name__)
app.config.from_object(Config)

# Initialize DB
models.db.init_app(app)

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# ---------------- DASHBOARD ----------------
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = models.User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

# ---------------- LOGOUT ----------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------- MONITOR ----------------
@app.route('/monitor')
@login_required
def monitor():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    return render_template('monitor.html', cpu=cpu, ram=ram, disk=disk)

# ---------------- ADMIN ----------------
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash("Access Denied! Admins only.")
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

# ---------------- ALERTS ----------------
@app.route('/alerts')
@login_required
def alerts():
    all_alerts = models.Alert.query.all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/compliance')
@login_required
def compliance_check():

    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    issues = []

    # CPU Check
    if cpu < 75:
        issues.append(f"CPU usage ({cpu}%) passed")
    else:
        issues.append(f"CPU usage high ({cpu}%) failed")

    # RAM Check
    if ram < 80:
        issues.append(f"RAM usage ({ram}%) passed")
    else:
        issues.append(f"RAM usage high ({ram}%) failed")

    # Disk Check
    if disk < 85:
        issues.append(f"Disk usage ({disk}%) passed")
    else:
        issues.append(f"Disk usage high ({disk}%) failed")

    return render_template('compliance.html', issues=issues)

# ---------------- BACKGROUND MONITOR ----------------
def background_monitor():
    last_ram_alert_time = 0
    last_cpu_alert_time = 0
    last_disk_alert_time = 0
    cooldown = 120

    while True:
        with app.app_context():

            ram = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/').percent
            current_time = time.time()

            if ram > 80 and current_time - last_ram_alert_time > cooldown:
                models.db.session.add(models.Alert(message=f"⚠ RAM usage high ({ram}%)", level="Medium"))
                models.db.session.commit()
                last_ram_alert_time = current_time

            if cpu > 75 and current_time - last_cpu_alert_time > cooldown:
                models.db.session.add(models.Alert(message=f"⚠ CPU usage high ({cpu}%)", level="High"))
                models.db.session.commit()
                last_cpu_alert_time = current_time

            if disk > 85 and current_time - last_disk_alert_time > cooldown:
                models.db.session.add(models.Alert(message=f"⚠ Disk usage high ({disk}%)", level="High"))
                models.db.session.commit()
                last_disk_alert_time = current_time

            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            models.Alert.query.filter(models.Alert.timestamp < five_minutes_ago).delete()
            models.db.session.commit()

        time.sleep(5)

# ---------------- MAIN ----------------
if __name__ == '__main__':
    with app.app_context():
        models.db.create_all()

        if not models.User.query.filter_by(username='admin').first():
            admin = models.User(username='admin', role='admin')
            admin.set_password('admin123')
            models.db.session.add(admin)
            models.db.session.commit()

        if not models.User.query.filter_by(username='user').first():
            user = models.User(username='user', role='user')
            user.set_password('user123')
            models.db.session.add(user)
            models.db.session.commit()

    monitor_thread = threading.Thread(target=background_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()

    app.run(debug=True, use_reloader=False)