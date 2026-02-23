from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User, Alert
import threading
import time
import psutil

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

        user = User.query.filter_by(username=username).first()

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

# ---------------- BACKGROUND MONITOR ----------------
def background_monitor():
    last_ram_alert_time = 0
    last_cpu_alert_time = 0
    last_disk_alert_time = 0

    cooldown = 120   # 2 minutes cooldown

    while True:
        with app.app_context():
            ram = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/').percent

            current_time = time.time()

            # RAM ALERT
            if ram > 80:
                if current_time - last_ram_alert_time > cooldown:
                    db.session.add(Alert(
                        message=f"⚠ RAM usage high ({ram}%)",
                        level="Medium"
                    ))
                    db.session.commit()
                    last_ram_alert_time = current_time
            else:
                last_ram_alert_time = 0


            # CPU ALERT
            if cpu > 75:
                if current_time - last_cpu_alert_time > cooldown:
                    db.session.add(Alert(
                        message=f"⚠ CPU usage high ({cpu}%)",
                        level="High"
                    ))
                    db.session.commit()
                    last_cpu_alert_time = current_time
            else:
                last_cpu_alert_time = 0


            # DISK ALERT
            if disk > 85:
                if current_time - last_disk_alert_time > cooldown:
                    db.session.add(Alert(
                        message=f"⚠ Disk space high ({disk}%)",
                        level="High"
                    ))
                    db.session.commit()
                    last_disk_alert_time = current_time
            else:
                last_disk_alert_time = 0

        time.sleep(5)


            # DISK ALERT
        if disk > 85 and not disk_alert_active:
                alert = Alert(message=f"⚠ Disk almost full ({disk}%)", level="High")
                db.session.add(alert)
                disk_alert_active = True

        elif disk < 80:
                disk_alert_active = False

        db.session.commit()

        time.sleep(10)
# ---------------- ALERTS ----------------
@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/reset_alerts')
def reset_alerts():
    Alert.query.delete()
    db.session.commit()
    return "All Alerts Deleted Successfully!"

# ---------------- MAIN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not Alert.query.first():
            a1 = Alert(message="Unauthorized login attempt", level="High")
            a2 = Alert(message="Password changed successfully", level="Medium")
            db.session.add(a1)
            db.session.add(a2)
            db.session.commit()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

        if not User.query.filter_by(username='user').first():
            user = User(username='user', role='user')
            user.set_password('user123')
            db.session.add(user)
            db.session.commit()

    monitor_thread = threading.Thread(target=background_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()

app.run(debug=True, use_reloader=False)