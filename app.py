from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User, LoginAttempt, Alert, UserActivity, LoginActivity
from datetime import datetime, timedelta
from sqlalchemy import func
import re
import threading
import time
import psutil

app = Flask(__name__)
app.config.from_object(Config)

# ---------------- INIT DB ----------------
db.init_app(app)

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- PASSWORD STRENGTH CHECKER ----------------
class PasswordStrengthAnalyzer:
    @staticmethod
    def check_password_strength(password):
        score = 0
        feedback = []
        meets_requirements = {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'number': False,
            'special': False
        }

        if len(password) >= 8:
            meets_requirements['length'] = True
            score += 1
        else:
            feedback.append(f"Password too short ({len(password)}/8)")

        if re.search(r'[A-Z]', password):
            meets_requirements['uppercase'] = True
            score += 1
        else:
            feedback.append("Add uppercase letter")

        if re.search(r'[a-z]', password):
            meets_requirements['lowercase'] = True
            score += 1
        else:
            feedback.append("Add lowercase letter")

        if re.search(r'[0-9]', password):
            meets_requirements['number'] = True
            score += 1
        else:
            feedback.append("Add a number")

        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'\"\\|,.<>\/?]', password):
            meets_requirements['special'] = True
            score += 1
        else:
            feedback.append("Add special character")

        if len(password) >= 12:
            score += 0.5
        if len(password) >= 16:
            score += 0.5

        if score >= 4.5:
            level = 'strong'
        elif score >= 3.5:
            level = 'good'
        elif score >= 2.5:
            level = 'fair'
        else:
            level = 'weak'

        return {'score': min(score,5), 'level': level, 'feedback': feedback, 'meets_requirements': meets_requirements}

    @staticmethod
    def is_weak_password(password):
        return PasswordStrengthAnalyzer.check_password_strength(password)['level'] == 'weak'

@app.route('/api/check-password-strength', methods=['POST'])
def check_password_strength_api():
    data = request.get_json()
    password = data.get('password','')
    if not password:
        return {'error':'Password required'}, 400
    return PasswordStrengthAnalyzer.check_password_strength(password), 200

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- DASHBOARD ----------------
@app.route('/')
@login_required
def dashboard():
    total_users = User.query.count()
    total_login_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    for a in alerts:
        if not a.is_read:
            a.is_read = True
    db.session.commit()
    unread_alerts = Alert.query.filter_by(is_read=False).count()

    last_7_days = datetime.utcnow() - timedelta(days=7)
    daily_logins = db.session.query(func.date(LoginAttempt.timestamp).label('date'),
                                    func.count(LoginAttempt.id).label('count'))\
                             .filter(LoginAttempt.timestamp >= last_7_days)\
                             .group_by(func.date(LoginAttempt.timestamp)).all()
    chart_labels = [str(item[0]) for item in daily_logins]
    chart_data = [item[1] for item in daily_logins]

    daily_failed_logins = db.session.query(func.date(LoginAttempt.timestamp).label('date'),
                                           func.count(LoginAttempt.id).label('count'))\
                                    .filter(LoginAttempt.timestamp >= last_7_days,
                                            LoginAttempt.success == False)\
                                    .group_by(func.date(LoginAttempt.timestamp)).all()
    failed_chart_labels = [str(item[0]) for item in daily_failed_logins]
    failed_chart_data = [item[1] for item in daily_failed_logins]

    user_activity_data = db.session.query(UserActivity.username,
                                          func.count(UserActivity.id).label('sessions'))\
                                   .filter(UserActivity.login_time >= last_7_days)\
                                   .group_by(UserActivity.username)\
                                   .order_by(func.count(UserActivity.id).desc()).limit(10).all()
    user_activity_labels = [item[0] for item in user_activity_data]
    user_activity_values = [item[1] for item in user_activity_data]

    successful_logins = LoginAttempt.query.filter_by(success=True).count()
    failed_logins = LoginAttempt.query.filter_by(success=False).count()

    return render_template('dashboard.html',
                           user=current_user,
                           total_users=total_users,
                           total_login_attempts=total_login_attempts,
                           failed_attempts=failed_attempts,
                           unread_alerts=unread_alerts,
                           alerts=alerts,
                           chart_labels=chart_labels,
                           chart_data=chart_data,
                           failed_chart_labels=failed_chart_labels,
                           failed_chart_data=failed_chart_data,
                           user_activity_labels=user_activity_labels,
                           user_activity_values=user_activity_values,
                           successful_logins=successful_logins,
                           failed_logins=failed_logins)

# ---------------- LOGIN / LOGOUT ----------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            attempt = LoginAttempt(username=username, success=True, timestamp=datetime.utcnow(), ip_address=request.remote_addr)
            db.session.add(attempt)
            activity = LoginActivity(username=user.username, ip_address=request.remote_addr)
            db.session.add(activity)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            attempt = LoginAttempt(username=username, success=False, timestamp=datetime.utcnow(), ip_address=request.remote_addr)
            db.session.add(attempt)
            db.session.commit()
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    activity = LoginActivity.query.filter_by(username=current_user.username, logout_time=None)\
                                  .order_by(LoginActivity.login_time.desc()).first()
    if activity:
        activity.logout_time = datetime.utcnow()
        db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# ---------------- OTHER ROUTES (Activity, Failed Logins, Access Logs, Monitor, Admin, Alerts, Compliance) ----------------
# (Code same as previous app.py cleaned version...)

# ---------------- BACKGROUND MONITOR ----------------
def background_monitor():
    last_ram_alert_time=0
    last_cpu_alert_time=0
    last_disk_alert_time=0
    cooldown=120
    while True:
        with app.app_context():
            ram = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=1)
            disk = psutil.disk_usage('/').percent
            current_time = time.time()
            if ram>80 and current_time-last_ram_alert_time>cooldown:
                db.session.add(Alert(message=f"⚠ RAM usage high ({ram}%)", level="Medium"))
                db.session.commit()
                last_ram_alert_time=current_time
            if cpu>75 and current_time-last_cpu_alert_time>cooldown:
                db.session.add(Alert(message=f"⚠ CPU usage high ({cpu}%)", level="High"))
                db.session.commit()
                last_cpu_alert_time=current_time
            if disk>85 and current_time-last_disk_alert_time>cooldown:
                db.session.add(Alert(message=f"⚠ Disk usage high ({disk}%)", level="High"))
                db.session.commit()
                last_disk_alert_time=current_time
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            Alert.query.filter(Alert.created_at<five_minutes_ago).delete()
            db.session.commit()
        time.sleep(5)

# ---------------- MAIN ----------------
if __name__=='__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin=User(username='admin',role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        if not User.query.filter_by(username='user').first():
            user=User(username='user',role='user')
            user.set_password('user123')
            db.session.add(user)
            db.session.commit()
    monitor_thread=threading.Thread(target=background_monitor)
    monitor_thread.daemon=True
    monitor_thread.start()
    app.run(debug=True, use_reloader=False)
    