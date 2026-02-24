from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from datetime import datetime, timedelta
from sqlalchemy import func
import re
import threading
import time
import psutil

import models
from models import db, User, LoginAttempt, Alert, UserActivity

app = Flask(__name__)
app.config.from_object(Config)

# Initialize DB
models.db.init_app(app)

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Password Strength Checker Utility
class PasswordStrengthAnalyzer:
    """Analyzes and provides feedback on password strength"""
    
    @staticmethod
    def check_password_strength(password):
        """
        Analyze password strength and return detailed feedback
        Returns: {
            'score': int (0-5),
            'level': str ('weak', 'fair', 'good', 'strong'),
            'feedback': list of str,
            'meets_requirements': dict
        }
        """
        score = 0
        feedback = []
        meets_requirements = {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'number': False,
            'special': False
        }
        
        # Check length
        if len(password) >= 8:
            meets_requirements['length'] = True
            score += 1
        else:
            feedback.append(f"Password is too short. Use at least 8 characters ({len(password)}/8)")
        
        # Check uppercase
        if re.search(r'[A-Z]', password):
            meets_requirements['uppercase'] = True
            score += 1
        else:
            feedback.append("Add at least one uppercase letter (A-Z)")
        
        # Check lowercase
        if re.search(r'[a-z]', password):
            meets_requirements['lowercase'] = True
            score += 1
        else:
            feedback.append("Add at least one lowercase letter (a-z)")
        
        # Check number
        if re.search(r'[0-9]', password):
            meets_requirements['number'] = True
            score += 1
        else:
            feedback.append("Add at least one number (0-9)")
        
        # Check special character
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'\"\\|,.<>\/?]', password):
            meets_requirements['special'] = True
            score += 1
        else:
            feedback.append("Add at least one special character (!@#$%^&*)")
        
        # Extra length bonus
        if len(password) >= 12:
            score += 0.5
        if len(password) >= 16:
            score += 0.5
        
        # Determine level
        if score >= 4.5:
            level = 'strong'
        elif score >= 3.5:
            level = 'good'
        elif score >= 2.5:
            level = 'fair'
        else:
            level = 'weak'
        
        return {
            'score': min(score, 5),
            'level': level,
            'feedback': feedback,
            'meets_requirements': meets_requirements
        }
    
    @staticmethod
    def is_weak_password(password):
        """Quick check if password is weak"""
        analysis = PasswordStrengthAnalyzer.check_password_strength(password)
        return analysis['level'] == 'weak'

@app.route('/api/check-password-strength', methods=['POST'])
def check_password_strength_api():
    """API endpoint to check password strength"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return {'error': 'Password required'}, 400
    
    analysis = PasswordStrengthAnalyzer.check_password_strength(password)
    return analysis, 200

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# ---------------- DASHBOARD ----------------
@app.route('/')
@login_required
def dashboard():
    # Get dashboard statistics
    total_users = User.query.count()
    total_login_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    # automatically mark the displayed alerts as read
    for a in alerts:
        if not a.is_read:
            a.is_read = True
    models.db.session.commit()
    unread_alerts = Alert.query.filter_by(is_read=False).count()
    
    # Get activity data for last 7 days
    last_7_days = datetime.utcnow() - timedelta(days=7)
    daily_logins = db.session.query(
        func.date(LoginAttempt.timestamp).label('date'),
        func.count(LoginAttempt.id).label('count')
    ).filter(LoginAttempt.timestamp >= last_7_days).group_by(
        func.date(LoginAttempt.timestamp)
    ).all()
    
    # Format data for login activity chart
    chart_labels = [str(item[0]) for item in daily_logins]
    chart_data = [item[1] for item in daily_logins]
    
    # Get failed attempts data for last 7 days
    daily_failed_logins = db.session.query(
        func.date(LoginAttempt.timestamp).label('date'),
        func.count(LoginAttempt.id).label('count')
    ).filter(
        LoginAttempt.timestamp >= last_7_days,
        LoginAttempt.success == False
    ).group_by(func.date(LoginAttempt.timestamp)).all()
    
    failed_chart_labels = [str(item[0]) for item in daily_failed_logins]
    failed_chart_data = [item[1] for item in daily_failed_logins]
    
    # Get user activity data by username for last 7 days
    user_activity_data = db.session.query(
        UserActivity.username,
        func.count(UserActivity.id).label('sessions')
    ).filter(UserActivity.login_time >= last_7_days).group_by(
        UserActivity.username
    ).order_by(func.count(UserActivity.id).desc()).limit(10).all()
    
    user_activity_labels = [item[0] for item in user_activity_data]
    user_activity_values = [item[1] for item in user_activity_data]
    
    # Get successful vs failed login ratio
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

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = models.User.query.filter_by(username=username).first()
        success = False

        if user and user.check_password(password):
            login_user(user)
            success = True
            # record successful attempt
            attempt = LoginAttempt(username=username, success=True, timestamp=datetime.utcnow(), ip_address=request.remote_addr)
            models.db.session.add(attempt)
            # record user activity entry (include id for NOT NULL constraint)
            activity = UserActivity(user_id=user.id,
                                     username=username,
                                     login_time=datetime.utcnow(),
                                     ip_address=request.remote_addr)
            models.db.session.add(activity)
            models.db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            # record failed attempt
            attempt = LoginAttempt(username=username, success=False, timestamp=datetime.utcnow(), ip_address=request.remote_addr)
            models.db.session.add(attempt)
            models.db.session.commit()

    return render_template('login.html')

# ---------------- LOGOUT ----------------
@app.route('/logout')
@login_required
def logout():
    # update the most recent activity for this user
    last_activity = UserActivity.query.filter_by(user_id=current_user.id, logout_time=None).order_by(UserActivity.login_time.desc()).first()
    if last_activity:
        last_activity.logout_time = datetime.utcnow()
        models.db.session.commit()

    logout_user()
    return redirect(url_for('login'))

# ---------------- ACTIVITY ----------------
@app.route('/activity')
@login_required
def activity():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    if current_user.role == 'admin':
        query = UserActivity.query.order_by(UserActivity.login_time.desc())
    else:
        query = UserActivity.query.filter_by(user_id=current_user.id).order_by(UserActivity.login_time.desc())
    activities = query.paginate(page=page, per_page=per_page)

    total_active_sessions = UserActivity.query.filter(UserActivity.logout_time == None).count()
    total_users_active = UserActivity.query.filter(UserActivity.logout_time == None).distinct(UserActivity.username).count()

    return render_template('activity.html', user=current_user, activities=activities,
                           total_active_sessions=total_active_sessions,
                           total_users_active=total_users_active)

# ---------------- FAILED LOGINS ----------------
@app.route('/failed_logins')
@login_required
def failed_logins():
    if current_user.role != 'admin':
        flash("Access Denied! Admins only.")
        return redirect(url_for('dashboard'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = LoginAttempt.query.filter_by(success=False).order_by(LoginAttempt.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page)

    since = datetime.utcnow() - timedelta(hours=24)
    recent = LoginAttempt.query.filter(LoginAttempt.timestamp >= since, LoginAttempt.success == False)
    total_failed_today = recent.count()
    unique_usernames = recent.with_entities(LoginAttempt.username).distinct().count()
    unique_ips = recent.with_entities(LoginAttempt.ip_address).distinct().count()

    return render_template('failed_logins.html', user=current_user,
                           failed_logins=pagination,
                           total_failed_today=total_failed_today,
                           unique_usernames=unique_usernames,
                           unique_ips=unique_ips)

# ---------------- MONITOR ----------------
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
            models.Alert.query.filter(models.Alert.created_at < five_minutes_ago).delete()
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