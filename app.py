from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
import psutil 
from config import Config
from models import db, User, LoginAttempt, Alert, UserActivity, FailedLoginAttempt
from datetime import datetime, timedelta
from sqlalchemy import func

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
    # Get dashboard statistics
    total_users = User.query.count()
    total_login_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    unread_alerts = Alert.query.filter_by(is_read=False).count()
    
    # Get activity data for last 7 days
    last_7_days = datetime.utcnow() - timedelta(days=7)
    daily_logins = db.session.query(
        func.date(LoginAttempt.timestamp).label('date'),
        func.count(LoginAttempt.id).label('count')
    ).filter(LoginAttempt.timestamp >= last_7_days).group_by(
        func.date(LoginAttempt.timestamp)
    ).all()
    
    # Format data for chart
    chart_labels = [str(item[0]) for item in daily_logins]
    chart_data = [item[1] for item in daily_logins]
    
    return render_template('dashboard.html', 
                         user=current_user,
                         total_users=total_users,
                         total_login_attempts=total_login_attempts,
                         failed_attempts=failed_attempts,
                         unread_alerts=unread_alerts,
                         alerts=alerts,
                         chart_labels=chart_labels,
                         chart_data=chart_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        user = User.query.filter_by(username=username).first()
        
        # Check if account is locked
        if user and user.is_account_locked():
            remaining_time = (user.locked_until - datetime.utcnow()).total_seconds() / 60
            flash(f'Account locked due to multiple failed login attempts. Try again in {int(remaining_time)} minutes.', 'error')
            return render_template('login.html')
        
        # Check failed attempts in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        failed_attempts = FailedLoginAttempt.query.filter(
            FailedLoginAttempt.username == username,
            FailedLoginAttempt.timestamp >= one_hour_ago
        ).count()
        
        # Track login attempt
        attempt = LoginAttempt(
            username=username,
            success=False,
            ip_address=ip_address
        )
        
        if user and user.check_password(password):
            # Successful login
            attempt.success = True
            db.session.add(attempt)
            db.session.commit()
            
            # Clear failed attempts on successful login
            FailedLoginAttempt.query.filter_by(username=username).delete()
            db.session.commit()
            
            # Create user activity record
            activity = UserActivity(
                user_id=user.id,
                username=user.username,
                login_time=datetime.utcnow(),
                ip_address=ip_address
            )
            db.session.add(activity)
            db.session.commit()
            
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            # Failed login
            failed_attempt = FailedLoginAttempt(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                password_entered=password
            )
            db.session.add(failed_attempt)
            db.session.add(attempt)
            db.session.commit()
            
            # Check if we need to lock the account
            if failed_attempts >= 3:
                if user:
                    user.is_locked = True
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    db.session.commit()
                    
                    # Create security alert
                    alert = Alert(
                        message=f'Account "{username}" locked after 4+ failed login attempts from IP {ip_address}',
                        level='critical'
                    )
                    db.session.add(alert)
                    db.session.commit()
                
                flash('Account locked due to multiple failed login attempts. Please try again in 30 minutes.', 'error')
            else:
                remaining_attempts = 3 - failed_attempts
                flash(f'Invalid username or password. {remaining_attempts} attempts remaining before account lock.', 'error')
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Update user activity with logout time
    activity = UserActivity.query.filter_by(
        user_id=current_user.id,
        logout_time=None
    ).order_by(UserActivity.login_time.desc()).first()
    
    if activity:
        activity.logout_time = datetime.utcnow()
        db.session.commit()
    
    logout_user()
    return redirect(url_for('login'))


@app.route('/monitor')
@login_required
def monitor():
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('C:\\').percent
    return render_template('monitor.html', cpu=cpu, ram=ram, disk=disk)


@app.route('/activity')
@login_required
def activity():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Admin sees all activities, users see only their own
    if current_user.role == 'admin':
        activities = UserActivity.query.order_by(
            UserActivity.login_time.desc()
        ).paginate(page=page, per_page=per_page)
        total_active_sessions = UserActivity.query.filter_by(logout_time=None).count()
        total_users_active = db.session.query(
            func.count(func.distinct(UserActivity.user_id))
        ).filter(UserActivity.logout_time == None).scalar()
    else:
        activities = UserActivity.query.filter_by(
            user_id=current_user.id
        ).order_by(
            UserActivity.login_time.desc()
        ).paginate(page=page, per_page=per_page)
        total_active_sessions = UserActivity.query.filter_by(
            user_id=current_user.id,
            logout_time=None
        ).count()
        total_users_active = 1 if total_active_sessions > 0 else 0
    
    return render_template('activity.html',
                         user=current_user,
                         activities=activities,
                         total_active_sessions=total_active_sessions,
                         total_users_active=total_users_active)


@app.route('/failed-logins')
@login_required
def failed_logins():
    # Only admins can view failed login attempts
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get failed login attempts from last 24 hours
    last_24_hours = datetime.utcnow() - timedelta(hours=24)
    failed_logins = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.timestamp >= last_24_hours
    ).order_by(
        FailedLoginAttempt.timestamp.desc()
    ).paginate(page=page, per_page=per_page)
    
    # Get statistics
    total_failed_today = FailedLoginAttempt.query.filter(
        FailedLoginAttempt.timestamp >= last_24_hours
    ).count()
    
    unique_usernames = db.session.query(
        func.count(func.distinct(FailedLoginAttempt.username))
    ).filter(FailedLoginAttempt.timestamp >= last_24_hours).scalar()
    
    unique_ips = db.session.query(
        func.count(func.distinct(FailedLoginAttempt.ip_address))
    ).filter(FailedLoginAttempt.timestamp >= last_24_hours).scalar()
    
    return render_template('failed_logins.html',
                         user=current_user,
                         failed_logins=failed_logins,
                         total_failed_today=total_failed_today,
                         unique_usernames=unique_usernames,
                         unique_ips=unique_ips)


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
        
        # Create sample alerts if not exist
        if Alert.query.count() == 0:
            alerts_data = [
                Alert(message='System security scan completed successfully', level='info'),
                Alert(message='Multiple failed login attempts detected', level='warning'),
                Alert(message='Database backup completed', level='info'),
                Alert(message='Unusual traffic detected from IP 192.168.1.100', level='warning'),
                Alert(message='SSL certificate renewal required in 30 days', level='critical'),
            ]
            for alert in alerts_data:
                db.session.add(alert)
            db.session.commit()
        
        # Create sample login attempts if not exist
        if LoginAttempt.query.count() == 0:
            base_time = datetime.utcnow()
            attempts = []
            for i in range(20):
                attempt = LoginAttempt(
                    username='admin' if i % 3 == 0 else 'user',
                    success=True if i % 4 != 0 else False,
                    timestamp=base_time - timedelta(days=i % 7, hours=i % 24),
                    ip_address='192.168.1.100'
                )
                attempts.append(attempt)
            for attempt in attempts:
                db.session.add(attempt)
            db.session.commit()
        
        # Create sample user activities if not exist
        if UserActivity.query.count() == 0:
            admin_user = User.query.filter_by(username='admin').first()
            user_user = User.query.filter_by(username='user').first()
            base_time = datetime.utcnow()
            
            activities = [
                UserActivity(
                    user_id=admin_user.id,
                    username='admin',
                    login_time=base_time - timedelta(days=5, hours=10),
                    logout_time=base_time - timedelta(days=5, hours=11),
                    ip_address='192.168.1.100'
                ),
                UserActivity(
                    user_id=user_user.id,
                    username='user',
                    login_time=base_time - timedelta(days=3, hours=14),
                    logout_time=base_time - timedelta(days=3, hours=15),
                    ip_address='192.168.1.101'
                ),
                UserActivity(
                    user_id=admin_user.id,
                    username='admin',
                    login_time=base_time - timedelta(days=2, hours=9),
                    logout_time=base_time - timedelta(days=2, hours=12),
                    ip_address='192.168.1.100'
                ),
                UserActivity(
                    user_id=user_user.id,
                    username='user',
                    login_time=base_time - timedelta(hours=4),
                    logout_time=None,
                    ip_address='10.0.0.50'
                ),
                UserActivity(
                    user_id=admin_user.id,
                    username='admin',
                    login_time=base_time - timedelta(hours=2),
                    logout_time=base_time - timedelta(hours=1),
                    ip_address='192.168.1.100'
                ),
            ]
            
            for activity in activities:
                db.session.add(activity)
            db.session.commit()
        
        # Create sample failed login attempts if not exist
        if FailedLoginAttempt.query.count() == 0:
            base_time = datetime.utcnow()
            failed_attempts = [
                FailedLoginAttempt(username='admin', ip_address='203.0.113.45', timestamp=base_time - timedelta(hours=2)),
                FailedLoginAttempt(username='admin', ip_address='203.0.113.45', timestamp=base_time - timedelta(hours=1, minutes=50)),
                FailedLoginAttempt(username='admin', ip_address='203.0.113.45', timestamp=base_time - timedelta(hours=1, minutes=40)),
                FailedLoginAttempt(username='user', ip_address='198.51.100.20', timestamp=base_time - timedelta(minutes=45)),
                FailedLoginAttempt(username='user', ip_address='198.51.100.20', timestamp=base_time - timedelta(minutes=35)),
                FailedLoginAttempt(username='testuser', ip_address='192.0.2.50', timestamp=base_time - timedelta(minutes=30)),
                FailedLoginAttempt(username='testuser', ip_address='192.0.2.50', timestamp=base_time - timedelta(minutes=20)),
                FailedLoginAttempt(username='testuser', ip_address='192.0.2.50', timestamp=base_time - timedelta(minutes=10)),
                FailedLoginAttempt(username='hacker', ip_address='192.0.2.100', timestamp=base_time - timedelta(minutes=5)),
            ]
            for attempt in failed_attempts:
                db.session.add(attempt)
            db.session.commit()
    
    app.run(debug=True)
