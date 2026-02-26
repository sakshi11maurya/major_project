# from flask_sqlalchemy import SQLAlchemy 
# from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import UserMixin
# from datetime import datetime

# db = SQLAlchemy()

# class User(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(150), unique=True, nullable=False)
#     password_hash = db.Column(db.String(150), nullable=False)
#     role = db.Column(db.String(50), nullable=False)

#     def set_password(self, password):
#         self.password_hash = generate_password_hash(password)

#     def check_password(self, password):
#         return check_password_hash(self.password_hash, password)

# # ✅ ONLY ONE Alert class
# class Alert(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     message = db.Column(db.String(200))
#     level = db.Column(db.String(20))
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     is_read = db.Column(db.Boolean, default=False)


# # track login attempts for analytics and security
# class LoginAttempt(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(150), nullable=False)
#     ip_address = db.Column(db.String(45))
#     timestamp = db.Column(db.DateTime, default=datetime.utcnow)
#     success = db.Column(db.Boolean, nullable=False, default=False)


# # store user activity (login/logout) for monitoring
# class UserActivity(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     username = db.Column(db.String(150), nullable=False)
#     login_time = db.Column(db.DateTime, default=datetime.utcnow)
#     logout_time = db.Column(db.DateTime)
#     ip_address = db.Column(db.String(45))

#     # relationship back to User could be useful
#     user = db.relationship('User', backref=db.backref('activities', lazy='dynamic'))

#     def get_duration_display(self):
#         """Return a human-readable string of the session duration."""
#         end = self.logout_time or datetime.utcnow()
#         duration = end - self.login_time
#         seconds = int(duration.total_seconds())
#         hours, remainder = divmod(seconds, 3600)
#         minutes, secs = divmod(remainder, 60)
#         return f"{hours}h {minutes}m {secs}s"


from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# ---------------- USER ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ---------------- ALERT ----------------
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200))
    level = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


# ---------------- LOGIN ATTEMPT ----------------
class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False, default=False)


# ---------------- USER ACTIVITY ----------------
class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))

    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic'))

    def get_duration_display(self):
        """Return a human-readable string of the session duration."""
        end = self.logout_time or datetime.utcnow()
        duration = end - self.login_time
        seconds = int(duration.total_seconds())
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours}h {minutes}m {secs}s"


# ---------------- LOGIN ACTIVITY (ACCESS MANAGEMENT) ----------------
class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(50))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)